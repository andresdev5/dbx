use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::audit::AuditEvent;
use crate::sql_operations::{classify_sql_operations, ResolveContext};
use dbx_authz::{
    compile, ConnectionContext, Decision, EffectivePermissions, Need, Operations, Principal, Requirement, Resource,
};

use crate::connection::session_credentials::current_credential_owner;
use crate::connection::AppState;
use crate::models::connection::{ConnectionConfig, DatabaseType};
use crate::persistence::storage::{AuthzSnapshot, Storage};

pub const PERMISSION_DENIED_PREFIX: &str = "Permission denied:";

const QUIET_READS: Operations = Operations::SELECT;

fn audit_decision(
    state: &AppState,
    principal: &Principal,
    event: &str,
    requirement: &Requirement,
    decision: &Decision,
    statement: Option<&str>,
) {
    if !state.audit.is_enabled() {
        return;
    }
    let operations = requirement.operations();
    if statement.is_none() && decision.is_allowed() && operations.difference(QUIET_READS).is_empty() {
        return;
    }
    let mut record = AuditEvent::new(event).by(principal).operations(operations);
    record = match decision {
        Decision::Allow => {
            let mut tables: Vec<String> = Vec::new();
            for need in &requirement.needs {
                if let Some(table) = &need.resource.table {
                    if !tables.contains(table) {
                        tables.push(table.clone());
                    }
                }
            }
            match requirement.needs.first() {
                Some(need) => {
                    let mut resource = need.resource.clone();
                    resource.table = None;
                    record.resource(&resource).tables(tables).allowed()
                }
                None => record.allowed(),
            }
        }
        Decision::Deny(denial) => {
            record.resource(&denial.resource).denied(denial_message(decision).unwrap_or_default())
        }
    };
    if let Some(statement) = statement {
        record = record.statement(statement);
        if decision.is_allowed() {
            crate::audit::note_pending_statement(&record.event_id);
        }
    }
    state.audit.record_in_request(record);
}

#[derive(Default)]
pub struct AuthzRuntime {
    enforced: AtomicBool,
    version: AtomicU64,
    owners: std::sync::RwLock<HashMap<String, Principal>>,
    snapshot: std::sync::RwLock<Arc<AuthzSnapshot>>,
    pool_databases: std::sync::RwLock<HashMap<String, Option<String>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrentPrincipal {
    Unenforced,
    Background,
    Known(Principal),
    Unknown,
}

fn read<T>(lock: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write<T>(lock: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

pub fn default_schema(database_type: DatabaseType) -> Option<&'static str> {
    if database_type == DatabaseType::SqlServer {
        Some("dbo")
    } else if is_postgres_family(database_type) {
        Some("public")
    } else {
        None
    }
}

fn is_postgres_family(database_type: DatabaseType) -> bool {
    matches!(
        database_type,
        DatabaseType::Postgres
            | DatabaseType::Redshift
            | DatabaseType::Gaussdb
            | DatabaseType::OpenGauss
            | DatabaseType::Kingbase
            | DatabaseType::Highgo
            | DatabaseType::Uxdb
            | DatabaseType::Vastbase
            | DatabaseType::Gbase8c
            | DatabaseType::Kwdb
    )
}

fn schema_aware(database_type: DatabaseType) -> bool {
    database_type == DatabaseType::SqlServer || is_postgres_family(database_type)
}

pub const STANDARD_FUNCTIONS: &[&str] = &[
    "abs",
    "array_agg",
    "avg",
    "bit_length",
    "btrim",
    "ceil",
    "ceiling",
    "char_length",
    "character_length",
    "coalesce",
    "concat",
    "concat_ws",
    "count",
    "cume_dist",
    "current_date",
    "current_time",
    "current_timestamp",
    "date",
    "date_part",
    "date_trunc",
    "dateadd",
    "datediff",
    "datepart",
    "day",
    "dense_rank",
    "exp",
    "first_value",
    "floor",
    "format",
    "greatest",
    "group_concat",
    "hour",
    "if",
    "ifnull",
    "iif",
    "initcap",
    "instr",
    "isnull",
    "json_agg",
    "json_build_object",
    "json_extract",
    "json_object",
    "jsonb_agg",
    "jsonb_build_object",
    "lag",
    "last_value",
    "lead",
    "least",
    "left",
    "len",
    "length",
    "ln",
    "localtime",
    "localtimestamp",
    "log",
    "log10",
    "lower",
    "lpad",
    "ltrim",
    "max",
    "md5",
    "min",
    "minute",
    "mod",
    "month",
    "now",
    "nth_value",
    "ntile",
    "nullif",
    "nvl",
    "octet_length",
    "percent_rank",
    "position",
    "power",
    "quarter",
    "rank",
    "regexp_replace",
    "repeat",
    "replace",
    "reverse",
    "right",
    "round",
    "row_number",
    "rpad",
    "rtrim",
    "second",
    "sign",
    "split_part",
    "sqrt",
    "stddev",
    "string_agg",
    "strpos",
    "substr",
    "substring",
    "sum",
    "to_char",
    "to_date",
    "to_number",
    "to_timestamp",
    "trim",
    "trunc",
    "upper",
    "variance",
    "week",
    "year",
];

fn function_requires_execute(function: &str, allowlist: &[String]) -> bool {
    let short = function.rsplit('.').next().unwrap_or(function);
    !(STANDARD_FUNCTIONS.contains(&short) || allowlist.iter().any(|allowed| allowed == function || allowed == short))
}

pub fn denial_message(decision: &Decision) -> Option<String> {
    let Decision::Deny(denial) = decision else {
        return None;
    };
    let resource = &denial.resource;
    let location: Vec<&str> = [resource.database.as_deref(), resource.schema.as_deref(), resource.table.as_deref()]
        .into_iter()
        .flatten()
        .collect();
    let target = if location.is_empty() { resource.connection_id.clone() } else { location.join(".") };
    Some(format!("{PERMISSION_DENIED_PREFIX} {} required on {target}", denial.missing.names().join(", ")))
}

impl AuthzRuntime {
    pub fn set_enforced(&self, enforced: bool) {
        self.enforced.store(enforced, Ordering::Release);
    }

    pub fn is_enforced(&self) -> bool {
        self.enforced.load(Ordering::Acquire)
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    pub fn register_owner(&self, owner: &str, principal: Principal) {
        if read(&self.owners).get(owner) == Some(&principal) {
            return;
        }
        write(&self.owners).insert(owner.to_string(), principal);
    }

    pub fn forget_owner(&self, owner: &str) {
        write(&self.owners).remove(owner);
    }

    pub fn current(&self) -> CurrentPrincipal {
        if !self.is_enforced() {
            return CurrentPrincipal::Unenforced;
        }
        match current_credential_owner() {
            None => CurrentPrincipal::Background,
            Some(owner) => match read(&self.owners).get(&owner) {
                Some(principal) => CurrentPrincipal::Known(principal.clone()),
                None => CurrentPrincipal::Unknown,
            },
        }
    }

    pub fn replace_snapshot(&self, snapshot: AuthzSnapshot) {
        *write(&self.snapshot) = Arc::new(snapshot);
        self.version.fetch_add(1, Ordering::AcqRel);
    }

    pub async fn reload(&self, storage: &Storage) -> Result<(), String> {
        let snapshot = storage.load_authz_snapshot().await?;
        self.replace_snapshot(snapshot);
        Ok(())
    }

    pub fn snapshot(&self) -> Arc<AuthzSnapshot> {
        read(&self.snapshot).clone()
    }

    pub fn record_pool_database(&self, pool_key: &str, database: Option<&str>) {
        let database = database.map(str::trim).filter(|value| !value.is_empty()).map(str::to_string);
        if read(&self.pool_databases).get(pool_key) == Some(&database) {
            return;
        }
        write(&self.pool_databases).insert(pool_key.to_string(), database);
    }

    pub fn pool_database(&self, pool_key: &str) -> Option<Option<String>> {
        read(&self.pool_databases).get(pool_key).cloned()
    }

    pub fn with_groups(&self, principal: &Principal) -> Principal {
        match principal {
            Principal::User { user_id, role, .. } => Principal::User {
                user_id: user_id.clone(),
                groups: self.snapshot().memberships.get(user_id).cloned().unwrap_or_default(),
                role: *role,
            },
            other => other.clone(),
        }
    }

    pub fn permissions(
        &self,
        principal: &Principal,
        config: &ConnectionConfig,
        write_unlocked: bool,
    ) -> EffectivePermissions {
        let ceiling =
            if config.read_only && !write_unlocked { Operations::READ_ONLY_CEILING } else { Operations::all() };
        let snapshot = self.snapshot();
        compile(
            &self.with_groups(principal),
            &snapshot.grants,
            ConnectionContext { connection_id: &config.id, group_path: &[], ceiling, now: now_millis() },
        )
    }
}

async fn connection_config(state: &AppState, connection_id: &str) -> Option<ConnectionConfig> {
    state.configs.read().await.get(connection_id).cloned()
}

async fn principal_permissions(
    state: &AppState,
    principal: &Principal,
    config: &ConnectionConfig,
) -> EffectivePermissions {
    let write_unlocked = config.read_only && state.write_unlock_windows.is_active(&config.id).await;
    state.authz.permissions(principal, config, write_unlocked)
}

fn missing_principal() -> String {
    format!("{PERMISSION_DENIED_PREFIX} the request has no authenticated user")
}

pub async fn principal_can_see_connection(state: &AppState, principal: &Principal, connection_id: &str) -> bool {
    match connection_config(state, connection_id).await {
        Some(config) => principal_permissions(state, principal, &config).await.is_visible(),
        None => false,
    }
}

pub async fn authorize_connection_access(state: &AppState, connection_id: &str) -> Result<(), String> {
    let principal = match state.authz.current() {
        CurrentPrincipal::Unenforced | CurrentPrincipal::Background => return Ok(()),
        CurrentPrincipal::Unknown => return Err(missing_principal()),
        CurrentPrincipal::Known(principal) => principal,
    };
    let Some(config) = connection_config(state, connection_id).await else {
        return Ok(());
    };
    if principal_permissions(state, &principal, &config).await.is_visible() {
        Ok(())
    } else {
        let message = format!("{PERMISSION_DENIED_PREFIX} no access to connection {}", config.name);
        if state.audit.is_enabled() {
            state.audit.record_in_request(
                AuditEvent::new("connection_denied").by(&principal).connection(&config.id).denied(message.clone()),
            );
        }
        Err(message)
    }
}

pub async fn authorize_connection_operations(
    state: &AppState,
    connection_id: &str,
    operations: Operations,
) -> Result<(), String> {
    let principal = match state.authz.current() {
        CurrentPrincipal::Unenforced => return Ok(()),
        CurrentPrincipal::Background | CurrentPrincipal::Unknown => return Err(missing_principal()),
        CurrentPrincipal::Known(principal) => principal,
    };
    let Some(config) = connection_config(state, connection_id).await else {
        return Err(format!("{PERMISSION_DENIED_PREFIX} unknown connection"));
    };
    let permissions = principal_permissions(state, &principal, &config).await;
    let requirement = Requirement::single(Need::within(Resource::connection(config.id.clone()), operations));
    let decision = permissions.authorize(&requirement);
    audit_decision(state, &principal, "data_access", &requirement, &decision, None);
    match denial_message(&decision) {
        Some(message) => Err(message),
        None => Ok(()),
    }
}

pub async fn principal_allows(
    state: &AppState,
    principal: &Principal,
    connection_id: &str,
    database: Option<&str>,
    operations: Operations,
) -> bool {
    let Some(config) = connection_config(state, connection_id).await else {
        return false;
    };
    let mut resource = Resource::connection(config.id.clone());
    resource.database = database.map(str::trim).filter(|value| !value.is_empty()).map(str::to_string);
    principal_permissions(state, principal, &config).await.check(&Need::exact(resource, operations)).is_ok()
}

pub async fn authorize_resource(
    state: &AppState,
    connection_id: &str,
    database: Option<&str>,
    schema: Option<&str>,
    table: Option<&str>,
    operations: Operations,
    within: bool,
) -> Result<(), String> {
    let principal = match state.authz.current() {
        CurrentPrincipal::Unenforced => return Ok(()),
        CurrentPrincipal::Background | CurrentPrincipal::Unknown => return Err(missing_principal()),
        CurrentPrincipal::Known(principal) => principal,
    };
    let Some(config) = connection_config(state, connection_id).await else {
        return Err(format!("{PERMISSION_DENIED_PREFIX} unknown connection"));
    };
    let clean = |value: Option<&str>| value.map(str::trim).filter(|value| !value.is_empty()).map(str::to_string);
    let mut resource = Resource::connection(config.id.clone());
    if let Some(database) = clean(database) {
        resource.database = Some(database);
        resource.schema = clean(schema);
        resource.table = clean(table);
    }
    let need = if within { Need::within(resource, operations) } else { Need::exact(resource, operations) };
    let permissions = principal_permissions(state, &principal, &config).await;
    let requirement = Requirement::single(need);
    let decision = permissions.authorize(&requirement);
    audit_decision(state, &principal, "data_access", &requirement, &decision, None);
    match denial_message(&decision) {
        Some(message) => Err(message),
        None => Ok(()),
    }
}

pub async fn authorize_sql_for(
    state: &AppState,
    connection_id: &str,
    database: Option<&str>,
    statements: &[&str],
) -> Result<(), String> {
    let principal = match state.authz.current() {
        CurrentPrincipal::Unenforced => return Ok(()),
        CurrentPrincipal::Background | CurrentPrincipal::Unknown => return Err(missing_principal()),
        CurrentPrincipal::Known(principal) => principal,
    };
    let Some(config) = connection_config(state, connection_id).await else {
        return Err(format!("{PERMISSION_DENIED_PREFIX} unknown connection"));
    };
    let active_database = database.map(str::trim).filter(|value| !value.is_empty()).map(str::to_string);
    authorize_statements(state, &principal, &config, active_database, statements).await
}

async fn authorize_statements(
    state: &AppState,
    principal: &Principal,
    config: &ConnectionConfig,
    active_database: Option<String>,
    statements: &[&str],
) -> Result<(), String> {
    let permissions = principal_permissions(state, principal, config).await;
    let active_database =
        active_database.or_else(|| config.database.clone().filter(|database| !database.trim().is_empty()));
    let context = ResolveContext {
        connection_id: &config.id,
        active_database: active_database.as_deref(),
        default_schema: default_schema(config.db_type),
        schema_aware: schema_aware(config.db_type),
    };
    let strict_allowlist = state.authz.snapshot().strict_functions.get(&config.id).cloned();
    for sql in statements {
        let classified = classify_sql_operations(sql, config.db_type);
        let mut requirement = classified.resolve(&context);
        if let Some(allowlist) = &strict_allowlist {
            if classified.functions.iter().any(|function| function_requires_execute(function, allowlist)) {
                let mut resource = Resource::connection(config.id.clone());
                resource.database = active_database.clone();
                requirement.push(Need::within(resource, Operations::EXECUTE));
            }
        }
        let decision = permissions.authorize(&requirement);
        audit_decision(state, principal, "sql", &requirement, &decision, Some(sql));
        if let Some(message) = denial_message(&decision) {
            return Err(message);
        }
    }
    Ok(())
}

pub async fn authorize_sql(state: &AppState, pool_key: &str, statements: &[&str]) -> Result<(), String> {
    let principal = match state.authz.current() {
        CurrentPrincipal::Unenforced => return Ok(()),
        CurrentPrincipal::Background | CurrentPrincipal::Unknown => return Err(missing_principal()),
        CurrentPrincipal::Known(principal) => principal,
    };
    let config = {
        let configs = state.configs.read().await;
        crate::connection::config_for_pool_key(pool_key, &configs).cloned()
    };
    let Some(config) = config else {
        return Err(format!("{PERMISSION_DENIED_PREFIX} unknown connection"));
    };
    let active_database = state.authz.pool_database(pool_key).unwrap_or(None);
    authorize_statements(state, &principal, &config, active_database, statements).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::session_credentials::with_credential_owner;
    use crate::query::{connection_readonly_name, execute_sql_statement_with_options};
    use dbx_authz::{BuiltinRole, Effect, Grant, PlatformRole, Scope, Subject};

    const CONNECTION: &str = "orders";

    async fn state(read_only: bool) -> (tempfile::TempDir, AppState) {
        let root = tempfile::tempdir().unwrap();
        let storage = crate::persistence::test_storage::open(&root.path().join("dbx.db")).await.unwrap();
        let state = AppState::new_with_plugin_dir(storage, root.path().join("plugins"));
        let path = root.path().join("orders.db");
        crate::db::sqlite::connect_path_create_if_missing(path.to_str().unwrap()).await.unwrap();
        let config: ConnectionConfig = serde_json::from_value(serde_json::json!({
            "id": CONNECTION, "name": "Orders", "db_type": "sqlite", "host": path.to_str().unwrap(),
            "port": 0, "username": "", "password": "", "database": null,
            "one_time": false, "save_password": false, "read_only": false
        }))
        .unwrap();
        state.configs.write().await.insert(CONNECTION.to_string(), config);
        for sql in ["CREATE TABLE orders(id INTEGER PRIMARY KEY, status TEXT)", "CREATE TABLE audit(id INTEGER)"] {
            run(&state, sql).await.unwrap();
        }
        if read_only {
            state.configs.write().await.get_mut(CONNECTION).unwrap().read_only = true;
        }
        (root, state)
    }

    async fn run(state: &AppState, sql: &str) -> Result<(), String> {
        execute_sql_statement_with_options(state, CONNECTION, "main", sql, None, None, Default::default())
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn run_as(state: &AppState, owner: &str, sql: &str) -> Result<(), String> {
        with_credential_owner(Some(owner.to_string()), run(state, sql)).await
    }

    fn user(id: &str) -> Principal {
        Principal::User { user_id: id.into(), groups: Vec::new(), role: PlatformRole::User }
    }

    fn grant(id: &str, subject: Subject, scope: Scope, effect: Effect, operations: Operations) -> Grant {
        Grant { id: id.into(), subject, scope, effect, operations, expires_at: None }
    }

    fn table(name: &str) -> Scope {
        Scope::Resource(Resource::connection(CONNECTION).with_database("main").with_table(name))
    }

    fn enforce(state: &AppState, grants: Vec<Grant>, memberships: &[(&str, &str)]) {
        let mut groups: HashMap<String, Vec<String>> = HashMap::new();
        for (user, group) in memberships {
            groups.entry(user.to_string()).or_default().push(group.to_string());
        }
        state.authz.replace_snapshot(AuthzSnapshot { grants, memberships: groups, strict_functions: HashMap::new() });
        state.authz.set_enforced(true);
        state.authz.register_owner("ana-token", user("ana"));
        state.authz.register_owner("bob-token", user("bob"));
        state.authz.register_owner(
            "root-token",
            Principal::User { user_id: "root".into(), groups: Vec::new(), role: PlatformRole::Admin },
        );
    }

    #[tokio::test]
    async fn without_enforcement_everything_behaves_as_before() {
        let (_root, state) = state(false).await;
        assert!(run(&state, "INSERT INTO orders(status) VALUES ('paid')").await.is_ok());
        assert!(connection_readonly_name(&state, CONNECTION).await.is_none());
    }

    #[tokio::test]
    async fn readers_can_select_but_not_write() {
        let (_root, state) = state(false).await;
        enforce(
            &state,
            vec![grant(
                "r",
                Subject::User("ana".into()),
                Scope::Resource(Resource::connection(CONNECTION)),
                Effect::Allow,
                BuiltinRole::Reader.operations(),
            )],
            &[],
        );
        assert!(run_as(&state, "ana-token", "SELECT * FROM orders").await.is_ok());
        let denied = run_as(&state, "ana-token", "DELETE FROM orders").await.unwrap_err();
        assert!(denied.contains("Permission denied: DELETE required on main.orders"), "{denied}");
        assert!(run_as(&state, "ana-token", "INSERT INTO orders(status) VALUES ('x')").await.is_err());
        assert!(run_as(&state, "ana-token", "DROP TABLE audit").await.is_err());
        assert!(connection_readonly_name(&state, CONNECTION)
            .await
            .is_some_and(|name| name.contains("no authenticated user")));
        assert!(with_credential_owner(Some("ana-token".into()), connection_readonly_name(&state, CONNECTION))
            .await
            .is_some_and(|name| name.contains("UNCLASSIFIED")));
    }

    #[tokio::test]
    async fn group_editors_with_a_table_deny_cannot_touch_that_table() {
        let (_root, state) = state(false).await;
        enforce(
            &state,
            vec![
                grant(
                    "g",
                    Subject::Group("soporte".into()),
                    Scope::All,
                    Effect::Allow,
                    BuiltinRole::FullEditor.operations(),
                ),
                grant(
                    "d",
                    Subject::User("ana".into()),
                    table("audit"),
                    Effect::Deny,
                    Operations::DELETE | Operations::UPDATE,
                ),
            ],
            &[("ana", "soporte")],
        );
        assert!(run_as(&state, "ana-token", "DELETE FROM orders").await.is_ok());
        assert!(run_as(&state, "ana-token", "UPDATE orders SET status = 'x'").await.is_ok());
        assert!(run_as(&state, "ana-token", "INSERT INTO audit VALUES (1)").await.is_ok());
        assert!(run_as(&state, "ana-token", "DELETE FROM audit").await.unwrap_err().contains("main.audit"));
        assert!(run_as(&state, "ana-token", "ALTER TABLE orders ADD COLUMN x INT").await.is_err());
    }

    async fn audit_rows(state: &AppState, expected: usize) -> Vec<crate::persistence::storage::AuditEntry> {
        for _ in 0..200 {
            let rows = state
                .storage
                .list_audit_events(crate::persistence::storage::AuditFilter { limit: 100, ..Default::default() })
                .await
                .unwrap();
            if rows.len() >= expected {
                return rows;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("audit events were not written");
    }

    #[tokio::test]
    async fn audits_each_statement_with_its_decision_and_session() {
        let (_root, state) = state(false).await;
        state.audit.start(state.storage.clone(), None);
        enforce(
            &state,
            vec![grant(
                "r",
                Subject::User("ana".into()),
                Scope::Resource(Resource::connection(CONNECTION)),
                Effect::Allow,
                BuiltinRole::Reader.operations(),
            )],
            &[],
        );
        state.audit.remember_client("ana-token", Some("10.0.0.7"));
        run_as(&state, "ana-token", "SELECT * FROM orders").await.unwrap();
        run_as(&state, "ana-token", "DELETE FROM orders WHERE status = 'void'").await.unwrap_err();
        run_as(&state, "bob-token", "SELECT 1").await.unwrap_err();

        let rows = audit_rows(&state, 3).await;
        let sql: Vec<_> = rows.iter().filter(|row| row.event == "sql").collect();
        assert_eq!(sql.len(), 2, "{rows:?}");
        let denied = sql.iter().find(|row| row.decision.as_deref() == Some("deny")).unwrap();
        assert_eq!(denied.user_id.as_deref(), Some("ana"));
        assert_eq!(denied.operations, Some(Operations::DELETE));
        assert_eq!(denied.database_name.as_deref(), Some("main"));
        assert_eq!(denied.table_names.as_deref(), Some("orders"));
        assert_eq!(denied.ip.as_deref(), Some("10.0.0.7"));
        assert_eq!(denied.session_ref.as_deref(), Some(crate::audit::session_ref("ana-token").as_str()));
        assert!(denied.reason.as_deref().is_some_and(|reason| reason.contains("DELETE required")));
        assert_eq!(
            state.storage.reveal_audit_statement(&denied.event_id).await.unwrap().as_deref(),
            Some("DELETE FROM orders WHERE status = 'void'")
        );
        let allowed = sql.iter().find(|row| row.decision.as_deref() == Some("allow")).unwrap();
        assert_eq!(allowed.operations, Some(Operations::SELECT));
        assert_eq!(allowed.table_names.as_deref(), Some("orders"));
        let connection = rows.iter().find(|row| row.event == "connection_denied").unwrap();
        assert_eq!(connection.user_id.as_deref(), Some("bob"));
        assert_eq!(connection.connection_id.as_deref(), Some(CONNECTION));
    }

    async fn sql_rows_with_outcome(state: &AppState, expected: usize) -> Vec<crate::persistence::storage::AuditEntry> {
        for _ in 0..200 {
            let rows: Vec<_> = audit_rows(state, 0)
                .await
                .into_iter()
                .filter(|row| row.event == "sql" && (row.duration_ms.is_some() || row.reason.is_some()))
                .collect();
            if rows.len() >= expected {
                return rows;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("statement outcomes were not written");
    }

    #[tokio::test]
    async fn audited_statements_record_rows_duration_and_failures() {
        let (_root, state) = state(false).await;
        state.audit.start(state.storage.clone(), None);
        enforce(
            &state,
            vec![grant(
                "w",
                Subject::User("ana".into()),
                Scope::Resource(Resource::connection(CONNECTION)),
                Effect::Allow,
                BuiltinRole::FullEditor.operations(),
            )],
            &[],
        );
        run_as(&state, "ana-token", "INSERT INTO orders(status) VALUES ('a'), ('b'), ('c')").await.unwrap();
        run_as(&state, "ana-token", "UPDATE missing_table SET x = 1").await.unwrap_err();
        let rows = sql_rows_with_outcome(&state, 2).await;
        let insert = rows.iter().find(|row| row.operations == Some(Operations::INSERT)).unwrap();
        assert_eq!(insert.rows_affected, Some(3));
        assert!(insert.duration_ms.is_some());
        assert_eq!(insert.reason, None);
        let failed = rows.iter().find(|row| row.table_names.as_deref() == Some("missing_table")).unwrap();
        assert_eq!(failed.decision.as_deref(), Some("allow"));
        assert_eq!(failed.reason.as_deref(), Some("execution_failed"));
        assert_eq!(failed.rows_affected, None);

        with_credential_owner(
            Some("ana-token".into()),
            crate::query::execute_multi_core(
                &state,
                CONNECTION,
                "main",
                "UPDATE orders SET status = 'x' WHERE status = 'a'; DELETE FROM orders WHERE status <> 'x'",
                None,
                None,
            ),
        )
        .await
        .unwrap();
        let rows = sql_rows_with_outcome(&state, 4).await;
        let update = rows.iter().find(|row| row.operations == Some(Operations::UPDATE)).unwrap();
        assert_eq!(update.rows_affected, Some(1));
        let delete = rows.iter().find(|row| row.operations == Some(Operations::DELETE)).unwrap();
        assert_eq!(delete.rows_affected, Some(2));
    }

    #[tokio::test]
    async fn quiet_reads_outside_sql_are_not_audited() {
        let (_root, state) = state(false).await;
        state.audit.start(state.storage.clone(), None);
        enforce(
            &state,
            vec![grant(
                "r",
                Subject::User("ana".into()),
                Scope::Resource(Resource::connection(CONNECTION)),
                Effect::Allow,
                BuiltinRole::Analyst.operations(),
            )],
            &[],
        );
        with_credential_owner(Some("ana-token".into()), async {
            authorize_resource(&state, CONNECTION, Some("main"), None, None, Operations::SELECT, true).await.unwrap();
            authorize_resource(&state, CONNECTION, Some("main"), None, None, Operations::EXPORT, true).await.unwrap();
            authorize_resource(&state, CONNECTION, Some("main"), None, Some("orders"), Operations::DELETE, false)
                .await
                .unwrap_err();
        })
        .await;
        audit_rows(&state, 2).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let rows = audit_rows(&state, 2).await;
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(rows.iter().all(|row| row.event == "data_access"));
        assert!(rows
            .iter()
            .any(|row| row.operations == Some(Operations::EXPORT) && row.decision.as_deref() == Some("allow")));
        assert!(rows
            .iter()
            .any(|row| row.operations == Some(Operations::DELETE) && row.decision.as_deref() == Some("deny")));
    }

    #[tokio::test]
    async fn users_without_grants_cannot_even_open_the_connection() {
        let (_root, state) = state(false).await;
        enforce(&state, Vec::new(), &[]);
        let denied = run_as(&state, "bob-token", "SELECT 1").await.unwrap_err();
        assert!(denied.contains("no access to connection Orders"), "{denied}");
        assert!(!principal_can_see_connection(&state, &user("bob"), CONNECTION).await);
    }

    #[tokio::test]
    async fn administrators_keep_full_access_and_unknown_requests_are_denied() {
        let (_root, state) = state(false).await;
        enforce(&state, Vec::new(), &[]);
        assert!(run_as(&state, "root-token", "DELETE FROM orders").await.is_ok());
        assert!(with_credential_owner(Some("root-token".into()), connection_readonly_name(&state, CONNECTION))
            .await
            .is_none());
        let unknown = run_as(&state, "forged-token", "SELECT 1").await.unwrap_err();
        assert!(unknown.contains("no authenticated user"), "{unknown}");
        let background = run(&state, "SELECT 1").await.unwrap_err();
        assert!(background.contains("no authenticated user"), "{background}");
        state.authz.forget_owner("root-token");
        assert!(run_as(&state, "root-token", "SELECT 1").await.is_err());
    }

    #[tokio::test]
    async fn read_only_connections_cap_writes_until_a_write_window_opens() {
        let (_root, state) = state(true).await;
        enforce(
            &state,
            vec![grant("e", Subject::User("ana".into()), Scope::All, Effect::Allow, BuiltinRole::Editor.operations())],
            &[],
        );
        assert!(run_as(&state, "ana-token", "SELECT * FROM orders").await.is_ok());
        assert!(run_as(&state, "ana-token", "INSERT INTO orders(status) VALUES ('x')").await.is_err());
        with_credential_owner(Some("ana-token".into()), async {
            crate::query::unlock_connection_writes_core(&state, CONNECTION, 60).await.unwrap();
        })
        .await;
        assert!(run_as(&state, "ana-token", "INSERT INTO orders(status) VALUES ('x')").await.is_ok());
        assert!(run_as(&state, "ana-token", "DELETE FROM orders").await.is_err());
    }

    async fn check_as_ana(state: &AppState, sql: &str) -> Result<(), String> {
        with_credential_owner(Some("ana-token".into()), authorize_sql_for(state, CONNECTION, Some("main"), &[sql]))
            .await
    }

    #[tokio::test]
    async fn strict_function_mode_requires_execute_for_unknown_functions() {
        let (_root, state) = state(false).await;
        let reader = grant(
            "r",
            Subject::User("ana".into()),
            Scope::Resource(Resource::connection(CONNECTION)),
            Effect::Allow,
            Operations::SELECT,
        );
        enforce(&state, vec![reader.clone()], &[]);
        assert!(check_as_ana(&state, "SELECT audit_purge(1) FROM orders").await.is_ok());

        let mut strict = HashMap::new();
        strict.insert(CONNECTION.to_string(), vec!["safe_score".to_string()]);
        state.authz.replace_snapshot(AuthzSnapshot {
            grants: vec![reader],
            memberships: HashMap::new(),
            strict_functions: strict,
        });
        let denied = check_as_ana(&state, "SELECT audit_purge(1) FROM orders").await.unwrap_err();
        assert!(denied.contains("EXECUTE"), "{denied}");
        assert!(check_as_ana(&state, "SELECT lower(status), count(*) FROM orders GROUP BY 1").await.is_ok());
        assert!(check_as_ana(&state, "SELECT safe_score(id) FROM orders").await.is_ok());
        assert!(check_as_ana(&state, "SELECT * FROM orders").await.is_ok());
    }

    #[tokio::test]
    async fn system_tasks_only_get_system_grants() {
        let (_root, state) = state(false).await;
        enforce(
            &state,
            vec![grant(
                "s",
                Subject::System,
                Scope::Resource(Resource::connection(CONNECTION).with_database("main")),
                Effect::Allow,
                Operations::SELECT | Operations::EXPORT,
            )],
            &[],
        );
        state.authz.register_owner("system:backup:run-1", Principal::System { task_id: Some("run-1".into()) });
        let export = Operations::SELECT | Operations::EXPORT;
        let as_system = |operations| {
            with_credential_owner(
                Some("system:backup:run-1".into()),
                authorize_resource(&state, CONNECTION, Some("main"), None, None, operations, false),
            )
        };
        assert!(as_system(export).await.is_ok());
        assert!(as_system(Operations::DELETE).await.is_err());
        assert!(principal_allows(&state, &Principal::System { task_id: None }, CONNECTION, Some("main"), export).await);
        assert!(!principal_allows(&state, &user("ana"), CONNECTION, Some("main"), export).await);
        assert!(
            !principal_allows(&state, &Principal::System { task_id: None }, CONNECTION, Some("other"), export).await
        );
    }

    #[test]
    fn denial_messages_name_the_missing_operation_and_place() {
        let decision = Decision::Deny(dbx_authz::Denial {
            resource: Resource::connection("c").with_database("app").with_schema("public").with_table("t"),
            missing: Operations::INSERT | Operations::UPDATE,
            denied_by: None,
            limited_by_ceiling: false,
        });
        assert_eq!(denial_message(&decision).unwrap(), "Permission denied: INSERT, UPDATE required on app.public.t");
        assert!(denial_message(&Decision::Allow).is_none());
    }
}
