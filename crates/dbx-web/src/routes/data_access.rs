use dbx_authz::Operations;
use dbx_core::connection::AppState;

use crate::error::AppError;

#[derive(Debug, Clone, Copy, Default)]
pub struct Target<'a> {
    pub database: Option<&'a str>,
    pub schema: Option<&'a str>,
    pub object: Option<&'a str>,
    pub within: bool,
}

impl<'a> Target<'a> {
    pub fn connection() -> Self {
        Self::default()
    }

    pub fn anywhere() -> Self {
        Self { within: true, ..Self::default() }
    }

    pub fn database(database: &'a str) -> Self {
        Self { database: Some(database), ..Self::default() }
    }

    pub fn within_database(database: &'a str) -> Self {
        Self { database: Some(database), within: true, ..Self::default() }
    }

    pub fn object(database: &'a str, object: &'a str) -> Self {
        Self { database: Some(database), object: Some(object), ..Self::default() }
    }

    pub fn schema_object(database: &'a str, schema: Option<&'a str>, object: &'a str) -> Self {
        Self { database: Some(database), schema, object: Some(object), within: false }
    }
}

pub async fn ensure_access(
    app: &AppState,
    connection_id: &str,
    target: Target<'_>,
    operations: Operations,
    action: &str,
) -> Result<(), AppError> {
    if operations.has_write() {
        if let Some(name) = dbx_core::query::read_only_protection_name(app, connection_id).await {
            return Err(AppError::from(format!(
                "Read-only mode: connection '{name}' has read-only protection enabled. {action} blocked."
            )));
        }
    }
    dbx_core::authz::authorize_resource(
        app,
        connection_id,
        target.database,
        target.schema,
        target.object,
        operations,
        target.within,
    )
    .await
    .map_err(AppError::forbidden)
}

pub fn redis_command_operations(command: &str) -> Operations {
    use dbx_core::db::redis_driver::{classify_command, RedisCommandSafety};
    let name = command.to_ascii_uppercase();
    match name.as_str() {
        "SELECT" | "SWAPDB" | "MOVE" | "COPY" | "MIGRATE" => return Operations::UNCLASSIFIED,
        "DEL" | "UNLINK" | "GETDEL" => return Operations::DELETE,
        "FLUSHDB" => return Operations::TRUNCATE,
        _ => {}
    }
    match classify_command(&name) {
        RedisCommandSafety::Allowed => Operations::SELECT,
        RedisCommandSafety::Write => Operations::INSERT | Operations::UPDATE,
        RedisCommandSafety::Confirm if name.ends_with("STORE") || matches!(name.as_str(), "SORT" | "PFMERGE") => {
            Operations::SELECT | Operations::INSERT | Operations::UPDATE
        }
        RedisCommandSafety::Confirm => Operations::UPDATE | Operations::DELETE,
        RedisCommandSafety::Blocked => Operations::UNCLASSIFIED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use dbx_authz::{Effect, Grant, PlatformRole, Principal, Resource, Scope, Subject};
    use dbx_core::persistence::storage::AuthzSnapshot;
    use dbx_core::session_credentials::with_credential_owner;

    async fn app(read_only: bool) -> (tempfile::TempDir, AppState) {
        let root = tempfile::tempdir().unwrap();
        let storage = dbx_core::persistence::test_storage::open(&root.path().join("dbx.db")).await.unwrap();
        let app = AppState::new_with_plugin_dir(storage, root.path().join("plugins"));
        let config: dbx_core::models::connection::ConnectionConfig = serde_json::from_value(serde_json::json!({
            "id": "cache", "name": "Cache", "db_type": "redis", "host": "127.0.0.1",
            "port": 6379, "username": "", "password": "", "database": null,
            "one_time": false, "save_password": false, "read_only": read_only
        }))
        .unwrap();
        app.configs.write().await.insert("cache".into(), config);
        (root, app)
    }

    fn enforce(app: &AppState, operations: Operations) {
        app.authz.replace_snapshot(AuthzSnapshot {
            grants: vec![Grant {
                id: "g".into(),
                subject: Subject::User("ana".into()),
                scope: Scope::Resource(Resource::connection("cache").with_database("0")),
                effect: Effect::Allow,
                operations,
                expires_at: None,
            }],
            memberships: Default::default(),
            strict_functions: Default::default(),
        });
        app.authz.set_enforced(true);
        app.authz.register_owner(
            "ana-token",
            Principal::User { user_id: "ana".into(), groups: Vec::new(), role: PlatformRole::User },
        );
    }

    async fn as_ana(app: &AppState, target: Target<'_>, operations: Operations) -> Result<(), AppError> {
        with_credential_owner(Some("ana-token".into()), ensure_access(app, "cache", target, operations, "Test")).await
    }

    #[tokio::test]
    async fn read_only_protection_still_applies_without_enforcement() {
        let (_root, app) = app(true).await;
        assert!(ensure_access(&app, "cache", Target::database("0"), Operations::SELECT, "Read").await.is_ok());
        let blocked = ensure_access(&app, "cache", Target::database("0"), Operations::DELETE, "Delete key").await;
        assert!(blocked.unwrap_err().to_string().contains("Read-only mode"));
    }

    #[tokio::test]
    async fn database_grants_limit_redis_style_access() {
        let (_root, app) = app(false).await;
        enforce(&app, Operations::SELECT | Operations::INSERT | Operations::UPDATE);
        assert!(as_ana(&app, Target::database("0"), Operations::SELECT).await.is_ok());
        assert!(as_ana(&app, Target::database("0"), Operations::INSERT | Operations::UPDATE).await.is_ok());
        let delete = as_ana(&app, Target::database("0"), Operations::DELETE).await.unwrap_err().to_string();
        assert!(delete.contains("Permission denied: DELETE required on 0"), "{delete}");
        assert!(as_ana(&app, Target::database("1"), Operations::SELECT).await.is_err());
        assert!(as_ana(&app, Target::connection(), Operations::UNCLASSIFIED).await.is_err());
        assert!(as_ana(&app, Target::anywhere(), Operations::SELECT).await.is_ok());
    }

    #[tokio::test]
    async fn object_grants_apply_to_collections() {
        let (_root, app) = app(false).await;
        app.authz.replace_snapshot(AuthzSnapshot {
            grants: vec![Grant {
                id: "g".into(),
                subject: Subject::User("ana".into()),
                scope: Scope::Resource(Resource::connection("cache").with_database("shop").with_table("orders")),
                effect: Effect::Allow,
                operations: Operations::SELECT | Operations::EXPORT,
                expires_at: None,
            }],
            memberships: Default::default(),
            strict_functions: Default::default(),
        });
        app.authz.set_enforced(true);
        app.authz.register_owner(
            "ana-token",
            Principal::User { user_id: "ana".into(), groups: Vec::new(), role: PlatformRole::User },
        );
        assert!(as_ana(&app, Target::object("shop", "orders"), Operations::SELECT | Operations::EXPORT).await.is_ok());
        assert!(as_ana(&app, Target::object("shop", "users"), Operations::SELECT).await.is_err());
        assert!(as_ana(&app, Target::database("shop"), Operations::SELECT).await.is_err());
        assert!(as_ana(&app, Target::within_database("shop"), Operations::SELECT).await.is_ok());
        assert!(as_ana(&app, Target::schema_object("shop", None, "orders"), Operations::INSERT).await.is_err());
    }

    #[test]
    fn redis_commands_map_to_operations() {
        assert_eq!(redis_command_operations("get"), Operations::SELECT);
        assert_eq!(redis_command_operations("HGETALL"), Operations::SELECT);
        assert_eq!(redis_command_operations("SET"), Operations::INSERT | Operations::UPDATE);
        assert_eq!(redis_command_operations("del"), Operations::DELETE);
        assert_eq!(redis_command_operations("FLUSHDB"), Operations::TRUNCATE);
        assert_eq!(redis_command_operations("LPOP"), Operations::UPDATE | Operations::DELETE);
        assert_eq!(redis_command_operations("expire"), Operations::UPDATE | Operations::DELETE);
        assert_eq!(
            redis_command_operations("SUNIONSTORE"),
            Operations::SELECT | Operations::INSERT | Operations::UPDATE
        );
        assert_eq!(redis_command_operations("FLUSHALL"), Operations::UNCLASSIFIED);
        assert_eq!(redis_command_operations("CONFIG"), Operations::UNCLASSIFIED);
        assert_eq!(redis_command_operations("SELECT"), Operations::UNCLASSIFIED);
        assert_eq!(redis_command_operations("SOMENEWCOMMAND"), Operations::UNCLASSIFIED);
    }
}
