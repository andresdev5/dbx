use std::collections::HashMap;

use dbx_authz::{BuiltinRole, Effect, Grant, Operations, Resource, Scope, Subject};
use rusqlite::Row;
use uuid::Uuid;

use super::{params, OptionalExtension, Storage};

pub const GROUP_NAME_TAKEN: &str = "GROUP_NAME_TAKEN";
pub const GROUP_NOT_FOUND: &str = "GROUP_NOT_FOUND";
pub const ROLE_NAME_TAKEN: &str = "ROLE_NAME_TAKEN";
pub const ROLE_NOT_FOUND: &str = "ROLE_NOT_FOUND";
pub const ROLE_IN_USE: &str = "ROLE_IN_USE";
pub const GRANT_NOT_FOUND: &str = "GRANT_NOT_FOUND";
pub const GRANT_INVALID: &str = "GRANT_INVALID";

const BUILTIN_ROLE_PREFIX: &str = "builtin:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserGroup {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub member_ids: Vec<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRole {
    pub id: String,
    pub name: String,
    pub operations: Operations,
    pub builtin: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredGrant {
    pub id: String,
    pub subject: Subject,
    pub scope: Scope,
    pub effect: Effect,
    pub operations: Option<Operations>,
    pub role_id: Option<String>,
    pub expires_at: Option<i64>,
    pub note: Option<String>,
    pub created_by: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthzSnapshot {
    pub grants: Vec<Grant>,
    pub memberships: HashMap<String, Vec<String>>,
}

pub(super) const WEB_GRANT_SCHEMA_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS user_groups (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        description TEXT,
        created_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS user_group_members (
        group_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        PRIMARY KEY (group_id, user_id)
    )",
    "CREATE TABLE IF NOT EXISTS data_roles (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        operations INTEGER NOT NULL,
        description TEXT
    )",
    "CREATE TABLE IF NOT EXISTS grants (
        id TEXT PRIMARY KEY,
        principal_kind TEXT NOT NULL CHECK (principal_kind IN ('user', 'group', 'system')),
        principal_id TEXT,
        scope_kind TEXT NOT NULL CHECK (scope_kind IN ('all', 'connection_group', 'connection', 'database', 'schema', 'table')),
        connection_group_id TEXT,
        connection_id TEXT,
        database_name TEXT,
        schema_name TEXT,
        table_name TEXT,
        effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
        operations INTEGER,
        role_id TEXT,
        expires_at INTEGER,
        note TEXT,
        created_by TEXT,
        created_at INTEGER NOT NULL,
        CHECK ((operations IS NULL) <> (role_id IS NULL))
    )",
    "CREATE INDEX IF NOT EXISTS idx_grants_principal ON grants(principal_kind, principal_id)",
    "CREATE INDEX IF NOT EXISTS idx_grants_connection ON grants(connection_id)",
    "CREATE INDEX IF NOT EXISTS idx_user_group_members_user ON user_group_members(user_id)",
];

pub fn builtin_role_id(role: BuiltinRole) -> String {
    let name = serde_json::to_value(role).ok().and_then(|value| value.as_str().map(str::to_string)).unwrap_or_default();
    format!("{BUILTIN_ROLE_PREFIX}{name}")
}

pub fn builtin_roles() -> Vec<DataRole> {
    BuiltinRole::ALL
        .iter()
        .map(|role| DataRole {
            id: builtin_role_id(*role),
            name: builtin_role_id(*role).trim_start_matches(BUILTIN_ROLE_PREFIX).to_string(),
            operations: role.operations(),
            builtin: true,
            description: None,
        })
        .collect()
}

fn sql_error(error: rusqlite::Error) -> String {
    error.to_string()
}

fn unique_violation(error: &rusqlite::Error) -> bool {
    matches!(error, rusqlite::Error::SqliteFailure(failure, _) if failure.code == rusqlite::ErrorCode::ConstraintViolation)
}

const GRANT_COLUMNS: &str = "id, principal_kind, principal_id, scope_kind, connection_group_id, connection_id, \
     database_name, schema_name, table_name, effect, operations, role_id, expires_at, note, created_by, created_at";

fn subject_from_columns(kind: &str, id: Option<String>) -> Option<Subject> {
    match (kind, id) {
        ("user", Some(id)) => Some(Subject::User(id)),
        ("group", Some(id)) => Some(Subject::Group(id)),
        ("system", _) => Some(Subject::System),
        _ => None,
    }
}

fn subject_columns(subject: &Subject) -> (&'static str, Option<String>) {
    match subject {
        Subject::User(id) => ("user", Some(id.clone())),
        Subject::Group(id) => ("group", Some(id.clone())),
        Subject::System => ("system", None),
    }
}

struct ScopeColumns {
    kind: &'static str,
    group: Option<String>,
    connection: Option<String>,
    database: Option<String>,
    schema: Option<String>,
    table: Option<String>,
}

fn scope_columns(scope: &Scope) -> Result<ScopeColumns, String> {
    let blank = |value: &Option<String>| value.as_deref().is_some_and(|value| value.trim().is_empty());
    match scope {
        Scope::All => {
            Ok(ScopeColumns { kind: "all", group: None, connection: None, database: None, schema: None, table: None })
        }
        Scope::ConnectionGroup(group) if !group.trim().is_empty() => Ok(ScopeColumns {
            kind: "connection_group",
            group: Some(group.clone()),
            connection: None,
            database: None,
            schema: None,
            table: None,
        }),
        Scope::Resource(resource) => {
            if resource.connection_id.trim().is_empty()
                || blank(&resource.database)
                || blank(&resource.schema)
                || blank(&resource.table)
                || (resource.database.is_none() && (resource.schema.is_some() || resource.table.is_some()))
            {
                return Err(GRANT_INVALID.to_string());
            }
            let kind = match (&resource.database, &resource.schema, &resource.table) {
                (None, _, _) => "connection",
                (Some(_), None, None) => "database",
                (Some(_), Some(_), None) => "schema",
                (Some(_), _, Some(_)) => "table",
            };
            Ok(ScopeColumns {
                kind,
                group: None,
                connection: Some(resource.connection_id.clone()),
                database: resource.database.clone(),
                schema: resource.schema.clone(),
                table: resource.table.clone(),
            })
        }
        Scope::ConnectionGroup(_) => Err(GRANT_INVALID.to_string()),
    }
}

fn grant_from_row(row: &Row<'_>) -> rusqlite::Result<Option<StoredGrant>> {
    let principal_kind: String = row.get(1)?;
    let scope_kind: String = row.get(3)?;
    let connection_id: Option<String> = row.get(5)?;
    let scope = match scope_kind.as_str() {
        "all" => Some(Scope::All),
        "connection_group" => row.get::<_, Option<String>>(4)?.map(Scope::ConnectionGroup),
        _ => connection_id.map(|connection_id| {
            Scope::Resource(Resource {
                connection_id,
                database: row.get(6).ok().flatten(),
                schema: row.get(7).ok().flatten(),
                table: row.get(8).ok().flatten(),
            })
        }),
    };
    let effect = match row.get::<_, String>(9)?.as_str() {
        "deny" => Effect::Deny,
        _ => Effect::Allow,
    };
    let (Some(subject), Some(scope)) = (subject_from_columns(&principal_kind, row.get(2)?), scope) else {
        return Ok(None);
    };
    Ok(Some(StoredGrant {
        id: row.get(0)?,
        subject,
        scope,
        effect,
        operations: row.get::<_, Option<i64>>(10)?.map(Operations::from_stored),
        role_id: row.get(11)?,
        expires_at: row.get(12)?,
        note: row.get(13)?,
        created_by: row.get(14)?,
        created_at: row.get(15)?,
    }))
}

fn load_grants(
    conn: &rusqlite::Connection,
    filter: &str,
    values: &[&dyn rusqlite::ToSql],
) -> Result<Vec<StoredGrant>, String> {
    let mut statement = conn
        .prepare(&format!("SELECT {GRANT_COLUMNS} FROM grants {filter} ORDER BY created_at, id"))
        .map_err(sql_error)?;
    let rows = statement.query_map(values, grant_from_row).map_err(sql_error)?;
    let mut grants = Vec::new();
    for row in rows {
        if let Some(grant) = row.map_err(sql_error)? {
            grants.push(grant);
        }
    }
    Ok(grants)
}

fn load_custom_roles(conn: &rusqlite::Connection) -> Result<Vec<DataRole>, String> {
    let mut statement = conn
        .prepare("SELECT id, name, operations, description FROM data_roles ORDER BY name COLLATE NOCASE")
        .map_err(sql_error)?;
    let roles = statement
        .query_map([], |row| {
            Ok(DataRole {
                id: row.get(0)?,
                name: row.get(1)?,
                operations: Operations::from_stored(row.get(2)?),
                builtin: false,
                description: row.get(3)?,
            })
        })
        .map_err(sql_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql_error);
    roles
}

fn role_exists(conn: &rusqlite::Connection, role_id: &str) -> Result<bool, String> {
    if builtin_roles().iter().any(|role| role.id == role_id) {
        return Ok(true);
    }
    conn.query_row("SELECT 1 FROM data_roles WHERE id = ?1", params![role_id], |_| Ok(()))
        .optional()
        .map(|found| found.is_some())
        .map_err(sql_error)
}

impl Storage {
    pub async fn list_user_groups(&self) -> Result<Vec<UserGroup>, String> {
        self.with_conn(|conn| {
            let mut members: HashMap<String, Vec<String>> = HashMap::new();
            {
                let mut statement = conn
                    .prepare("SELECT group_id, user_id FROM user_group_members ORDER BY user_id")
                    .map_err(sql_error)?;
                let rows = statement
                    .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
                    .map_err(sql_error)?;
                for row in rows {
                    let (group, user) = row.map_err(sql_error)?;
                    members.entry(group).or_default().push(user);
                }
            }
            let mut statement = conn
                .prepare("SELECT id, name, description, created_at FROM user_groups ORDER BY name COLLATE NOCASE")
                .map_err(sql_error)?;
            let groups = statement
                .query_map([], |row| {
                    let id: String = row.get(0)?;
                    Ok(UserGroup {
                        member_ids: members.get(&id).cloned().unwrap_or_default(),
                        id,
                        name: row.get(1)?,
                        description: row.get(2)?,
                        created_at: row.get(3)?,
                    })
                })
                .map_err(sql_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql_error);
            groups
        })
        .await
    }

    pub async fn create_user_group(
        &self,
        name: &str,
        description: Option<String>,
        now: i64,
    ) -> Result<UserGroup, String> {
        let group = UserGroup {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description,
            member_ids: Vec::new(),
            created_at: now,
        };
        let row = group.clone();
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO user_groups (id, name, description, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![row.id, row.name, row.description, row.created_at],
            )
            .map(|_| ())
            .map_err(|error| {
                if unique_violation(&error) {
                    GROUP_NAME_TAKEN.to_string()
                } else {
                    sql_error(error)
                }
            })
        })
        .await?;
        Ok(group)
    }

    pub async fn update_user_group(&self, id: &str, name: &str, description: Option<String>) -> Result<(), String> {
        let (id, name) = (id.to_string(), name.to_string());
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE user_groups SET name = ?2, description = ?3 WHERE id = ?1",
                    params![id, name, description],
                )
                .map_err(
                    |error| if unique_violation(&error) { GROUP_NAME_TAKEN.to_string() } else { sql_error(error) },
                )?;
            if changed == 0 {
                return Err(GROUP_NOT_FOUND.to_string());
            }
            Ok(())
        })
        .await
    }

    pub async fn set_user_group_members(&self, id: &str, user_ids: Vec<String>) -> Result<(), String> {
        let id = id.to_string();
        self.with_conn(move |conn| {
            let transaction = conn.transaction().map_err(sql_error)?;
            let exists = transaction
                .query_row("SELECT 1 FROM user_groups WHERE id = ?1", params![id], |_| Ok(()))
                .optional()
                .map_err(sql_error)?
                .is_some();
            if !exists {
                return Err(GROUP_NOT_FOUND.to_string());
            }
            transaction
                .execute("DELETE FROM user_group_members WHERE group_id = ?1", params![id])
                .map_err(sql_error)?;
            for user_id in user_ids {
                transaction
                    .execute(
                        "INSERT OR IGNORE INTO user_group_members (group_id, user_id) \
                         SELECT ?1, id FROM users WHERE id = ?2",
                        params![id, user_id],
                    )
                    .map_err(sql_error)?;
            }
            transaction.commit().map_err(sql_error)
        })
        .await
    }

    pub async fn delete_user_group(&self, id: &str) -> Result<(), String> {
        let id = id.to_string();
        self.with_conn(move |conn| {
            let transaction = conn.transaction().map_err(sql_error)?;
            transaction
                .execute("DELETE FROM user_group_members WHERE group_id = ?1", params![id])
                .map_err(sql_error)?;
            transaction
                .execute("DELETE FROM grants WHERE principal_kind = 'group' AND principal_id = ?1", params![id])
                .map_err(sql_error)?;
            let changed =
                transaction.execute("DELETE FROM user_groups WHERE id = ?1", params![id]).map_err(sql_error)?;
            if changed == 0 {
                return Err(GROUP_NOT_FOUND.to_string());
            }
            transaction.commit().map_err(sql_error)
        })
        .await
    }

    pub async fn list_data_roles(&self) -> Result<Vec<DataRole>, String> {
        let custom = self.with_conn(|conn| load_custom_roles(conn)).await?;
        Ok(builtin_roles().into_iter().chain(custom).collect())
    }

    pub async fn create_data_role(
        &self,
        name: &str,
        operations: Operations,
        description: Option<String>,
    ) -> Result<DataRole, String> {
        let role = DataRole {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            operations,
            builtin: false,
            description,
        };
        let row = role.clone();
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO data_roles (id, name, operations, description) VALUES (?1, ?2, ?3, ?4)",
                params![row.id, row.name, row.operations.to_stored(), row.description],
            )
            .map(|_| ())
            .map_err(|error| if unique_violation(&error) { ROLE_NAME_TAKEN.to_string() } else { sql_error(error) })
        })
        .await?;
        Ok(role)
    }

    pub async fn update_data_role(
        &self,
        id: &str,
        name: &str,
        operations: Operations,
        description: Option<String>,
    ) -> Result<(), String> {
        let (id, name) = (id.to_string(), name.to_string());
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE data_roles SET name = ?2, operations = ?3, description = ?4 WHERE id = ?1",
                    params![id, name, operations.to_stored(), description],
                )
                .map_err(
                    |error| if unique_violation(&error) { ROLE_NAME_TAKEN.to_string() } else { sql_error(error) },
                )?;
            if changed == 0 {
                return Err(ROLE_NOT_FOUND.to_string());
            }
            Ok(())
        })
        .await
    }

    pub async fn delete_data_role(&self, id: &str) -> Result<(), String> {
        let id = id.to_string();
        self.with_conn(move |conn| {
            let used = conn
                .query_row("SELECT 1 FROM grants WHERE role_id = ?1 LIMIT 1", params![id], |_| Ok(()))
                .optional()
                .map_err(sql_error)?
                .is_some();
            if used {
                return Err(ROLE_IN_USE.to_string());
            }
            let changed = conn.execute("DELETE FROM data_roles WHERE id = ?1", params![id]).map_err(sql_error)?;
            if changed == 0 {
                return Err(ROLE_NOT_FOUND.to_string());
            }
            Ok(())
        })
        .await
    }

    pub async fn list_grants(&self) -> Result<Vec<StoredGrant>, String> {
        self.with_conn(|conn| load_grants(conn, "", &[])).await
    }

    pub async fn save_grant(&self, grant: StoredGrant) -> Result<StoredGrant, String> {
        let columns = scope_columns(&grant.scope)?;
        if grant.operations.is_some() == grant.role_id.is_some() {
            return Err(GRANT_INVALID.to_string());
        }
        let (principal_kind, principal_id) = subject_columns(&grant.subject);
        let row = grant.clone();
        self.with_conn(move |conn| {
            if let Some(role_id) = &row.role_id {
                if !role_exists(conn, role_id)? {
                    return Err(ROLE_NOT_FOUND.to_string());
                }
            }
            conn.execute(
                &format!(
                    "INSERT OR REPLACE INTO grants ({GRANT_COLUMNS}) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)"
                ),
                params![
                    row.id,
                    principal_kind,
                    principal_id,
                    columns.kind,
                    columns.group,
                    columns.connection,
                    columns.database,
                    columns.schema,
                    columns.table,
                    match row.effect {
                        Effect::Allow => "allow",
                        Effect::Deny => "deny",
                    },
                    row.operations.map(Operations::to_stored),
                    row.role_id,
                    row.expires_at,
                    row.note,
                    row.created_by,
                    row.created_at
                ],
            )
            .map(|_| ())
            .map_err(sql_error)
        })
        .await?;
        Ok(grant)
    }

    pub async fn delete_grant(&self, id: &str) -> Result<(), String> {
        let id = id.to_string();
        self.with_conn(move |conn| {
            let changed = conn.execute("DELETE FROM grants WHERE id = ?1", params![id]).map_err(sql_error)?;
            if changed == 0 {
                return Err(GRANT_NOT_FOUND.to_string());
            }
            Ok(())
        })
        .await
    }

    pub async fn delete_grants_for_user(&self, user_id: &str) -> Result<(), String> {
        let user_id = user_id.to_string();
        self.with_conn(move |conn| {
            conn.execute("DELETE FROM grants WHERE principal_kind = 'user' AND principal_id = ?1", params![user_id])
                .map_err(sql_error)?;
            conn.execute("DELETE FROM user_group_members WHERE user_id = ?1", params![user_id]).map_err(sql_error)?;
            Ok(())
        })
        .await
    }

    pub async fn load_authz_snapshot(&self) -> Result<AuthzSnapshot, String> {
        self.with_conn(|conn| {
            let roles: HashMap<String, Operations> = builtin_roles()
                .into_iter()
                .chain(load_custom_roles(conn)?)
                .map(|role| (role.id, role.operations))
                .collect();
            let grants = load_grants(conn, "", &[])?
                .into_iter()
                .map(|stored| Grant {
                    operations: stored
                        .operations
                        .or_else(|| stored.role_id.as_ref().and_then(|role| roles.get(role).copied()))
                        .unwrap_or_default(),
                    id: stored.id,
                    subject: stored.subject,
                    scope: stored.scope,
                    effect: stored.effect,
                    expires_at: stored.expires_at,
                })
                .collect();
            let mut memberships: HashMap<String, Vec<String>> = HashMap::new();
            let mut statement = conn.prepare("SELECT user_id, group_id FROM user_group_members").map_err(sql_error)?;
            let rows = statement
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
                .map_err(sql_error)?;
            for row in rows {
                let (user, group) = row.map_err(sql_error)?;
                memberships.entry(user).or_default().push(group);
            }
            Ok(AuthzSnapshot { grants, memberships })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::storage::NewWebUser;
    use dbx_authz::PlatformRole;

    async fn storage() -> (tempfile::TempDir, Storage) {
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::persistence::test_storage::open(&directory.path().join("storage.db")).await.unwrap();
        (directory, storage)
    }

    async fn user(storage: &Storage, name: &str) -> String {
        storage
            .create_web_user(
                NewWebUser {
                    username: name.into(),
                    display_name: None,
                    password_hash: "h".into(),
                    role: PlatformRole::User,
                    must_change_password: false,
                },
                0,
            )
            .await
            .unwrap()
            .id
    }

    fn grant(
        id: &str,
        subject: Subject,
        scope: Scope,
        operations: Option<Operations>,
        role_id: Option<&str>,
    ) -> StoredGrant {
        StoredGrant {
            id: id.into(),
            subject,
            scope,
            effect: Effect::Allow,
            operations,
            role_id: role_id.map(str::to_string),
            expires_at: None,
            note: None,
            created_by: None,
            created_at: 1,
        }
    }

    #[tokio::test]
    async fn groups_keep_members_and_unique_names() {
        let (_directory, storage) = storage().await;
        let ana = user(&storage, "ana").await;
        let group = storage.create_user_group("Soporte", None, 1).await.unwrap();
        assert_eq!(storage.create_user_group("soporte", None, 1).await.unwrap_err(), GROUP_NAME_TAKEN);
        storage.set_user_group_members(&group.id, vec![ana.clone(), "ghost".into()]).await.unwrap();
        let groups = storage.list_user_groups().await.unwrap();
        assert_eq!(groups[0].member_ids, vec![ana]);
        storage.update_user_group(&group.id, "Support", Some("L1".into())).await.unwrap();
        assert_eq!(storage.list_user_groups().await.unwrap()[0].name, "Support");
        storage.delete_user_group(&group.id).await.unwrap();
        assert!(storage.list_user_groups().await.unwrap().is_empty());
        assert_eq!(storage.delete_user_group(&group.id).await.unwrap_err(), GROUP_NOT_FOUND);
    }

    #[tokio::test]
    async fn roles_list_builtins_first_and_cannot_be_deleted_while_used() {
        let (_directory, storage) = storage().await;
        let role = storage.create_data_role("Auditor", Operations::SELECT | Operations::EXPORT, None).await.unwrap();
        let roles = storage.list_data_roles().await.unwrap();
        assert_eq!(roles.len(), 7);
        assert_eq!(roles[0].id, "builtin:reader");
        assert!(roles[0].builtin);
        storage.save_grant(grant("g1", Subject::User("u".into()), Scope::All, None, Some(&role.id))).await.unwrap();
        assert_eq!(storage.delete_data_role(&role.id).await.unwrap_err(), ROLE_IN_USE);
        storage.delete_grant("g1").await.unwrap();
        storage.delete_data_role(&role.id).await.unwrap();
    }

    #[tokio::test]
    async fn grants_round_trip_every_scope_and_reject_incoherent_ones() {
        let (_directory, storage) = storage().await;
        let scopes = [
            Scope::All,
            Scope::ConnectionGroup("prod".into()),
            Scope::Resource(Resource::connection("c")),
            Scope::Resource(Resource::connection("c").with_database("app")),
            Scope::Resource(Resource::connection("c").with_database("app").with_schema("public")),
            Scope::Resource(Resource::connection("c").with_database("app").with_schema("public").with_table("t")),
            Scope::Resource(Resource::connection("c").with_database("app").with_table("t")),
        ];
        for (index, scope) in scopes.iter().enumerate() {
            storage
                .save_grant(grant(
                    &format!("g{index}"),
                    Subject::Group("grp".into()),
                    scope.clone(),
                    Some(Operations::SELECT),
                    None,
                ))
                .await
                .unwrap();
        }
        let stored: Vec<Scope> = storage.list_grants().await.unwrap().into_iter().map(|grant| grant.scope).collect();
        assert_eq!(stored, scopes.to_vec());

        let invalid = Resource { connection_id: "c".into(), database: None, schema: Some("s".into()), table: None };
        assert_eq!(
            storage
                .save_grant(grant("bad", Subject::System, Scope::Resource(invalid), Some(Operations::SELECT), None))
                .await
                .unwrap_err(),
            GRANT_INVALID
        );
        assert_eq!(
            storage.save_grant(grant("bad", Subject::System, Scope::All, None, None)).await.unwrap_err(),
            GRANT_INVALID
        );
        assert_eq!(
            storage.save_grant(grant("bad", Subject::System, Scope::All, None, Some("nope"))).await.unwrap_err(),
            ROLE_NOT_FOUND
        );
    }

    #[tokio::test]
    async fn snapshot_resolves_roles_and_memberships() {
        let (_directory, storage) = storage().await;
        let ana = user(&storage, "ana").await;
        let group = storage.create_user_group("Soporte", None, 1).await.unwrap();
        storage.set_user_group_members(&group.id, vec![ana.clone()]).await.unwrap();
        storage
            .save_grant(grant("g1", Subject::Group(group.id.clone()), Scope::All, None, Some("builtin:editor")))
            .await
            .unwrap();
        storage
            .save_grant(grant("g2", Subject::User(ana.clone()), Scope::All, Some(Operations::DELETE), None))
            .await
            .unwrap();
        let snapshot = storage.load_authz_snapshot().await.unwrap();
        assert_eq!(snapshot.memberships.get(&ana), Some(&vec![group.id.clone()]));
        let editor = snapshot.grants.iter().find(|grant| grant.id == "g1").unwrap();
        assert_eq!(editor.operations, BuiltinRole::Editor.operations());
        storage.delete_grants_for_user(&ana).await.unwrap();
        let snapshot = storage.load_authz_snapshot().await.unwrap();
        assert!(snapshot.memberships.is_empty());
        assert_eq!(snapshot.grants.len(), 1);
    }
}
