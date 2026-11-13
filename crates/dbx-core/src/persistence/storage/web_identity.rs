use dbx_authz::PlatformRole;
use rusqlite::Row;
use uuid::Uuid;

use super::{params, OptionalExtension, Storage, WebUser, GLOBAL_SECRET_NAMESPACE, USERNAME_TAKEN};

pub const IDENTITY_PROVIDER_NOT_FOUND: &str = "IDENTITY_PROVIDER_NOT_FOUND";
pub const IDENTITY_PROVIDER_NAME_TAKEN: &str = "IDENTITY_PROVIDER_NAME_TAKEN";
pub const IDENTITY_PROVIDER_IN_USE: &str = "IDENTITY_PROVIDER_IN_USE";
const UNUSABLE_PASSWORD: &str = "!external";

pub(super) const WEB_IDENTITY_SCHEMA_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS identity_providers (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('oidc', 'ldap')),
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        config_json TEXT NOT NULL DEFAULT '{}',
        auto_create_users INTEGER NOT NULL DEFAULT 0,
        default_group_id TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_external_subject
        ON users(identity_provider, external_subject) WHERE external_subject IS NOT NULL",
];

#[derive(Debug, Clone, PartialEq)]
pub struct IdentityProvider {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub config: serde_json::Value,
    pub auto_create_users: bool,
    pub default_group_id: Option<String>,
    pub enabled: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

fn provider_from_row(row: &Row<'_>) -> rusqlite::Result<IdentityProvider> {
    let config: String = row.get(3)?;
    Ok(IdentityProvider {
        id: row.get(0)?,
        kind: row.get(1)?,
        name: row.get(2)?,
        config: serde_json::from_str(&config).unwrap_or_else(|_| serde_json::json!({})),
        auto_create_users: row.get::<_, i64>(4)? != 0,
        default_group_id: row.get(5)?,
        enabled: row.get::<_, i64>(6)? != 0,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

const PROVIDER_COLUMNS: &str =
    "id, kind, name, config_json, auto_create_users, default_group_id, enabled, created_at, updated_at";

fn sql_error(error: rusqlite::Error) -> String {
    error.to_string()
}

fn secret_key(id: &str) -> String {
    format!("identity_provider.{id}")
}

impl Storage {
    pub async fn list_identity_providers(&self) -> Result<Vec<IdentityProvider>, String> {
        self.with_conn(|conn| {
            let mut statement = conn
                .prepare(&format!("SELECT {PROVIDER_COLUMNS} FROM identity_providers ORDER BY name COLLATE NOCASE"))
                .map_err(sql_error)?;
            let providers = statement
                .query_map([], provider_from_row)
                .map_err(sql_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql_error)?;
            Ok(providers)
        })
        .await
    }

    pub async fn find_identity_provider(&self, id: &str) -> Result<Option<IdentityProvider>, String> {
        let id = id.to_string();
        self.with_conn(move |conn| {
            conn.query_row(
                &format!("SELECT {PROVIDER_COLUMNS} FROM identity_providers WHERE id = ?1"),
                params![id],
                provider_from_row,
            )
            .optional()
            .map_err(sql_error)
        })
        .await
    }

    pub async fn save_identity_provider(&self, provider: IdentityProvider) -> Result<IdentityProvider, String> {
        let config = serde_json::to_string(&provider.config).map_err(|error| error.to_string())?;
        self.with_conn(move |conn| {
            let result = conn.execute(
                "INSERT INTO identity_providers (id, kind, name, config_json, auto_create_users, default_group_id, enabled, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                 ON CONFLICT(id) DO UPDATE SET name = excluded.name, config_json = excluded.config_json, \
                 auto_create_users = excluded.auto_create_users, default_group_id = excluded.default_group_id, \
                 enabled = excluded.enabled, updated_at = excluded.updated_at",
                params![
                    provider.id,
                    provider.kind,
                    provider.name,
                    config,
                    i64::from(provider.auto_create_users),
                    provider.default_group_id,
                    i64::from(provider.enabled),
                    provider.created_at,
                    provider.updated_at
                ],
            );
            match result {
                Ok(_) => Ok(provider),
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if error.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    Err(IDENTITY_PROVIDER_NAME_TAKEN.to_string())
                }
                Err(error) => Err(sql_error(error)),
            }
        })
        .await
    }

    pub async fn delete_identity_provider(&self, id: &str) -> Result<(), String> {
        let id = id.to_string();
        let secret = secret_key(&id);
        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(sql_error)?;
            let linked: i64 = tx
                .query_row("SELECT COUNT(*) FROM users WHERE identity_provider = ?1", params![id], |row| row.get(0))
                .map_err(sql_error)?;
            if linked > 0 {
                return Err(IDENTITY_PROVIDER_IN_USE.to_string());
            }
            let changed = tx.execute("DELETE FROM identity_providers WHERE id = ?1", params![id]).map_err(sql_error)?;
            if changed == 0 {
                return Err(IDENTITY_PROVIDER_NOT_FOUND.to_string());
            }
            tx.execute(
                "DELETE FROM connection_secrets WHERE connection_id = ?1 AND key = ?2",
                params![GLOBAL_SECRET_NAMESPACE, secret],
            )
            .map_err(sql_error)?;
            tx.commit().map_err(sql_error)
        })
        .await
    }

    pub async fn load_identity_provider_secret(&self, id: &str) -> Result<Option<String>, String> {
        self.get_secret(GLOBAL_SECRET_NAMESPACE, &secret_key(id)).await
    }

    pub async fn save_identity_provider_secret(&self, id: &str, secret: Option<&str>) -> Result<(), String> {
        match secret.filter(|secret| !secret.is_empty()) {
            Some(secret) => self.set_secret(GLOBAL_SECRET_NAMESPACE, &secret_key(id), secret).await,
            None => self.delete_secret(GLOBAL_SECRET_NAMESPACE, &secret_key(id)).await,
        }
    }

    pub async fn find_web_user_by_external_subject(
        &self,
        provider_id: &str,
        subject: &str,
    ) -> Result<Option<WebUser>, String> {
        let (provider_id, subject) = (provider_id.to_string(), subject.to_string());
        let id: Option<String> = self
            .with_conn(move |conn| {
                conn.query_row(
                    "SELECT id FROM users WHERE identity_provider = ?1 AND external_subject = ?2",
                    params![provider_id, subject],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)
            })
            .await?;
        match id {
            Some(id) => self.find_web_user(&id).await,
            None => Ok(None),
        }
    }

    pub async fn create_external_web_user(
        &self,
        username: &str,
        display_name: Option<String>,
        provider_id: &str,
        subject: &str,
        default_group_id: Option<&str>,
        now: i64,
    ) -> Result<WebUser, String> {
        let id = Uuid::new_v4().to_string();
        let (user_id, username_owned, provider, subject_owned) =
            (id.clone(), username.to_string(), provider_id.to_string(), subject.to_string());
        let group = default_group_id.map(str::to_string);
        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(sql_error)?;
            let inserted = tx.execute(
                "INSERT INTO users (id, username, display_name, password_hash, platform_role, status, must_change_password, \
                 mfa_required, identity_provider, external_subject, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 'active', 0, 0, ?6, ?7, ?8, ?8)",
                params![user_id, username_owned, display_name, UNUSABLE_PASSWORD, PlatformRole::User.as_str(), provider, subject_owned, now],
            );
            match inserted {
                Ok(_) => {}
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if error.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    return Err(USERNAME_TAKEN.to_string());
                }
                Err(error) => return Err(sql_error(error)),
            }
            if let Some(group) = group {
                tx.execute(
                    "INSERT OR IGNORE INTO user_group_members (group_id, user_id) \
                     SELECT id, ?2 FROM user_groups WHERE id = ?1",
                    params![group, user_id],
                )
                .map_err(sql_error)?;
            }
            tx.commit().map_err(sql_error)
        })
        .await?;
        self.find_web_user(&id).await?.ok_or_else(|| super::USER_NOT_FOUND.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(name: &str) -> IdentityProvider {
        IdentityProvider {
            id: Uuid::new_v4().to_string(),
            kind: "oidc".into(),
            name: name.into(),
            config: serde_json::json!({ "issuer": "https://id.example.com" }),
            auto_create_users: true,
            default_group_id: None,
            enabled: true,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[tokio::test]
    async fn stores_providers_and_links_external_accounts_by_subject() {
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::persistence::test_storage::open(&directory.path().join("storage.db")).await.unwrap();
        let keycloak = storage.save_identity_provider(provider("Keycloak")).await.unwrap();
        assert_eq!(
            storage.save_identity_provider(provider("keycloak")).await.unwrap_err(),
            IDENTITY_PROVIDER_NAME_TAKEN
        );
        storage.save_identity_provider_secret(&keycloak.id, Some("client-secret")).await.unwrap();
        assert_eq!(
            storage.load_identity_provider_secret(&keycloak.id).await.unwrap().as_deref(),
            Some("client-secret")
        );
        assert_eq!(storage.list_identity_providers().await.unwrap().len(), 1);

        let group = storage.create_user_group("SSO", None, 1).await.unwrap();
        let user = storage
            .create_external_web_user("ana", Some("Ana".into()), &keycloak.id, "sub-1", Some(&group.id), 5)
            .await
            .unwrap();
        assert_eq!(user.identity_provider, keycloak.id);
        assert!(!user.password_hash.starts_with('$'));
        let found = storage.find_web_user_by_external_subject(&keycloak.id, "sub-1").await.unwrap().unwrap();
        assert_eq!(found.id, user.id);
        assert!(storage.find_web_user_by_external_subject(&keycloak.id, "sub-2").await.unwrap().is_none());
        assert!(storage.find_web_user_by_external_subject("other", "sub-1").await.unwrap().is_none());
        let groups = storage.list_user_groups().await.unwrap();
        assert_eq!(groups[0].member_ids, vec![user.id.clone()]);
        assert_eq!(
            storage.create_external_web_user("ana", None, &keycloak.id, "sub-9", None, 6).await.unwrap_err(),
            USERNAME_TAKEN
        );

        assert_eq!(storage.delete_identity_provider(&keycloak.id).await.unwrap_err(), IDENTITY_PROVIDER_IN_USE);
        storage.delete_web_user(&user.id).await.unwrap();
        storage.delete_identity_provider(&keycloak.id).await.unwrap();
        assert!(storage.load_identity_provider_secret(&keycloak.id).await.unwrap().is_none());
    }
}
