use dbx_authz::PlatformRole;
use rusqlite::Row;
use uuid::Uuid;

use super::{params, OptionalExtension, Storage};

pub const USERNAME_TAKEN: &str = "USERNAME_TAKEN";
pub const USER_NOT_FOUND: &str = "USER_NOT_FOUND";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebUser {
    pub id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub password_hash: String,
    pub role: PlatformRole,
    pub active: bool,
    pub must_change_password: bool,
    pub mfa_required: bool,
    pub identity_provider: String,
    pub last_login_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWebUser {
    pub username: String,
    pub display_name: Option<String>,
    pub password_hash: String,
    pub role: PlatformRole,
    pub must_change_password: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSession {
    pub token_hash: String,
    pub user_id: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub mfa_verified: bool,
}

pub(super) const WEB_USER_SCHEMA_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        display_name TEXT,
        password_hash TEXT NOT NULL,
        platform_role TEXT NOT NULL CHECK (platform_role IN ('admin', 'user')),
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
        must_change_password INTEGER NOT NULL DEFAULT 0,
        mfa_required INTEGER NOT NULL DEFAULT 0,
        identity_provider TEXT NOT NULL DEFAULT 'local',
        external_subject TEXT,
        last_login_at INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS user_sessions (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        expires_at INTEGER,
        revoked_at INTEGER,
        ip TEXT,
        user_agent TEXT,
        mfa_verified INTEGER NOT NULL DEFAULT 0
    )",
    "CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_user_sessions_last_seen ON user_sessions(last_seen_at)",
];

const USER_COLUMNS: &str = "id, username, display_name, password_hash, platform_role, status, must_change_password, \
     mfa_required, identity_provider, last_login_at, created_at, updated_at";

const SESSION_COLUMNS: &str =
    "token_hash, user_id, created_at, last_seen_at, expires_at, revoked_at, ip, user_agent, mfa_verified";

fn user_from_row(row: &Row<'_>) -> rusqlite::Result<WebUser> {
    let role: String = row.get(4)?;
    let status: String = row.get(5)?;
    Ok(WebUser {
        id: row.get(0)?,
        username: row.get(1)?,
        display_name: row.get(2)?,
        password_hash: row.get(3)?,
        role: PlatformRole::parse(&role).unwrap_or(PlatformRole::User),
        active: status == "active",
        must_change_password: row.get::<_, i64>(6)? != 0,
        mfa_required: row.get::<_, i64>(7)? != 0,
        identity_provider: row.get(8)?,
        last_login_at: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

fn session_from_row(row: &Row<'_>) -> rusqlite::Result<WebSession> {
    Ok(WebSession {
        token_hash: row.get(0)?,
        user_id: row.get(1)?,
        created_at: row.get(2)?,
        last_seen_at: row.get(3)?,
        expires_at: row.get(4)?,
        revoked_at: row.get(5)?,
        ip: row.get(6)?,
        user_agent: row.get(7)?,
        mfa_verified: row.get::<_, i64>(8)? != 0,
    })
}

fn sql_error(error: rusqlite::Error) -> String {
    error.to_string()
}

impl Storage {
    pub async fn count_web_users(&self) -> Result<i64, String> {
        self.with_conn(|conn| conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0)).map_err(sql_error))
            .await
    }

    pub async fn count_active_web_admins(&self) -> Result<i64, String> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM users WHERE platform_role = 'admin' AND status = 'active'",
                [],
                |row| row.get(0),
            )
            .map_err(sql_error)
        })
        .await
    }

    pub async fn create_web_user(&self, user: NewWebUser, now: i64) -> Result<WebUser, String> {
        let created = WebUser {
            id: Uuid::new_v4().to_string(),
            username: user.username,
            display_name: user.display_name,
            password_hash: user.password_hash,
            role: user.role,
            active: true,
            must_change_password: user.must_change_password,
            mfa_required: false,
            identity_provider: "local".to_string(),
            last_login_at: None,
            created_at: now,
            updated_at: now,
        };
        let row = created.clone();
        self.with_conn(move |conn| {
            let result = conn.execute(
                "INSERT INTO users (id, username, display_name, password_hash, platform_role, status, \
                 must_change_password, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?7, ?7)",
                params![
                    row.id,
                    row.username,
                    row.display_name,
                    row.password_hash,
                    row.role.as_str(),
                    i64::from(row.must_change_password),
                    now
                ],
            );
            match result {
                Ok(_) => Ok(()),
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if error.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    Err(USERNAME_TAKEN.to_string())
                }
                Err(error) => Err(error.to_string()),
            }
        })
        .await?;
        Ok(created)
    }

    pub async fn find_web_user_by_username(&self, username: &str) -> Result<Option<WebUser>, String> {
        let username = username.to_string();
        self.with_conn(move |conn| {
            conn.query_row(
                &format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?1 COLLATE NOCASE"),
                params![username],
                user_from_row,
            )
            .optional()
            .map_err(sql_error)
        })
        .await
    }

    pub async fn find_web_user(&self, id: &str) -> Result<Option<WebUser>, String> {
        let id = id.to_string();
        self.with_conn(move |conn| {
            conn.query_row(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1"), params![id], user_from_row)
                .optional()
                .map_err(sql_error)
        })
        .await
    }

    pub async fn set_web_user_password(
        &self,
        id: &str,
        password_hash: &str,
        must_change_password: bool,
        now: i64,
    ) -> Result<(), String> {
        let (id, password_hash) = (id.to_string(), password_hash.to_string());
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE users SET password_hash = ?2, must_change_password = ?3, updated_at = ?4 WHERE id = ?1",
                    params![id, password_hash, i64::from(must_change_password), now],
                )
                .map_err(sql_error)?;
            if changed == 0 {
                return Err(USER_NOT_FOUND.to_string());
            }
            Ok(())
        })
        .await
    }

    pub async fn set_web_user_active(&self, id: &str, active: bool, now: i64) -> Result<(), String> {
        let id = id.to_string();
        let status = if active { "active" } else { "disabled" };
        self.with_conn(move |conn| {
            let changed = conn
                .execute("UPDATE users SET status = ?2, updated_at = ?3 WHERE id = ?1", params![id, status, now])
                .map_err(sql_error)?;
            if changed == 0 {
                return Err(USER_NOT_FOUND.to_string());
            }
            Ok(())
        })
        .await
    }

    pub async fn record_web_user_login(&self, id: &str, now: i64) -> Result<(), String> {
        let id = id.to_string();
        self.with_conn(move |conn| {
            conn.execute("UPDATE users SET last_login_at = ?2 WHERE id = ?1", params![id, now])
                .map(|_| ())
                .map_err(sql_error)
        })
        .await
    }

    pub async fn insert_web_session(&self, session: WebSession) -> Result<(), String> {
        self.with_conn(move |conn| {
            conn.execute(
                &format!("INSERT OR REPLACE INTO user_sessions ({SESSION_COLUMNS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"),
                params![
                    session.token_hash,
                    session.user_id,
                    session.created_at,
                    session.last_seen_at,
                    session.expires_at,
                    session.revoked_at,
                    session.ip,
                    session.user_agent,
                    i64::from(session.mfa_verified)
                ],
            )
            .map(|_| ())
            .map_err(sql_error)
        })
        .await
    }

    pub async fn find_web_session(&self, token_hash: &str) -> Result<Option<WebSession>, String> {
        let token_hash = token_hash.to_string();
        self.with_conn(move |conn| {
            conn.query_row(
                &format!("SELECT {SESSION_COLUMNS} FROM user_sessions WHERE token_hash = ?1"),
                params![token_hash],
                session_from_row,
            )
            .optional()
            .map_err(sql_error)
        })
        .await
    }

    pub async fn touch_web_session(&self, token_hash: &str, now: i64) -> Result<(), String> {
        let token_hash = token_hash.to_string();
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE user_sessions SET last_seen_at = MAX(last_seen_at, ?2) WHERE token_hash = ?1",
                params![token_hash, now],
            )
            .map(|_| ())
            .map_err(sql_error)
        })
        .await
    }

    pub async fn revoke_web_session(&self, token_hash: &str, now: i64) -> Result<(), String> {
        let token_hash = token_hash.to_string();
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE user_sessions SET revoked_at = ?2 WHERE token_hash = ?1 AND revoked_at IS NULL",
                params![token_hash, now],
            )
            .map(|_| ())
            .map_err(sql_error)
        })
        .await
    }

    pub async fn revoke_web_user_sessions(
        &self,
        user_id: &str,
        keep_token_hash: Option<&str>,
        now: i64,
    ) -> Result<Vec<String>, String> {
        let user_id = user_id.to_string();
        let keep = keep_token_hash.unwrap_or_default().to_string();
        self.with_conn(move |conn| {
            let transaction = conn.transaction().map_err(sql_error)?;
            let revoked = {
                let mut statement = transaction
                    .prepare(
                        "SELECT token_hash FROM user_sessions \
                         WHERE user_id = ?1 AND token_hash <> ?2 AND revoked_at IS NULL",
                    )
                    .map_err(sql_error)?;
                let rows = statement
                    .query_map(params![user_id, keep], |row| row.get::<_, String>(0))
                    .map_err(sql_error)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sql_error)?;
                rows
            };
            transaction
                .execute(
                    "UPDATE user_sessions SET revoked_at = ?3 \
                     WHERE user_id = ?1 AND token_hash <> ?2 AND revoked_at IS NULL",
                    params![user_id, keep, now],
                )
                .map_err(sql_error)?;
            transaction.commit().map_err(sql_error)?;
            Ok(revoked)
        })
        .await
    }

    pub async fn purge_web_sessions(&self, idle_cutoff: i64, now: i64) -> Result<usize, String> {
        self.with_conn(move |conn| {
            conn.execute(
                "DELETE FROM user_sessions WHERE revoked_at IS NOT NULL OR last_seen_at < ?1 \
                 OR (expires_at IS NOT NULL AND expires_at <= ?2)",
                params![idle_cutoff, now],
            )
            .map_err(sql_error)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn storage() -> (tempfile::TempDir, Storage) {
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::persistence::test_storage::open(&directory.path().join("storage.db")).await.unwrap();
        (directory, storage)
    }

    fn new_user(username: &str, role: PlatformRole) -> NewWebUser {
        NewWebUser {
            username: username.to_string(),
            display_name: None,
            password_hash: "hash".to_string(),
            role,
            must_change_password: false,
        }
    }

    fn session(token_hash: &str, user_id: &str, last_seen_at: i64) -> WebSession {
        WebSession {
            token_hash: token_hash.to_string(),
            user_id: user_id.to_string(),
            created_at: last_seen_at,
            last_seen_at,
            expires_at: None,
            revoked_at: None,
            ip: Some("10.0.0.1".into()),
            user_agent: None,
            mfa_verified: false,
        }
    }

    #[tokio::test]
    async fn users_are_unique_case_insensitively_and_counted_by_role() {
        let (_directory, storage) = storage().await;
        assert_eq!(storage.count_web_users().await.unwrap(), 0);
        let admin = storage.create_web_user(new_user("Admin", PlatformRole::Admin), 10).await.unwrap();
        storage.create_web_user(new_user("ana", PlatformRole::User), 10).await.unwrap();
        assert_eq!(
            storage.create_web_user(new_user("ADMIN", PlatformRole::User), 10).await.unwrap_err(),
            USERNAME_TAKEN
        );
        assert_eq!(storage.count_web_users().await.unwrap(), 2);
        assert_eq!(storage.count_active_web_admins().await.unwrap(), 1);
        let found = storage.find_web_user_by_username("aDmIn").await.unwrap().unwrap();
        assert_eq!(found, admin);
        assert_eq!(storage.find_web_user(&admin.id).await.unwrap().unwrap().username, "Admin");
        assert!(storage.find_web_user_by_username("nobody").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn password_status_and_login_updates_are_persisted() {
        let (_directory, storage) = storage().await;
        let user = storage.create_web_user(new_user("ana", PlatformRole::User), 10).await.unwrap();
        storage.set_web_user_password(&user.id, "new-hash", true, 20).await.unwrap();
        storage.set_web_user_active(&user.id, false, 30).await.unwrap();
        storage.record_web_user_login(&user.id, 40).await.unwrap();
        let updated = storage.find_web_user(&user.id).await.unwrap().unwrap();
        assert_eq!(updated.password_hash, "new-hash");
        assert!(updated.must_change_password);
        assert!(!updated.active);
        assert_eq!(updated.last_login_at, Some(40));
        assert_eq!(updated.updated_at, 30);
        assert_eq!(storage.set_web_user_password("missing", "h", false, 1).await.unwrap_err(), USER_NOT_FOUND);
        assert_eq!(storage.count_active_web_admins().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn sessions_round_trip_touch_and_revoke() {
        let (_directory, storage) = storage().await;
        storage.insert_web_session(session("h1", "u1", 100)).await.unwrap();
        storage.touch_web_session("h1", 200).await.unwrap();
        storage.touch_web_session("h1", 150).await.unwrap();
        let found = storage.find_web_session("h1").await.unwrap().unwrap();
        assert_eq!(found.last_seen_at, 200);
        assert_eq!(found.ip.as_deref(), Some("10.0.0.1"));
        storage.revoke_web_session("h1", 300).await.unwrap();
        storage.revoke_web_session("h1", 400).await.unwrap();
        assert_eq!(storage.find_web_session("h1").await.unwrap().unwrap().revoked_at, Some(300));
        assert!(storage.find_web_session("missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoking_a_user_keeps_the_current_session_and_other_users() {
        let (_directory, storage) = storage().await;
        for (hash, user) in [("a1", "u1"), ("a2", "u1"), ("a3", "u1"), ("b1", "u2")] {
            storage.insert_web_session(session(hash, user, 100)).await.unwrap();
        }
        let mut revoked = storage.revoke_web_user_sessions("u1", Some("a1"), 500).await.unwrap();
        revoked.sort();
        assert_eq!(revoked, vec!["a2".to_string(), "a3".to_string()]);
        assert!(storage.find_web_session("a1").await.unwrap().unwrap().revoked_at.is_none());
        assert!(storage.find_web_session("b1").await.unwrap().unwrap().revoked_at.is_none());
        assert!(storage.revoke_web_user_sessions("u1", Some("a1"), 600).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn purge_removes_revoked_idle_and_expired_sessions_only() {
        let (_directory, storage) = storage().await;
        storage.insert_web_session(session("fresh", "u", 1_000)).await.unwrap();
        storage.insert_web_session(session("idle", "u", 10)).await.unwrap();
        storage
            .insert_web_session(WebSession { expires_at: Some(900), ..session("expired", "u", 1_000) })
            .await
            .unwrap();
        storage.insert_web_session(session("revoked", "u", 1_000)).await.unwrap();
        storage.revoke_web_session("revoked", 1_000).await.unwrap();
        assert_eq!(storage.purge_web_sessions(500, 1_000).await.unwrap(), 3);
        assert!(storage.find_web_session("fresh").await.unwrap().is_some());
    }
}
