use std::collections::HashMap;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dbx_authz::PlatformRole;
use dbx_core::storage::{Storage, WebSession, WebUser};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

const TOUCH_INTERVAL_MS: i64 = 60_000;
const DEFAULT_IDLE_MINUTES: u64 = 120;
const DEFAULT_MAX_HOURS: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionConfig {
    pub idle: Duration,
    pub max_age: Option<Duration>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self::from_values(None, None)
    }
}

impl SessionConfig {
    pub fn from_env() -> Self {
        Self::from_values(
            std::env::var("DBX_SESSION_IDLE_MINUTES").ok().as_deref(),
            std::env::var("DBX_SESSION_MAX_HOURS").ok().as_deref(),
        )
    }

    pub fn from_values(idle_minutes: Option<&str>, max_hours: Option<&str>) -> Self {
        let idle_minutes = idle_minutes
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|minutes| *minutes > 0)
            .unwrap_or(DEFAULT_IDLE_MINUTES);
        let max_hours = max_hours.and_then(|value| value.trim().parse::<u64>().ok()).unwrap_or(DEFAULT_MAX_HOURS);
        Self {
            idle: Duration::from_secs(idle_minutes * 60),
            max_age: (max_hours > 0).then(|| Duration::from_secs(max_hours * 3600)),
        }
    }

    fn idle_ms(&self) -> i64 {
        i64::try_from(self.idle.as_millis()).unwrap_or(i64::MAX)
    }

    fn expires_at(&self, created_at: i64) -> Option<i64> {
        self.max_age.map(|age| created_at.saturating_add(i64::try_from(age.as_millis()).unwrap_or(i64::MAX)))
    }

    fn is_live(&self, last_seen_at: i64, expires_at: Option<i64>, now: i64) -> bool {
        now.saturating_sub(last_seen_at) <= self.idle_ms() && expires_at.is_none_or(|expires_at| now < expires_at)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUser {
    pub user_id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub role: PlatformRole,
    pub must_change_password: bool,
    pub token_hash: String,
}

impl SessionUser {
    fn from_user(user: &WebUser, token_hash: String) -> Self {
        Self {
            user_id: user.id.clone(),
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            role: user.role,
            must_change_password: user.must_change_password,
            token_hash,
        }
    }
}

#[derive(Debug, Clone)]
struct CachedSession {
    user: SessionUser,
    last_seen_at: i64,
    persisted_seen_at: i64,
    expires_at: Option<i64>,
}

pub fn hash_token(raw: &str) -> String {
    Sha256::digest(raw.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn generate_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| error.to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub struct SessionManager {
    config: SessionConfig,
    cache: RwLock<HashMap<String, CachedSession>>,
}

impl SessionManager {
    pub fn new(config: SessionConfig) -> Self {
        Self { config, cache: RwLock::new(HashMap::new()) }
    }

    pub async fn create(
        &self,
        storage: &Storage,
        user: &WebUser,
        ip: Option<String>,
        user_agent: Option<String>,
        now: i64,
    ) -> Result<(String, SessionUser), String> {
        let raw = generate_token()?;
        let token_hash = hash_token(&raw);
        let expires_at = self.config.expires_at(now);
        storage
            .insert_web_session(WebSession {
                token_hash: token_hash.clone(),
                user_id: user.id.clone(),
                created_at: now,
                last_seen_at: now,
                expires_at,
                revoked_at: None,
                ip,
                user_agent,
                mfa_verified: false,
            })
            .await?;
        let session_user = SessionUser::from_user(user, token_hash.clone());
        self.cache.write().await.insert(
            token_hash,
            CachedSession { user: session_user.clone(), last_seen_at: now, persisted_seen_at: now, expires_at },
        );
        Ok((raw, session_user))
    }

    pub async fn validate(&self, storage: &Storage, raw: &str, now: i64) -> Option<SessionUser> {
        let token_hash = hash_token(raw);
        let cached = {
            let mut cache = self.cache.write().await;
            match cache.get_mut(&token_hash) {
                Some(entry) if self.config.is_live(entry.last_seen_at, entry.expires_at, now) => {
                    entry.last_seen_at = entry.last_seen_at.max(now);
                    let touch = now - entry.persisted_seen_at >= TOUCH_INTERVAL_MS;
                    if touch {
                        entry.persisted_seen_at = now;
                    }
                    Some(Some((entry.user.clone(), touch)))
                }
                Some(_) => {
                    cache.remove(&token_hash);
                    Some(None)
                }
                None => None,
            }
        };
        match cached {
            Some(Some((user, touch))) => {
                if touch {
                    if let Err(error) = storage.touch_web_session(&token_hash, now).await {
                        log::warn!("Failed to persist web session activity: {error}");
                    }
                }
                return Some(user);
            }
            Some(None) => return None,
            None => {}
        }

        let session = storage.find_web_session(&token_hash).await.ok()??;
        if session.revoked_at.is_some() || !self.config.is_live(session.last_seen_at, session.expires_at, now) {
            return None;
        }
        let user = storage.find_web_user(&session.user_id).await.ok()??;
        if !user.active {
            return None;
        }
        if let Err(error) = storage.touch_web_session(&token_hash, now).await {
            log::warn!("Failed to persist web session activity: {error}");
        }
        let session_user = SessionUser::from_user(&user, token_hash.clone());
        self.cache.write().await.insert(
            token_hash,
            CachedSession {
                user: session_user.clone(),
                last_seen_at: now,
                persisted_seen_at: now,
                expires_at: session.expires_at,
            },
        );
        Some(session_user)
    }

    pub async fn revoke(&self, storage: &Storage, raw: &str, now: i64) -> Result<(), String> {
        let token_hash = hash_token(raw);
        self.cache.write().await.remove(&token_hash);
        storage.revoke_web_session(&token_hash, now).await
    }

    pub async fn revoke_user(
        &self,
        storage: &Storage,
        user_id: &str,
        keep_token_hash: Option<&str>,
        now: i64,
    ) -> Result<Vec<String>, String> {
        let revoked = storage.revoke_web_user_sessions(user_id, keep_token_hash, now).await?;
        self.forget_user(user_id).await;
        Ok(revoked)
    }

    pub async fn forget_user(&self, user_id: &str) {
        self.cache.write().await.retain(|_, entry| entry.user.user_id != user_id);
    }

    pub async fn purge(&self, storage: &Storage, now: i64) -> Result<usize, String> {
        self.cache.write().await.retain(|_, entry| self.config.is_live(entry.last_seen_at, entry.expires_at, now));
        storage.purge_web_sessions(now.saturating_sub(self.config.idle_ms()), now).await
    }
}

pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbx_core::storage::NewWebUser;

    const MINUTE: i64 = 60_000;
    const HOUR: i64 = 60 * MINUTE;

    async fn storage_with_user() -> (tempfile::TempDir, Storage, WebUser) {
        let directory = tempfile::tempdir().unwrap();
        let storage = dbx_core::persistence::test_storage::open(&directory.path().join("storage.db")).await.unwrap();
        let user = storage
            .create_web_user(
                NewWebUser {
                    username: "ana".into(),
                    display_name: Some("Ana".into()),
                    password_hash: "hash".into(),
                    role: PlatformRole::User,
                    must_change_password: false,
                },
                0,
            )
            .await
            .unwrap();
        (directory, storage, user)
    }

    #[test]
    fn config_defaults_to_two_hours_idle_and_four_hours_max() {
        let config = SessionConfig::from_values(None, None);
        assert_eq!(config.idle, Duration::from_secs(2 * 3600));
        assert_eq!(config.max_age, Some(Duration::from_secs(4 * 3600)));
        let custom = SessionConfig::from_values(Some("30"), Some("0"));
        assert_eq!(custom.idle, Duration::from_secs(30 * 60));
        assert_eq!(custom.max_age, None);
        assert_eq!(SessionConfig::from_values(Some("0"), Some("x")), config);
    }

    #[test]
    fn tokens_are_random_and_only_their_hash_is_kept() {
        let first = generate_token().unwrap();
        assert_ne!(first, generate_token().unwrap());
        assert_eq!(first.len(), 43);
        assert_eq!(hash_token(&first).len(), 64);
        assert_ne!(hash_token(&first), first);
    }

    #[tokio::test]
    async fn sessions_survive_a_restart_and_store_only_the_hash() {
        let (_directory, storage, user) = storage_with_user().await;
        let manager = SessionManager::new(SessionConfig::default());
        let (raw, created) = manager.create(&storage, &user, Some("10.0.0.1".into()), None, 1_000).await.unwrap();
        assert!(storage.find_web_session(&raw).await.unwrap().is_none());
        assert!(storage.find_web_session(&created.token_hash).await.unwrap().is_some());

        let restarted = SessionManager::new(SessionConfig::default());
        let validated = restarted.validate(&storage, &raw, 1_000 + 10 * MINUTE).await.unwrap();
        assert_eq!(validated.username, "ana");
        assert_eq!(validated.display_name.as_deref(), Some("Ana"));
        assert!(restarted.validate(&storage, "forged", 1_000).await.is_none());
    }

    #[tokio::test]
    async fn idle_sessions_expire_and_activity_extends_them() {
        let (_directory, storage, user) = storage_with_user().await;
        let manager = SessionManager::new(SessionConfig::from_values(Some("120"), Some("0")));
        let (raw, _) = manager.create(&storage, &user, None, None, 0).await.unwrap();
        assert!(manager.validate(&storage, &raw, 90 * MINUTE).await.is_some());
        assert!(manager.validate(&storage, &raw, 200 * MINUTE).await.is_some());
        assert!(manager.validate(&storage, &raw, 321 * MINUTE).await.is_none());
    }

    #[tokio::test]
    async fn activity_is_persisted_so_a_restart_keeps_the_idle_window() {
        let (_directory, storage, user) = storage_with_user().await;
        let manager = SessionManager::new(SessionConfig::from_values(Some("120"), Some("0")));
        let (raw, _) = manager.create(&storage, &user, None, None, 0).await.unwrap();
        assert!(manager.validate(&storage, &raw, 100 * MINUTE).await.is_some());
        let restarted = SessionManager::new(SessionConfig::from_values(Some("120"), Some("0")));
        assert!(restarted.validate(&storage, &raw, 210 * MINUTE).await.is_some());
    }

    #[tokio::test]
    async fn absolute_lifetime_ends_even_an_active_session() {
        let (_directory, storage, user) = storage_with_user().await;
        let manager = SessionManager::new(SessionConfig::default());
        let (raw, _) = manager.create(&storage, &user, None, None, 0).await.unwrap();
        for minute in (30..240).step_by(30) {
            assert!(manager.validate(&storage, &raw, minute * MINUTE).await.is_some(), "minute {minute}");
        }
        assert!(manager.validate(&storage, &raw, 4 * HOUR).await.is_none());
        let restarted = SessionManager::new(SessionConfig::default());
        assert!(restarted.validate(&storage, &raw, 4 * HOUR).await.is_none());
    }

    #[tokio::test]
    async fn revoked_and_disabled_users_lose_access() {
        let (_directory, storage, user) = storage_with_user().await;
        let manager = SessionManager::new(SessionConfig::default());
        let (first, first_user) = manager.create(&storage, &user, None, None, 0).await.unwrap();
        let (second, _) = manager.create(&storage, &user, None, None, 0).await.unwrap();
        let (third, _) = manager.create(&storage, &user, None, None, 0).await.unwrap();

        manager.revoke(&storage, &third, 1).await.unwrap();
        assert!(manager.validate(&storage, &third, 2).await.is_none());

        manager.revoke_user(&storage, &user.id, Some(&first_user.token_hash), 3).await.unwrap();
        assert!(manager.validate(&storage, &first, 4).await.is_some());
        assert!(manager.validate(&storage, &second, 4).await.is_none());

        storage.set_web_user_active(&user.id, false, 5).await.unwrap();
        manager.forget_user(&user.id).await;
        assert!(manager.validate(&storage, &first, 6).await.is_none());
    }

    #[tokio::test]
    async fn purge_drops_dead_sessions_from_storage() {
        let (_directory, storage, user) = storage_with_user().await;
        let manager = SessionManager::new(SessionConfig::default());
        let (_raw, created) = manager.create(&storage, &user, None, None, 0).await.unwrap();
        assert_eq!(manager.purge(&storage, HOUR).await.unwrap(), 0);
        assert_eq!(manager.purge(&storage, 5 * HOUR).await.unwrap(), 1);
        assert!(storage.find_web_session(&created.token_hash).await.unwrap().is_none());
    }
}
