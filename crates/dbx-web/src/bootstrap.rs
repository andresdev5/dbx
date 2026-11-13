use std::sync::Mutex;
use std::time::{Duration, Instant};

use dbx_authz::PlatformRole;
use dbx_core::storage::{NewWebUser, Storage};

use crate::identity::{hash_password, normalize_username};

pub const DEFAULT_ADMIN_USERNAME: &str = "admin";
pub const SETUP_TOKEN_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootstrapEnv {
    pub password: Option<String>,
    pub admin_username: Option<String>,
    pub admin_reset: bool,
}

impl BootstrapEnv {
    pub fn from_env() -> Self {
        Self {
            password: std::env::var("DBX_PASSWORD").ok().filter(|value| !value.is_empty()),
            admin_username: std::env::var("DBX_ADMIN_USER").ok().filter(|value| !value.trim().is_empty()),
            admin_reset: std::env::var("DBX_ADMIN_RESET")
                .is_ok_and(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")),
        }
    }

    fn admin_username(&self) -> Result<String, String> {
        normalize_username(self.admin_username.as_deref().unwrap_or(DEFAULT_ADMIN_USERNAME))
            .map_err(|_| "DBX_ADMIN_USER is not a valid username".to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapOutcome {
    CreatedFromEnv,
    CreatedFromLegacyPassword,
    ResetFromEnv,
    Existing,
    SetupRequired,
}

impl BootstrapOutcome {
    pub fn users_configured(self) -> bool {
        self != Self::SetupRequired
    }
}

pub async fn bootstrap_users(storage: &Storage, env: &BootstrapEnv, now: i64) -> Result<BootstrapOutcome, String> {
    let username = env.admin_username()?;
    if storage.count_web_users().await? == 0 {
        if let Some(password) = &env.password {
            create_admin(storage, &username, hash_password(password)?, now).await?;
            log::info!("Created DBX Web administrator '{username}' from DBX_PASSWORD");
            return Ok(BootstrapOutcome::CreatedFromEnv);
        }
        if let Some(legacy_hash) = storage.load_password_hash().await? {
            create_admin(storage, &username, legacy_hash, now).await?;
            log::info!("Migrated the previous DBX Web password to administrator '{username}'");
            return Ok(BootstrapOutcome::CreatedFromLegacyPassword);
        }
        return Ok(BootstrapOutcome::SetupRequired);
    }

    let Some(password) = &env.password else {
        return Ok(BootstrapOutcome::Existing);
    };
    if !env.admin_reset {
        log::warn!(
            "DBX_PASSWORD is ignored because DBX Web users already exist; set DBX_ADMIN_RESET=1 to reset '{username}'"
        );
        return Ok(BootstrapOutcome::Existing);
    }
    let hash = hash_password(password)?;
    match storage.find_web_user_by_username(&username).await? {
        Some(user) => {
            storage.set_web_user_password(&user.id, &hash, false, now).await?;
            storage.set_web_user_active(&user.id, true, now).await?;
            storage.revoke_web_user_sessions(&user.id, None, now).await?;
            if user.mfa_enabled {
                storage.disable_mfa(&user.id, now).await?;
                log::warn!("DBX_ADMIN_RESET removed the two-factor setup of '{}'", user.username);
            }
            log::warn!("DBX_ADMIN_RESET reset the password of '{}'", user.username);
            if user.role != PlatformRole::Admin {
                log::warn!("DBX_ADMIN_RESET target '{}' is not an administrator", user.username);
            }
        }
        None => {
            create_admin(storage, &username, hash, now).await?;
            log::warn!("DBX_ADMIN_RESET created administrator '{username}'");
        }
    }
    Ok(BootstrapOutcome::ResetFromEnv)
}

async fn create_admin(storage: &Storage, username: &str, password_hash: String, now: i64) -> Result<(), String> {
    storage
        .create_web_user(
            NewWebUser {
                username: username.to_string(),
                display_name: None,
                password_hash,
                role: PlatformRole::Admin,
                must_change_password: false,
            },
            now,
        )
        .await
        .map(|_| ())
}

struct IssuedToken {
    value: String,
    issued_at: Instant,
}

#[derive(Default)]
pub struct SetupTokenSlot {
    current: Mutex<Option<IssuedToken>>,
}

impl SetupTokenSlot {
    pub fn ensure_issued(&self) {
        self.ensure_issued_at(Instant::now());
    }

    fn ensure_issued_at(&self, now: Instant) -> Option<String> {
        let mut current = self.current.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if current.as_ref().is_some_and(|token| now.duration_since(token.issued_at) < SETUP_TOKEN_TTL) {
            return None;
        }
        let value = match crate::sessions::generate_token() {
            Ok(value) => value,
            Err(error) => {
                log::error!("Could not generate a DBX Web setup token: {error}");
                return None;
            }
        };
        log::warn!("DBX Web has no users yet. Setup token (valid for 60 minutes, single use): {value}");
        *current = Some(IssuedToken { value: value.clone(), issued_at: now });
        Some(value)
    }

    pub fn verify(&self, candidate: &str) -> bool {
        self.verify_at(candidate, Instant::now())
    }

    fn verify_at(&self, candidate: &str, now: Instant) -> bool {
        let current = self.current.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        current.as_ref().is_some_and(|token| {
            now.duration_since(token.issued_at) < SETUP_TOKEN_TTL
                && constant_time_eq(token.value.as_bytes(), candidate.as_bytes())
        })
    }

    #[cfg(test)]
    pub fn peek(&self) -> Option<String> {
        self.current.lock().unwrap().as_ref().map(|token| token.value.clone())
    }

    pub fn clear(&self) {
        *self.current.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::verify_password;

    async fn storage() -> (tempfile::TempDir, Storage) {
        let directory = tempfile::tempdir().unwrap();
        let storage = dbx_core::persistence::test_storage::open(&directory.path().join("storage.db")).await.unwrap();
        (directory, storage)
    }

    fn env(password: Option<&str>, username: Option<&str>, reset: bool) -> BootstrapEnv {
        BootstrapEnv {
            password: password.map(str::to_string),
            admin_username: username.map(str::to_string),
            admin_reset: reset,
        }
    }

    #[tokio::test]
    async fn empty_instance_without_credentials_requires_setup() {
        let (_directory, storage) = storage().await;
        assert_eq!(
            bootstrap_users(&storage, &env(None, None, false), 0).await.unwrap(),
            BootstrapOutcome::SetupRequired
        );
        assert_eq!(storage.count_web_users().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn env_password_creates_the_admin_with_a_custom_name() {
        let (_directory, storage) = storage().await;
        let outcome = bootstrap_users(&storage, &env(Some("changeme"), Some("root"), false), 0).await.unwrap();
        assert_eq!(outcome, BootstrapOutcome::CreatedFromEnv);
        let admin = storage.find_web_user_by_username("root").await.unwrap().unwrap();
        assert_eq!(admin.role, PlatformRole::Admin);
        assert!(verify_password("changeme", &admin.password_hash));
    }

    #[tokio::test]
    async fn legacy_single_password_becomes_the_admin_login() {
        let (_directory, storage) = storage().await;
        storage.save_password_hash(&hash_password("old-secret").unwrap()).await.unwrap();
        let outcome = bootstrap_users(&storage, &env(None, None, false), 0).await.unwrap();
        assert_eq!(outcome, BootstrapOutcome::CreatedFromLegacyPassword);
        let admin = storage.find_web_user_by_username(DEFAULT_ADMIN_USERNAME).await.unwrap().unwrap();
        assert!(verify_password("old-secret", &admin.password_hash));
        assert!(!admin.must_change_password);
        assert!(storage.load_password_hash().await.unwrap().is_some());
    }

    #[tokio::test]
    async fn env_password_is_ignored_once_users_exist_unless_reset_is_requested() {
        let (_directory, storage) = storage().await;
        bootstrap_users(&storage, &env(Some("first-pass"), None, false), 0).await.unwrap();
        let outcome = bootstrap_users(&storage, &env(Some("second-pass"), None, false), 1).await.unwrap();
        assert_eq!(outcome, BootstrapOutcome::Existing);
        let admin = storage.find_web_user_by_username("admin").await.unwrap().unwrap();
        assert!(verify_password("first-pass", &admin.password_hash));

        storage
            .create_web_user(
                NewWebUser {
                    username: "backup".into(),
                    display_name: None,
                    password_hash: "hash".into(),
                    role: PlatformRole::Admin,
                    must_change_password: false,
                },
                2,
            )
            .await
            .unwrap();
        storage.set_web_user_active(&admin.id, false, 2).await.unwrap();
        let outcome = bootstrap_users(&storage, &env(Some("second-pass"), None, true), 3).await.unwrap();
        assert_eq!(outcome, BootstrapOutcome::ResetFromEnv);
        let admin = storage.find_web_user_by_username("admin").await.unwrap().unwrap();
        assert!(verify_password("second-pass", &admin.password_hash));
        assert!(admin.active);
    }

    #[tokio::test]
    async fn invalid_admin_username_is_reported() {
        let (_directory, storage) = storage().await;
        assert!(bootstrap_users(&storage, &env(Some("x"), Some("bad name"), false), 0).await.is_err());
    }

    #[test]
    fn setup_token_is_single_slot_expiring_and_compared_exactly() {
        let slot = SetupTokenSlot::default();
        let start = Instant::now();
        let token = slot.ensure_issued_at(start).unwrap();
        assert!(slot.ensure_issued_at(start + Duration::from_secs(10)).is_none());
        assert!(slot.verify_at(&token, start + Duration::from_secs(10)));
        assert!(!slot.verify_at(&format!("{token}x"), start));
        assert!(!slot.verify_at("", start));
        assert!(!slot.verify_at(&token, start + SETUP_TOKEN_TTL));
        let renewed = slot.ensure_issued_at(start + SETUP_TOKEN_TTL).unwrap();
        assert_ne!(renewed, token);
        slot.clear();
        assert!(!slot.verify_at(&renewed, start + SETUP_TOKEN_TTL));
    }
}
