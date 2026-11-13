use dbx_core::connection::AppState;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::{broadcast, watch, Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use crate::sse::TransferProgressChannel;

pub const LOGIN_MAX_ATTEMPTS: u32 = 5;
pub const LOGIN_LOCKOUT: std::time::Duration = std::time::Duration::from_secs(60);
const LOGIN_FORGET_AFTER: std::time::Duration = std::time::Duration::from_secs(15 * 60);
const LOGIN_MAX_TRACKED_KEYS: usize = 10_000;

#[derive(Debug, Default, Clone, Copy)]
struct LoginAttempts {
    failures: u32,
    locked_until: Option<std::time::Instant>,
    last_failure: Option<std::time::Instant>,
}

pub const MFA_CHALLENGE_TTL: std::time::Duration = std::time::Duration::from_secs(5 * 60);
pub const MFA_CHALLENGE_MAX_FAILURES: u8 = 5;

#[derive(Debug, Clone)]
pub struct MfaChallenge {
    pub user_id: String,
    pub created_at: std::time::Instant,
    pub failures: u8,
}

#[derive(Debug, Default)]
pub struct MfaChallenges {
    entries: HashMap<String, MfaChallenge>,
}

impl MfaChallenges {
    pub fn issue(&mut self, token_hash: String, user_id: String, now: std::time::Instant) {
        self.entries.retain(|_, challenge| now.duration_since(challenge.created_at) < MFA_CHALLENGE_TTL);
        self.entries.insert(token_hash, MfaChallenge { user_id, created_at: now, failures: 0 });
    }

    pub fn get(&self, token_hash: &str, now: std::time::Instant) -> Option<MfaChallenge> {
        self.entries
            .get(token_hash)
            .filter(|challenge| now.duration_since(challenge.created_at) < MFA_CHALLENGE_TTL)
            .cloned()
    }

    pub fn record_failure(&mut self, token_hash: &str) {
        let exhausted = match self.entries.get_mut(token_hash) {
            Some(challenge) => {
                challenge.failures += 1;
                challenge.failures >= MFA_CHALLENGE_MAX_FAILURES
            }
            None => false,
        };
        if exhausted {
            self.entries.remove(token_hash);
        }
    }

    pub fn remove(&mut self, token_hash: &str) {
        self.entries.remove(token_hash);
    }
}

#[derive(Debug, Default)]
pub struct LoginThrottle {
    entries: HashMap<String, LoginAttempts>,
}

impl LoginThrottle {
    pub fn ip_key(ip: Option<std::net::IpAddr>) -> String {
        format!("ip:{}", ip.map(|ip| ip.to_string()).unwrap_or_else(|| "unknown".into()))
    }

    pub fn user_key(username: &str) -> String {
        format!("user:{}", username.trim().to_lowercase())
    }

    pub fn failures(&self, key: &str) -> u32 {
        self.entries.get(key).map_or(0, |attempts| attempts.failures)
    }

    pub fn locked_for(&self, key: &str, now: std::time::Instant) -> Option<std::time::Duration> {
        self.entries
            .get(key)
            .and_then(|attempts| attempts.locked_until)
            .filter(|until| *until > now)
            .map(|until| until - now)
    }

    pub fn record_failure(&mut self, key: &str, now: std::time::Instant) {
        self.prune(now);
        let attempts = self.entries.entry(key.to_string()).or_default();
        attempts.failures = attempts.failures.saturating_add(1);
        attempts.last_failure = Some(now);
        if attempts.failures.is_multiple_of(LOGIN_MAX_ATTEMPTS) {
            attempts.locked_until = Some(now + LOGIN_LOCKOUT);
        }
    }

    pub fn clear(&mut self, key: &str) {
        self.entries.remove(key);
    }

    fn prune(&mut self, now: std::time::Instant) {
        self.entries.retain(|_, attempts| {
            attempts.locked_until.is_some_and(|until| until > now)
                || attempts.last_failure.is_some_and(|last| now.duration_since(last) < LOGIN_FORGET_AFTER)
        });
        if self.entries.len() >= LOGIN_MAX_TRACKED_KEYS {
            self.entries.retain(|_, attempts| attempts.locked_until.is_some_and(|until| until > now));
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebExportFile {
    pub file_path: String,
    pub download_filename: String,
    pub format: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NacosImportContext {
    pub owner_session: Option<String>,
    pub connection_id: String,
    pub target_namespace: String,
    pub plan_hash: String,
}

pub struct WebState {
    pub app: Arc<AppState>,
    pub data_dir: PathBuf,
    /// Extra absolute roots allowed for connection-level `docsNotesPath`
    /// beyond `data_dir/docs-notes` (`DBX_DOCS_NOTES_ROOTS`), resolved once at
    /// startup; injectable so notes containment is testable (see `docs`).
    pub notes_roots: Vec<PathBuf>,
    pub public_base_path: String,
    pub password_disabled: bool,
    /// Whether the web UI may reveal saved connection passwords.
    pub password_viewer_enabled: bool,
    /// `DBX_DEMO_MODE`：公网演示部署的封锁开关（见 `demo` 模块）。
    pub demo_mode: bool,
    pub users_configured: AtomicBool,
    pub session_manager: crate::sessions::SessionManager,
    pub setup_token: crate::bootstrap::SetupTokenSlot,
    pub trusted_origins: Vec<String>,
    pub sessions: RwLock<HashSet<String>>,
    pub sse_channels: RwLock<HashMap<String, broadcast::Sender<String>>>,
    pub transfer_progress_channels: RwLock<HashMap<String, Arc<TransferProgressChannel>>>,
    pub table_import_channels: RwLock<HashMap<String, watch::Sender<String>>>,
    pub sql_file_executions: RwLock<HashMap<String, CancellationToken>>,
    /// Failure logs of the executions this process ran, scoped to the session
    /// that started them (dbx#11619).
    pub sql_file_failure_logs: dbx_core::sql_file_import::SqlFileFailureLogRegistry,
    pub managed_sql_previews: crate::routes::sql_file::ManagedSqlPreviews,
    pub nacos_imports: RwLock<HashMap<String, NacosImportContext>>,
    pub login_throttle: Mutex<LoginThrottle>,
    pub mfa_challenges: Mutex<MfaChallenges>,
    /// Single-use image challenges gating `auth::login`.
    pub captchas: crate::captcha::CaptchaStore,
    /// When `auth::login` demands a challenge. Editable from `设置 → 安全`
    /// unless `DBX_WEB_CAPTCHA` pinned it.
    pub captcha_mode: tokio::sync::RwLock<crate::captcha::CaptchaMode>,
    /// `DBX_WEB_CAPTCHA` was set, so the settings dialog must not offer to
    /// change it.
    pub captcha_env_locked: bool,
    pub captcha_provider: tokio::sync::RwLock<crate::captcha_provider::CaptchaProviderConfig>,
    pub captcha_provider_env_locked: bool,
    pub captcha_fallback: Mutex<crate::captcha_provider::CaptchaFallback>,
    pub captcha_http: reqwest::Client,
    pub captcha_targets: crate::captcha_provider::VerifyTargets,
    /// Completed Web export temp files waiting for the browser download.
    pub export_files: RwLock<HashMap<String, WebExportFile>>,
    pub ssh_prompts: Arc<crate::ssh_prompt::SshPromptHub>,
    pub migration_ready: Arc<AtomicBool>,
    pub web_mcp: Arc<crate::web_mcp::WebMcpRuntime>,
}

impl WebState {
    pub fn users_configured(&self) -> bool {
        self.users_configured.load(std::sync::atomic::Ordering::Acquire)
    }

    pub async fn remove_sse_channel(&self, id: &str) {
        self.sse_channels.write().await.remove(id);
    }

    /// Test helper: full field set so new WebState fields don't break scattered test fixtures.
    #[cfg(test)]
    pub fn for_tests(app: Arc<AppState>, data_dir: PathBuf) -> Self {
        Self {
            app,
            data_dir,
            notes_roots: Vec::new(),
            public_base_path: "/".to_string(),
            password_disabled: false,
            password_viewer_enabled: true,
            demo_mode: false,
            users_configured: AtomicBool::new(false),
            session_manager: crate::sessions::SessionManager::new(crate::sessions::SessionConfig::default()),
            setup_token: Default::default(),
            trusted_origins: Vec::new(),
            sessions: RwLock::new(HashSet::new()),
            sse_channels: RwLock::new(HashMap::new()),
            transfer_progress_channels: RwLock::new(HashMap::new()),
            table_import_channels: RwLock::new(HashMap::new()),
            sql_file_failure_logs: Default::default(),
            sql_file_executions: RwLock::new(HashMap::new()),
            managed_sql_previews: Default::default(),
            nacos_imports: RwLock::new(HashMap::new()),
            login_throttle: Mutex::new(LoginThrottle::default()),
            mfa_challenges: Mutex::new(MfaChallenges::default()),
            captchas: crate::captcha::CaptchaStore::new(),
            captcha_mode: tokio::sync::RwLock::new(crate::captcha::CaptchaMode::Auto),
            captcha_env_locked: false,
            captcha_provider: tokio::sync::RwLock::new(Default::default()),
            captcha_provider_env_locked: false,
            captcha_fallback: Mutex::new(Default::default()),
            captcha_http: reqwest::Client::new(),
            captcha_targets: Default::default(),
            export_files: RwLock::new(HashMap::new()),
            ssh_prompts: Arc::new(crate::ssh_prompt::SshPromptHub::new()),
            migration_ready: Arc::new(AtomicBool::new(true)),
            web_mcp: Arc::new(crate::web_mcp::WebMcpRuntime::disabled()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LoginThrottle, LOGIN_LOCKOUT, LOGIN_MAX_ATTEMPTS};
    use std::time::{Duration, Instant};

    #[test]
    fn throttle_locks_each_key_independently_and_keeps_counting_for_captcha() {
        let mut throttle = LoginThrottle::default();
        let now = Instant::now();
        let ana = LoginThrottle::user_key(" Ana ");
        let bob = LoginThrottle::user_key("bob");
        assert_eq!(ana, "user:ana");
        for _ in 0..LOGIN_MAX_ATTEMPTS - 1 {
            throttle.record_failure(&ana, now);
        }
        assert_eq!(throttle.locked_for(&ana, now), None);
        throttle.record_failure(&ana, now);
        assert_eq!(throttle.locked_for(&ana, now), Some(LOGIN_LOCKOUT));
        assert_eq!(throttle.failures(&ana), LOGIN_MAX_ATTEMPTS);
        assert_eq!(throttle.locked_for(&bob, now), None);
        assert_eq!(throttle.locked_for(&ana, now + LOGIN_LOCKOUT), None);
        throttle.clear(&ana);
        assert_eq!(throttle.failures(&ana), 0);
    }

    #[test]
    fn throttle_forgets_old_failures() {
        let mut throttle = LoginThrottle::default();
        let start = Instant::now();
        throttle.record_failure("ip:1.2.3.4", start);
        throttle.record_failure("ip:5.6.7.8", start + Duration::from_secs(20 * 60));
        assert_eq!(throttle.failures("ip:1.2.3.4"), 0);
        assert_eq!(throttle.failures("ip:5.6.7.8"), 1);
        assert_eq!(LoginThrottle::ip_key(None), "ip:unknown");
    }
}
