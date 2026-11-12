use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use dbx_authz::{Operations, Principal, Resource};
use regex::Regex;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::connection::session_credentials::current_credential_owner;
use crate::persistence::storage::Storage;

pub const AUDIT_NAMESPACE: &str = "audit_log";
pub const AUDIT_DIGEST_LABEL: &str = "audit_statement";
pub const DEFAULT_RETENTION_DAYS: u32 = 270;
pub const SESSION_REF_CHARS: usize = 16;
const CHANNEL_CAPACITY: usize = 10_000;
const BATCH_SIZE: usize = 256;
const RETENTION_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const DAY_MILLIS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditActor {
    User,
    System,
    Local,
    Anonymous,
}

impl AuditActor {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::System => "system",
            Self::Local => "local",
            Self::Anonymous => "anonymous",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditDecision {
    Allow,
    Deny,
}

impl AuditDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuditEvent {
    pub event_id: String,
    pub ts: i64,
    pub actor: AuditActor,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub task_id: Option<String>,
    pub session_ref: Option<String>,
    pub ip: Option<String>,
    pub event: String,
    pub connection_id: Option<String>,
    pub database_name: Option<String>,
    pub schema_name: Option<String>,
    pub table_names: Option<String>,
    pub operations: Option<Operations>,
    pub decision: Option<AuditDecision>,
    pub reason: Option<String>,
    pub statement: Option<String>,
    pub rows_affected: Option<i64>,
    pub duration_ms: Option<i64>,
    pub detail: Option<serde_json::Value>,
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

pub fn retention_days_from(value: Option<&str>) -> Option<u32> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        None => Some(DEFAULT_RETENTION_DAYS),
        Some(value) => match value.parse::<u32>() {
            Ok(0) => None,
            Ok(days) => Some(days),
            Err(_) => {
                log::warn!(
                    "Ignoring invalid DBX_AUDIT_RETENTION_DAYS '{value}'; keeping {DEFAULT_RETENTION_DAYS} days"
                );
                Some(DEFAULT_RETENTION_DAYS)
            }
        },
    }
}

pub fn session_ref(token: &str) -> String {
    Sha256::digest(token.as_bytes()).iter().map(|byte| format!("{byte:02x}")).take(SESSION_REF_CHARS / 2).collect()
}

impl AuditEvent {
    pub fn new(event: &str) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            ts: now_millis(),
            actor: AuditActor::Anonymous,
            user_id: None,
            username: None,
            task_id: None,
            session_ref: None,
            ip: None,
            event: event.to_string(),
            connection_id: None,
            database_name: None,
            schema_name: None,
            table_names: None,
            operations: None,
            decision: None,
            reason: None,
            statement: None,
            rows_affected: None,
            duration_ms: None,
            detail: None,
        }
    }

    pub fn by(mut self, principal: &Principal) -> Self {
        match principal {
            Principal::User { user_id, .. } => {
                self.actor = AuditActor::User;
                self.user_id = Some(user_id.clone());
            }
            Principal::System { task_id } => {
                self.actor = AuditActor::System;
                self.task_id = task_id.clone();
            }
            Principal::Local => self.actor = AuditActor::Local,
        }
        self
    }

    pub fn by_user(mut self, user_id: &str, username: &str) -> Self {
        self.actor = AuditActor::User;
        self.user_id = Some(user_id.to_string());
        self.username = Some(username.to_string());
        self
    }

    pub fn username(mut self, username: &str) -> Self {
        self.username = Some(username.to_string());
        self
    }

    pub fn session(mut self, token: &str) -> Self {
        self.session_ref = Some(session_ref(token));
        self
    }

    pub fn ip(mut self, ip: Option<&str>) -> Self {
        self.ip = ip.map(str::to_string);
        self
    }

    pub fn connection(mut self, connection_id: &str) -> Self {
        self.connection_id = Some(connection_id.to_string());
        self
    }

    pub fn resource(mut self, resource: &Resource) -> Self {
        self.connection_id = Some(resource.connection_id.clone());
        self.database_name.clone_from(&resource.database);
        self.schema_name.clone_from(&resource.schema);
        self.table_names.clone_from(&resource.table);
        self
    }

    pub fn tables(mut self, tables: Vec<String>) -> Self {
        if !tables.is_empty() {
            self.table_names = Some(tables.join(","));
        }
        self
    }

    pub fn operations(mut self, operations: Operations) -> Self {
        if !operations.is_empty() {
            self.operations = Some(operations);
        }
        self
    }

    pub fn allowed(mut self) -> Self {
        self.decision = Some(AuditDecision::Allow);
        self
    }

    pub fn denied(mut self, reason: impl Into<String>) -> Self {
        self.decision = Some(AuditDecision::Deny);
        self.reason = Some(reason.into());
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn statement(mut self, statement: &str) -> Self {
        self.statement = Some(statement.to_string());
        self
    }

    pub fn detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }
}

#[derive(Default)]
pub struct AuditLog {
    sender: RwLock<Option<mpsc::Sender<AuditEvent>>>,
    dropped: Arc<AtomicU64>,
    clients: RwLock<HashMap<String, String>>,
}

fn read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl AuditLog {
    pub fn start(&self, storage: Storage, retention_days: Option<u32>) {
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
        *write(&self.sender) = Some(sender);
        tokio::spawn(run_writer(storage.clone(), receiver, self.dropped.clone()));
        if let Some(days) = retention_days.filter(|days| *days > 0) {
            tokio::spawn(run_retention(storage, days));
        }
    }

    pub fn is_enabled(&self) -> bool {
        read(&self.sender).is_some()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn record(&self, event: AuditEvent) {
        let guard = read(&self.sender);
        let Some(sender) = guard.as_ref() else {
            return;
        };
        if sender.try_send(event).is_err() {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if dropped.is_power_of_two() {
                log::warn!("DBX audit queue is full; {dropped} events dropped so far");
            }
        }
    }

    pub fn record_in_request(&self, mut event: AuditEvent) {
        if !self.is_enabled() {
            return;
        }
        if let Some(owner) = current_credential_owner() {
            if !owner.starts_with("system:") {
                if event.session_ref.is_none() {
                    event.session_ref = Some(session_ref(&owner));
                }
                if event.ip.is_none() {
                    event.ip = read(&self.clients).get(&owner).cloned();
                }
            }
        }
        self.record(event);
    }

    pub fn remember_client(&self, owner: &str, ip: Option<&str>) {
        let Some(ip) = ip else {
            return;
        };
        if read(&self.clients).get(owner).is_some_and(|known| known == ip) {
            return;
        }
        write(&self.clients).insert(owner.to_string(), ip.to_string());
    }

    pub fn forget_client(&self, owner: &str) {
        write(&self.clients).remove(owner);
    }
}

async fn run_writer(storage: Storage, mut receiver: mpsc::Receiver<AuditEvent>, dropped: Arc<AtomicU64>) {
    let mut reported_drops = 0;
    while let Some(first) = receiver.recv().await {
        let mut batch = vec![first];
        while batch.len() < BATCH_SIZE {
            match receiver.try_recv() {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }
        let total_drops = dropped.load(Ordering::Relaxed);
        if total_drops > reported_drops {
            batch.push(
                AuditEvent::new("audit_events_dropped")
                    .reason("queue_full")
                    .detail(serde_json::json!({ "dropped": total_drops - reported_drops })),
            );
            reported_drops = total_drops;
        }
        if let Err(error) = storage.insert_audit_events(batch).await {
            log::error!("DBX audit failed to write events: {error}");
        }
    }
}

async fn run_retention(storage: Storage, days: u32) {
    let mut interval = tokio::time::interval(RETENTION_INTERVAL);
    loop {
        interval.tick().await;
        let cutoff = now_millis().saturating_sub(i64::from(days).saturating_mul(DAY_MILLIS));
        match storage.purge_audit_before(cutoff).await {
            Ok(0) => {}
            Ok(purged) => log::info!("DBX audit purged {purged} events older than {days} days"),
            Err(error) => log::warn!("DBX audit retention failed: {error}"),
        }
    }
}

const QUOTED: &str = r#"N?'(?:[^']|'')*'|"(?:[^"]|"")*""#;

fn password_patterns() -> &'static [Regex] {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            format!(
                r"(?i)(\bIDENTIFIED\b(?:\s+WITH\s+[\w$]+)?\s+BY\s+(?:PASSWORD\s+|VALUES\s+)?)(?:{QUOTED}|[^\s;,)]+)"
            ),
            format!(r"(?i)(\bPASSWORD\b\s*(?:=\s*)?(?:\(\s*)?)(?:{QUOTED})"),
        ]
        .iter()
        .map(|pattern| Regex::new(pattern).expect("audit masking pattern is valid"))
        .collect()
    })
}

pub fn mask_sensitive_sql(sql: &str) -> String {
    password_patterns()
        .iter()
        .fold(sql.to_string(), |masked, pattern| pattern.replace_all(&masked, "${1}'***'").into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_passwords_in_account_statements() {
        let cases = [
            ("CREATE USER bob WITH PASSWORD 'hunter2'", "CREATE USER bob WITH PASSWORD '***'"),
            (
                "alter role app password 'it''s secret' valid until 'infinity'",
                "alter role app password '***' valid until 'infinity'",
            ),
            ("CREATE USER 'bob'@'%' IDENTIFIED BY 'pw'", "CREATE USER 'bob'@'%' IDENTIFIED BY '***'"),
            (
                "ALTER USER bob IDENTIFIED WITH mysql_native_password BY 'pw'",
                "ALTER USER bob IDENTIFIED WITH mysql_native_password BY '***'",
            ),
            ("CREATE USER scott IDENTIFIED BY tiger;", "CREATE USER scott IDENTIFIED BY '***';"),
            ("SET PASSWORD = 'abc'", "SET PASSWORD = '***'"),
            ("SET PASSWORD FOR 'bob'@'%' = PASSWORD('abc')", "SET PASSWORD FOR 'bob'@'%' = PASSWORD('***')"),
            ("CREATE LOGIN app WITH PASSWORD = N'x'", "CREATE LOGIN app WITH PASSWORD = '***'"),
            ("ALTER USER scott IDENTIFIED BY VALUES 'S:ABC'", "ALTER USER scott IDENTIFIED BY VALUES '***'"),
            ("select password from users where id = 1", "select password from users where id = 1"),
        ];
        for (input, expected) in cases {
            assert_eq!(mask_sensitive_sql(input), expected, "{input}");
        }
    }

    #[test]
    fn session_ref_is_a_prefix_of_the_stored_session_hash() {
        let token = "opaque-session-token";
        let full: String = Sha256::digest(token.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(session_ref(token), full[..SESSION_REF_CHARS]);
    }

    #[test]
    fn retention_defaults_to_270_days_and_zero_keeps_everything() {
        assert_eq!(retention_days_from(None), Some(270));
        assert_eq!(retention_days_from(Some(" 30 ")), Some(30));
        assert_eq!(retention_days_from(Some("0")), None);
        assert_eq!(retention_days_from(Some("forever")), Some(270));
    }

    #[test]
    fn records_nothing_until_started() {
        let log = AuditLog::default();
        log.record(AuditEvent::new("login_succeeded"));
        assert!(!log.is_enabled());
        assert_eq!(log.dropped(), 0);
    }
}
