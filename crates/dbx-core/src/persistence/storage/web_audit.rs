use std::collections::{HashMap, HashSet};

use dbx_authz::Operations;
use rusqlite::Row;

use super::{params, OptionalExtension, Storage};
use crate::audit::{mask_sensitive_sql, AuditEvent, AUDIT_DIGEST_LABEL, AUDIT_NAMESPACE};

pub(super) const WEB_AUDIT_SCHEMA_STATEMENTS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        ts INTEGER NOT NULL,
        user_id TEXT,
        username TEXT,
        acting_principal TEXT NOT NULL,
        task_id TEXT,
        session_ref TEXT,
        ip TEXT,
        event TEXT NOT NULL,
        connection_id TEXT,
        database_name TEXT,
        schema_name TEXT,
        table_names TEXT,
        operations INTEGER,
        decision TEXT CHECK (decision IS NULL OR decision IN ('allow', 'deny')),
        reason TEXT,
        statement_enc TEXT,
        statement_hmac TEXT,
        rows_affected INTEGER,
        duration_ms INTEGER,
        detail TEXT
    )",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts)",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_user_ts ON audit_log(user_id, ts)",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_connection_ts ON audit_log(connection_id, ts)",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_statement_hmac ON audit_log(statement_hmac)",
];

const AUDIT_COLUMNS: &str = "id, event_id, ts, user_id, username, acting_principal, task_id, session_ref, ip, event, \
     connection_id, database_name, schema_name, table_names, operations, decision, reason, \
     statement_enc IS NOT NULL, rows_affected, duration_ms, detail";

const PURGE_BATCH: i64 = 5_000;
pub const MAX_AUDIT_PAGE: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: i64,
    pub event_id: String,
    pub ts: i64,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub acting_principal: String,
    pub task_id: Option<String>,
    pub session_ref: Option<String>,
    pub ip: Option<String>,
    pub event: String,
    pub connection_id: Option<String>,
    pub database_name: Option<String>,
    pub schema_name: Option<String>,
    pub table_names: Option<String>,
    pub operations: Option<Operations>,
    pub decision: Option<String>,
    pub reason: Option<String>,
    pub has_statement: bool,
    pub rows_affected: Option<i64>,
    pub duration_ms: Option<i64>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    pub user_id: Option<String>,
    pub connection_id: Option<String>,
    pub decision: Option<String>,
    pub event: Option<String>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub statement_hmac: Option<String>,
    pub before_id: Option<i64>,
    pub limit: usize,
}

struct PreparedEvent {
    event: AuditEvent,
    statement_enc: Option<String>,
    statement_hmac: Option<String>,
}

fn entry_from_row(row: &Row<'_>) -> rusqlite::Result<AuditEntry> {
    Ok(AuditEntry {
        id: row.get(0)?,
        event_id: row.get(1)?,
        ts: row.get(2)?,
        user_id: row.get(3)?,
        username: row.get(4)?,
        acting_principal: row.get(5)?,
        task_id: row.get(6)?,
        session_ref: row.get(7)?,
        ip: row.get(8)?,
        event: row.get(9)?,
        connection_id: row.get(10)?,
        database_name: row.get(11)?,
        schema_name: row.get(12)?,
        table_names: row.get(13)?,
        operations: row.get::<_, Option<i64>>(14)?.map(Operations::from_stored),
        decision: row.get(15)?,
        reason: row.get(16)?,
        has_statement: row.get(17)?,
        rows_affected: row.get(18)?,
        duration_ms: row.get(19)?,
        detail: row.get(20)?,
    })
}

fn sql_error(error: rusqlite::Error) -> String {
    error.to_string()
}

impl Storage {
    pub async fn insert_audit_events(&self, events: Vec<AuditEvent>) -> Result<usize, String> {
        if events.is_empty() {
            return Ok(0);
        }
        let needs_key = events.iter().any(|event| event.statement.is_some());
        let codec = if needs_key {
            match self.secret_codec_for_write(true).await {
                Ok(codec) => Some(codec),
                Err(error) => {
                    log::warn!("DBX audit cannot encrypt statements, storing them without SQL: {error}");
                    None
                }
            }
        } else {
            None
        };
        let mut prepared = Vec::with_capacity(events.len());
        for mut event in events {
            let statement = event.statement.take();
            let (statement_enc, statement_hmac) = match (statement, &codec) {
                (Some(statement), Some(codec)) => {
                    let masked = mask_sensitive_sql(&statement);
                    match codec.encrypt(AUDIT_NAMESPACE, &event.event_id, &masked) {
                        Ok(envelope) => (Some(envelope), Some(codec.keyed_digest(AUDIT_DIGEST_LABEL, &masked))),
                        Err(error) => {
                            log::warn!("DBX audit failed to encrypt a statement: {error}");
                            (None, None)
                        }
                    }
                }
                _ => (None, None),
            };
            prepared.push(PreparedEvent { event, statement_enc, statement_hmac });
        }
        self.with_conn(move |conn| {
            let missing: HashSet<String> = prepared
                .iter()
                .filter(|item| item.event.username.is_none())
                .filter_map(|item| item.event.user_id.clone())
                .collect();
            let mut usernames = HashMap::new();
            if !missing.is_empty() {
                let mut lookup = conn.prepare("SELECT username FROM users WHERE id = ?1").map_err(sql_error)?;
                for user_id in missing {
                    if let Some(username) =
                        lookup.query_row(params![user_id], |row| row.get::<_, String>(0)).optional().map_err(sql_error)?
                    {
                        usernames.insert(user_id, username);
                    }
                }
            }
            let tx = conn.transaction().map_err(sql_error)?;
            let count = prepared.len();
            {
                let mut insert = tx
                    .prepare(
                        "INSERT OR IGNORE INTO audit_log (event_id, ts, user_id, username, acting_principal, task_id, \
                         session_ref, ip, event, connection_id, database_name, schema_name, table_names, operations, \
                         decision, reason, statement_enc, statement_hmac, rows_affected, duration_ms, detail) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
                    )
                    .map_err(sql_error)?;
                for item in prepared {
                    let event = item.event;
                    let username = event
                        .username
                        .clone()
                        .or_else(|| event.user_id.as_ref().and_then(|id| usernames.get(id).cloned()));
                    insert
                        .execute(params![
                            event.event_id,
                            event.ts,
                            event.user_id,
                            username,
                            event.actor.as_str(),
                            event.task_id,
                            event.session_ref,
                            event.ip,
                            event.event,
                            event.connection_id,
                            event.database_name,
                            event.schema_name,
                            event.table_names,
                            event.operations.map(Operations::to_stored),
                            event.decision.map(|decision| decision.as_str()),
                            event.reason,
                            item.statement_enc,
                            item.statement_hmac,
                            event.rows_affected,
                            event.duration_ms,
                            event.detail.map(|detail| detail.to_string()),
                        ])
                        .map_err(sql_error)?;
                }
            }
            tx.commit().map_err(sql_error)?;
            Ok(count)
        })
        .await
    }

    pub async fn purge_audit_before(&self, cutoff: i64) -> Result<usize, String> {
        self.with_conn(move |conn| {
            let mut total = 0;
            loop {
                let deleted = conn
                    .execute(
                        "DELETE FROM audit_log WHERE id IN (SELECT id FROM audit_log WHERE ts < ?1 ORDER BY id LIMIT ?2)",
                        params![cutoff, PURGE_BATCH],
                    )
                    .map_err(sql_error)?;
                total += deleted;
                if deleted < usize::try_from(PURGE_BATCH).unwrap_or(usize::MAX) {
                    return Ok(total);
                }
            }
        })
        .await
    }

    pub async fn list_audit_events(&self, filter: AuditFilter) -> Result<Vec<AuditEntry>, String> {
        self.with_conn(move |conn| {
            let mut clauses: Vec<String> = Vec::new();
            let mut values: Vec<rusqlite::types::Value> = Vec::new();
            let mut push = |clause: &str, value: rusqlite::types::Value| {
                values.push(value);
                clauses.push(clause.replace('?', &format!("?{}", values.len())));
            };
            if let Some(user_id) = filter.user_id {
                push("user_id = ?", user_id.into());
            }
            if let Some(connection_id) = filter.connection_id {
                push("connection_id = ?", connection_id.into());
            }
            if let Some(decision) = filter.decision {
                push("decision = ?", decision.into());
            }
            if let Some(event) = filter.event {
                push("event = ?", event.into());
            }
            if let Some(from) = filter.from {
                push("ts >= ?", from.into());
            }
            if let Some(to) = filter.to {
                push("ts <= ?", to.into());
            }
            if let Some(statement_hmac) = filter.statement_hmac {
                push("statement_hmac = ?", statement_hmac.into());
            }
            if let Some(before_id) = filter.before_id {
                push("id < ?", before_id.into());
            }
            let limit = filter.limit.clamp(1, MAX_AUDIT_PAGE);
            let where_clause =
                if clauses.is_empty() { String::new() } else { format!(" WHERE {}", clauses.join(" AND ")) };
            let sql = format!("SELECT {AUDIT_COLUMNS} FROM audit_log{where_clause} ORDER BY id DESC LIMIT {limit}");
            let mut statement = conn.prepare(&sql).map_err(sql_error)?;
            let entries = statement
                .query_map(rusqlite::params_from_iter(values), entry_from_row)
                .map_err(sql_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql_error)?;
            Ok(entries)
        })
        .await
    }

    pub async fn reveal_audit_statement(&self, event_id: &str) -> Result<Option<String>, String> {
        let id = event_id.to_string();
        let envelope: Option<Option<String>> = self
            .with_conn(move |conn| {
                conn.query_row("SELECT statement_enc FROM audit_log WHERE event_id = ?1", params![id], |row| row.get(0))
                    .optional()
                    .map_err(sql_error)
            })
            .await?;
        let Some(Some(envelope)) = envelope else {
            return Ok(None);
        };
        let codec = self.secret_codec(false)?;
        codec.decrypt(AUDIT_NAMESPACE, event_id, &envelope).map(Some)
    }

    pub fn audit_statement_digest(&self, statement: &str) -> Result<String, String> {
        let codec = self.secret_codec(false)?;
        Ok(codec.keyed_digest(AUDIT_DIGEST_LABEL, &mask_sensitive_sql(statement)))
    }

    pub async fn count_audit_events(&self) -> Result<i64, String> {
        self.with_conn(|conn| conn.query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0)).map_err(sql_error))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditEvent;
    use crate::persistence::storage::NewWebUser;
    use dbx_authz::{PlatformRole, Principal, Resource};

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

    fn sql_event(user_id: &str, statement: &str, ts: i64) -> AuditEvent {
        let principal = Principal::User { user_id: user_id.into(), groups: Vec::new(), role: PlatformRole::User };
        let mut event = AuditEvent::new("sql")
            .by(&principal)
            .resource(&Resource { connection_id: "c1".into(), database: Some("crm".into()), schema: None, table: None })
            .operations(Operations::UPDATE)
            .allowed()
            .statement(statement);
        event.ts = ts;
        event
    }

    #[tokio::test]
    async fn stores_statements_encrypted_and_reveals_them_masked() {
        let (_directory, storage) = storage().await;
        let ana = user(&storage, "ana").await;
        let statement = "ALTER USER app IDENTIFIED BY 'TopSecret1'; UPDATE accounts SET plan = 'gold-plan'";
        let event = sql_event(&ana, statement, 1_000);
        let event_id = event.event_id.clone();
        assert_eq!(storage.insert_audit_events(vec![event]).await.unwrap(), 1);

        let raw: (String, String) = storage
            .with_conn(|conn| {
                conn.query_row("SELECT statement_enc, statement_hmac FROM audit_log", [], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(sql_error)
            })
            .await
            .unwrap();
        assert!(!raw.0.contains("gold-plan") && !raw.0.contains("accounts"));
        for file in std::fs::read_dir(storage.data_dir()).unwrap().flatten() {
            let bytes = std::fs::read(file.path()).unwrap_or_default();
            assert!(!String::from_utf8_lossy(&bytes).contains("gold-plan"), "{:?}", file.path());
        }

        let entries = storage.list_audit_events(AuditFilter { limit: 10, ..AuditFilter::default() }).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].username.as_deref(), Some("ana"));
        assert_eq!(entries[0].operations, Some(Operations::UPDATE));
        assert!(entries[0].has_statement);

        let revealed = storage.reveal_audit_statement(&event_id).await.unwrap().unwrap();
        assert_eq!(revealed, "ALTER USER app IDENTIFIED BY '***'; UPDATE accounts SET plan = 'gold-plan'");
        assert_eq!(storage.audit_statement_digest(statement).unwrap(), raw.1);
        let by_digest = storage
            .list_audit_events(AuditFilter { statement_hmac: Some(raw.1), limit: 10, ..AuditFilter::default() })
            .await
            .unwrap();
        assert_eq!(by_digest.len(), 1);
    }

    #[tokio::test]
    async fn ciphertext_is_bound_to_its_event() {
        let (_directory, storage) = storage().await;
        let ana = user(&storage, "ana").await;
        let first = sql_event(&ana, "DELETE FROM a", 1);
        let second = sql_event(&ana, "DELETE FROM b", 2);
        let (first_id, second_id) = (first.event_id.clone(), second.event_id.clone());
        storage.insert_audit_events(vec![first, second]).await.unwrap();
        let (a, b) = (first_id.clone(), second_id.clone());
        storage
            .with_conn(move |conn| {
                conn.execute(
                    "UPDATE audit_log SET statement_enc = (SELECT statement_enc FROM audit_log WHERE event_id = ?1) \
                     WHERE event_id = ?2",
                    params![a, b],
                )
                .map_err(sql_error)
            })
            .await
            .unwrap();
        assert!(storage.reveal_audit_statement(&second_id).await.is_err());
        assert_eq!(storage.reveal_audit_statement(&first_id).await.unwrap().as_deref(), Some("DELETE FROM a"));
    }

    #[tokio::test]
    async fn filters_pages_and_purges_by_age() {
        let (_directory, storage) = storage().await;
        let ana = user(&storage, "ana").await;
        let bob = user(&storage, "bob").await;
        let mut events: Vec<AuditEvent> = (0..5).map(|index| sql_event(&ana, "SELECT 1", 100 + index)).collect();
        events.push(sql_event(&bob, "SELECT 2", 200).denied("Permission denied: SELECT required on crm"));
        events.push(AuditEvent::new("login_failed").username("ghost").reason("invalid_credentials"));
        storage.insert_audit_events(events).await.unwrap();

        let page = storage
            .list_audit_events(AuditFilter { user_id: Some(ana.clone()), limit: 3, ..AuditFilter::default() })
            .await
            .unwrap();
        assert_eq!(page.iter().map(|entry| entry.ts).collect::<Vec<_>>(), vec![104, 103, 102]);
        let next = storage
            .list_audit_events(AuditFilter {
                user_id: Some(ana),
                before_id: Some(page[2].id),
                limit: 3,
                ..AuditFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(next.iter().map(|entry| entry.ts).collect::<Vec<_>>(), vec![101, 100]);
        let denied = storage
            .list_audit_events(AuditFilter { decision: Some("deny".into()), limit: 10, ..AuditFilter::default() })
            .await
            .unwrap();
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].username.as_deref(), Some("bob"));
        let failed = storage
            .list_audit_events(AuditFilter { event: Some("login_failed".into()), limit: 10, ..AuditFilter::default() })
            .await
            .unwrap();
        assert_eq!(failed[0].username.as_deref(), Some("ghost"));
        assert_eq!(failed[0].acting_principal, "anonymous");

        assert_eq!(storage.purge_audit_before(150).await.unwrap(), 5);
        assert_eq!(storage.count_audit_events().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn keeps_audit_rows_when_the_user_is_deleted() {
        let (_directory, storage) = storage().await;
        let ana = user(&storage, "ana").await;
        storage.insert_audit_events(vec![sql_event(&ana, "SELECT 1", 1)]).await.unwrap();
        storage.delete_web_user(&ana).await.unwrap();
        let entries = storage.list_audit_events(AuditFilter { limit: 10, ..AuditFilter::default() }).await.unwrap();
        assert_eq!(entries[0].username.as_deref(), Some("ana"));
    }
}
