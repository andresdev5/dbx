use super::*;
use crate::audit::{AuditEvent, AUDIT_DIGEST_LABEL, AUDIT_NAMESPACE};

const AUDIT_ROTATION_BATCH: i64 = 1_000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyRotationReport {
    pub backup_path: Option<PathBuf>,
    pub connection_secrets: usize,
    pub audit_statements: usize,
    pub unreadable_audit_statements: usize,
}

impl KeyRotationReport {
    pub fn rotated_anything(&self) -> bool {
        self.connection_secrets > 0 || self.audit_statements > 0
    }
}

enum Readable {
    Current,
    Previous(String),
    Neither,
}

fn classify(current: &SecretCodec, previous: &SecretCodec, namespace: &str, key: &str, envelope: &str) -> Readable {
    if current.decrypt(namespace, key, envelope).is_ok() {
        return Readable::Current;
    }
    match previous.decrypt(namespace, key, envelope) {
        Ok(plaintext) => Readable::Previous(plaintext),
        Err(_) => Readable::Neither,
    }
}

fn load_connection_secrets(conn: &Connection) -> Result<Vec<(String, String, String)>, String> {
    let mut statement = conn
        .prepare(
            "SELECT connection_id, key, secret_enc FROM connection_secrets \
             WHERE secret_enc IS NOT NULL AND secret_enc <> ''",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string());
    rows
}

fn load_audit_batch(conn: &Connection, after_id: i64) -> Result<Vec<(i64, String, String)>, String> {
    let mut statement = conn
        .prepare(
            "SELECT id, event_id, statement_enc FROM audit_log \
             WHERE statement_enc IS NOT NULL AND id > ?1 ORDER BY id LIMIT ?2",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(params![after_id, AUDIT_ROTATION_BATCH], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string());
    rows
}

fn audit_needs_rotation(conn: &Connection, current: &SecretCodec, previous: &SecretCodec) -> Result<bool, String> {
    let mut after_id = 0;
    loop {
        let batch = load_audit_batch(conn, after_id)?;
        let Some(last) = batch.last() else {
            return Ok(false);
        };
        after_id = last.0;
        if batch.iter().any(|(_, event_id, envelope)| {
            matches!(classify(current, previous, AUDIT_NAMESPACE, event_id, envelope), Readable::Previous(_))
        }) {
            return Ok(true);
        }
    }
}

struct RotationPlan {
    secrets: usize,
    unreadable_secrets: usize,
    audit: bool,
}

fn plan_rotation(conn: &Connection, current: &SecretCodec, previous: &SecretCodec) -> Result<RotationPlan, String> {
    let mut plan = RotationPlan { secrets: 0, unreadable_secrets: 0, audit: false };
    for (namespace, key, envelope) in load_connection_secrets(conn)? {
        match classify(current, previous, &namespace, &key, &envelope) {
            Readable::Current => {}
            Readable::Previous(_) => plan.secrets += 1,
            Readable::Neither => plan.unreadable_secrets += 1,
        }
    }
    plan.audit = audit_needs_rotation(conn, current, previous)?;
    Ok(plan)
}

fn rotate_connection_secrets(
    conn: &mut Connection,
    current: &SecretCodec,
    previous: &SecretCodec,
) -> Result<usize, String> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|error| error.to_string())?;
    let mut rotated = 0;
    for (namespace, key, envelope) in load_connection_secrets(&tx)? {
        match classify(current, previous, &namespace, &key, &envelope) {
            Readable::Current => {}
            Readable::Previous(plaintext) => {
                let encrypted = current.encrypt(&namespace, &key, &plaintext)?;
                tx.execute(
                    "UPDATE connection_secrets SET secret_enc = ?3 WHERE connection_id = ?1 AND key = ?2",
                    params![namespace, key, encrypted],
                )
                .map_err(|error| error.to_string())?;
                rotated += 1;
            }
            Readable::Neither => return Err("SECRET_KEY_ROTATION_UNREADABLE".to_string()),
        }
    }
    tx.commit().map_err(|error| error.to_string())?;
    Ok(rotated)
}

fn rotate_audit_statements(
    conn: &mut Connection,
    current: &SecretCodec,
    previous: &SecretCodec,
) -> Result<(usize, usize), String> {
    let mut after_id = 0;
    let mut rotated = 0;
    let mut unreadable = 0;
    loop {
        let batch = load_audit_batch(conn, after_id)?;
        let Some(last) = batch.last() else {
            return Ok((rotated, unreadable));
        };
        after_id = last.0;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|error| error.to_string())?;
        for (id, event_id, envelope) in batch {
            match classify(current, previous, AUDIT_NAMESPACE, &event_id, &envelope) {
                Readable::Current => {}
                Readable::Previous(statement) => {
                    let encrypted = current.encrypt(AUDIT_NAMESPACE, &event_id, &statement)?;
                    let digest = current.keyed_digest(AUDIT_DIGEST_LABEL, &statement);
                    tx.execute(
                        "UPDATE audit_log SET statement_enc = ?2, statement_hmac = ?3 WHERE id = ?1",
                        params![id, encrypted, digest],
                    )
                    .map_err(|error| error.to_string())?;
                    rotated += 1;
                }
                Readable::Neither => unreadable += 1,
            }
        }
        tx.commit().map_err(|error| error.to_string())?;
    }
}

impl Storage {
    pub async fn rotate_secret_key(&self, previous: SecretCodec) -> Result<KeyRotationReport, String> {
        let current = self.secret_codec(false).map_err(|_| "SECRET_KEY_ROTATION_CURRENT_KEY_MISSING".to_string())?;
        if current.same_key_as(&previous) {
            return Err("SECRET_KEY_ROTATION_SAME_KEY".to_string());
        }
        let plan = self.with_conn(move |conn| plan_rotation(conn, &current, &previous)).await?;
        if plan.unreadable_secrets > 0 {
            return Err("SECRET_KEY_ROTATION_UNREADABLE".to_string());
        }
        if plan.secrets == 0 && !plan.audit {
            return Ok(KeyRotationReport::default());
        }

        let backup = self.data_dir().join(format!("dbx-key-rotation-{}", Uuid::new_v4()));
        std::fs::create_dir(&backup).map_err(|_| "SECRET_KEY_ROTATION_BACKUP_FAILED".to_string())?;
        restrict_backup_permissions(&backup);
        let backup_db = backup.join(STORAGE_DB_FILE_NAME);
        let copy = backup_db.clone();
        self.with_conn(move |conn| conn.backup(DatabaseName::Main, &copy, None).map_err(|error| error.to_string()))
            .await
            .map_err(|_| "SECRET_KEY_ROTATION_BACKUP_FAILED".to_string())?;
        restrict_backup_file_permissions(&backup_db);
        {
            let source = Connection::open_with_flags(&backup_db, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|_| "SECRET_KEY_ROTATION_BACKUP_FAILED".to_string())?;
            let integrity: String = source
                .query_row("PRAGMA integrity_check", [], |row| row.get(0))
                .map_err(|_| "SECRET_KEY_ROTATION_BACKUP_FAILED".to_string())?;
            if integrity != "ok" {
                return Err("SECRET_KEY_ROTATION_BACKUP_FAILED".to_string());
            }
        }

        let connection_secrets =
            self.with_conn(move |conn| rotate_connection_secrets(conn, &current, &previous)).await?;
        self.validate_existing_encrypted_data(current)
            .await
            .map_err(|_| "SECRET_KEY_ROTATION_VERIFICATION_FAILED".to_string())?;
        let (audit_statements, unreadable_audit_statements) =
            self.with_conn(move |conn| rotate_audit_statements(conn, &current, &previous)).await?;

        let report = KeyRotationReport {
            backup_path: Some(backup),
            connection_secrets,
            audit_statements,
            unreadable_audit_statements,
        };
        let event = AuditEvent::new("secret_key_rotated").reason("previous_key_supplied").detail(serde_json::json!({
            "connection_secrets": report.connection_secrets,
            "audit_statements": report.audit_statements,
            "unreadable_audit_statements": report.unreadable_audit_statements,
        }));
        let mut event = event;
        event.actor = crate::audit::AuditActor::System;
        self.insert_audit_events(vec![event]).await?;
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditEvent;
    use crate::persistence::storage::AuditFilter;

    const OLD_KEY: [u8; 32] = [7u8; 32];

    fn install_key(storage: &Storage, key: [u8; 32]) {
        let path = crate::persistence::secret_codec::managed_key_path(storage.data_dir());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        std::fs::write(&path, hex).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        storage.invalidate_secret_codec();
    }

    async fn storage_with_key(directory: &Path, key: [u8; 32]) -> Storage {
        let storage = crate::persistence::test_storage::open(&directory.join("dbx.db")).await.unwrap();
        install_key(&storage, key);
        storage
    }

    async fn seed(storage: &Storage) -> String {
        let codec = SecretCodec::new(OLD_KEY);
        let password = codec.encrypt("conn-1", "password", "db-secret").unwrap();
        let token = codec.encrypt("conn-2", "token", "api-token").unwrap();
        storage
            .with_conn(move |conn| {
                conn.execute(
                    "INSERT INTO connection_secrets (connection_id, key, secret, secret_enc) VALUES \
                     ('conn-1', 'password', '', ?1), ('conn-2', 'token', '', ?2)",
                    params![password, token],
                )
                .map_err(|error| error.to_string())
            })
            .await
            .unwrap();
        let event = AuditEvent::new("sql").statement("DELETE FROM accounts");
        let event_id = event.event_id.clone();
        storage.insert_audit_events(vec![event]).await.unwrap();
        event_id
    }

    async fn secret(storage: &Storage, connection: &str, key: &str) -> String {
        let (connection, key) = (connection.to_string(), key.to_string());
        storage
            .with_conn(move |conn| {
                conn.query_row(
                    "SELECT secret_enc FROM connection_secrets WHERE connection_id = ?1 AND key = ?2",
                    params![connection, key],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn rotates_connection_secrets_and_audit_statements_to_the_new_key() {
        let directory = tempfile::tempdir().unwrap();
        let storage = storage_with_key(directory.path(), OLD_KEY).await;
        let event_id = seed(&storage).await;
        let old_digest = storage.audit_statement_digest("DELETE FROM accounts").unwrap();

        let new_key = [9u8; 32];
        install_key(&storage, new_key);
        assert!(storage.reveal_audit_statement(&event_id).await.is_err());

        let report = storage.rotate_secret_key(SecretCodec::new(OLD_KEY)).await.unwrap();
        assert_eq!(report.connection_secrets, 2);
        assert_eq!(report.audit_statements, 1);
        assert_eq!(report.unreadable_audit_statements, 0);
        let backup = report.backup_path.unwrap();
        assert!(backup.join("dbx.db").is_file());

        let current = SecretCodec::new(new_key);
        assert_eq!(
            current.decrypt("conn-1", "password", &secret(&storage, "conn-1", "password").await).unwrap(),
            "db-secret"
        );
        assert_eq!(
            current.decrypt("conn-2", "token", &secret(&storage, "conn-2", "token").await).unwrap(),
            "api-token"
        );
        assert_eq!(storage.reveal_audit_statement(&event_id).await.unwrap().as_deref(), Some("DELETE FROM accounts"));
        let new_digest = storage.audit_statement_digest("DELETE FROM accounts").unwrap();
        assert_ne!(new_digest, old_digest);
        let found = storage
            .list_audit_events(AuditFilter { statement_hmac: Some(new_digest), limit: 10, ..AuditFilter::default() })
            .await
            .unwrap();
        assert_eq!(found.len(), 1);
        let rotated = storage
            .list_audit_events(AuditFilter {
                event: Some("secret_key_rotated".into()),
                limit: 10,
                ..AuditFilter::default()
            })
            .await
            .unwrap();
        assert_eq!(rotated.len(), 1);
        assert_eq!(rotated[0].acting_principal, "system");

        let backup_secret: String = Connection::open(backup.join("dbx.db"))
            .unwrap()
            .query_row("SELECT secret_enc FROM connection_secrets WHERE connection_id = 'conn-1'", [], |row| row.get(0))
            .unwrap();
        assert_eq!(SecretCodec::new(OLD_KEY).decrypt("conn-1", "password", &backup_secret).unwrap(), "db-secret");

        let again = storage.rotate_secret_key(SecretCodec::new(OLD_KEY)).await.unwrap();
        assert!(!again.rotated_anything());
        assert!(again.backup_path.is_none());
    }

    #[tokio::test]
    async fn refuses_to_rotate_when_a_secret_matches_neither_key() {
        let directory = tempfile::tempdir().unwrap();
        let storage = storage_with_key(directory.path(), OLD_KEY).await;
        seed(&storage).await;
        install_key(&storage, [9u8; 32]);
        let before = secret(&storage, "conn-1", "password").await;

        let error = storage.rotate_secret_key(SecretCodec::new([3u8; 32])).await.unwrap_err();
        assert_eq!(error, "SECRET_KEY_ROTATION_UNREADABLE");
        assert_eq!(secret(&storage, "conn-1", "password").await, before);
        assert!(!std::fs::read_dir(storage.data_dir())
            .unwrap()
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().starts_with("dbx-key-rotation-")));
    }

    #[tokio::test]
    async fn refuses_the_same_key_twice() {
        let directory = tempfile::tempdir().unwrap();
        let storage = storage_with_key(directory.path(), OLD_KEY).await;
        assert_eq!(
            storage.rotate_secret_key(SecretCodec::new(OLD_KEY)).await.unwrap_err(),
            "SECRET_KEY_ROTATION_SAME_KEY"
        );
    }

    #[test]
    fn reads_the_previous_key_from_the_environment() {
        let hex = "07".repeat(32);
        let lookup = |name: &str| (name == "DBX_SECRET_KEY_PREVIOUS").then(|| std::ffi::OsString::from(hex.clone()));
        assert!(SecretCodec::previous_from_lookup(lookup).unwrap().unwrap().same_key_as(&SecretCodec::new(OLD_KEY)));
        assert!(SecretCodec::previous_from_lookup(|_| None).unwrap().is_none());
        assert_eq!(
            SecretCodec::previous_from_lookup(|name| {
                (name == "DBX_SECRET_KEY_PREVIOUS_FILE").then(|| "/nonexistent/dbx/previous.key".into())
            })
            .err()
            .as_deref(),
            Some("PREVIOUS_SECRET_KEY_INVALID")
        );
    }
}
