use super::{params, OptionalExtension, Storage};

pub const MFA_NAMESPACE: &str = "user_mfa";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMfa {
    pub user_id: String,
    pub enabled: bool,
    pub has_pending_secret: bool,
    pub recovery_hashes: Vec<String>,
    pub last_used_step: i64,
    pub enabled_at: Option<i64>,
}

fn sql_error(error: rusqlite::Error) -> String {
    error.to_string()
}

impl Storage {
    pub async fn save_pending_mfa_secret(&self, user_id: &str, secret: &str) -> Result<(), String> {
        let codec = self.secret_codec_for_write(true).await?;
        let encrypted = codec.encrypt(MFA_NAMESPACE, user_id, secret)?;
        let user_id = user_id.to_string();
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO user_mfa (user_id, pending_secret_enc) VALUES (?1, ?2) \
                 ON CONFLICT(user_id) DO UPDATE SET pending_secret_enc = excluded.pending_secret_enc",
                params![user_id, encrypted],
            )
            .map(|_| ())
            .map_err(sql_error)
        })
        .await
    }

    async fn load_mfa_envelope(&self, user_id: &str, column: &'static str) -> Result<Option<String>, String> {
        let id = user_id.to_string();
        let envelope: Option<Option<String>> = self
            .with_conn(move |conn| {
                conn.query_row(&format!("SELECT {column} FROM user_mfa WHERE user_id = ?1"), params![id], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(sql_error)
            })
            .await?;
        let Some(Some(envelope)) = envelope else {
            return Ok(None);
        };
        let codec = self.secret_codec(false)?;
        codec.decrypt(MFA_NAMESPACE, user_id, &envelope).map(Some)
    }

    pub async fn load_pending_mfa_secret(&self, user_id: &str) -> Result<Option<String>, String> {
        self.load_mfa_envelope(user_id, "pending_secret_enc").await
    }

    pub async fn load_mfa_secret(&self, user_id: &str) -> Result<Option<String>, String> {
        self.load_mfa_envelope(user_id, "totp_secret_enc").await
    }

    pub async fn load_user_mfa(&self, user_id: &str) -> Result<Option<UserMfa>, String> {
        let id = user_id.to_string();
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT user_id, totp_secret_enc IS NOT NULL AND enabled_at IS NOT NULL, pending_secret_enc IS NOT NULL, \
                 recovery_codes, last_used_step, enabled_at FROM user_mfa WHERE user_id = ?1",
                params![id],
                |row| {
                    let codes: String = row.get(3)?;
                    Ok(UserMfa {
                        user_id: row.get(0)?,
                        enabled: row.get(1)?,
                        has_pending_secret: row.get(2)?,
                        recovery_hashes: serde_json::from_str(&codes).unwrap_or_default(),
                        last_used_step: row.get(4)?,
                        enabled_at: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(sql_error)
        })
        .await
    }

    pub async fn activate_mfa(
        &self,
        user_id: &str,
        recovery_hashes: Vec<String>,
        step: i64,
        now: i64,
    ) -> Result<(), String> {
        let id = user_id.to_string();
        let codes = serde_json::to_string(&recovery_hashes).map_err(|error| error.to_string())?;
        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(sql_error)?;
            let changed = tx
                .execute(
                    "UPDATE user_mfa SET totp_secret_enc = pending_secret_enc, pending_secret_enc = NULL, \
                     recovery_codes = ?2, enabled_at = ?3, last_used_step = ?4 \
                     WHERE user_id = ?1 AND pending_secret_enc IS NOT NULL",
                    params![id, codes, now, step],
                )
                .map_err(sql_error)?;
            if changed == 0 {
                return Err("MFA_SETUP_NOT_STARTED".to_string());
            }
            tx.execute("UPDATE users SET mfa_enabled = 1, updated_at = ?2 WHERE id = ?1", params![id, now])
                .map_err(sql_error)?;
            tx.commit().map_err(sql_error)
        })
        .await
    }

    pub async fn claim_mfa_step(&self, user_id: &str, step: i64) -> Result<bool, String> {
        let id = user_id.to_string();
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE user_mfa SET last_used_step = ?2 WHERE user_id = ?1 AND last_used_step < ?2",
                params![id, step],
            )
            .map(|changed| changed == 1)
            .map_err(sql_error)
        })
        .await
    }

    pub async fn replace_recovery_codes(&self, user_id: &str, recovery_hashes: Vec<String>) -> Result<(), String> {
        let id = user_id.to_string();
        let codes = serde_json::to_string(&recovery_hashes).map_err(|error| error.to_string())?;
        self.with_conn(move |conn| {
            conn.execute("UPDATE user_mfa SET recovery_codes = ?2 WHERE user_id = ?1", params![id, codes])
                .map(|_| ())
                .map_err(sql_error)
        })
        .await
    }

    pub async fn consume_recovery_code(&self, user_id: &str, hash: &str) -> Result<bool, String> {
        let (id, hash) = (user_id.to_string(), hash.to_string());
        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(sql_error)?;
            let codes: Option<String> = tx
                .query_row("SELECT recovery_codes FROM user_mfa WHERE user_id = ?1", params![id], |row| row.get(0))
                .optional()
                .map_err(sql_error)?;
            let mut hashes: Vec<String> = codes.and_then(|codes| serde_json::from_str(&codes).ok()).unwrap_or_default();
            let before = hashes.len();
            hashes.retain(|candidate| candidate != &hash);
            if hashes.len() == before {
                return Ok(false);
            }
            let codes = serde_json::to_string(&hashes).map_err(|error| error.to_string())?;
            tx.execute("UPDATE user_mfa SET recovery_codes = ?2 WHERE user_id = ?1", params![id, codes])
                .map_err(sql_error)?;
            tx.commit().map_err(sql_error)?;
            Ok(true)
        })
        .await
    }

    pub async fn disable_mfa(&self, user_id: &str, now: i64) -> Result<(), String> {
        let id = user_id.to_string();
        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(sql_error)?;
            tx.execute("DELETE FROM user_mfa WHERE user_id = ?1", params![id]).map_err(sql_error)?;
            tx.execute("UPDATE users SET mfa_enabled = 0, updated_at = ?2 WHERE id = ?1", params![id, now])
                .map_err(sql_error)?;
            tx.commit().map_err(sql_error)
        })
        .await
    }

    pub async fn set_web_user_mfa_required(&self, user_id: &str, required: bool, now: i64) -> Result<(), String> {
        let id = user_id.to_string();
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE users SET mfa_required = ?2, updated_at = ?3 WHERE id = ?1",
                    params![id, i64::from(required), now],
                )
                .map_err(sql_error)?;
            if changed == 0 {
                return Err(super::USER_NOT_FOUND.to_string());
            }
            Ok(())
        })
        .await
    }

    pub async fn set_all_web_users_mfa_required(&self, required: bool, now: i64) -> Result<usize, String> {
        self.with_conn(move |conn| {
            conn.execute(
                "UPDATE users SET mfa_required = ?1, updated_at = ?2 WHERE mfa_required <> ?1",
                params![i64::from(required), now],
            )
            .map_err(sql_error)
        })
        .await
    }

    pub async fn mark_web_session_mfa_verified(&self, token_hash: &str) -> Result<(), String> {
        let hash = token_hash.to_string();
        self.with_conn(move |conn| {
            conn.execute("UPDATE user_sessions SET mfa_verified = 1 WHERE token_hash = ?1", params![hash])
                .map(|_| ())
                .map_err(sql_error)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::storage::NewWebUser;
    use dbx_authz::PlatformRole;

    async fn storage_with_user() -> (tempfile::TempDir, Storage, String) {
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::persistence::test_storage::open(&directory.path().join("storage.db")).await.unwrap();
        let id = storage
            .create_web_user(
                NewWebUser {
                    username: "ana".into(),
                    display_name: None,
                    password_hash: "h".into(),
                    role: PlatformRole::User,
                    must_change_password: false,
                },
                0,
            )
            .await
            .unwrap()
            .id;
        (directory, storage, id)
    }

    #[tokio::test]
    async fn enrollment_keeps_the_secret_encrypted_until_confirmed() {
        let (_directory, storage, id) = storage_with_user().await;
        assert!(storage.load_user_mfa(&id).await.unwrap().is_none());
        storage.save_pending_mfa_secret(&id, "JBSWY3DPEHPK3PXP").await.unwrap();
        let raw: String = storage
            .with_conn(|conn| {
                conn.query_row("SELECT pending_secret_enc FROM user_mfa", [], |row| row.get(0)).map_err(sql_error)
            })
            .await
            .unwrap();
        assert!(!raw.contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(storage.load_pending_mfa_secret(&id).await.unwrap().as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(storage.load_mfa_secret(&id).await.unwrap().is_none());
        assert!(!storage.find_web_user(&id).await.unwrap().unwrap().mfa_enabled);

        storage.activate_mfa(&id, vec!["h1".into(), "h2".into()], 100, 5).await.unwrap();
        let mfa = storage.load_user_mfa(&id).await.unwrap().unwrap();
        assert!(mfa.enabled && !mfa.has_pending_secret);
        assert_eq!(mfa.recovery_hashes, vec!["h1", "h2"]);
        assert_eq!(storage.load_mfa_secret(&id).await.unwrap().as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(storage.find_web_user(&id).await.unwrap().unwrap().mfa_enabled);
        assert_eq!(storage.activate_mfa(&id, vec![], 1, 6).await.unwrap_err(), "MFA_SETUP_NOT_STARTED");
    }

    #[tokio::test]
    async fn steps_and_recovery_codes_are_single_use() {
        let (_directory, storage, id) = storage_with_user().await;
        storage.save_pending_mfa_secret(&id, "SECRET").await.unwrap();
        storage.activate_mfa(&id, vec!["h1".into(), "h2".into()], 100, 0).await.unwrap();
        assert!(!storage.claim_mfa_step(&id, 100).await.unwrap());
        assert!(storage.claim_mfa_step(&id, 101).await.unwrap());
        assert!(!storage.claim_mfa_step(&id, 101).await.unwrap());
        assert!(storage.consume_recovery_code(&id, "h1").await.unwrap());
        assert!(!storage.consume_recovery_code(&id, "h1").await.unwrap());
        assert_eq!(storage.load_user_mfa(&id).await.unwrap().unwrap().recovery_hashes, vec!["h2"]);

        storage.disable_mfa(&id, 9).await.unwrap();
        assert!(storage.load_user_mfa(&id).await.unwrap().is_none());
        assert!(!storage.find_web_user(&id).await.unwrap().unwrap().mfa_enabled);
        storage.set_web_user_mfa_required(&id, true, 10).await.unwrap();
        assert!(storage.find_web_user(&id).await.unwrap().unwrap().mfa_required);
    }
}
