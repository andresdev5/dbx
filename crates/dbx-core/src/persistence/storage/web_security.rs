use super::{Storage, GLOBAL_SECRET_NAMESPACE};

const CAPTCHA_PROVIDER_KEY: &str = "web_captcha_provider";
const CAPTCHA_SECRET_KEY: &str = "web_captcha_secret";

impl Storage {
    pub async fn load_web_captcha_provider(&self) -> Result<Option<serde_json::Value>, String> {
        self.load_app_state_value(CAPTCHA_PROVIDER_KEY).await
    }

    pub async fn save_web_captcha_provider(&self, settings: &serde_json::Value) -> Result<(), String> {
        self.save_app_state_value(CAPTCHA_PROVIDER_KEY, settings).await
    }

    pub async fn load_web_captcha_secret(&self) -> Result<Option<String>, String> {
        self.get_secret(GLOBAL_SECRET_NAMESPACE, CAPTCHA_SECRET_KEY).await
    }

    pub async fn save_web_captcha_secret(&self, secret: Option<&str>) -> Result<(), String> {
        match secret.filter(|secret| !secret.is_empty()) {
            Some(secret) => self.set_secret(GLOBAL_SECRET_NAMESPACE, CAPTCHA_SECRET_KEY, secret).await,
            None => self.delete_secret(GLOBAL_SECRET_NAMESPACE, CAPTCHA_SECRET_KEY).await,
        }
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn keeps_the_provider_settings_and_an_encrypted_secret() {
        let directory = tempfile::tempdir().unwrap();
        let storage = crate::persistence::test_storage::open(&directory.path().join("storage.db")).await.unwrap();
        assert!(storage.load_web_captcha_provider().await.unwrap().is_none());
        assert!(storage.load_web_captcha_secret().await.unwrap().is_none());
        let settings = serde_json::json!({ "provider": "turnstile", "site_key": "0x4AAA" });
        storage.save_web_captcha_provider(&settings).await.unwrap();
        storage.save_web_captcha_secret(Some("turnstile-secret")).await.unwrap();
        assert_eq!(storage.load_web_captcha_provider().await.unwrap(), Some(settings));
        assert_eq!(storage.load_web_captcha_secret().await.unwrap().as_deref(), Some("turnstile-secret"));
        let raw: Option<String> = storage
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT secret_enc FROM connection_secrets WHERE key = 'web_captcha_secret'",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| error.to_string())
            })
            .await
            .unwrap();
        assert!(!raw.unwrap_or_default().contains("turnstile-secret"));
        storage.save_web_captcha_secret(None).await.unwrap();
        assert!(storage.load_web_captcha_secret().await.unwrap().is_none());
    }
}
