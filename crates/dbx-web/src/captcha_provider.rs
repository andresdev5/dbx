use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);
pub const FALLBACK_WINDOW: Duration = Duration::from_secs(5 * 60);
const MAX_TOKEN_BYTES: usize = 4096;

const TURNSTILE_VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const HCAPTCHA_VERIFY_URL: &str = "https://api.hcaptcha.com/siteverify";
const RECAPTCHA_VERIFY_URL: &str = "https://www.google.com/recaptcha/api/siteverify";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptchaProviderKind {
    #[default]
    Builtin,
    Cap,
    Turnstile,
    Hcaptcha,
    Recaptcha,
}

impl CaptchaProviderKind {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "builtin" | "" => Some(Self::Builtin),
            "cap" => Some(Self::Cap),
            "turnstile" => Some(Self::Turnstile),
            "hcaptcha" => Some(Self::Hcaptcha),
            "recaptcha" => Some(Self::Recaptcha),
            _ => None,
        }
    }

    pub fn is_external(self) -> bool {
        self != Self::Builtin
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptchaProviderSettings {
    #[serde(default)]
    pub provider: CaptchaProviderKind,
    #[serde(default)]
    pub site_key: String,
    #[serde(default)]
    pub endpoint: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptchaProviderConfig {
    pub settings: CaptchaProviderSettings,
    pub secret: Option<String>,
}

impl CaptchaProviderConfig {
    pub fn active_external(&self) -> bool {
        self.settings.provider.is_external()
            && !self.settings.site_key.is_empty()
            && self.secret.as_deref().is_some_and(|secret| !secret.is_empty())
    }

    pub fn from_env() -> Option<Self> {
        let provider = std::env::var("DBX_WEB_CAPTCHA_PROVIDER").ok().filter(|value| !value.trim().is_empty())?;
        let kind = match CaptchaProviderKind::parse(&provider) {
            Some(kind) => kind,
            None => {
                log::warn!("DBX_WEB_CAPTCHA_PROVIDER={provider:?} is not builtin|cap|turnstile|hcaptcha|recaptcha; using builtin");
                CaptchaProviderKind::Builtin
            }
        };
        let read = |name: &str| std::env::var(name).ok().map(|value| value.trim().to_string()).unwrap_or_default();
        let config = Self {
            settings: CaptchaProviderSettings {
                provider: kind,
                site_key: read("DBX_WEB_CAPTCHA_SITE_KEY"),
                endpoint: read("DBX_WEB_CAPTCHA_ENDPOINT"),
            },
            secret: Some(read("DBX_WEB_CAPTCHA_SECRET")).filter(|secret| !secret.is_empty()),
        };
        if let Err(code) = validate(&config) {
            log::warn!("DBX_WEB_CAPTCHA_PROVIDER is incomplete ({code}); the built-in captcha stays in use");
        }
        Some(config)
    }
}

pub fn validate(config: &CaptchaProviderConfig) -> Result<(), &'static str> {
    let settings = &config.settings;
    if !settings.provider.is_external() {
        return Ok(());
    }
    if settings.site_key.is_empty() || settings.site_key.len() > 512 {
        return Err("captcha_site_key_required");
    }
    if config.secret.as_deref().is_none_or(str::is_empty) {
        return Err("captcha_secret_required");
    }
    if settings.provider == CaptchaProviderKind::Cap {
        let endpoint = settings.endpoint.trim_end_matches('/');
        let valid = (endpoint.starts_with("https://") || endpoint.starts_with("http://"))
            && endpoint.len() > "https://".len()
            && !endpoint.contains(char::is_whitespace);
        if !valid {
            return Err("captcha_endpoint_invalid");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    Passed,
    Rejected,
    Unavailable,
}

#[derive(Deserialize)]
struct VerifyResponse {
    #[serde(default)]
    success: bool,
}

pub struct VerifyTargets {
    pub turnstile: String,
    pub hcaptcha: String,
    pub recaptcha: String,
}

impl Default for VerifyTargets {
    fn default() -> Self {
        Self {
            turnstile: TURNSTILE_VERIFY_URL.to_string(),
            hcaptcha: HCAPTCHA_VERIFY_URL.to_string(),
            recaptcha: RECAPTCHA_VERIFY_URL.to_string(),
        }
    }
}

pub async fn verify(
    client: &reqwest::Client,
    targets: &VerifyTargets,
    config: &CaptchaProviderConfig,
    token: &str,
    ip: Option<&str>,
) -> Verification {
    let token = token.trim();
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Verification::Rejected;
    }
    let Some(secret) = config.secret.as_deref() else {
        return Verification::Unavailable;
    };
    let settings = &config.settings;
    let request = match settings.provider {
        CaptchaProviderKind::Builtin => return Verification::Unavailable,
        CaptchaProviderKind::Cap => {
            let url = format!("{}/{}/siteverify", settings.endpoint.trim_end_matches('/'), settings.site_key);
            client.post(url).json(&serde_json::json!({ "secret": secret, "response": token }))
        }
        CaptchaProviderKind::Turnstile | CaptchaProviderKind::Hcaptcha | CaptchaProviderKind::Recaptcha => {
            let url = match settings.provider {
                CaptchaProviderKind::Turnstile => &targets.turnstile,
                CaptchaProviderKind::Hcaptcha => &targets.hcaptcha,
                _ => &targets.recaptcha,
            };
            let mut form = vec![("secret", secret.to_string()), ("response", token.to_string())];
            if let Some(ip) = ip {
                form.push(("remoteip", ip.to_string()));
            }
            if settings.provider == CaptchaProviderKind::Hcaptcha {
                form.push(("sitekey", settings.site_key.clone()));
            }
            client.post(url.as_str()).form(&form)
        }
    };
    let response = match request.timeout(VERIFY_TIMEOUT).send().await {
        Ok(response) => response,
        Err(error) => {
            log::warn!("Captcha provider {:?} did not answer: {error}", settings.provider);
            return Verification::Unavailable;
        }
    };
    if !response.status().is_success() {
        log::warn!("Captcha provider {:?} answered HTTP {}", settings.provider, response.status());
        return Verification::Unavailable;
    }
    match response.json::<VerifyResponse>().await {
        Ok(body) if body.success => Verification::Passed,
        Ok(_) => Verification::Rejected,
        Err(error) => {
            log::warn!("Captcha provider {:?} sent an unreadable answer: {error}", settings.provider);
            Verification::Unavailable
        }
    }
}

#[derive(Debug, Default)]
pub struct CaptchaFallback {
    until: Option<Instant>,
}

impl CaptchaFallback {
    pub fn activate(&mut self, now: Instant) {
        self.until = Some(now + FALLBACK_WINDOW);
    }

    pub fn active(&self, now: Instant) -> bool {
        self.until.is_some_and(|until| now < until)
    }

    pub fn clear(&mut self) {
        self.until = None;
    }
}

#[cfg(test)]
pub(crate) mod test_server {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::Router;

    #[derive(Clone, Default)]
    pub struct Recorded {
        pub requests: Arc<Mutex<Vec<(String, String, String)>>>,
    }

    async fn answer(
        State(recorded): State<Recorded>,
        uri: axum::http::Uri,
        headers: HeaderMap,
        body: String,
    ) -> impl IntoResponse {
        let content_type =
            headers.get("content-type").and_then(|value| value.to_str().ok()).unwrap_or_default().to_string();
        recorded.requests.lock().unwrap().push((uri.path().to_string(), content_type, body.clone()));
        if body.contains("token-down") {
            return (StatusCode::SERVICE_UNAVAILABLE, "down").into_response();
        }
        let success = body.contains("token-good");
        axum::Json(serde_json::json!({ "success": success })).into_response()
    }

    pub async fn spawn() -> (SocketAddr, Recorded, tokio::task::JoinHandle<()>) {
        let recorded = Recorded::default();
        let router = Router::new().fallback(post(answer)).with_state(recorded.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (address, recorded, task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(provider: CaptchaProviderKind, endpoint: &str) -> CaptchaProviderConfig {
        CaptchaProviderConfig {
            settings: CaptchaProviderSettings { provider, site_key: "site-1".into(), endpoint: endpoint.into() },
            secret: Some("secret-1".into()),
        }
    }

    #[test]
    fn validates_each_provider_configuration() {
        assert_eq!(validate(&CaptchaProviderConfig::default()), Ok(()));
        assert_eq!(validate(&config(CaptchaProviderKind::Turnstile, "")), Ok(()));
        let mut missing_secret = config(CaptchaProviderKind::Hcaptcha, "");
        missing_secret.secret = None;
        assert_eq!(validate(&missing_secret), Err("captcha_secret_required"));
        let mut missing_site = config(CaptchaProviderKind::Recaptcha, "");
        missing_site.settings.site_key.clear();
        assert_eq!(validate(&missing_site), Err("captcha_site_key_required"));
        assert_eq!(validate(&config(CaptchaProviderKind::Cap, "ftp://cap")), Err("captcha_endpoint_invalid"));
        assert_eq!(validate(&config(CaptchaProviderKind::Cap, "https://cap.example.com/")), Ok(()));
        assert_eq!(CaptchaProviderKind::parse(" Turnstile "), Some(CaptchaProviderKind::Turnstile));
        assert_eq!(CaptchaProviderKind::parse("other"), None);
    }

    #[tokio::test]
    async fn verifies_tokens_with_each_provider_wire_format() {
        let (address, recorded, task) = test_server::spawn().await;
        let base = format!("http://{address}");
        let targets = VerifyTargets {
            turnstile: format!("{base}/turnstile"),
            hcaptcha: format!("{base}/hcaptcha"),
            recaptcha: format!("{base}/recaptcha"),
        };
        let client = reqwest::Client::new();
        for provider in [
            CaptchaProviderKind::Cap,
            CaptchaProviderKind::Turnstile,
            CaptchaProviderKind::Hcaptcha,
            CaptchaProviderKind::Recaptcha,
        ] {
            let config = config(provider, &base);
            assert_eq!(verify(&client, &targets, &config, "token-good", Some("10.0.0.1")).await, Verification::Passed);
            assert_eq!(verify(&client, &targets, &config, "token-bad", None).await, Verification::Rejected);
            assert_eq!(verify(&client, &targets, &config, "token-down", None).await, Verification::Unavailable);
            assert_eq!(verify(&client, &targets, &config, " ", None).await, Verification::Rejected);
        }
        let requests = recorded.requests.lock().unwrap().clone();
        let cap = requests.iter().find(|(path, _, _)| path == "/site-1/siteverify").unwrap();
        assert!(cap.1.starts_with("application/json"));
        assert!(cap.2.contains("\"secret\":\"secret-1\"") && cap.2.contains("\"response\":\"token-good\""));
        let turnstile = requests.iter().find(|(path, _, _)| path == "/turnstile").unwrap();
        assert!(turnstile.1.starts_with("application/x-www-form-urlencoded"));
        assert!(turnstile.2.contains("secret=secret-1") && turnstile.2.contains("remoteip=10.0.0.1"));
        let hcaptcha = requests.iter().find(|(path, _, _)| path == "/hcaptcha").unwrap();
        assert!(hcaptcha.2.contains("sitekey=site-1"));
        assert!(requests.iter().any(|(path, _, _)| path == "/recaptcha"));
        task.abort();

        let unreachable = config(CaptchaProviderKind::Cap, "http://127.0.0.1:9");
        assert_eq!(
            verify(&client, &VerifyTargets::default(), &unreachable, "token-good", None).await,
            Verification::Unavailable
        );
    }

    #[test]
    fn the_fallback_lasts_five_minutes() {
        let now = Instant::now();
        let mut fallback = CaptchaFallback::default();
        assert!(!fallback.active(now));
        fallback.activate(now);
        assert!(fallback.active(now + Duration::from_secs(60)));
        assert!(!fallback.active(now + FALLBACK_WINDOW));
        fallback.clear();
        assert!(!fallback.active(now));
    }
}
