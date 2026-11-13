use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const FLOW_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_PENDING_FLOWS: usize = 1000;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const CLOCK_LEEWAY_SECONDS: u64 = 60;
const DEFAULT_SCOPES: &str = "openid profile email";
const DEFAULT_USERNAME_CLAIM: &str = "preferred_username";
const ALLOWED_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenAuth {
    #[default]
    Basic,
    Post,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scopes: String,
    #[serde(default)]
    pub username_claim: String,
    #[serde(default)]
    pub token_auth: TokenAuth,
}

fn http_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "https" | "http") && url.host().is_some())
}

impl OidcConfig {
    pub fn normalized(mut self) -> Self {
        self.issuer = self.issuer.trim().trim_end_matches('/').to_string();
        self.client_id = self.client_id.trim().to_string();
        self.redirect_uri = self.redirect_uri.trim().to_string();
        self.scopes = self.scopes.trim().to_string();
        self.username_claim = self.username_claim.trim().to_string();
        self
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if !http_url(&self.issuer) {
            return Err("oidc_issuer_invalid");
        }
        if self.client_id.is_empty() || self.client_id.len() > 512 {
            return Err("oidc_client_id_required");
        }
        if !http_url(&self.redirect_uri) {
            return Err("oidc_redirect_uri_invalid");
        }
        Ok(())
    }

    fn scopes(&self) -> String {
        let scopes = if self.scopes.is_empty() { DEFAULT_SCOPES } else { self.scopes.as_str() };
        if scopes.split_whitespace().any(|scope| scope == "openid") {
            scopes.to_string()
        } else {
            format!("openid {scopes}")
        }
    }

    fn username_claim(&self) -> &str {
        if self.username_claim.is_empty() {
            DEFAULT_USERNAME_CLAIM
        } else {
            &self.username_claim
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

pub async fn discover(client: &reqwest::Client, issuer: &str) -> Result<Discovery, String> {
    let issuer = issuer.trim_end_matches('/');
    let url = format!("{issuer}/.well-known/openid-configuration");
    let response =
        client.get(&url).timeout(HTTP_TIMEOUT).send().await.map_err(|error| format!("discovery failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("discovery answered HTTP {}", response.status()));
    }
    let discovery: Discovery = response.json().await.map_err(|error| format!("discovery is not valid: {error}"))?;
    if discovery.issuer.trim_end_matches('/') != issuer {
        return Err("discovery issuer does not match the configured issuer".to_string());
    }
    for endpoint in [&discovery.authorization_endpoint, &discovery.token_endpoint, &discovery.jwks_uri] {
        if !http_url(endpoint) {
            return Err("discovery returned an invalid endpoint".to_string());
        }
    }
    Ok(discovery)
}

fn random_token(bytes: usize) -> Result<String, String> {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer).map_err(|error| error.to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[derive(Debug, Clone)]
pub struct PendingFlow {
    pub provider_id: String,
    pub nonce: String,
    pub verifier: String,
    pub created_at: Instant,
}

#[derive(Debug, Default)]
pub struct OidcFlows {
    entries: HashMap<String, PendingFlow>,
}

pub struct StartedFlow {
    pub state: String,
    pub nonce: String,
    pub challenge: String,
}

fn state_key(state: &str) -> String {
    Sha256::digest(state.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

impl OidcFlows {
    pub fn start(&mut self, provider_id: &str, now: Instant) -> Result<StartedFlow, String> {
        self.entries.retain(|_, flow| now.duration_since(flow.created_at) < FLOW_TTL);
        if self.entries.len() >= MAX_PENDING_FLOWS {
            return Err("too many pending sign-ins".to_string());
        }
        let state = random_token(32)?;
        let nonce = random_token(32)?;
        let verifier = random_token(48)?;
        let challenge = pkce_challenge(&verifier);
        self.entries.insert(
            state_key(&state),
            PendingFlow { provider_id: provider_id.to_string(), nonce: nonce.clone(), verifier, created_at: now },
        );
        Ok(StartedFlow { state, nonce, challenge })
    }

    pub fn take(&mut self, state: &str, now: Instant) -> Option<PendingFlow> {
        self.entries.remove(&state_key(state)).filter(|flow| now.duration_since(flow.created_at) < FLOW_TTL)
    }
}

pub fn authorization_url(discovery: &Discovery, config: &OidcConfig, flow: &StartedFlow) -> Result<String, String> {
    let scopes = config.scopes();
    let url = reqwest::Url::parse_with_params(
        &discovery.authorization_endpoint,
        &[
            ("response_type", "code"),
            ("client_id", config.client_id.as_str()),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("scope", scopes.as_str()),
            ("state", flow.state.as_str()),
            ("nonce", flow.nonce.as_str()),
            ("code_challenge", flow.challenge.as_str()),
            ("code_challenge_method", "S256"),
        ],
    )
    .map_err(|error| error.to_string())?;
    Ok(url.to_string())
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

pub async fn exchange_code(
    client: &reqwest::Client,
    discovery: &Discovery,
    config: &OidcConfig,
    secret: Option<&str>,
    code: &str,
    verifier: &str,
) -> Result<String, String> {
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", config.redirect_uri.clone()),
        ("code_verifier", verifier.to_string()),
    ];
    let mut request = client.post(&discovery.token_endpoint).timeout(HTTP_TIMEOUT);
    match (config.token_auth, secret) {
        (TokenAuth::Basic, Some(secret)) => request = request.basic_auth(&config.client_id, Some(secret)),
        (TokenAuth::Post, Some(secret)) => {
            form.push(("client_id", config.client_id.clone()));
            form.push(("client_secret", secret.to_string()));
        }
        (_, None) => form.push(("client_id", config.client_id.clone())),
    }
    let response = request.form(&form).send().await.map_err(|error| format!("token request failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("token endpoint answered HTTP {}", response.status()));
    }
    let body: TokenResponse = response.json().await.map_err(|error| format!("token response is not valid: {error}"))?;
    body.id_token.ok_or_else(|| "token response has no id_token".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityClaims {
    pub subject: String,
    pub username: Option<String>,
    pub display_name: Option<String>,
}

fn claim_text(claims: &serde_json::Value, name: &str) -> Option<String> {
    claims
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub async fn validate_id_token(
    client: &reqwest::Client,
    discovery: &Discovery,
    config: &OidcConfig,
    id_token: &str,
    nonce: &str,
) -> Result<IdentityClaims, String> {
    let header = decode_header(id_token).map_err(|error| format!("id_token header is not valid: {error}"))?;
    if !ALLOWED_ALGORITHMS.contains(&header.alg) {
        return Err(format!("id_token algorithm {:?} is not allowed", header.alg));
    }
    let response = client
        .get(&discovery.jwks_uri)
        .timeout(HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|error| format!("jwks failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("jwks answered HTTP {}", response.status()));
    }
    let keys: JwkSet = response.json().await.map_err(|error| format!("jwks is not valid: {error}"))?;
    let jwk = match header.kid.as_deref() {
        Some(kid) => keys.find(kid),
        None if keys.keys.len() == 1 => keys.keys.first(),
        None => None,
    }
    .ok_or_else(|| "id_token signing key is unknown".to_string())?;
    let key = DecodingKey::from_jwk(jwk).map_err(|error| format!("signing key is not usable: {error}"))?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[discovery.issuer.as_str()]);
    validation.set_audience(&[config.client_id.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = CLOCK_LEEWAY_SECONDS;
    let claims = decode::<serde_json::Value>(id_token, &key, &validation)
        .map_err(|error| format!("id_token is not valid: {error}"))?
        .claims;
    if claim_text(&claims, "nonce").as_deref() != Some(nonce) {
        return Err("id_token nonce does not match".to_string());
    }
    let audiences = match claims.get("aud") {
        Some(serde_json::Value::Array(values)) => values.len(),
        _ => 1,
    };
    if let Some(azp) = claim_text(&claims, "azp") {
        if azp != config.client_id {
            return Err("id_token azp does not match the client".to_string());
        }
    } else if audiences > 1 {
        return Err("id_token has several audiences and no azp".to_string());
    }
    let subject = claim_text(&claims, "sub").ok_or_else(|| "id_token has no subject".to_string())?;
    let username = claim_text(&claims, config.username_claim()).or_else(|| claim_text(&claims, "email"));
    let display_name = claim_text(&claims, "name");
    Ok(IdentityClaims { subject, username, display_name })
}

#[cfg(test)]
pub(crate) mod test_provider {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use axum::extract::{Form, State};
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use jsonwebtoken::{encode, EncodingKey, Header};

    pub const PRIVATE_KEY: &str = include_str!("testdata/oidc_rsa.pem");
    pub const MODULUS: &str = include_str!("testdata/oidc_rsa_n.txt");
    pub const CLIENT_ID: &str = "dbx-web";
    pub const CLIENT_SECRET: &str = "client-secret";

    #[derive(Clone, Default)]
    pub struct Expectations {
        pub nonce: Arc<Mutex<String>>,
        pub challenge: Arc<Mutex<String>>,
        pub subject: Arc<Mutex<String>>,
        pub claims: Arc<Mutex<serde_json::Value>>,
        pub issuer: Arc<Mutex<String>>,
        pub token_requests: Arc<Mutex<Vec<std::collections::HashMap<String, String>>>>,
    }

    async fn discovery(State(state): State<Expectations>) -> impl IntoResponse {
        let issuer = state.issuer.lock().unwrap().clone();
        Json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
        }))
    }

    async fn jwks() -> impl IntoResponse {
        Json(
            serde_json::json!({ "keys": [{ "kty": "RSA", "kid": "test-key", "alg": "RS256", "use": "sig", "n": MODULUS.trim(), "e": "AQAB" }] }),
        )
    }

    async fn token(
        State(state): State<Expectations>,
        headers: HeaderMap,
        Form(form): Form<std::collections::HashMap<String, String>>,
    ) -> impl IntoResponse {
        state.token_requests.lock().unwrap().push(form.clone());
        let expected_basic = format!(
            "Basic {}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{CLIENT_ID}:{CLIENT_SECRET}"))
        );
        if headers.get("authorization").and_then(|value| value.to_str().ok()) != Some(expected_basic.as_str()) {
            return (StatusCode::UNAUTHORIZED, "client").into_response();
        }
        let verifier = form.get("code_verifier").cloned().unwrap_or_default();
        if super::pkce_challenge(&verifier) != *state.challenge.lock().unwrap()
            || form.get("code").map(String::as_str) != Some("code-1")
        {
            return (StatusCode::BAD_REQUEST, "grant").into_response();
        }
        let issuer = state.issuer.lock().unwrap().clone();
        let mut claims = serde_json::json!({
            "iss": issuer,
            "aud": CLIENT_ID,
            "sub": state.subject.lock().unwrap().clone(),
            "nonce": state.nonce.lock().unwrap().clone(),
            "exp": chrono::Utc::now().timestamp() + 300,
            "iat": chrono::Utc::now().timestamp(),
        });
        if let serde_json::Value::Object(extra) = state.claims.lock().unwrap().clone() {
            for (key, value) in extra {
                claims[key] = value;
            }
        }
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("test-key".into());
        let id_token = encode(&header, &claims, &EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes()).unwrap()).unwrap();
        Json(serde_json::json!({ "access_token": "access", "token_type": "Bearer", "id_token": id_token }))
            .into_response()
    }

    pub async fn spawn() -> (SocketAddr, Expectations, tokio::task::JoinHandle<()>) {
        let expectations = Expectations::default();
        let router = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(expectations.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        *expectations.issuer.lock().unwrap() = format!("http://{address}");
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (address, expectations, task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_the_configuration_and_always_requests_openid() {
        let config = OidcConfig {
            issuer: " https://id.example.com/realms/dbx/ ".into(),
            client_id: "dbx".into(),
            redirect_uri: "https://dbx.example.com/api/auth/oidc/callback".into(),
            scopes: "profile".into(),
            ..Default::default()
        }
        .normalized();
        assert_eq!(config.issuer, "https://id.example.com/realms/dbx");
        assert_eq!(config.validate(), Ok(()));
        assert_eq!(config.scopes(), "openid profile");
        assert_eq!(config.username_claim(), "preferred_username");
        assert_eq!(OidcConfig { issuer: "ftp://x".into(), ..config.clone() }.validate(), Err("oidc_issuer_invalid"));
        assert_eq!(
            OidcConfig { client_id: String::new(), ..config.clone() }.validate(),
            Err("oidc_client_id_required")
        );
        assert_eq!(OidcConfig { redirect_uri: "nope".into(), ..config }.validate(), Err("oidc_redirect_uri_invalid"));
    }

    #[test]
    fn flows_are_single_use_and_expire() {
        let now = Instant::now();
        let mut flows = OidcFlows::default();
        let started = flows.start("p1", now).unwrap();
        assert_eq!(started.challenge, pkce_challenge(&flows.entries.values().next().unwrap().verifier));
        let taken = flows.take(&started.state, now).unwrap();
        assert_eq!((taken.provider_id.as_str(), taken.nonce.as_str()), ("p1", started.nonce.as_str()));
        assert!(flows.take(&started.state, now).is_none());
        let late = flows.start("p1", now).unwrap();
        assert!(flows.take(&late.state, now + FLOW_TTL).is_none());
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[tokio::test]
    async fn runs_discovery_code_exchange_and_token_validation_against_a_provider() {
        let (_address, expectations, task) = test_provider::spawn().await;
        let issuer = expectations.issuer.lock().unwrap().clone();
        let client = reqwest::Client::new();
        let config = OidcConfig {
            issuer: issuer.clone(),
            client_id: test_provider::CLIENT_ID.into(),
            redirect_uri: "http://dbx.local/api/auth/oidc/callback".into(),
            ..Default::default()
        };
        let discovery = discover(&client, &issuer).await.unwrap();
        assert!(discover(&client, &format!("{issuer}/other")).await.is_err());

        let mut flows = OidcFlows::default();
        let started = flows.start("p1", Instant::now()).unwrap();
        let url = authorization_url(&discovery, &config, &started).unwrap();
        assert!(url.starts_with(&format!("{issuer}/authorize?response_type=code&client_id=dbx-web")));
        assert!(url.contains("code_challenge_method=S256") && url.contains("scope=openid+profile+email"));
        let flow = flows.take(&started.state, Instant::now()).unwrap();
        *expectations.nonce.lock().unwrap() = flow.nonce.clone();
        *expectations.challenge.lock().unwrap() = started.challenge.clone();
        *expectations.subject.lock().unwrap() = "user-123".into();
        *expectations.claims.lock().unwrap() = serde_json::json!({ "preferred_username": "ana", "name": "Ana López" });

        let id_token =
            exchange_code(&client, &discovery, &config, Some(test_provider::CLIENT_SECRET), "code-1", &flow.verifier)
                .await
                .unwrap();
        let claims = validate_id_token(&client, &discovery, &config, &id_token, &flow.nonce).await.unwrap();
        assert_eq!(
            claims,
            IdentityClaims {
                subject: "user-123".into(),
                username: Some("ana".into()),
                display_name: Some("Ana López".into())
            }
        );
        assert!(validate_id_token(&client, &discovery, &config, &id_token, "other-nonce").await.is_err());
        let other_client = OidcConfig { client_id: "someone-else".into(), ..config.clone() };
        assert!(validate_id_token(&client, &discovery, &other_client, &id_token, &flow.nonce).await.is_err());
        assert!(exchange_code(&client, &discovery, &config, Some("wrong"), "code-1", &flow.verifier).await.is_err());
        assert!(exchange_code(
            &client,
            &discovery,
            &config,
            Some(test_provider::CLIENT_SECRET),
            "code-1",
            "bad-verifier"
        )
        .await
        .is_err());

        let unsigned = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::json!({ "sub": "x" }).to_string())
        );
        assert!(validate_id_token(&client, &discovery, &config, &unsigned, &flow.nonce).await.is_err());
        task.abort();
    }
}
