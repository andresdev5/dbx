use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use dbx_core::storage::{IdentityProvider, WebUser, USERNAME_TAKEN};
use serde::{Deserialize, Serialize};

use crate::auth::{audit_auth_failure, start_session};
use crate::identity::normalize_username;
use crate::oidc::{authorization_url, discover, exchange_code, validate_id_token, OidcConfig};
use crate::request_context::ClientInfo;
use crate::sessions::now_millis;
use crate::state::WebState;

#[derive(Serialize)]
struct PublicProvider {
    id: String,
    name: String,
    kind: String,
}

pub async fn list_providers(State(state): State<Arc<WebState>>) -> Response {
    if state.password_disabled {
        return Json(Vec::<PublicProvider>::new()).into_response();
    }
    match state.app.storage.list_identity_providers().await {
        Ok(providers) => Json(
            providers
                .into_iter()
                .filter(|provider| provider.enabled)
                .map(|provider| PublicProvider { id: provider.id, name: provider.name, kind: provider.kind })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => {
            log::error!("Failed to list identity providers: {error}");
            Json(Vec::<PublicProvider>::new()).into_response()
        }
    }
}

fn login_redirect(state: &WebState, code: &str) -> Response {
    let base = state.public_base_path.trim_end_matches('/');
    Redirect::to(&format!("{base}/login?sso_error={code}")).into_response()
}

pub fn oidc_config(provider: &IdentityProvider) -> Option<OidcConfig> {
    (provider.kind == "oidc")
        .then(|| serde_json::from_value::<OidcConfig>(provider.config.clone()).ok())
        .flatten()
        .map(OidcConfig::normalized)
}

pub async fn start_oidc(State(state): State<Arc<WebState>>, Path(id): Path<String>) -> Response {
    if state.password_disabled {
        return login_redirect(&state, "sso_unavailable");
    }
    let provider = match state.app.storage.find_identity_provider(&id).await {
        Ok(Some(provider)) if provider.enabled => provider,
        _ => return login_redirect(&state, "sso_provider_unknown"),
    };
    let Some(config) = oidc_config(&provider) else {
        return login_redirect(&state, "sso_provider_unknown");
    };
    let discovery = match discover(&state.captcha_http, &config.issuer).await {
        Ok(discovery) => discovery,
        Err(error) => {
            log::warn!("OIDC discovery for '{}' failed: {error}", provider.name);
            return login_redirect(&state, "sso_provider_unavailable");
        }
    };
    let started = match state.oidc_flows.lock().await.start(&provider.id, std::time::Instant::now()) {
        Ok(started) => started,
        Err(error) => {
            log::warn!("OIDC sign-in could not start: {error}");
            return login_redirect(&state, "sso_busy");
        }
    };
    match authorization_url(&discovery, &config, &started) {
        Ok(url) => {
            let mut response = Redirect::to(&url).into_response();
            response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => {
            log::warn!("OIDC authorization URL for '{}' is not valid: {error}", provider.name);
            login_redirect(&state, "sso_provider_unavailable")
        }
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

pub(crate) async fn resolve_user(
    state: &WebState,
    provider: &IdentityProvider,
    subject: &str,
    username: Option<&str>,
    display_name: Option<String>,
) -> Result<WebUser, &'static str> {
    let storage = &state.app.storage;
    if let Some(user) = storage.find_web_user_by_external_subject(&provider.id, subject).await.map_err(|error| {
        log::error!("Failed to look up an SSO user: {error}");
        "sso_failed"
    })? {
        return if user.active { Ok(user) } else { Err("sso_user_disabled") };
    }
    if !provider.auto_create_users {
        return Err("sso_user_not_provisioned");
    }
    let username = normalize_username(username.unwrap_or(subject)).map_err(|_| "sso_username_invalid")?;
    match storage
        .create_external_web_user(
            &username,
            display_name,
            &provider.id,
            subject,
            provider.default_group_id.as_deref(),
            now_millis(),
        )
        .await
    {
        Ok(user) => {
            if let Err(error) = state.app.authz.reload(storage).await {
                log::warn!("Failed to reload permissions after creating an SSO user: {error}");
            }
            state.app.audit.record(
                dbx_core::audit::AuditEvent::new("user_created")
                    .by_user(&user.id, &user.username)
                    .reason("sso_auto_create")
                    .detail(serde_json::json!({ "provider": provider.name, "username": user.username })),
            );
            Ok(user)
        }
        Err(error) if error == USERNAME_TAKEN => Err("sso_username_taken"),
        Err(error) => {
            log::error!("Failed to create an SSO user: {error}");
            Err("sso_failed")
        }
    }
}

pub async fn oidc_callback(
    State(state): State<Arc<WebState>>,
    client: ClientInfo,
    Query(query): Query<CallbackQuery>,
) -> Response {
    if state.password_disabled {
        return login_redirect(&state, "sso_unavailable");
    }
    let Some(flow_state) = query.state.as_deref() else {
        return login_redirect(&state, "sso_state_invalid");
    };
    let Some(flow) = state.oidc_flows.lock().await.take(flow_state, std::time::Instant::now()) else {
        return login_redirect(&state, "sso_state_invalid");
    };
    if query.error.is_some() {
        return login_redirect(&state, "sso_denied");
    }
    let Some(code) = query.code.as_deref().filter(|code| !code.is_empty()) else {
        return login_redirect(&state, "sso_denied");
    };
    let provider = match state.app.storage.find_identity_provider(&flow.provider_id).await {
        Ok(Some(provider)) if provider.enabled => provider,
        _ => return login_redirect(&state, "sso_provider_unknown"),
    };
    let Some(config) = oidc_config(&provider) else {
        return login_redirect(&state, "sso_provider_unknown");
    };
    let secret = state.app.storage.load_identity_provider_secret(&provider.id).await.unwrap_or(None);
    let http = &state.captcha_http;
    let claims = async {
        let discovery = discover(http, &config.issuer).await?;
        let id_token = exchange_code(http, &discovery, &config, secret.as_deref(), code, &flow.verifier).await?;
        validate_id_token(http, &discovery, &config, &id_token, &flow.nonce).await
    }
    .await;
    let claims = match claims {
        Ok(claims) => claims,
        Err(error) => {
            log::warn!("OIDC sign-in with '{}' failed: {error}", provider.name);
            audit_auth_failure(&state, "login_failed", "", &client, "sso_invalid");
            return login_redirect(&state, "sso_invalid");
        }
    };
    let user = match resolve_user(&state, &provider, &claims.subject, claims.username.as_deref(), claims.display_name)
        .await
    {
        Ok(user) => user,
        Err(code) => {
            audit_auth_failure(&state, "login_failed", claims.username.as_deref().unwrap_or_default(), &client, code);
            return login_redirect(&state, code);
        }
    };
    let mut response = start_session(&state, &user, &client, "login_succeeded", true).await;
    if response.status() != StatusCode::OK {
        return login_redirect(&state, "sso_failed");
    }
    let base = state.public_base_path.clone();
    *response.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(location) = HeaderValue::from_str(&base) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

pub(crate) async fn ldap_login(
    state: &WebState,
    client: &ClientInfo,
    provider_id: &str,
    username: &str,
    password: &str,
) -> Response {
    use crate::auth::{error_response, INVALID_CREDENTIALS};
    use crate::state::LoginThrottle;

    let provider = match state.app.storage.find_identity_provider(provider_id).await {
        Ok(Some(provider)) if provider.enabled && provider.kind == "ldap" => provider,
        _ => return error_response(StatusCode::BAD_REQUEST, "sso_provider_unknown"),
    };
    let user_key = LoginThrottle::user_key(username);
    let ip_key = LoginThrottle::ip_key(client.ip);
    let secret = state.app.storage.load_identity_provider_secret(&provider.id).await.unwrap_or(None);
    let identity = match crate::ldap::authenticate(&provider.config, secret.as_deref(), username, password).await {
        Ok(identity) => identity,
        Err(crate::ldap::LdapFailure::InvalidCredentials) => {
            let now = std::time::Instant::now();
            {
                let mut throttle = state.login_throttle.lock().await;
                throttle.record_failure(&ip_key, now);
                throttle.record_failure(&user_key, now);
            }
            audit_auth_failure(state, "login_failed", username, client, "invalid_credentials");
            return error_response(StatusCode::UNAUTHORIZED, INVALID_CREDENTIALS);
        }
        Err(crate::ldap::LdapFailure::Unavailable(detail)) => {
            log::warn!("LDAP sign-in with '{}' failed: {detail}", provider.name);
            audit_auth_failure(state, "login_failed", username, client, "ldap_unavailable");
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "ldap_unavailable");
        }
    };
    let user = match resolve_user(state, &provider, &identity.subject, Some(&identity.username), identity.display_name)
        .await
    {
        Ok(user) => user,
        Err(code) => {
            audit_auth_failure(state, "login_failed", username, client, code);
            return error_response(StatusCode::FORBIDDEN, code);
        }
    };
    {
        let mut throttle = state.login_throttle.lock().await;
        throttle.clear(&ip_key);
        throttle.clear(&user_key);
    }
    if user.mfa_enabled {
        return crate::routes::mfa::issue_login_challenge(state, &user).await;
    }
    start_session(state, &user, client, "login_succeeded", false).await
}
