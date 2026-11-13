use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use dbx_core::storage::WebUser;
use serde::Deserialize;

use crate::audit_events::record_action;
use crate::auth::{audit_auth_failure, error_response, rate_limited, start_session, CurrentUser, SESSION_EXPIRED};
use crate::identity::{hash_password, verify_password};
use crate::mfa::{generate_recovery_codes, generate_secret, normalize_recovery_code, otpauth_uri, verify};
use crate::request_context::ClientInfo;
use crate::sessions::{generate_token, hash_token, now_millis};
use crate::state::{LoginThrottle, WebState};

pub const MFA_REQUIRED_ALL_FLAG: &str = "mfa_required_all";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecondFactor {
    Totp,
    Recovery { remaining: usize },
}

async fn check_second_factor(
    state: &WebState,
    user_id: &str,
    code: &str,
    allow_recovery: bool,
) -> Option<SecondFactor> {
    let digits: String = code.chars().filter(|ch| !ch.is_whitespace()).collect();
    if digits.len() == crate::mfa::DIGITS as usize && digits.chars().all(|ch| ch.is_ascii_digit()) {
        let secret = state.app.storage.load_mfa_secret(user_id).await.ok().flatten()?;
        let step = verify(&secret, &digits, now_millis())?;
        return state.app.storage.claim_mfa_step(user_id, step).await.ok()?.then_some(SecondFactor::Totp);
    }
    if !allow_recovery {
        return None;
    }
    let normalized = normalize_recovery_code(code);
    let mfa = state.app.storage.load_user_mfa(user_id).await.ok().flatten()?;
    let hash = mfa.recovery_hashes.iter().find(|hash| verify_password(&normalized, hash))?;
    state
        .app
        .storage
        .consume_recovery_code(user_id, hash)
        .await
        .ok()?
        .then_some(SecondFactor::Recovery { remaining: mfa.recovery_hashes.len().saturating_sub(1) })
}

fn hash_recovery_codes(codes: &[String]) -> Result<Vec<String>, String> {
    codes.iter().map(|code| hash_password(code)).collect()
}

pub async fn issue_login_challenge(state: &WebState, user: &WebUser) -> Response {
    let token = match generate_token() {
        Ok(token) => token,
        Err(error) => {
            log::error!("Failed to issue a DBX Web two-factor challenge: {error}");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "session_unavailable");
        }
    };
    state.mfa_challenges.lock().await.issue(hash_token(&token), user.id.clone(), std::time::Instant::now());
    (
        StatusCode::OK,
        [("cache-control", "no-store")],
        Json(serde_json::json!({ "ok": false, "mfa_required": true, "challenge": token })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct VerifyLoginRequest {
    pub challenge: String,
    pub code: String,
}

pub async fn verify_login(
    State(state): State<Arc<WebState>>,
    client: ClientInfo,
    Json(body): Json<VerifyLoginRequest>,
) -> Response {
    if state.password_disabled {
        return error_response(StatusCode::FORBIDDEN, "login_not_required");
    }
    let key = hash_token(body.challenge.trim());
    let now = std::time::Instant::now();
    let Some(challenge) = state.mfa_challenges.lock().await.get(&key, now) else {
        return error_response(StatusCode::UNAUTHORIZED, "mfa_challenge_expired");
    };
    let user = match state.app.storage.find_web_user(&challenge.user_id).await {
        Ok(Some(user)) if user.active && user.mfa_enabled => user,
        _ => {
            state.mfa_challenges.lock().await.remove(&key);
            return error_response(StatusCode::UNAUTHORIZED, "mfa_challenge_expired");
        }
    };
    let user_key = LoginThrottle::user_key(&user.username);
    let ip_key = LoginThrottle::ip_key(client.ip);
    let locked = {
        let throttle = state.login_throttle.lock().await;
        throttle.locked_for(&user_key, now).max(throttle.locked_for(&ip_key, now))
    };
    if let Some(remaining) = locked {
        return rate_limited(remaining);
    }
    let Some(factor) = check_second_factor(&state, &user.id, &body.code, true).await else {
        {
            let mut throttle = state.login_throttle.lock().await;
            throttle.record_failure(&user_key, now);
            throttle.record_failure(&ip_key, now);
        }
        state.mfa_challenges.lock().await.record_failure(&key);
        audit_auth_failure(&state, "login_failed", &user.username, &client, "mfa_invalid");
        return error_response(StatusCode::UNAUTHORIZED, "mfa_code_invalid");
    };
    state.mfa_challenges.lock().await.remove(&key);
    {
        let mut throttle = state.login_throttle.lock().await;
        throttle.clear(&user_key);
        throttle.clear(&ip_key);
    }
    if let SecondFactor::Recovery { remaining } = factor {
        state.app.audit.record(
            dbx_core::audit::AuditEvent::new("mfa_recovery_code_used")
                .by_user(&user.id, &user.username)
                .ip(client.ip_string().as_deref())
                .detail(serde_json::json!({ "remaining": remaining })),
        );
    }
    start_session(&state, &user, &client, "login_succeeded", true).await
}

async fn current_user(state: &WebState, session: &CurrentUser) -> Result<WebUser, Box<Response>> {
    match state.app.storage.find_web_user(&session.0.user_id).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) => Err(Box::new(error_response(StatusCode::UNAUTHORIZED, SESSION_EXPIRED))),
        Err(error) => {
            log::error!("Failed to load a DBX Web user: {error}");
            Err(Box::new(error_response(StatusCode::INTERNAL_SERVER_ERROR, "mfa_failed")))
        }
    }
}

fn storage_failure(error: String) -> Response {
    log::error!("DBX Web two-factor operation failed: {error}");
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "mfa_failed")
}

pub async fn status(State(state): State<Arc<WebState>>, session: CurrentUser) -> Response {
    let user = match current_user(&state, &session).await {
        Ok(user) => user,
        Err(response) => return *response,
    };
    let mfa = match state.app.storage.load_user_mfa(&user.id).await {
        Ok(mfa) => mfa,
        Err(error) => return storage_failure(error),
    };
    Json(serde_json::json!({
        "enabled": user.mfa_enabled,
        "required": user.mfa_required,
        "setup_required": user.mfa_required && !user.mfa_enabled,
        "recovery_codes_left": mfa.filter(|mfa| mfa.enabled).map_or(0, |mfa| mfa.recovery_hashes.len()),
    }))
    .into_response()
}

pub async fn setup(State(state): State<Arc<WebState>>, session: CurrentUser) -> Response {
    let user = match current_user(&state, &session).await {
        Ok(user) => user,
        Err(response) => return *response,
    };
    if user.mfa_enabled {
        return error_response(StatusCode::CONFLICT, "mfa_already_enabled");
    }
    let secret = match generate_secret() {
        Ok(secret) => secret,
        Err(error) => return storage_failure(error),
    };
    if let Err(error) = state.app.storage.save_pending_mfa_secret(&user.id, &secret).await {
        return storage_failure(error);
    }
    (
        StatusCode::OK,
        [("cache-control", "no-store")],
        Json(serde_json::json!({ "secret": secret, "otpauth_uri": otpauth_uri(&user.username, &secret) })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct CodeRequest {
    pub code: String,
}

pub async fn confirm(
    State(state): State<Arc<WebState>>,
    session: CurrentUser,
    Json(body): Json<CodeRequest>,
) -> Response {
    let user = match current_user(&state, &session).await {
        Ok(user) => user,
        Err(response) => return *response,
    };
    if user.mfa_enabled {
        return error_response(StatusCode::CONFLICT, "mfa_already_enabled");
    }
    let secret = match state.app.storage.load_pending_mfa_secret(&user.id).await {
        Ok(Some(secret)) => secret,
        Ok(None) => return error_response(StatusCode::CONFLICT, "mfa_setup_not_started"),
        Err(error) => return storage_failure(error),
    };
    let user_key = LoginThrottle::user_key(&user.username);
    let now = std::time::Instant::now();
    if let Some(remaining) = state.login_throttle.lock().await.locked_for(&user_key, now) {
        return rate_limited(remaining);
    }
    let Some(step) = verify(&secret, &body.code, now_millis()) else {
        state.login_throttle.lock().await.record_failure(&user_key, now);
        return error_response(StatusCode::BAD_REQUEST, "mfa_code_invalid");
    };
    let codes = match generate_recovery_codes() {
        Ok(codes) => codes,
        Err(error) => return storage_failure(error),
    };
    let hashes = match hash_recovery_codes(&codes) {
        Ok(hashes) => hashes,
        Err(error) => return storage_failure(error),
    };
    if let Err(error) = state.app.storage.activate_mfa(&user.id, hashes, step, now_millis()).await {
        return storage_failure(error);
    }
    if let Err(error) = state.app.storage.mark_web_session_mfa_verified(&session.0.token_hash).await {
        log::warn!("Failed to mark the DBX Web session as two-factor verified: {error}");
    }
    state.login_throttle.lock().await.clear(&user_key);
    state.session_manager.forget_user(&user.id).await;
    record_action(&state, &session.0, "mfa_enabled", serde_json::json!({ "user_id": user.id }));
    (StatusCode::OK, [("cache-control", "no-store")], Json(serde_json::json!({ "recovery_codes": codes })))
        .into_response()
}

#[derive(Deserialize)]
pub struct DisableRequest {
    pub password: String,
    pub code: String,
}

pub async fn disable(
    State(state): State<Arc<WebState>>,
    session: CurrentUser,
    Json(body): Json<DisableRequest>,
) -> Response {
    let user = match current_user(&state, &session).await {
        Ok(user) => user,
        Err(response) => return *response,
    };
    if !user.mfa_enabled {
        return error_response(StatusCode::CONFLICT, "mfa_not_enabled");
    }
    if user.mfa_required {
        return error_response(StatusCode::CONFLICT, "mfa_required_by_policy");
    }
    let user_key = LoginThrottle::user_key(&user.username);
    let now = std::time::Instant::now();
    if let Some(remaining) = state.login_throttle.lock().await.locked_for(&user_key, now) {
        return rate_limited(remaining);
    }
    if !verify_password(&body.password, &user.password_hash)
        || check_second_factor(&state, &user.id, &body.code, true).await.is_none()
    {
        state.login_throttle.lock().await.record_failure(&user_key, now);
        return error_response(StatusCode::UNAUTHORIZED, "mfa_code_invalid");
    }
    if let Err(error) = state.app.storage.disable_mfa(&user.id, now_millis()).await {
        return storage_failure(error);
    }
    state.login_throttle.lock().await.clear(&user_key);
    state.session_manager.forget_user(&user.id).await;
    record_action(&state, &session.0, "mfa_disabled", serde_json::json!({ "user_id": user.id }));
    Json(serde_json::json!({ "ok": true })).into_response()
}

pub async fn regenerate_recovery_codes(
    State(state): State<Arc<WebState>>,
    session: CurrentUser,
    Json(body): Json<CodeRequest>,
) -> Response {
    let user = match current_user(&state, &session).await {
        Ok(user) => user,
        Err(response) => return *response,
    };
    if !user.mfa_enabled {
        return error_response(StatusCode::CONFLICT, "mfa_not_enabled");
    }
    let user_key = LoginThrottle::user_key(&user.username);
    let now = std::time::Instant::now();
    if let Some(remaining) = state.login_throttle.lock().await.locked_for(&user_key, now) {
        return rate_limited(remaining);
    }
    if check_second_factor(&state, &user.id, &body.code, false).await != Some(SecondFactor::Totp) {
        state.login_throttle.lock().await.record_failure(&user_key, now);
        return error_response(StatusCode::UNAUTHORIZED, "mfa_code_invalid");
    }
    let codes = match generate_recovery_codes() {
        Ok(codes) => codes,
        Err(error) => return storage_failure(error),
    };
    let hashes = match hash_recovery_codes(&codes) {
        Ok(hashes) => hashes,
        Err(error) => return storage_failure(error),
    };
    if let Err(error) = state.app.storage.replace_recovery_codes(&user.id, hashes).await {
        return storage_failure(error);
    }
    record_action(&state, &session.0, "mfa_recovery_codes_regenerated", serde_json::json!({ "user_id": user.id }));
    (StatusCode::OK, [("cache-control", "no-store")], Json(serde_json::json!({ "recovery_codes": codes })))
        .into_response()
}
