use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dbx_authz::{PlatformRole, Principal};
use dbx_core::storage::USERNAME_TAKEN;
use serde::{Deserialize, Serialize};

use crate::captcha::CAPTCHA_TTL;
use crate::identity::{burn_verification, check_new_password, hash_password, normalize_username, verify_password};
use crate::request_context::{is_cross_site, ClientInfo};
use crate::route_policy::{self, RouteClass};
use crate::sessions::{hash_token, now_millis, SessionUser};
use crate::state::{LoginThrottle, WebState};

pub const SESSION_EXPIRED: &str = "session_expired";
pub const SETUP_REQUIRED: &str = "setup_required";
pub const PASSWORD_CHANGE_REQUIRED: &str = "password_change_required";
pub const INVALID_CREDENTIALS: &str = "invalid_credentials";
pub const CROSS_SITE_REQUEST: &str = "cross_site_request";
pub const ROUTE_NOT_CLASSIFIED: &str = "route_not_classified";
pub const ADMIN_REQUIRED: &str = "admin_required";

#[derive(Deserialize)]
pub struct LoginRequest {
    #[serde(default)]
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub captcha_id: Option<String>,
    #[serde(default)]
    pub captcha_code: Option<String>,
}

#[derive(Deserialize)]
pub struct SetupRequest {
    #[serde(default)]
    pub setup_token: String,
    #[serde(default)]
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, Default)]
pub struct CaptchaQuery {
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Serialize)]
pub struct CaptchaResponse {
    pub id: String,
    pub image: String,
    pub expires_in: u64,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuthUserView {
    pub id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub role: PlatformRole,
    pub must_change_password: bool,
}

impl From<&SessionUser> for AuthUserView {
    fn from(user: &SessionUser) -> Self {
        Self {
            id: user.user_id.clone(),
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            role: user.role,
            must_change_password: user.must_change_password,
        }
    }
}

#[derive(Serialize)]
pub struct AuthCheckResponse {
    pub authenticated: bool,
    pub required: bool,
    pub setup_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<AuthUserView>,
}

pub(crate) fn error_response(status: StatusCode, code: &str) -> Response {
    (status, [("cache-control", "no-store")], Json(serde_json::json!({ "error": code }))).into_response()
}

fn rate_limited(wait: std::time::Duration) -> Response {
    let remaining = wait.as_secs().max(1);
    error_response(StatusCode::TOO_MANY_REQUESTS, &format!("Please try again in {remaining}s"))
}

fn session_cookie_path(state: &WebState) -> &str {
    state.public_base_path.as_str()
}

fn cookie_secure_enabled() -> bool {
    static SECURE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SECURE.get_or_init(|| matches!(std::env::var("DBX_WEB_COOKIE_SECURE").ok().as_deref(), Some("1") | Some("true")))
}

pub(crate) fn session_cookie(state: &WebState, token: &str) -> String {
    let secure = if cookie_secure_enabled() { "; Secure" } else { "" };
    format!("dbx_session={token}; Path={}; HttpOnly; SameSite=Lax{secure}", session_cookie_path(state))
}

fn cleared_session_cookie(state: &WebState) -> String {
    format!("dbx_session=; Path={}; HttpOnly; Max-Age=0", session_cookie_path(state))
}

fn api_path_suffix<'a>(path: &'a str, public_base_path: &str) -> Option<&'a str> {
    if let Some(suffix) = path.strip_prefix("/api/") {
        return Some(suffix);
    }
    let base = public_base_path.trim_end_matches('/');
    if base.is_empty() || base == "/" {
        return None;
    }
    path.strip_prefix(base)?.strip_prefix("/api/")
}

pub(crate) fn middleware_api_path_suffix<'a>(path: &'a str, public_base_path: &str) -> Option<&'a str> {
    if let Some(suffix) = api_path_suffix(path, public_base_path) {
        return Some(suffix);
    }

    let base = public_base_path.trim_end_matches('/');
    if !base.is_empty() && base != "/" && path.strip_prefix(base).is_some() {
        return None;
    }

    path.strip_prefix('/').filter(|suffix| !suffix.is_empty())
}

pub fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get("cookie")?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix("dbx_session=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

async fn forget_live_session(state: &WebState, token: &str) {
    state.app.authz.forget_owner(token);
    let removed = {
        let mut sessions = state.sessions.write().await;
        let removed = sessions.remove(token);
        if removed {
            dbx_core::query::pl_debug::pl_debug_revoke_web_owner_core(&state.app, token);
        }
        removed
    };
    if removed {
        state.app.session_credentials.clear_owner(token);
    }
}

pub(crate) async fn forget_live_sessions_by_hash(state: &WebState, token_hashes: &[String]) {
    if token_hashes.is_empty() {
        return;
    }
    let tokens: Vec<String> =
        state.sessions.read().await.iter().filter(|token| token_hashes.contains(&hash_token(token))).cloned().collect();
    for token in tokens {
        forget_live_session(state, &token).await;
    }
}

async fn start_session(state: &WebState, user: &dbx_core::storage::WebUser, client: &ClientInfo) -> Response {
    let now = now_millis();
    let created = state
        .session_manager
        .create(&state.app.storage, user, client.ip_string(), client.user_agent.clone(), now)
        .await;
    let (token, session_user) = match created {
        Ok(created) => created,
        Err(error) => {
            log::error!("Failed to create a DBX Web session: {error}");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "session_unavailable");
        }
    };
    if let Err(error) = state.app.storage.record_web_user_login(&user.id, now).await {
        log::warn!("Failed to record the last login of '{}': {error}", user.username);
    }
    state.sessions.write().await.insert(token.clone());
    let cookie = session_cookie(state, &token);
    let view = AuthUserView::from(&session_user);
    (
        StatusCode::OK,
        [("set-cookie", cookie.as_str()), ("cache-control", "no-store")],
        Json(serde_json::json!({ "ok": true, "must_change_password": view.must_change_password, "user": view })),
    )
        .into_response()
}

pub async fn captcha(
    State(state): State<Arc<WebState>>,
    client: ClientInfo,
    Query(query): Query<CaptchaQuery>,
) -> Response {
    let failed_attempts = {
        let throttle = state.login_throttle.lock().await;
        let by_user = query.username.as_deref().map_or(0, |name| throttle.failures(&LoginThrottle::user_key(name)));
        throttle.failures(&LoginThrottle::ip_key(client.ip)).max(by_user)
    };
    let mode = *state.captcha_mode.read().await;
    if !mode.requires_challenge(failed_attempts) {
        return StatusCode::NO_CONTENT.into_response();
    }
    let (id, png) = state.captchas.issue();
    let image = format!("data:image/png;base64,{}", BASE64.encode(&png));
    (
        StatusCode::OK,
        [("cache-control", "no-store")],
        Json(CaptchaResponse { id, image, expires_in: CAPTCHA_TTL.as_secs() }),
    )
        .into_response()
}

pub async fn login(State(state): State<Arc<WebState>>, client: ClientInfo, Json(body): Json<LoginRequest>) -> Response {
    if state.password_disabled {
        return error_response(StatusCode::FORBIDDEN, "login_not_required");
    }
    if !state.users_configured() {
        return error_response(StatusCode::FORBIDDEN, SETUP_REQUIRED);
    }

    let ip_key = LoginThrottle::ip_key(client.ip);
    let user_key = LoginThrottle::user_key(&body.username);
    let (failed_attempts, locked_for) = {
        let throttle = state.login_throttle.lock().await;
        let now = std::time::Instant::now();
        let failed = throttle.failures(&ip_key).max(throttle.failures(&user_key));
        let locked = throttle.locked_for(&ip_key, now).max(throttle.locked_for(&user_key, now));
        (failed, locked)
    };

    if state.captcha_mode.read().await.requires_challenge(failed_attempts) {
        let captcha_ok = state
            .captchas
            .verify(body.captcha_id.as_deref().unwrap_or_default(), body.captcha_code.as_deref().unwrap_or_default());
        if !captcha_ok {
            return error_response(StatusCode::BAD_REQUEST, "captcha_invalid");
        }
    }

    if let Some(remaining) = locked_for {
        return rate_limited(remaining);
    }

    let user = match normalize_username(&body.username) {
        Ok(username) => state.app.storage.find_web_user_by_username(&username).await.unwrap_or_else(|error| {
            log::error!("Failed to look up a DBX Web user: {error}");
            None
        }),
        Err(_) => None,
    };
    let authenticated = match &user {
        Some(user) => verify_password(&body.password, &user.password_hash) && user.active,
        None => {
            burn_verification(&body.password);
            false
        }
    };

    let mut throttle = state.login_throttle.lock().await;
    if !authenticated {
        let now = std::time::Instant::now();
        throttle.record_failure(&ip_key, now);
        throttle.record_failure(&user_key, now);
        return error_response(StatusCode::UNAUTHORIZED, INVALID_CREDENTIALS);
    }
    throttle.clear(&ip_key);
    throttle.clear(&user_key);
    drop(throttle);

    let Some(user) = user else {
        return error_response(StatusCode::UNAUTHORIZED, INVALID_CREDENTIALS);
    };
    start_session(&state, &user, &client).await
}

pub async fn setup(State(state): State<Arc<WebState>>, client: ClientInfo, Json(body): Json<SetupRequest>) -> Response {
    static SETUP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    if state.password_disabled || state.users_configured() {
        return error_response(StatusCode::FORBIDDEN, "setup_not_available");
    }
    let ip_key = LoginThrottle::ip_key(client.ip);
    if let Some(remaining) = state.login_throttle.lock().await.locked_for(&ip_key, std::time::Instant::now()) {
        return rate_limited(remaining);
    }
    if !state.setup_token.verify(body.setup_token.trim()) {
        state.login_throttle.lock().await.record_failure(&ip_key, std::time::Instant::now());
        return error_response(StatusCode::FORBIDDEN, "setup_token_invalid");
    }
    let username = match normalize_username(&body.username) {
        Ok(username) => username,
        Err(code) => return error_response(StatusCode::BAD_REQUEST, code),
    };
    if let Err(code) = check_new_password(&body.password) {
        return error_response(StatusCode::BAD_REQUEST, code);
    }
    let password_hash = match hash_password(&body.password) {
        Ok(hash) => hash,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "setup_failed"),
    };

    let _guard = SETUP_LOCK.lock().await;
    match state.app.storage.count_web_users().await {
        Ok(0) => {}
        Ok(_) => return error_response(StatusCode::FORBIDDEN, "setup_not_available"),
        Err(error) => {
            log::error!("Failed to inspect DBX Web users during setup: {error}");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "setup_failed");
        }
    }
    let created = state
        .app
        .storage
        .create_web_user(
            dbx_core::storage::NewWebUser {
                username,
                display_name: None,
                password_hash,
                role: PlatformRole::Admin,
                must_change_password: false,
            },
            now_millis(),
        )
        .await;
    let user = match created {
        Ok(user) => user,
        Err(error) if error == USERNAME_TAKEN => return error_response(StatusCode::FORBIDDEN, "setup_not_available"),
        Err(error) => {
            log::error!("Failed to create the first DBX Web administrator: {error}");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "setup_failed");
        }
    };
    state.users_configured.store(true, std::sync::atomic::Ordering::Release);
    state.setup_token.clear();
    log::info!("Created the first DBX Web administrator '{}'", user.username);

    if state.migration_ready.load(std::sync::atomic::Ordering::Acquire) {
        if let Err(error) = state.web_mcp.reload(&state.app.storage, true).await {
            log::error!("Web MCP remained disabled after the first administrator was created: {error}");
        }
    }
    start_session(&state, &user, &client).await
}

pub async fn check(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Json<AuthCheckResponse> {
    if state.password_disabled {
        return Json(AuthCheckResponse { authenticated: true, required: false, setup_required: false, user: None });
    }
    if !state.users_configured() {
        state.setup_token.ensure_issued();
        return Json(AuthCheckResponse { authenticated: false, required: false, setup_required: true, user: None });
    }
    let user = match session_token_from_headers(&headers) {
        Some(token) => state.session_manager.validate(&state.app.storage, &token, now_millis()).await,
        None => None,
    };
    Json(AuthCheckResponse {
        authenticated: user.is_some(),
        required: true,
        setup_required: false,
        user: user.as_ref().map(AuthUserView::from),
    })
}

pub async fn change_password(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> Response {
    let Some(token) = session_token_from_headers(&headers) else {
        return error_response(StatusCode::UNAUTHORIZED, SESSION_EXPIRED);
    };
    let Some(session_user) = state.session_manager.validate(&state.app.storage, &token, now_millis()).await else {
        return error_response(StatusCode::UNAUTHORIZED, SESSION_EXPIRED);
    };
    let user_key = LoginThrottle::user_key(&session_user.username);
    if let Some(remaining) = state.login_throttle.lock().await.locked_for(&user_key, std::time::Instant::now()) {
        return rate_limited(remaining);
    }
    let user = match state.app.storage.find_web_user(&session_user.user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return error_response(StatusCode::UNAUTHORIZED, SESSION_EXPIRED),
        Err(error) => {
            log::error!("Failed to load a DBX Web user: {error}");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "change_password_failed");
        }
    };
    if !verify_password(&body.old_password, &user.password_hash) {
        state.login_throttle.lock().await.record_failure(&user_key, std::time::Instant::now());
        return error_response(StatusCode::UNAUTHORIZED, "old_password_invalid");
    }
    if let Err(code) = check_new_password(&body.new_password) {
        return error_response(StatusCode::BAD_REQUEST, code);
    }
    if body.new_password == body.old_password {
        return error_response(StatusCode::BAD_REQUEST, "password_unchanged");
    }
    let now = now_millis();
    let updated = match hash_password(&body.new_password) {
        Ok(hash) => state.app.storage.set_web_user_password(&user.id, &hash, false, now).await,
        Err(error) => Err(error),
    };
    if let Err(error) = updated {
        log::error!("Failed to change the password of '{}': {error}", user.username);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "change_password_failed");
    }
    state.login_throttle.lock().await.clear(&user_key);

    let revoked = state
        .session_manager
        .revoke_user(&state.app.storage, &user.id, Some(&session_user.token_hash), now)
        .await
        .unwrap_or_else(|error| {
            log::error!("Failed to revoke the other sessions of '{}': {error}", user.username);
            Vec::new()
        });
    forget_live_sessions_by_hash(&state, &revoked).await;

    (StatusCode::OK, Json(serde_json::json!({ "ok": true }))).into_response()
}

pub async fn logout(State(state): State<Arc<WebState>>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token_from_headers(&headers) {
        if !state.password_disabled {
            if let Err(error) = state.session_manager.revoke(&state.app.storage, &token, now_millis()).await {
                log::warn!("Failed to revoke a DBX Web session: {error}");
            }
        }
        forget_live_session(&state, &token).await;
    }
    let cookie = cleared_session_cookie(&state);
    (StatusCode::OK, [("set-cookie", cookie.as_str())], Json(serde_json::json!({ "ok": true }))).into_response()
}

fn allowed_while_password_change_required(suffix: &str) -> bool {
    matches!(suffix, "auth/change-password" | "auth/logout")
}

pub async fn auth_middleware(
    State(state): State<Arc<WebState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(suffix) = middleware_api_path_suffix(req.uri().path(), &state.public_base_path).map(str::to_string) else {
        return next.run(req).await;
    };

    if is_cross_site(req.method(), req.headers(), &state.trusted_origins) {
        return error_response(StatusCode::FORBIDDEN, CROSS_SITE_REQUEST);
    }

    let Some(route_class) = route_policy::classify(req.method(), &suffix) else {
        log::warn!("Rejected {} /api/{suffix}: the route has no access policy", req.method());
        return error_response(StatusCode::FORBIDDEN, ROUTE_NOT_CLASSIFIED);
    };

    if route_class == RouteClass::Public {
        return next.run(req).await;
    }

    if state.password_disabled {
        req.extensions_mut().insert(Principal::Local);
        return next.run(req).await;
    }

    if !state.users_configured() {
        return error_response(StatusCode::UNAUTHORIZED, SETUP_REQUIRED);
    }

    let Some(token) = session_token_from_headers(req.headers()) else {
        return error_response(StatusCode::UNAUTHORIZED, SESSION_EXPIRED);
    };
    let Some(user) = state.session_manager.validate(&state.app.storage, &token, now_millis()).await else {
        forget_live_session(&state, &token).await;
        return error_response(StatusCode::UNAUTHORIZED, SESSION_EXPIRED);
    };
    if user.must_change_password && !allowed_while_password_change_required(&suffix) {
        return error_response(StatusCode::FORBIDDEN, PASSWORD_CHANGE_REQUIRED);
    }
    if route_class == RouteClass::Admin && user.role != PlatformRole::Admin {
        return error_response(StatusCode::FORBIDDEN, ADMIN_REQUIRED);
    }

    if !state.sessions.read().await.contains(&token) {
        state.sessions.write().await.insert(token.clone());
    }
    let principal = Principal::User { user_id: user.user_id.clone(), groups: Vec::new(), role: user.role };
    state.app.authz.register_owner(&token, principal.clone());
    req.extensions_mut().insert(principal);
    req.extensions_mut().insert(user);
    let owner = token;
    dbx_core::session_credentials::with_credential_owner(Some(owner), async move { next.run(req).await }).await
}

pub struct CurrentUser(pub SessionUser);

pub struct MaybeUser(pub Option<SessionUser>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for MaybeUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut axum::http::request::Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(MaybeUser(parts.extensions.get::<SessionUser>().cloned()))
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for CurrentUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut axum::http::request::Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<SessionUser>()
            .cloned()
            .map(CurrentUser)
            .ok_or_else(|| error_response(StatusCode::UNAUTHORIZED, SESSION_EXPIRED))
    }
}

#[cfg(test)]
pub(crate) mod test_sessions {
    use dbx_authz::PlatformRole;
    use dbx_core::storage::{NewWebUser, WebSession};

    use crate::sessions::{hash_token, now_millis};
    use crate::state::WebState;

    pub(crate) const TEST_USERNAME: &str = "tester";

    pub(crate) async fn ensure_user(state: &WebState, password: &str) -> String {
        state.users_configured.store(true, std::sync::atomic::Ordering::Release);
        let storage = &state.app.storage;
        if let Some(user) = storage.find_web_user_by_username(TEST_USERNAME).await.unwrap() {
            return user.id;
        }
        storage
            .create_web_user(
                NewWebUser {
                    username: TEST_USERNAME.into(),
                    display_name: None,
                    password_hash: crate::identity::hash_password(password).unwrap(),
                    role: PlatformRole::Admin,
                    must_change_password: false,
                },
                now_millis(),
            )
            .await
            .unwrap()
            .id
    }

    pub(crate) async fn issue(state: &WebState, token: &str) {
        issue_with_password(state, token, "test-password").await;
    }

    pub(crate) async fn issue_with_password(state: &WebState, token: &str, password: &str) {
        let user_id = ensure_user(state, password).await;
        let now = now_millis();
        state
            .app
            .storage
            .insert_web_session(WebSession {
                token_hash: hash_token(token),
                user_id,
                created_at: now,
                last_seen_at: now,
                expires_at: None,
                revoked_at: None,
                ip: None,
                user_agent: None,
                mfa_verified: false,
            })
            .await
            .unwrap();
        state.sessions.write().await.insert(token.to_string());
    }
}

#[cfg(test)]
mod http_tests;

#[cfg(test)]
mod tests {
    use super::{api_path_suffix, middleware_api_path_suffix};

    #[test]
    fn api_path_suffix_handles_root_api_paths() {
        assert_eq!(api_path_suffix("/api/auth/check", "/"), Some("auth/check"));
        assert_eq!(api_path_suffix("/api/query/execute", "/"), Some("query/execute"));
        assert_eq!(api_path_suffix("/dbx/api/auth/check", "/"), None);
    }

    #[test]
    fn api_path_suffix_handles_mounted_api_paths() {
        assert_eq!(api_path_suffix("/dbx/api/auth/check", "/dbx"), Some("auth/check"));
        assert_eq!(api_path_suffix("/tools/dbx/api/query/execute", "/tools/dbx"), Some("query/execute"));
        assert_eq!(api_path_suffix("/dbx/login", "/dbx"), None);
    }

    #[test]
    pub(crate) fn middleware_api_path_suffix_handles_nested_router_paths() {
        assert_eq!(middleware_api_path_suffix("/auth/check", "/"), Some("auth/check"));
        assert_eq!(middleware_api_path_suffix("/connection/list", "/"), Some("connection/list"));
        assert_eq!(middleware_api_path_suffix("/api/connection/list", "/"), Some("connection/list"));
        assert_eq!(middleware_api_path_suffix("/dbx/api/connection/list", "/dbx"), Some("connection/list"));
        assert_eq!(middleware_api_path_suffix("/dbx/login", "/dbx"), None);
    }
}
