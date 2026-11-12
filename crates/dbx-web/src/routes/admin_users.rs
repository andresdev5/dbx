use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dbx_authz::PlatformRole;
use dbx_core::storage::{NewWebUser, WebUser, LAST_ADMIN, USERNAME_TAKEN, USER_NOT_FOUND};
use serde::{Deserialize, Serialize};

use crate::auth::{error_response, forget_live_sessions_by_hash, CurrentUser};
use crate::identity::{check_new_password, hash_password, normalize_username};
use crate::sessions::now_millis;
use crate::state::WebState;

const MAX_DISPLAY_NAME_CHARS: usize = 120;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct UserSummary {
    pub id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub role: PlatformRole,
    pub active: bool,
    pub must_change_password: bool,
    pub last_login_at: Option<i64>,
    pub created_at: i64,
}

impl From<WebUser> for UserSummary {
    fn from(user: WebUser) -> Self {
        Self {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            role: user.role,
            active: user.active,
            must_change_password: user.must_change_password,
            last_login_at: user.last_login_at,
            created_at: user.created_at,
        }
    }
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub role: PlatformRole,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub must_change_password: Option<bool>,
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub role: PlatformRole,
}

#[derive(Deserialize)]
pub struct SetActiveRequest {
    pub id: String,
    pub active: bool,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub id: String,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct UserIdRequest {
    pub id: String,
}

#[derive(Serialize)]
struct PasswordIssued {
    user: UserSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    temporary_password: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminError {
    status: StatusCode,
    code: &'static str,
}

impl AdminError {
    const fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code }
    }

    fn storage(error: String) -> Self {
        match error.as_str() {
            USER_NOT_FOUND => Self::new(StatusCode::NOT_FOUND, "user_not_found"),
            LAST_ADMIN => Self::new(StatusCode::CONFLICT, "last_admin"),
            USERNAME_TAKEN => Self::new(StatusCode::CONFLICT, "username_taken"),
            _ => {
                log::error!("DBX Web user administration failed: {error}");
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "user_admin_failed")
            }
        }
    }
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        error_response(self.status, self.code)
    }
}

type AdminResult = Result<Response, AdminError>;

fn normalize_display_name(value: Option<String>) -> Result<Option<String>, AdminError> {
    let Some(value) = value.map(|value| value.trim().to_string()).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > MAX_DISPLAY_NAME_CHARS || value.chars().any(char::is_control) {
        return Err(AdminError::new(StatusCode::BAD_REQUEST, "display_name_invalid"));
    }
    Ok(Some(value))
}

fn chosen_or_temporary_password(password: Option<String>) -> Result<(String, Option<String>), AdminError> {
    if let Some(password) = password.filter(|password| !password.is_empty()) {
        check_new_password(&password).map_err(|code| AdminError::new(StatusCode::BAD_REQUEST, code))?;
        return Ok((password, None));
    }
    let mut bytes = [0u8; 12];
    getrandom::fill(&mut bytes).map_err(|_| AdminError::new(StatusCode::INTERNAL_SERVER_ERROR, "user_admin_failed"))?;
    let temporary = URL_SAFE_NO_PAD.encode(bytes);
    Ok((temporary.clone(), Some(temporary)))
}

fn reject_self(current: &CurrentUser, id: &str) -> Result<(), AdminError> {
    if current.0.user_id == id {
        return Err(AdminError::new(StatusCode::CONFLICT, "self_modification_not_allowed"));
    }
    Ok(())
}

async fn load_summary(state: &WebState, id: &str) -> Result<UserSummary, AdminError> {
    match state.app.storage.find_web_user(id).await.map_err(AdminError::storage)? {
        Some(user) => Ok(user.into()),
        None => Err(AdminError::storage(USER_NOT_FOUND.to_string())),
    }
}

async fn end_all_sessions(state: &WebState, user_id: &str) {
    match state.session_manager.revoke_user(&state.app.storage, user_id, None, now_millis()).await {
        Ok(revoked) => forget_live_sessions_by_hash(state, &revoked).await,
        Err(error) => log::error!("Failed to revoke the sessions of user {user_id}: {error}"),
    }
}

pub async fn list(State(state): State<Arc<WebState>>, _admin: CurrentUser) -> AdminResult {
    let users = state.app.storage.list_web_users().await.map_err(AdminError::storage)?;
    Ok(Json(users.into_iter().map(UserSummary::from).collect::<Vec<_>>()).into_response())
}

pub async fn create(
    State(state): State<Arc<WebState>>,
    _admin: CurrentUser,
    Json(body): Json<CreateUserRequest>,
) -> AdminResult {
    let username = normalize_username(&body.username).map_err(|code| AdminError::new(StatusCode::BAD_REQUEST, code))?;
    let display_name = normalize_display_name(body.display_name)?;
    let (password, temporary_password) = chosen_or_temporary_password(body.password)?;
    let password_hash = hash_password(&password).map_err(AdminError::storage)?;
    let must_change_password = temporary_password.is_some() || body.must_change_password.unwrap_or(true);
    let user = state
        .app
        .storage
        .create_web_user(
            NewWebUser { username, display_name, password_hash, role: body.role, must_change_password },
            now_millis(),
        )
        .await
        .map_err(AdminError::storage)?;
    log::info!("Created DBX Web user '{}' ({})", user.username, user.role.as_str());
    Ok((StatusCode::CREATED, Json(PasswordIssued { user: user.into(), temporary_password })).into_response())
}

pub async fn update(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<UpdateUserRequest>,
) -> AdminResult {
    let display_name = normalize_display_name(body.display_name)?;
    if admin.0.user_id == body.id && body.role != admin.0.role {
        return Err(AdminError::new(StatusCode::CONFLICT, "self_modification_not_allowed"));
    }
    state
        .app
        .storage
        .update_web_user_profile(&body.id, display_name, body.role, now_millis())
        .await
        .map_err(AdminError::storage)?;
    state.session_manager.forget_user(&body.id).await;
    Ok(Json(load_summary(&state, &body.id).await?).into_response())
}

pub async fn set_active(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<SetActiveRequest>,
) -> AdminResult {
    reject_self(&admin, &body.id)?;
    state.app.storage.set_web_user_active(&body.id, body.active, now_millis()).await.map_err(AdminError::storage)?;
    if !body.active {
        end_all_sessions(&state, &body.id).await;
    }
    Ok(Json(load_summary(&state, &body.id).await?).into_response())
}

pub async fn reset_password(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<ResetPasswordRequest>,
) -> AdminResult {
    reject_self(&admin, &body.id)?;
    let (password, temporary_password) = chosen_or_temporary_password(body.password)?;
    let hash = hash_password(&password).map_err(AdminError::storage)?;
    state.app.storage.set_web_user_password(&body.id, &hash, true, now_millis()).await.map_err(AdminError::storage)?;
    end_all_sessions(&state, &body.id).await;
    let user = load_summary(&state, &body.id).await?;
    Ok(Json(PasswordIssued { user, temporary_password }).into_response())
}

pub async fn delete(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<UserIdRequest>,
) -> AdminResult {
    reject_self(&admin, &body.id)?;
    end_all_sessions(&state, &body.id).await;
    state.app.storage.delete_web_user(&body.id).await.map_err(AdminError::storage)?;
    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}
