use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use dbx_authz::{Effect, Operations, Principal, Resource, Scope, Subject};
use dbx_core::storage::{
    ConnectionAuthzPolicy, DataRole, StoredGrant, UserGroup, GRANT_INVALID, GRANT_NOT_FOUND, GROUP_NAME_TAKEN,
    GROUP_NOT_FOUND, ROLE_IN_USE, ROLE_NAME_TAKEN, ROLE_NOT_FOUND,
};
use serde::{Deserialize, Serialize};

use crate::audit_events::record_action;
use crate::auth::{error_response, CurrentUser};
use crate::sessions::now_millis;
use crate::state::WebState;

const MAX_NAME_CHARS: usize = 80;
const MAX_TEXT_CHARS: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessError {
    status: StatusCode,
    code: &'static str,
}

impl AccessError {
    const fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code }
    }

    fn storage(error: String) -> Self {
        match error.as_str() {
            GROUP_NAME_TAKEN => Self::new(StatusCode::CONFLICT, "group_name_taken"),
            GROUP_NOT_FOUND => Self::new(StatusCode::NOT_FOUND, "group_not_found"),
            ROLE_NAME_TAKEN => Self::new(StatusCode::CONFLICT, "role_name_taken"),
            ROLE_NOT_FOUND => Self::new(StatusCode::NOT_FOUND, "role_not_found"),
            ROLE_IN_USE => Self::new(StatusCode::CONFLICT, "role_in_use"),
            GRANT_NOT_FOUND => Self::new(StatusCode::NOT_FOUND, "grant_not_found"),
            GRANT_INVALID => Self::new(StatusCode::BAD_REQUEST, "grant_invalid"),
            _ => {
                log::error!("DBX Web access administration failed: {error}");
                Self::new(StatusCode::INTERNAL_SERVER_ERROR, "access_admin_failed")
            }
        }
    }
}

impl IntoResponse for AccessError {
    fn into_response(self) -> Response {
        error_response(self.status, self.code)
    }
}

type AccessResult = Result<Response, AccessError>;

fn operation_names(operations: Operations) -> Vec<&'static str> {
    operations.names()
}

fn parse_operations(names: &[String]) -> Result<Operations, AccessError> {
    names.iter().try_fold(Operations::empty(), |acc, name| {
        Operations::from_name(&name.trim().to_ascii_uppercase())
            .map(|operation| acc | operation)
            .ok_or(AccessError::new(StatusCode::BAD_REQUEST, "operation_invalid"))
    })
}

fn clean_name(value: &str, code: &'static str) -> Result<String, AccessError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > MAX_NAME_CHARS || value.chars().any(char::is_control) {
        return Err(AccessError::new(StatusCode::BAD_REQUEST, code));
    }
    Ok(value.to_string())
}

fn clean_text(value: Option<String>) -> Result<Option<String>, AccessError> {
    let Some(value) = value.map(|value| value.trim().to_string()).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > MAX_TEXT_CHARS {
        return Err(AccessError::new(StatusCode::BAD_REQUEST, "text_too_long"));
    }
    Ok(Some(value))
}

async fn reload(state: &WebState) -> Result<(), AccessError> {
    state.app.authz.reload(&state.app.storage).await.map_err(AccessError::storage)
}

#[derive(Serialize)]
struct GroupView {
    id: String,
    name: String,
    description: Option<String>,
    member_ids: Vec<String>,
    created_at: i64,
}

impl From<UserGroup> for GroupView {
    fn from(group: UserGroup) -> Self {
        Self {
            id: group.id,
            name: group.name,
            description: group.description,
            member_ids: group.member_ids,
            created_at: group.created_at,
        }
    }
}

#[derive(Deserialize)]
pub struct GroupRequest {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct GroupMembersRequest {
    pub id: String,
    pub user_ids: Vec<String>,
}

#[derive(Deserialize)]
pub struct IdRequest {
    pub id: String,
}

pub async fn list_groups(State(state): State<Arc<WebState>>, _admin: CurrentUser) -> AccessResult {
    let groups = state.app.storage.list_user_groups().await.map_err(AccessError::storage)?;
    Ok(Json(groups.into_iter().map(GroupView::from).collect::<Vec<_>>()).into_response())
}

pub async fn create_group(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<GroupRequest>,
) -> AccessResult {
    let name = clean_name(&body.name, "group_name_invalid")?;
    let description = clean_text(body.description)?;
    let group =
        state.app.storage.create_user_group(&name, description, now_millis()).await.map_err(AccessError::storage)?;
    record_action(&state, &admin.0, "group_created", serde_json::json!({ "group_id": group.id, "name": group.name }));
    Ok((StatusCode::CREATED, Json(GroupView::from(group))).into_response())
}

pub async fn update_group(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<GroupRequest>,
) -> AccessResult {
    let id = body.id.ok_or(AccessError::new(StatusCode::BAD_REQUEST, "group_not_found"))?;
    let name = clean_name(&body.name, "group_name_invalid")?;
    let description = clean_text(body.description)?;
    state.app.storage.update_user_group(&id, &name, description).await.map_err(AccessError::storage)?;
    record_action(&state, &admin.0, "group_updated", serde_json::json!({ "group_id": id, "name": name }));
    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

pub async fn set_group_members(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<GroupMembersRequest>,
) -> AccessResult {
    let detail = serde_json::json!({ "group_id": body.id, "user_ids": body.user_ids });
    state.app.storage.set_user_group_members(&body.id, body.user_ids).await.map_err(AccessError::storage)?;
    reload(&state).await?;
    record_action(&state, &admin.0, "group_members_set", detail);
    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

pub async fn delete_group(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<IdRequest>,
) -> AccessResult {
    state.app.storage.delete_user_group(&body.id).await.map_err(AccessError::storage)?;
    reload(&state).await?;
    record_action(&state, &admin.0, "group_deleted", serde_json::json!({ "group_id": body.id }));
    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

#[derive(Serialize)]
struct RoleView {
    id: String,
    name: String,
    operations: Vec<&'static str>,
    builtin: bool,
    description: Option<String>,
}

impl From<DataRole> for RoleView {
    fn from(role: DataRole) -> Self {
        Self {
            id: role.id,
            name: role.name,
            operations: operation_names(role.operations),
            builtin: role.builtin,
            description: role.description,
        }
    }
}

#[derive(Deserialize)]
pub struct RoleRequest {
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub operations: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

fn reject_builtin(id: &str) -> Result<(), AccessError> {
    if id.starts_with("builtin:") {
        return Err(AccessError::new(StatusCode::CONFLICT, "role_builtin"));
    }
    Ok(())
}

pub async fn list_roles(State(state): State<Arc<WebState>>, _admin: CurrentUser) -> AccessResult {
    let roles = state.app.storage.list_data_roles().await.map_err(AccessError::storage)?;
    Ok(Json(roles.into_iter().map(RoleView::from).collect::<Vec<_>>()).into_response())
}

pub async fn create_role(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<RoleRequest>,
) -> AccessResult {
    let name = clean_name(&body.name, "role_name_invalid")?;
    let operations = parse_operations(&body.operations)?;
    let description = clean_text(body.description)?;
    let role =
        state.app.storage.create_data_role(&name, operations, description).await.map_err(AccessError::storage)?;
    record_action(
        &state,
        &admin.0,
        "role_created",
        serde_json::json!({ "role_id": role.id, "name": role.name, "operations": operation_names(role.operations) }),
    );
    Ok((StatusCode::CREATED, Json(RoleView::from(role))).into_response())
}

pub async fn update_role(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<RoleRequest>,
) -> AccessResult {
    let id = body.id.ok_or(AccessError::new(StatusCode::BAD_REQUEST, "role_not_found"))?;
    reject_builtin(&id)?;
    let name = clean_name(&body.name, "role_name_invalid")?;
    let operations = parse_operations(&body.operations)?;
    let description = clean_text(body.description)?;
    state.app.storage.update_data_role(&id, &name, operations, description).await.map_err(AccessError::storage)?;
    reload(&state).await?;
    record_action(
        &state,
        &admin.0,
        "role_updated",
        serde_json::json!({ "role_id": id, "name": name, "operations": operation_names(operations) }),
    );
    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

pub async fn delete_role(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<IdRequest>,
) -> AccessResult {
    reject_builtin(&body.id)?;
    state.app.storage.delete_data_role(&body.id).await.map_err(AccessError::storage)?;
    record_action(&state, &admin.0, "role_deleted", serde_json::json!({ "role_id": body.id }));
    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

#[derive(Serialize)]
struct GrantView {
    id: String,
    subject: Subject,
    scope: Scope,
    effect: Effect,
    operations: Option<Vec<&'static str>>,
    role_id: Option<String>,
    expires_at: Option<i64>,
    note: Option<String>,
    created_by: Option<String>,
    created_at: i64,
}

impl From<StoredGrant> for GrantView {
    fn from(grant: StoredGrant) -> Self {
        Self {
            id: grant.id,
            subject: grant.subject,
            scope: grant.scope,
            effect: grant.effect,
            operations: grant.operations.map(operation_names),
            role_id: grant.role_id,
            expires_at: grant.expires_at,
            note: grant.note,
            created_by: grant.created_by,
            created_at: grant.created_at,
        }
    }
}

#[derive(Deserialize, Default)]
pub struct GrantFilter {
    #[serde(default)]
    pub subject: Option<Subject>,
    #[serde(default)]
    pub connection_id: Option<String>,
}

#[derive(Deserialize)]
pub struct GrantRequest {
    #[serde(default)]
    pub id: Option<String>,
    pub subject: Subject,
    pub scope: Scope,
    pub effect: Effect,
    #[serde(default)]
    pub operations: Option<Vec<String>>,
    #[serde(default)]
    pub role_id: Option<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub note: Option<String>,
}

fn grant_touches_connection(grant: &StoredGrant, connection_id: &str) -> bool {
    match &grant.scope {
        Scope::All | Scope::ConnectionGroup(_) => true,
        Scope::Resource(resource) => resource.connection_id == connection_id,
    }
}

pub async fn list_grants(
    State(state): State<Arc<WebState>>,
    _admin: CurrentUser,
    Json(filter): Json<GrantFilter>,
) -> AccessResult {
    let grants = state.app.storage.list_grants().await.map_err(AccessError::storage)?;
    let grants: Vec<GrantView> = grants
        .into_iter()
        .filter(|grant| filter.subject.as_ref().is_none_or(|subject| grant.subject == *subject))
        .filter(|grant| {
            filter.connection_id.as_deref().is_none_or(|connection| grant_touches_connection(grant, connection))
        })
        .map(GrantView::from)
        .collect();
    Ok(Json(grants).into_response())
}

async fn subject_exists(state: &WebState, subject: &Subject) -> Result<bool, AccessError> {
    match subject {
        Subject::System => Ok(true),
        Subject::User(id) => Ok(state.app.storage.find_web_user(id).await.map_err(AccessError::storage)?.is_some()),
        Subject::Group(id) => Ok(state
            .app
            .storage
            .list_user_groups()
            .await
            .map_err(AccessError::storage)?
            .iter()
            .any(|group| group.id == *id)),
    }
}

pub async fn save_grant(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<GrantRequest>,
) -> AccessResult {
    if !subject_exists(&state, &body.subject).await? {
        return Err(AccessError::new(StatusCode::NOT_FOUND, "subject_not_found"));
    }
    if let Scope::Resource(resource) = &body.scope {
        if !state.app.configs.read().await.contains_key(&resource.connection_id) {
            return Err(AccessError::new(StatusCode::NOT_FOUND, "connection_not_found"));
        }
    }
    let operations = body.operations.as_deref().map(parse_operations).transpose()?;
    if operations.is_some_and(|operations| operations.is_empty()) {
        return Err(AccessError::new(StatusCode::BAD_REQUEST, "grant_invalid"));
    }
    let existing_created_at = match &body.id {
        Some(id) => state
            .app
            .storage
            .list_grants()
            .await
            .map_err(AccessError::storage)?
            .into_iter()
            .find(|grant| grant.id == *id)
            .map(|grant| grant.created_at)
            .ok_or(AccessError::new(StatusCode::NOT_FOUND, "grant_not_found"))
            .map(Some)?,
        None => None,
    };
    let grant = StoredGrant {
        id: body.id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        subject: body.subject,
        scope: body.scope,
        effect: body.effect,
        operations,
        role_id: body.role_id.filter(|role| !role.trim().is_empty()),
        expires_at: body.expires_at,
        note: clean_text(body.note)?,
        created_by: Some(admin.0.user_id.clone()),
        created_at: existing_created_at.unwrap_or_else(now_millis),
    };
    let saved = state.app.storage.save_grant(grant).await.map_err(AccessError::storage)?;
    reload(&state).await?;
    let view = GrantView::from(saved);
    record_action(&state, &admin.0, "grant_saved", serde_json::to_value(&view).unwrap_or_default());
    Ok(Json(view).into_response())
}

pub async fn delete_grant(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<IdRequest>,
) -> AccessResult {
    let removed = state
        .app
        .storage
        .list_grants()
        .await
        .map_err(AccessError::storage)?
        .into_iter()
        .find(|grant| grant.id == body.id)
        .map(GrantView::from);
    state.app.storage.delete_grant(&body.id).await.map_err(AccessError::storage)?;
    reload(&state).await?;
    record_action(
        &state,
        &admin.0,
        "grant_deleted",
        removed
            .and_then(|view| serde_json::to_value(view).ok())
            .unwrap_or_else(|| serde_json::json!({ "id": body.id })),
    );
    Ok(Json(serde_json::json!({ "ok": true })).into_response())
}

#[derive(Deserialize)]
pub struct EffectiveRequest {
    pub user_id: String,
    pub connection_id: String,
}

#[derive(Serialize)]
struct EffectiveRule {
    grant_id: String,
    via_group: Option<String>,
    resource: Resource,
    effect: Effect,
    operations: Vec<&'static str>,
}

#[derive(Serialize)]
struct EffectiveView {
    visible: bool,
    implicit_admin: bool,
    connection_operations: Vec<&'static str>,
    rules: Vec<EffectiveRule>,
}

pub async fn effective(
    State(state): State<Arc<WebState>>,
    _admin: CurrentUser,
    Json(body): Json<EffectiveRequest>,
) -> AccessResult {
    let user = state
        .app
        .storage
        .find_web_user(&body.user_id)
        .await
        .map_err(AccessError::storage)?
        .ok_or(AccessError::new(StatusCode::NOT_FOUND, "user_not_found"))?;
    let config = state
        .app
        .configs
        .read()
        .await
        .get(&body.connection_id)
        .cloned()
        .ok_or(AccessError::new(StatusCode::NOT_FOUND, "connection_not_found"))?;
    let principal =
        state.app.authz.with_groups(&Principal::User { user_id: user.id.clone(), groups: Vec::new(), role: user.role });
    let permissions = state.app.authz.permissions(&principal, &config, false);
    let snapshot = state.app.authz.snapshot();
    let now = now_millis();
    let user_groups = match &principal {
        Principal::User { groups, .. } => groups.clone(),
        _ => Vec::new(),
    };
    let rules = snapshot
        .grants
        .iter()
        .filter(|grant| grant.is_active(now) && principal.is_subject(&grant.subject))
        .filter_map(|grant| {
            grant.pattern_for(&config.id, &[]).map(|resource| EffectiveRule {
                grant_id: grant.id.clone(),
                via_group: match &grant.subject {
                    Subject::Group(id) if user_groups.contains(id) => Some(id.clone()),
                    _ => None,
                },
                resource,
                effect: grant.effect,
                operations: operation_names(grant.operations),
            })
        })
        .collect();
    Ok(Json(EffectiveView {
        visible: user.active && permissions.is_visible(),
        implicit_admin: principal.is_admin(),
        connection_operations: operation_names(permissions.operations_at(&Resource::connection(config.id.clone()))),
        rules,
    })
    .into_response())
}

#[derive(Serialize, Deserialize)]
pub struct ConnectionPolicyView {
    pub connection_id: String,
    pub strict_function_mode: bool,
    #[serde(default)]
    pub function_allowlist: Vec<String>,
}

const MAX_ALLOWLIST_ENTRIES: usize = 500;

fn valid_function_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= 128
        && name.chars().all(|ch| ch.is_alphanumeric() || matches!(ch, '_' | '.' | '$'))
}

pub async fn list_connection_policies(State(state): State<Arc<WebState>>, _admin: CurrentUser) -> AccessResult {
    let policies = state.app.storage.list_connection_authz_policies().await.map_err(AccessError::storage)?;
    let views: Vec<ConnectionPolicyView> = policies
        .into_iter()
        .map(|policy| ConnectionPolicyView {
            connection_id: policy.connection_id,
            strict_function_mode: policy.strict_function_mode,
            function_allowlist: policy.function_allowlist,
        })
        .collect();
    Ok(Json(views).into_response())
}

pub async fn save_connection_policy(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<ConnectionPolicyView>,
) -> AccessResult {
    if !state.app.configs.read().await.contains_key(&body.connection_id) {
        return Err(AccessError::new(StatusCode::NOT_FOUND, "connection_not_found"));
    }
    let mut allowlist: Vec<String> =
        body.function_allowlist.iter().map(|name| name.trim().to_lowercase()).filter(|name| !name.is_empty()).collect();
    allowlist.sort();
    allowlist.dedup();
    if allowlist.len() > MAX_ALLOWLIST_ENTRIES || !allowlist.iter().all(|name| valid_function_name(name)) {
        return Err(AccessError::new(StatusCode::BAD_REQUEST, "function_allowlist_invalid"));
    }
    let policy = ConnectionAuthzPolicy {
        connection_id: body.connection_id.clone(),
        strict_function_mode: body.strict_function_mode,
        function_allowlist: allowlist.clone(),
    };
    state.app.storage.save_connection_authz_policy(policy).await.map_err(AccessError::storage)?;
    reload(&state).await?;
    record_action(
        &state,
        &admin.0,
        "connection_policy_saved",
        serde_json::json!({
            "connection_id": body.connection_id,
            "strict_function_mode": body.strict_function_mode,
            "function_allowlist": allowlist,
        }),
    );
    Ok(Json(ConnectionPolicyView {
        connection_id: body.connection_id,
        strict_function_mode: body.strict_function_mode,
        function_allowlist: allowlist,
    })
    .into_response())
}
