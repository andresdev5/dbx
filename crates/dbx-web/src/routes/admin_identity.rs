use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use dbx_core::storage::{
    IdentityProvider, IDENTITY_PROVIDER_IN_USE, IDENTITY_PROVIDER_NAME_TAKEN, IDENTITY_PROVIDER_NOT_FOUND,
};
use serde::{Deserialize, Serialize};

use crate::audit_events::record_action;
use crate::auth::{error_response, CurrentUser};
use crate::oidc::{discover, OidcConfig};
use crate::sessions::now_millis;
use crate::state::WebState;

const MAX_NAME_CHARS: usize = 80;
const MAX_SECRET_CHARS: usize = 4096;

#[derive(Serialize)]
struct ProviderView {
    id: String,
    kind: String,
    name: String,
    config: serde_json::Value,
    auto_create_users: bool,
    default_group_id: Option<String>,
    enabled: bool,
    has_secret: bool,
}

async fn view(state: &WebState, provider: IdentityProvider) -> ProviderView {
    let has_secret = state.app.storage.load_identity_provider_secret(&provider.id).await.ok().flatten().is_some();
    ProviderView {
        id: provider.id,
        kind: provider.kind,
        name: provider.name,
        config: provider.config,
        auto_create_users: provider.auto_create_users,
        default_group_id: provider.default_group_id,
        enabled: provider.enabled,
        has_secret,
    }
}

fn storage_error(error: String) -> Response {
    match error.as_str() {
        IDENTITY_PROVIDER_NAME_TAKEN => error_response(StatusCode::CONFLICT, "identity_provider_name_taken"),
        IDENTITY_PROVIDER_NOT_FOUND => error_response(StatusCode::NOT_FOUND, "identity_provider_not_found"),
        IDENTITY_PROVIDER_IN_USE => error_response(StatusCode::CONFLICT, "identity_provider_in_use"),
        _ => {
            log::error!("Identity provider administration failed: {error}");
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "identity_provider_failed")
        }
    }
}

pub async fn list(State(state): State<Arc<WebState>>, _admin: CurrentUser) -> Response {
    let providers = match state.app.storage.list_identity_providers().await {
        Ok(providers) => providers,
        Err(error) => return storage_error(error),
    };
    let mut views = Vec::with_capacity(providers.len());
    for provider in providers {
        views.push(view(&state, provider).await);
    }
    Json(views).into_response()
}

#[derive(Deserialize)]
pub struct SaveProviderRequest {
    #[serde(default)]
    pub id: Option<String>,
    pub kind: String,
    pub name: String,
    pub config: serde_json::Value,
    #[serde(default)]
    pub auto_create_users: bool,
    #[serde(default)]
    pub default_group_id: Option<String>,
    #[serde(default = "enabled_default")]
    pub enabled: bool,
    #[serde(default)]
    pub secret: Option<String>,
}

fn enabled_default() -> bool {
    true
}

pub fn validated_config(kind: &str, config: serde_json::Value) -> Result<serde_json::Value, &'static str> {
    match kind {
        "oidc" => {
            let config = serde_json::from_value::<OidcConfig>(config)
                .map_err(|_| "identity_provider_config_invalid")?
                .normalized();
            config.validate()?;
            serde_json::to_value(config).map_err(|_| "identity_provider_config_invalid")
        }
        "ldap" => crate::ldap::validated_config(config),
        _ => Err("identity_provider_kind_invalid"),
    }
}

pub async fn save(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<SaveProviderRequest>,
) -> Response {
    let name = body.name.trim().to_string();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) {
        return error_response(StatusCode::BAD_REQUEST, "identity_provider_name_invalid");
    }
    if body.secret.as_deref().is_some_and(|secret| secret.len() > MAX_SECRET_CHARS) {
        return error_response(StatusCode::BAD_REQUEST, "identity_provider_config_invalid");
    }
    let existing = match &body.id {
        Some(id) => match state.app.storage.find_identity_provider(id).await {
            Ok(Some(existing)) => Some(existing),
            Ok(None) => return error_response(StatusCode::NOT_FOUND, "identity_provider_not_found"),
            Err(error) => return storage_error(error),
        },
        None => None,
    };
    if existing.as_ref().is_some_and(|existing| existing.kind != body.kind) {
        return error_response(StatusCode::BAD_REQUEST, "identity_provider_kind_invalid");
    }
    let config = match validated_config(&body.kind, body.config) {
        Ok(config) => config,
        Err(code) => return error_response(StatusCode::BAD_REQUEST, code),
    };
    if let Some(group_id) = body.default_group_id.as_deref().filter(|group| !group.is_empty()) {
        let groups = state.app.storage.list_user_groups().await.unwrap_or_default();
        if !groups.iter().any(|group| group.id == group_id) {
            return error_response(StatusCode::NOT_FOUND, "group_not_found");
        }
    }
    let now = now_millis();
    let provider = IdentityProvider {
        id: existing.as_ref().map_or_else(|| uuid::Uuid::new_v4().to_string(), |existing| existing.id.clone()),
        kind: body.kind,
        name,
        config,
        auto_create_users: body.auto_create_users,
        default_group_id: body.default_group_id.filter(|group| !group.is_empty()),
        enabled: body.enabled,
        created_at: existing.as_ref().map_or(now, |existing| existing.created_at),
        updated_at: now,
    };
    let saved = match state.app.storage.save_identity_provider(provider).await {
        Ok(saved) => saved,
        Err(error) => return storage_error(error),
    };
    if let Some(secret) = body.secret.as_deref() {
        if let Err(error) = state.app.storage.save_identity_provider_secret(&saved.id, Some(secret.trim())).await {
            return storage_error(error);
        }
    }
    record_action(
        &state,
        &admin.0,
        "identity_provider_saved",
        serde_json::json!({ "id": saved.id, "kind": saved.kind, "name": saved.name, "enabled": saved.enabled }),
    );
    Json(view(&state, saved).await).into_response()
}

#[derive(Deserialize)]
pub struct ProviderIdRequest {
    pub id: String,
}

pub async fn delete(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<ProviderIdRequest>,
) -> Response {
    if let Err(error) = state.app.storage.delete_identity_provider(&body.id).await {
        return storage_error(error);
    }
    record_action(&state, &admin.0, "identity_provider_deleted", serde_json::json!({ "id": body.id }));
    Json(serde_json::json!({ "ok": true })).into_response()
}

pub async fn test(
    State(state): State<Arc<WebState>>,
    _admin: CurrentUser,
    Json(body): Json<ProviderIdRequest>,
) -> Response {
    let provider = match state.app.storage.find_identity_provider(&body.id).await {
        Ok(Some(provider)) => provider,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "identity_provider_not_found"),
        Err(error) => return storage_error(error),
    };
    let result = match provider.kind.as_str() {
        "oidc" => match crate::routes::sso::oidc_config(&provider) {
            Some(config) => discover(&state.captcha_http, &config.issuer).await.map(|discovery| {
                serde_json::json!({
                    "ok": true,
                    "issuer": discovery.issuer,
                    "authorization_endpoint": discovery.authorization_endpoint,
                    "token_endpoint": discovery.token_endpoint,
                })
            }),
            None => Err("the stored configuration is not valid".to_string()),
        },
        "ldap" => {
            let secret = state.app.storage.load_identity_provider_secret(&provider.id).await.ok().flatten();
            crate::ldap::test_connection(&provider.config, secret.as_deref())
                .await
                .map(|()| serde_json::json!({ "ok": true }))
        }
        _ => Err("unknown provider kind".to_string()),
    };
    match result {
        Ok(result) => Json(result).into_response(),
        Err(detail) => Json(serde_json::json!({ "ok": false, "detail": detail })).into_response(),
    }
}
