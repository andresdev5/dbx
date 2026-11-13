use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::audit_events::record_action;
use crate::auth::{error_response, CurrentUser};
use crate::captcha_provider::{validate, CaptchaProviderConfig, CaptchaProviderKind, CaptchaProviderSettings};
use crate::state::WebState;

const MAX_FIELD_CHARS: usize = 2048;

#[derive(Serialize)]
struct CaptchaSettingsView {
    mode: &'static str,
    mode_env_locked: bool,
    provider: CaptchaProviderKind,
    site_key: String,
    endpoint: String,
    has_secret: bool,
    provider_env_locked: bool,
    fallback_active: bool,
}

async fn view(state: &WebState) -> CaptchaSettingsView {
    let provider = state.captcha_provider.read().await.clone();
    CaptchaSettingsView {
        mode: state.captcha_mode.read().await.as_str(),
        mode_env_locked: state.captcha_env_locked,
        provider: provider.settings.provider,
        site_key: provider.settings.site_key,
        endpoint: provider.settings.endpoint,
        has_secret: provider.secret.as_deref().is_some_and(|secret| !secret.is_empty()),
        provider_env_locked: state.captcha_provider_env_locked,
        fallback_active: state.captcha_fallback.lock().await.active(std::time::Instant::now()),
    }
}

pub async fn captcha_settings(State(state): State<Arc<WebState>>, _admin: CurrentUser) -> Response {
    Json(view(&state).await).into_response()
}

#[derive(Deserialize)]
pub struct SaveCaptchaProviderRequest {
    pub provider: String,
    #[serde(default)]
    pub site_key: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub secret: Option<String>,
}

pub async fn save_captcha_provider(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<SaveCaptchaProviderRequest>,
) -> Response {
    if state.captcha_provider_env_locked {
        return error_response(StatusCode::CONFLICT, "captcha_provider_env_locked");
    }
    let Some(provider) = CaptchaProviderKind::parse(&body.provider) else {
        return error_response(StatusCode::BAD_REQUEST, "captcha_provider_invalid");
    };
    let site_key = body.site_key.trim().to_string();
    let endpoint = body.endpoint.trim().trim_end_matches('/').to_string();
    if [site_key.len(), endpoint.len(), body.secret.as_deref().map_or(0, str::len)]
        .iter()
        .any(|len| *len > MAX_FIELD_CHARS)
    {
        return error_response(StatusCode::BAD_REQUEST, "captcha_field_too_long");
    }
    let current_secret = state.captcha_provider.read().await.secret.clone();
    let secret = match body.secret.as_deref().map(str::trim) {
        None => current_secret,
        Some("") => None,
        Some(secret) => Some(secret.to_string()),
    };
    let config = CaptchaProviderConfig {
        settings: CaptchaProviderSettings {
            provider,
            site_key: if provider.is_external() { site_key } else { String::new() },
            endpoint: if provider == CaptchaProviderKind::Cap { endpoint } else { String::new() },
        },
        secret: if provider.is_external() { secret } else { None },
    };
    if let Err(code) = validate(&config) {
        return error_response(StatusCode::BAD_REQUEST, code);
    }
    let settings = match serde_json::to_value(&config.settings) {
        Ok(settings) => settings,
        Err(error) => {
            log::error!("Failed to encode the captcha provider settings: {error}");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "captcha_settings_failed");
        }
    };
    if let Err(error) = state.app.storage.save_web_captcha_secret(config.secret.as_deref()).await {
        log::error!("Failed to store the captcha provider secret: {error}");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "captcha_settings_failed");
    }
    if let Err(error) = state.app.storage.save_web_captcha_provider(&settings).await {
        log::error!("Failed to store the captcha provider settings: {error}");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "captcha_settings_failed");
    }
    record_action(
        &state,
        &admin.0,
        "captcha_provider_changed",
        serde_json::json!({ "provider": config.settings.provider, "site_key": config.settings.site_key }),
    );
    *state.captcha_provider.write().await = config;
    state.captcha_fallback.lock().await.clear();
    Json(view(&state).await).into_response()
}
