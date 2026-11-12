use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use dbx_core::audit::SESSION_REF_CHARS;
use dbx_core::storage::{AuditEntry, AuditFilter, MAX_AUDIT_PAGE};
use serde::{Deserialize, Serialize};

use crate::audit_events::record_action;
use crate::auth::{error_response, forget_live_sessions_by_hash, CurrentUser};
use crate::sessions::now_millis;
use crate::state::WebState;

const DEFAULT_PAGE: usize = 100;
const MAX_EXPORT_ROWS: usize = 100_000;
const MAX_FILTER_CHARS: usize = 200;
const MAX_STATEMENT_FILTER_CHARS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditApiError {
    status: StatusCode,
    code: &'static str,
}

impl AuditApiError {
    const fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code }
    }

    fn storage(error: String) -> Self {
        log::error!("DBX Web audit administration failed: {error}");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "audit_admin_failed")
    }
}

impl IntoResponse for AuditApiError {
    fn into_response(self) -> Response {
        error_response(self.status, self.code)
    }
}

type AuditResult = Result<Response, AuditApiError>;

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub connection_id: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub from: Option<i64>,
    #[serde(default)]
    pub to: Option<i64>,
    #[serde(default)]
    pub statement: Option<String>,
    #[serde(default)]
    pub before_id: Option<i64>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub include_statements: bool,
}

#[derive(Serialize)]
struct AuditEntryView {
    id: i64,
    event_id: String,
    ts: i64,
    user_id: Option<String>,
    username: Option<String>,
    acting_principal: String,
    task_id: Option<String>,
    session_ref: Option<String>,
    ip: Option<String>,
    event: String,
    connection_id: Option<String>,
    database_name: Option<String>,
    schema_name: Option<String>,
    table_names: Option<String>,
    operations: Vec<&'static str>,
    decision: Option<String>,
    reason: Option<String>,
    has_statement: bool,
    rows_affected: Option<i64>,
    duration_ms: Option<i64>,
    detail: Option<serde_json::Value>,
}

impl From<AuditEntry> for AuditEntryView {
    fn from(entry: AuditEntry) -> Self {
        Self {
            id: entry.id,
            event_id: entry.event_id,
            ts: entry.ts,
            user_id: entry.user_id,
            username: entry.username,
            acting_principal: entry.acting_principal,
            task_id: entry.task_id,
            session_ref: entry.session_ref,
            ip: entry.ip,
            event: entry.event,
            connection_id: entry.connection_id,
            database_name: entry.database_name,
            schema_name: entry.schema_name,
            table_names: entry.table_names,
            operations: entry.operations.map(|operations| operations.names()).unwrap_or_default(),
            decision: entry.decision,
            reason: entry.reason,
            has_statement: entry.has_statement,
            rows_affected: entry.rows_affected,
            duration_ms: entry.duration_ms,
            detail: entry.detail.and_then(|detail| serde_json::from_str(&detail).ok()),
        }
    }
}

fn clean(value: Option<String>) -> Result<Option<String>, AuditApiError> {
    let Some(value) = value.map(|value| value.trim().to_string()).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > MAX_FILTER_CHARS {
        return Err(AuditApiError::new(StatusCode::BAD_REQUEST, "audit_filter_invalid"));
    }
    Ok(Some(value))
}

fn filter_for(state: &WebState, query: &AuditQuery, limit: usize) -> Result<AuditFilter, AuditApiError> {
    let decision = clean(query.decision.clone())?;
    if decision.as_deref().is_some_and(|decision| !matches!(decision, "allow" | "deny")) {
        return Err(AuditApiError::new(StatusCode::BAD_REQUEST, "audit_filter_invalid"));
    }
    if matches!((query.from, query.to), (Some(from), Some(to)) if from > to) {
        return Err(AuditApiError::new(StatusCode::BAD_REQUEST, "audit_filter_invalid"));
    }
    let statement_hmac = match query.statement.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        None => None,
        Some(statement) if statement.len() > MAX_STATEMENT_FILTER_CHARS => {
            return Err(AuditApiError::new(StatusCode::BAD_REQUEST, "audit_filter_invalid"));
        }
        Some(statement) => Some(state.app.storage.audit_statement_digest(statement).map_err(|error| {
            log::warn!("DBX Web audit cannot search statements: {error}");
            AuditApiError::new(StatusCode::CONFLICT, "audit_key_unavailable")
        })?),
    };
    Ok(AuditFilter {
        user_id: clean(query.user_id.clone())?,
        connection_id: clean(query.connection_id.clone())?,
        decision,
        event: clean(query.event.clone())?,
        from: query.from,
        to: query.to,
        statement_hmac,
        before_id: query.before_id,
        limit,
    })
}

fn filter_summary(query: &AuditQuery) -> serde_json::Value {
    serde_json::json!({
        "user_id": query.user_id,
        "connection_id": query.connection_id,
        "decision": query.decision,
        "event": query.event,
        "from": query.from,
        "to": query.to,
        "statement_search": query.statement.as_deref().is_some_and(|value| !value.trim().is_empty()),
    })
}

pub async fn list(
    State(state): State<Arc<WebState>>,
    _admin: CurrentUser,
    Json(query): Json<AuditQuery>,
) -> AuditResult {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_AUDIT_PAGE);
    let filter = filter_for(&state, &query, limit)?;
    let entries = state.app.storage.list_audit_events(filter).await.map_err(AuditApiError::storage)?;
    let next_before_id = (entries.len() == limit).then(|| entries.last().map(|entry| entry.id)).flatten();
    let entries: Vec<AuditEntryView> = entries.into_iter().map(AuditEntryView::from).collect();
    Ok(Json(serde_json::json!({
        "entries": entries,
        "next_before_id": next_before_id,
        "dropped_events": state.app.audit.dropped(),
    }))
    .into_response())
}

#[derive(Deserialize)]
pub struct RevealRequest {
    pub event_id: String,
}

pub async fn reveal(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<RevealRequest>,
) -> AuditResult {
    let event_id = body.event_id.trim().to_string();
    let statement = match state.app.storage.reveal_audit_statement(&event_id).await {
        Ok(Some(statement)) => statement,
        Ok(None) => return Err(AuditApiError::new(StatusCode::NOT_FOUND, "audit_statement_unavailable")),
        Err(error) => {
            log::warn!("DBX Web audit could not decrypt event {event_id}: {error}");
            return Err(AuditApiError::new(StatusCode::CONFLICT, "audit_key_unavailable"));
        }
    };
    record_action(&state, &admin.0, "audit_revealed", serde_json::json!({ "event_id": event_id }));
    Ok(Json(serde_json::json!({ "event_id": event_id, "statement": statement })).into_response())
}

fn csv_cell(value: &str) -> String {
    let guarded =
        if value.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{value}") } else { value.to_string() };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

const CSV_HEADER: &[&str] = &[
    "id",
    "event_id",
    "timestamp",
    "user_id",
    "username",
    "principal",
    "task_id",
    "session",
    "ip",
    "event",
    "connection_id",
    "database",
    "schema",
    "tables",
    "operations",
    "decision",
    "reason",
    "detail",
    "statement",
];

fn iso_timestamp(millis: i64) -> String {
    chrono::DateTime::from_timestamp_millis(millis)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_default()
}

pub async fn export(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(query): Json<AuditQuery>,
) -> AuditResult {
    let mut filter = filter_for(&state, &query, MAX_AUDIT_PAGE)?;
    let mut csv = CSV_HEADER.join(",");
    csv.push('\n');
    let mut rows = 0;
    let mut truncated = false;
    loop {
        let page = state.app.storage.list_audit_events(filter.clone()).await.map_err(AuditApiError::storage)?;
        let full = page.len() == MAX_AUDIT_PAGE;
        filter.before_id = page.last().map(|entry| entry.id);
        for entry in page {
            if rows == MAX_EXPORT_ROWS {
                truncated = true;
                break;
            }
            let statement = if query.include_statements && entry.has_statement {
                state.app.storage.reveal_audit_statement(&entry.event_id).await.ok().flatten().unwrap_or_default()
            } else {
                String::new()
            };
            let operations = entry.operations.map(|operations| operations.names().join("|")).unwrap_or_default();
            let cells = [
                entry.id.to_string(),
                entry.event_id,
                iso_timestamp(entry.ts),
                entry.user_id.unwrap_or_default(),
                entry.username.unwrap_or_default(),
                entry.acting_principal,
                entry.task_id.unwrap_or_default(),
                entry.session_ref.unwrap_or_default(),
                entry.ip.unwrap_or_default(),
                entry.event,
                entry.connection_id.unwrap_or_default(),
                entry.database_name.unwrap_or_default(),
                entry.schema_name.unwrap_or_default(),
                entry.table_names.unwrap_or_default(),
                operations,
                entry.decision.unwrap_or_default(),
                entry.reason.unwrap_or_default(),
                entry.detail.unwrap_or_default(),
                statement,
            ];
            csv.push_str(&cells.iter().map(|cell| csv_cell(cell)).collect::<Vec<_>>().join(","));
            csv.push('\n');
            rows += 1;
        }
        if truncated || !full {
            break;
        }
    }
    let mut detail = filter_summary(&query);
    detail["rows"] = serde_json::json!(rows);
    detail["truncated"] = serde_json::json!(truncated);
    detail["include_statements"] = serde_json::json!(query.include_statements);
    record_action(&state, &admin.0, "audit_exported", detail);
    let filename = format!("dbx-audit-{}.csv", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
            (header::CACHE_CONTROL, "no-store".to_string()),
            (header::HeaderName::from_static("x-dbx-export-truncated"), truncated.to_string()),
        ],
        csv,
    )
        .into_response())
}

#[derive(Deserialize, Default)]
pub struct SessionQuery {
    #[serde(default)]
    pub user_id: Option<String>,
}

#[derive(Serialize)]
struct SessionView {
    id: String,
    session_ref: String,
    user_id: String,
    username: Option<String>,
    created_at: i64,
    last_seen_at: i64,
    expires_at: Option<i64>,
    ip: Option<String>,
    user_agent: Option<String>,
    current: bool,
}

pub async fn list_sessions(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(query): Json<SessionQuery>,
) -> AuditResult {
    let now = now_millis();
    let sessions = state
        .app
        .storage
        .list_live_web_sessions(state.session_manager.idle_cutoff(now), now)
        .await
        .map_err(AuditApiError::storage)?;
    let users = state.app.storage.list_web_users().await.map_err(AuditApiError::storage)?;
    let user_filter = clean(query.user_id)?;
    let views: Vec<SessionView> = sessions
        .into_iter()
        .filter(|session| user_filter.as_ref().is_none_or(|user_id| &session.user_id == user_id))
        .map(|session| SessionView {
            session_ref: session.token_hash.chars().take(SESSION_REF_CHARS).collect(),
            current: session.token_hash == admin.0.token_hash,
            username: users.iter().find(|user| user.id == session.user_id).map(|user| user.username.clone()),
            id: session.token_hash,
            user_id: session.user_id,
            created_at: session.created_at,
            last_seen_at: session.last_seen_at,
            expires_at: session.expires_at,
            ip: session.ip,
            user_agent: session.user_agent,
        })
        .collect();
    Ok(Json(views).into_response())
}

#[derive(Deserialize)]
pub struct RevokeSessionRequest {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
}

pub async fn revoke_session(
    State(state): State<Arc<WebState>>,
    admin: CurrentUser,
    Json(body): Json<RevokeSessionRequest>,
) -> AuditResult {
    let now = now_millis();
    let revoked = match (clean(body.id)?, clean(body.user_id)?) {
        (Some(id), None) => {
            if id == admin.0.token_hash {
                return Err(AuditApiError::new(StatusCode::CONFLICT, "self_modification_not_allowed"));
            }
            let session = state.app.storage.find_web_session(&id).await.map_err(AuditApiError::storage)?;
            let Some(session) = session.filter(|session| session.revoked_at.is_none()) else {
                return Err(AuditApiError::new(StatusCode::NOT_FOUND, "session_not_found"));
            };
            state.session_manager.revoke_hash(&state.app.storage, &id, now).await.map_err(AuditApiError::storage)?;
            record_action(
                &state,
                &admin.0,
                "session_revoked",
                serde_json::json!({
                    "session_ref": id.chars().take(SESSION_REF_CHARS).collect::<String>(),
                    "user_id": session.user_id,
                }),
            );
            vec![id]
        }
        (None, Some(user_id)) => {
            let keep = (user_id == admin.0.user_id).then_some(admin.0.token_hash.as_str());
            let revoked = state
                .session_manager
                .revoke_user(&state.app.storage, &user_id, keep, now)
                .await
                .map_err(AuditApiError::storage)?;
            record_action(
                &state,
                &admin.0,
                "user_sessions_revoked",
                serde_json::json!({ "user_id": user_id, "sessions": revoked.len() }),
            );
            revoked
        }
        _ => return Err(AuditApiError::new(StatusCode::BAD_REQUEST, "session_not_found")),
    };
    forget_live_sessions_by_hash(&state, &revoked).await;
    Ok(Json(serde_json::json!({ "revoked": revoked.len() })).into_response())
}
