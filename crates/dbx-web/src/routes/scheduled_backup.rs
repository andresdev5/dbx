use crate::audit_events::record_action;
use crate::auth::MaybeUser;
use crate::{error::AppError, state::WebState};
use axum::{
    body::Body,
    extract::{Path, State},
    http::header,
    response::Response,
    Json,
};
use dbx_authz::{Effect, Operations, Principal, Resource, Scope, Subject};
use dbx_core::authz::principal_allows;
use dbx_core::scheduled_backup::BackupConfig;
use dbx_core::scheduled_backup::{BackupCommand, BackupService};
use dbx_core::storage::StoredGrant;
use std::{path::PathBuf, sync::Arc};
use tokio_util::io::ReaderStream;

pub fn service(state: &WebState) -> Result<BackupService, String> {
    let root = std::env::var_os("DBX_BACKUP_ROOT").map(PathBuf::from).unwrap_or_else(|| state.data_dir.join("backups"));
    let root = root.canonicalize().map_err(|e| format!("Cannot resolve the server backup root: {e}"))?;
    Ok(BackupService::new(state.app.clone(), &state.data_dir, Some(root)))
}

pub async fn command(
    State(state): State<Arc<WebState>>,
    MaybeUser(user): MaybeUser,
    Json(mut command): Json<BackupCommand>,
) -> Result<Json<serde_json::Value>, AppError> {
    let service = service(&state)?;
    if state.app.authz.is_enforced() {
        match &mut command {
            BackupCommand::Save { schedule } => {
                let existing_owner = service
                    .store
                    .snapshot()
                    .await?
                    .schedules
                    .into_iter()
                    .find(|existing| existing.id == schedule.id)
                    .and_then(|existing| existing.owner_user_id);
                let owner = schedule
                    .owner_user_id
                    .clone()
                    .or(existing_owner)
                    .or_else(|| user.as_ref().map(|user| user.user_id.clone()))
                    .ok_or_else(|| AppError::forbidden("backup_owner_missing"))?;
                validate_backup_access(&state, &owner, &schedule.config).await?;
                schedule.owner_user_id = Some(owner);
            }
            BackupCommand::SetOwner { owner_user_id, .. } => {
                let owner = state.app.storage.find_web_user(owner_user_id).await?;
                if !owner.is_some_and(|owner| owner.active) {
                    return Err(AppError::not_found("backup_owner_not_found"));
                }
            }
            _ => {}
        }
    }
    let audit = match &command {
        BackupCommand::Save { schedule } => Some((
            "backup_schedule_saved",
            serde_json::json!({
                "schedule_id": schedule.id,
                "connection_id": schedule.config.connection_id,
                "owner_user_id": schedule.owner_user_id,
            }),
        )),
        BackupCommand::SetOwner { id, owner_user_id } => {
            Some(("backup_owner_changed", serde_json::json!({ "schedule_id": id, "owner_user_id": owner_user_id })))
        }
        BackupCommand::DeleteSchedule { id } => {
            Some(("backup_schedule_deleted", serde_json::json!({ "schedule_id": id })))
        }
        _ => None,
    };
    let result = service.command(command).await?;
    if let (Some((event, detail)), Some(user)) = (audit, &user) {
        record_action(&state, user, event, detail);
    }
    Ok(Json(result))
}

const BACKUP_OPERATIONS: Operations = Operations::SELECT.union(Operations::EXPORT);

async fn validate_backup_access(state: &WebState, owner_id: &str, config: &BackupConfig) -> Result<(), AppError> {
    let owner = state
        .app
        .storage
        .find_web_user(owner_id)
        .await?
        .filter(|owner| owner.active)
        .ok_or_else(|| AppError::not_found("backup_owner_not_found"))?;
    let owner = Principal::User { user_id: owner.id, groups: Vec::new(), role: owner.role };
    let owner = state.app.authz.with_groups(&owner);
    let system = Principal::System { task_id: None };
    let databases: Vec<Option<&str>> = if config.databases.is_empty() {
        vec![None]
    } else {
        config.databases.iter().map(|database| Some(database.as_str())).collect()
    };
    for database in databases {
        let target = database.unwrap_or(config.connection_id.as_str());
        if !principal_allows(&state.app, &owner, &config.connection_id, database, BACKUP_OPERATIONS).await {
            return Err(AppError::forbidden(format!(
                "Permission denied: SELECT, EXPORT required on {target} for the backup owner"
            )));
        }
        if !principal_allows(&state.app, &system, &config.connection_id, database, BACKUP_OPERATIONS).await {
            return Err(AppError::forbidden(format!(
                "Permission denied: SELECT, EXPORT required on {target} for the system principal"
            )));
        }
    }
    Ok(())
}

pub const BACKUP_ACCESS_MIGRATION: &str = "scheduled_backup_access_v1";

pub async fn migrate_backup_access(state: &WebState, service: &BackupService) -> Result<(), String> {
    let storage = &state.app.storage;
    if storage.authz_flag(BACKUP_ACCESS_MIGRATION).await? {
        return Ok(());
    }
    let schedules = service.store.snapshot().await?.schedules;
    let grants = storage.list_grants().await?;
    let connections: std::collections::BTreeSet<String> =
        schedules.iter().map(|schedule| schedule.config.connection_id.clone()).collect();
    for connection_id in connections {
        let covered = grants.iter().any(|grant| {
            grant.subject == Subject::System
                && grant.effect == Effect::Allow
                && match &grant.scope {
                    Scope::All => true,
                    Scope::Resource(resource) => resource.connection_id == connection_id && resource.database.is_none(),
                    Scope::ConnectionGroup(_) => false,
                }
        });
        if covered {
            continue;
        }
        storage
            .save_grant(StoredGrant {
                id: uuid::Uuid::new_v4().to_string(),
                subject: Subject::System,
                scope: Scope::Resource(Resource::connection(connection_id)),
                effect: Effect::Allow,
                operations: Some(BACKUP_OPERATIONS),
                role_id: None,
                expires_at: None,
                note: Some("Migrated so existing scheduled backups keep running".into()),
                created_by: None,
                created_at: crate::sessions::now_millis(),
            })
            .await?;
    }
    let admin = storage
        .list_web_users()
        .await?
        .into_iter()
        .find(|user| user.active && user.role == dbx_authz::PlatformRole::Admin);
    if let Some(admin) = admin {
        for schedule in schedules.into_iter().filter(|schedule| schedule.owner_user_id.is_none()) {
            service.command(BackupCommand::SetOwner { id: schedule.id, owner_user_id: admin.id.clone() }).await?;
        }
    }
    storage.set_authz_flag(BACKUP_ACCESS_MIGRATION).await?;
    state.app.authz.reload(storage).await
}

pub async fn download(
    State(state): State<Arc<WebState>>,
    Path((id, index)): Path<(String, usize)>,
) -> Result<Response, AppError> {
    let path = service(&state)?.file(&id, index).await?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let disposition = super::export_download::attachment_content_disposition(&name);
    let file = tokio::fs::File::open(&path).await.map_err(|e| AppError::from(e.to_string()))?;
    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from_stream(ReaderStream::new(file)))
        .map_err(|e| AppError::from(e.to_string()))
}

pub async fn prepare_restore(
    State(state): State<Arc<WebState>>,
    Path((id, index)): Path<(String, usize)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let source = service(&state)?.file(&id, index).await?;
    Ok(Json(super::sql_file::prepare_backup_preview(&state, source).await?))
}
