use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dbx_authz::{Operations, Principal};
use serde_json::Value;

use crate::auth::{error_response, middleware_api_path_suffix};
use crate::error::AppError;
use crate::state::WebState;

const MAX_INSPECTED_BODY_BYTES: usize = 1024 * 1024 * 1024;

const R: Operations = Operations::SELECT;
const I: Operations = Operations::INSERT;
const U: Operations = Operations::UPDATE;
const D: Operations = Operations::DELETE;
const C: Operations = Operations::CREATE;
const A: Operations = Operations::ALTER;
const X: Operations = Operations::DROP;
const G: Operations = Operations::GRANT;
const E: Operations = Operations::EXECUTE;
const OWNER: Operations = Operations::UNCLASSIFIED;
const UPSERT: Operations = I.union(U);
const MOVE: Operations = I.union(D);
const READ_EXPORT: Operations = R.union(Operations::EXPORT);
const IMPORT_UPSERT: Operations = Operations::IMPORT.union(UPSERT);
const BATCH_EDIT: Operations = UPSERT.union(D);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    Consul,
    DocumentStore,
    Etcd,
    HBase,
    MessageQueue,
    Nacos,
    Vector,
    ZooKeeper,
}

const ENGINE_PREFIXES: &[(&str, Engine)] = &[
    ("consul/", Engine::Consul),
    ("document-store/", Engine::DocumentStore),
    ("etcd/", Engine::Etcd),
    ("hbase/", Engine::HBase),
    ("mq/", Engine::MessageQueue),
    ("nacos/", Engine::Nacos),
    ("vector/", Engine::Vector),
    ("zookeeper/", Engine::ZooKeeper),
];

pub fn engine_of(suffix: &str) -> Option<(Engine, &str)> {
    ENGINE_PREFIXES.iter().find_map(|(prefix, engine)| suffix.strip_prefix(prefix).map(|action| (*engine, action)))
}

const CONSUL: &[(&str, Operations)] = &[
    ("capabilities", R),
    ("txn", OWNER),
    ("rename-key", MOVE),
    ("blocking-query", R),
    ("domain-watch", R),
    ("cancel-blocking", R),
    ("list-prefix", R),
    ("list-recursive", R),
    ("search", R),
    ("search-progress", R),
    ("cancel-search", R),
    ("export-bundle", READ_EXPORT),
    ("import-preview", R),
    ("import-execute", IMPORT_UPSERT),
    ("delete-prefix-preview", R),
    ("delete-prefix-execute", D),
    ("get", R),
    ("put", UPSERT),
    ("delete", D),
    ("prepared-query/list", R),
    ("prepared-query/read", R),
    ("prepared-query/create", C),
    ("prepared-query/update", A),
    ("prepared-query/delete", X),
    ("prepared-query/execute", R),
    ("prepared-query/explain", R),
    ("event/list", R),
    ("event/fire", E),
    ("coordinate/nodes", R),
    ("operator/read", R),
    ("operator/snapshot/generate", OWNER),
    ("operator/snapshot/restore", OWNER),
    ("operator/autopilot/update", OWNER),
    ("operator/raft/transfer", OWNER),
    ("operator/raft/remove", OWNER),
    ("operator/keyring/write", OWNER),
    ("operator/license/write", OWNER),
    ("status/leader", R),
    ("status/peers", R),
    ("agent/self", R),
    ("agent/members", R),
    ("agent/metrics", R),
    ("catalog/datacenters", R),
    ("catalog/nodes", R),
    ("catalog/services", R),
    ("catalog/service-nodes", R),
    ("catalog/node-services", R),
    ("health/node", R),
    ("health/checks", R),
    ("health/service", R),
    ("health/state", R),
    ("agent/services", R),
    ("agent/service", R),
    ("agent/checks", R),
    ("agent/service/register", I),
    ("agent/service/deregister", D),
    ("agent/service/maintenance", U),
    ("agent/check/register", I),
    ("agent/check/deregister", D),
    ("agent/check/ttl", U),
    ("sessions", R),
    ("sessions/node", R),
    ("session", R),
    ("session/keys", R),
    ("session/destroy-impact", R),
    ("session/create", I),
    ("session/renew", U),
    ("session/destroy", D),
    ("lock/acquire", U),
    ("lock/release", U),
    ("acl/list", G),
    ("acl/token/self", R),
    ("acl/token/clone", G),
    ("acl/get", G),
    ("acl/apply", G),
    ("acl/references", G),
    ("acl/delete", G),
    ("enterprise/list", R),
    ("enterprise/get", R),
    ("enterprise/apply", A),
    ("enterprise/impact", R),
    ("enterprise/delete", X),
    ("mesh/config/list", R),
    ("mesh/config/get", R),
    ("mesh/config/apply", A),
    ("mesh/config/delete", X),
    ("mesh/intentions/list", R),
    ("mesh/intentions/get", R),
    ("mesh/intentions/get-exact", R),
    ("mesh/intentions/upsert", G),
    ("mesh/intentions/delete", G),
    ("mesh/intentions/delete-exact", G),
    ("mesh/intentions/match", R),
    ("mesh/intentions/check", R),
    ("mesh/discovery-chain", R),
    ("mesh/peerings/list", R),
    ("mesh/peerings/get", R),
    ("mesh/peerings/generate-token", G),
    ("mesh/peerings/establish", G),
    ("mesh/peerings/delete", G),
    ("mesh/exported-services/list", R),
    ("mesh/exported-services/apply", G),
];

const DOCUMENT_STORE: &[(&str, Operations)] = &[
    ("list-databases", R),
    ("list-collections", R),
    ("find-documents", R),
    ("count-documents", R),
    ("elasticsearch-count-documents", R),
    ("elasticsearch/index-metadata", R),
    ("elasticsearch/documents/delete-all", Operations::TRUNCATE),
    ("dynamodb-describe-table", R),
    ("list-gridfs-buckets", R),
    ("create-gridfs-bucket", C),
    ("delete-gridfs-bucket", X),
    ("list-gridfs-files", R),
    ("download-gridfs-file", R),
    ("upload-gridfs-file", I),
    ("delete-gridfs-file", D),
    ("insert-document", I),
    ("update-document", U),
    ("delete-document", D),
    ("save-meilisearch-batch", BATCH_EDIT),
    ("meilisearch/search", R),
    ("meilisearch/documents/fetch", R),
    ("meilisearch/documents/get", R),
    ("meilisearch/settings/get", R),
    ("meilisearch/settings/update", A),
    ("meilisearch/stats", R),
    ("meilisearch/overview", R),
    ("meilisearch/system/overview", R),
    ("meilisearch/documents/delete-all", Operations::TRUNCATE),
    ("meilisearch/index/create", C),
    ("meilisearch/index/delete", X),
    ("meilisearch/keys/list", G),
    ("meilisearch/keys/get", G),
    ("meilisearch/keys/create", G),
    ("meilisearch/keys/update", G),
    ("meilisearch/keys/delete", G),
    ("meilisearch/tasks/list", R),
    ("meilisearch/tasks/get", R),
    ("meilisearch/tasks/cancel", U),
    ("meilisearch/tasks/delete", D),
];

const ETCD: &[(&str, Operations)] = &[
    ("supports-ttl", R),
    ("list-prefix", R),
    ("get", R),
    ("put", UPSERT),
    ("delete", D),
    ("rename", MOVE),
    ("history", R),
    ("status", R),
    ("preflight", R),
    ("compact", OWNER),
    ("defrag", OWNER),
    ("watch/start", R),
    ("watch/poll", R),
    ("watch/stop", R),
    ("lease/list", R),
    ("auth/call", G),
];

const HBASE: &[(&str, Operations)] = &[
    ("table-schema", R),
    ("scan-rows", R),
    ("get-row", R),
    ("put-row", UPSERT),
    ("delete-row", D),
    ("create-table", C),
    ("delete-table", X),
];

const MESSAGE_QUEUE: &[(&str, Operations)] = &[
    ("test-connection", R),
    ("tenants/list", R),
    ("tenants/get", R),
    ("tenants/create", C),
    ("tenants/update", A),
    ("tenants/delete", X),
    ("namespaces/list", R),
    ("namespaces/create", C),
    ("namespaces/delete", X),
    ("namespaces/policies", R),
    ("topics/list", R),
    ("topics/list-page", R),
    ("topics/create", C),
    ("topics/delete", X),
    ("topics/update-partitions", A),
    ("topics/stats", R),
    ("topics/internal-stats", R),
    ("topics/route", R),
    ("topics/alter-config", A),
    ("topics/skip-accumulation", D),
    ("topics/unload", OWNER),
    ("exchanges/list", R),
    ("exchanges/list-page", R),
    ("exchanges/create", C),
    ("exchanges/delete", X),
    ("bindings/list", R),
    ("bindings/bind", A),
    ("bindings/unbind", A),
    ("messages/view", R),
    ("messages/query-by-key", R),
    ("messages/query-by-topic", R),
    ("messages/trace", R),
    ("subscriptions/list", R),
    ("subscriptions/enrich", R),
    ("kafka/consumer-groups", R),
    ("subscriptions/create", C),
    ("subscriptions/delete", X),
    ("subscriptions/skip-messages", U),
    ("subscriptions/reset-cursor", U),
    ("subscriptions/clear-backlog", D),
    ("subscriptions/peek-messages", R),
    ("subscriptions/expire-messages", D),
    ("consumers/group-config/get", R),
    ("consumers/group-config/alter", A),
    ("producers/list", R),
    ("consumers/list", R),
    ("client-connections/list", R),
    ("client-connections/close", OWNER),
    ("channels/list", R),
    ("policies/publish-rate", A),
    ("policies/dispatch-rate", A),
    ("policies/subscribe-rate", A),
    ("policies/backlog-quota", A),
    ("policies/retention", A),
    ("policies/effective", R),
    ("policies/list", R),
    ("policies/set", A),
    ("policies/delete", A),
    ("permissions/grant", G),
    ("permissions/revoke", G),
    ("permissions/list", R),
    ("users/list", R),
    ("users/create", G),
    ("users/delete", G),
    ("user-permissions/list", R),
    ("user-permissions/grant", G),
    ("user-permissions/revoke", G),
    ("tokens/issue", G),
    ("tokens/list", G),
    ("monitoring/backlog", R),
    ("monitoring/cluster-info", R),
    ("overview", R),
    ("nodes", R),
    ("send-message", I),
];

const NACOS: &[(&str, Operations)] = &[
    ("test-connection", R),
    ("namespaces/list", R),
    ("sidebar/snapshot", R),
    ("namespaces/create", C),
    ("namespaces/update", A),
    ("namespaces/delete", X),
    ("configs/list", R),
    ("configs/get", R),
    ("configs/publish", UPSERT),
    ("configs/delete", D),
    ("configs/history/list", R),
    ("configs/history/get", R),
    ("configs/history/rollback", U),
    ("configs/search", R),
    ("configs/search/cancel", R),
    ("configs/export", READ_EXPORT),
    ("configs/import/preview", R),
    ("configs/import/apply", IMPORT_UPSERT),
    ("configs/copy/preview", R),
    ("configs/copy/apply", UPSERT),
    ("rnacos-console/captcha", R),
    ("rnacos-console/login", R),
    ("users/list", G),
    ("users/create", G),
    ("users/update", G),
    ("users/delete", G),
    ("roles/list", G),
    ("roles/assign", G),
    ("roles/remove", G),
    ("access/snapshot", G),
    ("access/operations/start", G),
    ("access/operations/get", G),
    ("access/operations/retry", G),
    ("access/operations/undo", G),
    ("services/list", R),
    ("services/get", R),
    ("services/create", C),
    ("services/update", A),
    ("services/delete", X),
    ("instances/list", R),
    ("instances/update", U),
    ("instances/register", I),
    ("instances/deregister", D),
    ("dashboard", R),
];

const VECTOR: &[(&str, Operations)] =
    &[("collection-detail", R), ("drop-database", X), ("drop-collection", X), ("rename-collection", A)];

const ZOOKEEPER: &[(&str, Operations)] = &[("list-prefix", R), ("get", R), ("put", UPSERT), ("delete", D)];

fn table(engine: Engine) -> &'static [(&'static str, Operations)] {
    match engine {
        Engine::Consul => CONSUL,
        Engine::DocumentStore => DOCUMENT_STORE,
        Engine::Etcd => ETCD,
        Engine::HBase => HBASE,
        Engine::MessageQueue => MESSAGE_QUEUE,
        Engine::Nacos => NACOS,
        Engine::Vector => VECTOR,
        Engine::ZooKeeper => ZOOKEEPER,
    }
}

fn text<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key).and_then(Value::as_str).map(str::trim).filter(|value| !value.is_empty())
}

fn raw_request_operations(body: &Value) -> Operations {
    let method = body.get("req").and_then(|req| text(req, "method")).unwrap_or_default().to_ascii_uppercase();
    if matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        R
    } else {
        OWNER
    }
}

pub fn operations_for(engine: Engine, action: &str, body: &Value) -> Operations {
    match (engine, action) {
        (Engine::MessageQueue | Engine::Nacos, "raw") => return raw_request_operations(body),
        (Engine::Etcd, "lease/call") => return if text(body, "operation") == Some("get") { R } else { U },
        _ => {}
    }
    table(engine).iter().find(|(name, _)| *name == action).map_or(OWNER, |(_, operations)| *operations)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineTarget {
    pub connection_id: Option<String>,
    pub database: Option<String>,
    pub table: Option<String>,
}

pub fn target_for(engine: Engine, body: &Value) -> EngineTarget {
    let connection_id = text(body, "connectionId").or_else(|| text(body, "connection_id")).map(str::to_string);
    let (database, table) = match engine {
        Engine::HBase => (text(body, "namespace"), text(body, "table")),
        Engine::DocumentStore => (
            text(body, "database"),
            text(body, "collection").or_else(|| text(body, "index")).or_else(|| text(body, "table")),
        ),
        Engine::Vector => (text(body, "database"), text(body, "collection")),
        _ => (None, None),
    };
    EngineTarget {
        connection_id,
        database: database.map(str::to_string),
        table: database.and(table).map(str::to_string),
    }
}

async fn authorize(state: &WebState, target: &EngineTarget, operations: Operations) -> Result<(), String> {
    let Some(connection_id) = target.connection_id.as_deref() else {
        return Err(format!("{} the request does not name a connection", dbx_core::authz::PERMISSION_DENIED_PREFIX));
    };
    match target.database.as_deref() {
        None => dbx_core::authz::authorize_connection_operations(&state.app, connection_id, operations).await,
        Some(database) => {
            dbx_core::authz::authorize_resource(
                &state.app,
                connection_id,
                Some(database),
                None,
                target.table.as_deref(),
                operations,
                target.table.is_none(),
            )
            .await
        }
    }
}

pub async fn engine_access_middleware(State(state): State<Arc<WebState>>, req: Request<Body>, next: Next) -> Response {
    if !state.app.authz.is_enforced() {
        return next.run(req).await;
    }
    let Some(suffix) = middleware_api_path_suffix(req.uri().path(), &state.public_base_path).map(str::to_string) else {
        return next.run(req).await;
    };
    let Some((engine, action)) = engine_of(&suffix) else {
        return next.run(req).await;
    };
    if req.extensions().get::<Principal>().is_some_and(Principal::is_admin) {
        return next.run(req).await;
    }
    let action = action.to_string();
    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, MAX_INSPECTED_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return error_response(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"),
    };
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let operations = operations_for(engine, &action, &json);
    if let Err(message) = authorize(&state, &target_for(engine, &json), operations).await {
        return AppError::forbidden(message).into_response();
    }
    next.run(Request::from_parts(parts, Body::from(bytes))).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn maps_reads_writes_and_administration_per_engine() {
        let body = json!({ "connectionId": "c" });
        assert_eq!(operations_for(Engine::Nacos, "configs/get", &body), R);
        assert_eq!(operations_for(Engine::Nacos, "configs/publish", &body), I | U);
        assert_eq!(operations_for(Engine::Nacos, "users/create", &body), G);
        assert_eq!(operations_for(Engine::MessageQueue, "send-message", &body), I);
        assert_eq!(operations_for(Engine::MessageQueue, "topics/delete", &body), X);
        assert_eq!(operations_for(Engine::Consul, "operator/raft/remove", &body), OWNER);
        assert_eq!(operations_for(Engine::DocumentStore, "find-documents", &body), R);
        assert_eq!(operations_for(Engine::Etcd, "something-new", &body), OWNER);
    }

    #[test]
    fn raw_and_lease_requests_depend_on_their_body() {
        assert_eq!(operations_for(Engine::Nacos, "raw", &json!({ "req": { "method": "get" } })), R);
        assert_eq!(operations_for(Engine::MessageQueue, "raw", &json!({ "req": { "method": "DELETE" } })), OWNER);
        assert_eq!(operations_for(Engine::MessageQueue, "raw", &json!({})), OWNER);
        assert_eq!(operations_for(Engine::Etcd, "lease/call", &json!({ "operation": "get" })), R);
        assert_eq!(operations_for(Engine::Etcd, "lease/call", &json!({ "operation": "revoke" })), U);
    }

    #[test]
    fn reads_the_target_from_engine_specific_fields() {
        assert_eq!(
            target_for(Engine::HBase, &json!({ "connectionId": "h", "namespace": "ns", "table": "t" })),
            EngineTarget { connection_id: Some("h".into()), database: Some("ns".into()), table: Some("t".into()) }
        );
        assert_eq!(
            target_for(Engine::DocumentStore, &json!({ "connectionId": "d", "database": "app", "index": "logs" })),
            EngineTarget { connection_id: Some("d".into()), database: Some("app".into()), table: Some("logs".into()) }
        );
        assert_eq!(
            target_for(Engine::DocumentStore, &json!({ "connectionId": "d", "index": "logs" })),
            EngineTarget { connection_id: Some("d".into()), database: None, table: None }
        );
        assert_eq!(
            target_for(Engine::Nacos, &json!({ "connection_id": "n", "database": "ignored" })),
            EngineTarget { connection_id: Some("n".into()), database: None, table: None }
        );
    }

    #[test]
    fn every_registered_engine_route_has_an_explicit_mapping() {
        let unmapped: Vec<String> = crate::route_policy::test_support::registered_routes()
            .into_iter()
            .filter_map(|route| {
                let path = crate::route_policy::test_support::concrete(&route);
                let (engine, action) = engine_of(&path)?;
                let mapped = table(engine).iter().any(|(name, _)| *name == action)
                    || matches!(
                        (engine, action),
                        (Engine::MessageQueue | Engine::Nacos, "raw") | (Engine::Etcd, "lease/call")
                    );
                (!mapped).then_some(path)
            })
            .collect();
        assert!(unmapped.is_empty(), "engine routes without an operation mapping: {unmapped:?}");
    }
}
