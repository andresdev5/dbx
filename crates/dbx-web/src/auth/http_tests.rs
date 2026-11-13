use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::{middleware, Router};
use dbx_authz::PlatformRole;
use dbx_core::storage::NewWebUser;
use serde_json::{json, Value};

use super::*;
use crate::bootstrap::{bootstrap_users, BootstrapEnv};
use crate::captcha::CaptchaMode;
use crate::identity::hash_password;

const ADMIN_PASSWORD: &str = "admin-password";

struct Server {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
    client: reqwest::Client,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Reply {
    status: StatusCode,
    cookie: Option<String>,
    body: Value,
}

impl Server {
    async fn send(
        &self,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> Reply {
        let url = format!("http://{}{path}", self.address);
        let mut request = match method {
            "GET" => self.client.get(url),
            _ => self.client.post(url),
        };
        if let Some(body) = body {
            request = request.json(&body);
        }
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        let response = request.send().await.unwrap();
        let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
        let cookie = response
            .headers()
            .get("set-cookie")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::to_string);
        let text = response.text().await.unwrap();
        let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
        Reply { status, cookie, body }
    }

    async fn post(&self, path: &str, cookie: Option<&str>, body: Value) -> Reply {
        self.send("POST", path, cookie, Some(body), &[]).await
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> Reply {
        self.send("GET", path, cookie, None, &[]).await
    }

    async fn login(&self, username: &str, password: &str) -> Reply {
        self.post("/api/auth/login", None, json!({ "username": username, "password": password })).await
    }
}

async fn open_state(directory: &Path, configure: impl FnOnce(&mut WebState)) -> Arc<WebState> {
    let storage = dbx_core::persistence::test_storage::open(&directory.join("storage.db")).await.unwrap();
    let app = Arc::new(dbx_core::connection::AppState::new_with_plugin_and_agent_dir_and_app_version(
        storage,
        directory.join("plugins"),
        directory.join("agents"),
        "test",
    ));
    let mut state = WebState::for_tests(app, directory.to_path_buf());
    *state.captcha_mode.get_mut() = CaptchaMode::Off;
    let env = BootstrapEnv { password: Some(ADMIN_PASSWORD.into()), ..Default::default() };
    let outcome = bootstrap_users(&state.app.storage, &env, now_millis()).await.unwrap();
    *state.users_configured.get_mut() = outcome.users_configured();
    configure(&mut state);
    Arc::new(state)
}

async fn serve(state: Arc<WebState>) -> Server {
    let router = Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/auth/captcha", get(captcha))
        .route("/api/auth/check", get(check))
        .route("/api/auth/setup", post(setup))
        .route("/api/auth/change-password", post(change_password))
        .route("/api/auth/logout", post(logout))
        .route("/api/query/execute", get(|| async { "secret" }).post(|| async { "written" }))
        .route("/api/admin/users/list", post(crate::routes::admin_users::list))
        .route("/api/admin/users/create", post(crate::routes::admin_users::create))
        .route("/api/admin/users/update", post(crate::routes::admin_users::update))
        .route("/api/admin/users/set-active", post(crate::routes::admin_users::set_active))
        .route("/api/admin/users/reset-password", post(crate::routes::admin_users::reset_password))
        .route("/api/admin/users/delete", post(crate::routes::admin_users::delete))
        .route("/api/admin/groups/create", post(crate::routes::admin_access::create_group))
        .route("/api/admin/groups/set-members", post(crate::routes::admin_access::set_group_members))
        .route("/api/admin/roles/list", post(crate::routes::admin_access::list_roles))
        .route("/api/admin/roles/create", post(crate::routes::admin_access::create_role))
        .route("/api/admin/roles/update", post(crate::routes::admin_access::update_role))
        .route("/api/admin/grants/save", post(crate::routes::admin_access::save_grant))
        .route("/api/admin/grants/list", post(crate::routes::admin_access::list_grants))
        .route("/api/admin/grants/delete", post(crate::routes::admin_access::delete_grant))
        .route("/api/admin/grants/effective", post(crate::routes::admin_access::effective))
        .route("/api/admin/connection-policies/list", post(crate::routes::admin_access::list_connection_policies))
        .route("/api/admin/connection-policies/save", post(crate::routes::admin_access::save_connection_policy))
        .route("/api/admin/audit/list", post(crate::routes::admin_audit::list))
        .route("/api/admin/audit/reveal", post(crate::routes::admin_audit::reveal))
        .route("/api/admin/audit/export", post(crate::routes::admin_audit::export))
        .route("/api/admin/sessions/list", post(crate::routes::admin_audit::list_sessions))
        .route("/api/admin/sessions/revoke", post(crate::routes::admin_audit::revoke_session))
        .route("/api/connection/list", get(crate::routes::connection::load_connections))
        .route("/api/database-backups", post(crate::routes::scheduled_backup::command))
        .route("/api/admin/identity-providers/save", post(crate::routes::admin_identity::save))
        .route("/api/admin/identity-providers/test", post(crate::routes::admin_identity::test))
        .route("/api/auth/providers", get(crate::routes::sso::list_providers))
        .route("/api/auth/oidc/{id}/start", get(crate::routes::sso::start_oidc))
        .route("/api/auth/oidc/callback", get(crate::routes::sso::oidc_callback))
        .route("/api/admin/security/captcha", post(crate::routes::admin_security::captcha_settings))
        .route("/api/admin/security/captcha/save", post(crate::routes::admin_security::save_captcha_provider))
        .route("/api/auth/mfa/verify", post(crate::routes::mfa::verify_login))
        .route("/api/auth/mfa/status", post(crate::routes::mfa::status))
        .route("/api/auth/mfa/setup", post(crate::routes::mfa::setup))
        .route("/api/auth/mfa/confirm", post(crate::routes::mfa::confirm))
        .route("/api/auth/mfa/disable", post(crate::routes::mfa::disable))
        .route("/api/admin/users/reset-mfa", post(crate::routes::admin_users::reset_mfa))
        .route("/api/admin/users/set-mfa-required", post(crate::routes::admin_users::set_mfa_required))
        .route("/api/history/save", post(crate::routes::history::save_history))
        .route("/api/history/search", post(crate::routes::history::search_history))
        .route("/api/nacos/configs/get", post(|| async { "config" }))
        .route("/api/nacos/configs/publish", post(|| async { "published" }))
        .route("/api/etcd/compact", post(|| async { "compacted" }))
        .route("/api/document-store/find-documents", post(|| async { "documents" }))
        .fallback(|| async { "handled" })
        .layer(middleware::from_fn_with_state(state.clone(), crate::engine_access::engine_access_middleware))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap()
    });
    Server { address, task, client: reqwest::Client::new() }
}

async fn create_user(state: &WebState, username: &str, password: &str, must_change_password: bool) {
    state
        .app
        .storage
        .create_web_user(
            NewWebUser {
                username: username.into(),
                display_name: None,
                password_hash: hash_password(password).unwrap(),
                role: PlatformRole::User,
                must_change_password,
            },
            now_millis(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn login_with_username_opens_a_session_that_only_stores_its_hash() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    let server = serve(state.clone()).await;

    let reply = server.login("ADMIN", ADMIN_PASSWORD).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body["user"]["username"], "admin");
    assert_eq!(reply.body["user"]["role"], "admin");
    assert_eq!(reply.body["must_change_password"], false);
    let cookie = reply.cookie.unwrap();
    let token = cookie.strip_prefix("dbx_session=").unwrap();
    assert!(state.app.storage.find_web_session(token).await.unwrap().is_none());
    assert!(state.app.storage.find_web_session(&hash_token(token)).await.unwrap().is_some());

    assert_eq!(server.get("/api/query/execute", Some(&cookie)).await.body, "secret");
    let check = server.get("/api/auth/check", Some(&cookie)).await;
    assert_eq!(check.body["authenticated"], true);
    assert_eq!(check.body["user"]["username"], "admin");
    assert!(state.app.storage.find_web_user_by_username("admin").await.unwrap().unwrap().last_login_at.is_some());
}

#[tokio::test]
async fn wrong_password_unknown_user_and_disabled_user_share_one_answer() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    create_user(&state, "ana", "ana-password", false).await;
    let ana = state.app.storage.find_web_user_by_username("ana").await.unwrap().unwrap();
    state.app.storage.set_web_user_active(&ana.id, false, now_millis()).await.unwrap();
    let server = serve(state).await;

    for (username, password) in [("admin", "wrong-password"), ("ghost", ADMIN_PASSWORD), ("ana", "ana-password")] {
        let reply = server.login(username, password).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{username}");
        assert_eq!(reply.body["error"], INVALID_CREDENTIALS);
        assert!(reply.cookie.is_none());
    }
}

#[tokio::test]
async fn repeated_failures_lock_the_login_for_a_minute() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    let server = serve(state).await;
    for _ in 0..crate::state::LOGIN_MAX_ATTEMPTS {
        assert_eq!(server.login("admin", "wrong-password").await.status, StatusCode::UNAUTHORIZED);
    }
    let locked = server.login("admin", ADMIN_PASSWORD).await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(locked.body["error"].as_str().unwrap().starts_with("Please try again in "));
}

#[tokio::test]
async fn automatic_captcha_appears_after_a_failure_for_that_user() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |state| *state.captcha_mode.get_mut() = CaptchaMode::Auto).await;
    let server = serve(state).await;
    assert_eq!(server.get("/api/auth/captcha?username=admin", None).await.status, StatusCode::NO_CONTENT);
    server.login("admin", "wrong-password").await;
    let challenge = server.get("/api/auth/captcha?username=admin", None).await;
    assert_eq!(challenge.status, StatusCode::OK);
    assert!(challenge.body["image"].as_str().unwrap().starts_with("data:image/png;base64,"));
    let reply = server.login("admin", ADMIN_PASSWORD).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.body["error"], "captcha_invalid");
}

#[tokio::test]
async fn sessions_survive_a_server_restart_until_logout() {
    let directory = tempfile::tempdir().unwrap();
    let first = serve(open_state(directory.path(), |_| {}).await).await;
    let cookie = first.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();
    drop(first);

    let restarted = serve(open_state(directory.path(), |_| {}).await).await;
    assert_eq!(restarted.get("/api/query/execute", Some(&cookie)).await.status, StatusCode::OK);
    assert_eq!(restarted.post("/api/auth/logout", Some(&cookie), json!({})).await.status, StatusCode::OK);
    let after = restarted.get("/api/query/execute", Some(&cookie)).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    assert_eq!(after.body["error"], SESSION_EXPIRED);
    drop(restarted);

    let again = serve(open_state(directory.path(), |_| {}).await).await;
    assert_eq!(again.get("/api/query/execute", Some(&cookie)).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn forced_password_change_blocks_the_api_until_done_and_revokes_other_sessions() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    create_user(&state, "ana", "initial-password", true).await;
    let server = serve(state.clone()).await;

    let other = server.login("ana", "initial-password").await.cookie.unwrap();
    let reply = server.login("ana", "initial-password").await;
    assert_eq!(reply.body["must_change_password"], true);
    let current = reply.cookie.unwrap();

    let blocked = server.get("/api/query/execute", Some(&current)).await;
    assert_eq!(blocked.status, StatusCode::FORBIDDEN);
    assert_eq!(blocked.body["error"], PASSWORD_CHANGE_REQUIRED);
    assert_eq!(server.get("/api/auth/check", Some(&current)).await.body["user"]["must_change_password"], true);

    let change = |old: &str, new: &str| json!({ "old_password": old, "new_password": new });
    let short = server.post("/api/auth/change-password", Some(&current), change("initial-password", "short")).await;
    assert_eq!((short.status, short.body["error"].clone()), (StatusCode::BAD_REQUEST, json!("password_too_short")));
    let wrong = server.post("/api/auth/change-password", Some(&current), change("nope-nope", "better-password")).await;
    assert_eq!((wrong.status, wrong.body["error"].clone()), (StatusCode::UNAUTHORIZED, json!("old_password_invalid")));
    let same =
        server.post("/api/auth/change-password", Some(&current), change("initial-password", "initial-password")).await;
    assert_eq!(same.body["error"], "password_unchanged");
    let ok =
        server.post("/api/auth/change-password", Some(&current), change("initial-password", "better-password")).await;
    assert_eq!(ok.status, StatusCode::OK);

    assert_eq!(server.get("/api/query/execute", Some(&current)).await.status, StatusCode::OK);
    assert_eq!(server.get("/api/query/execute", Some(&other)).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(server.login("ana", "initial-password").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(server.login("ana", "better-password").await.body["must_change_password"], false);
    let other_token = other.strip_prefix("dbx_session=").unwrap();
    assert!(!state.sessions.read().await.contains(other_token));
}

#[tokio::test]
async fn first_administrator_needs_the_setup_token_from_the_log() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    let empty = tempfile::tempdir().unwrap();
    let state_without_users = {
        let storage = dbx_core::persistence::test_storage::open(&empty.path().join("storage.db")).await.unwrap();
        let app = Arc::new(dbx_core::connection::AppState::new_with_plugin_and_agent_dir_and_app_version(
            storage,
            empty.path().join("plugins"),
            empty.path().join("agents"),
            "test",
        ));
        Arc::new(WebState::for_tests(app, empty.path().to_path_buf()))
    };
    drop(state);
    let server = serve(state_without_users.clone()).await;

    assert_eq!(server.get("/api/query/execute", None).await.body["error"], SETUP_REQUIRED);
    let check = server.get("/api/auth/check", None).await;
    assert_eq!(check.body["setup_required"], true);
    let token = state_without_users.setup_token.peek().unwrap();

    let attempt = |token: &str, username: &str, password: &str| json!({ "setup_token": token, "username": username, "password": password });
    let wrong = server.post("/api/auth/setup", None, attempt("guess", "boss", "boss-password")).await;
    assert_eq!((wrong.status, wrong.body["error"].clone()), (StatusCode::FORBIDDEN, json!("setup_token_invalid")));
    let weak = server.post("/api/auth/setup", None, attempt(&token, "boss", "weak")).await;
    assert_eq!(weak.body["error"], "password_too_short");
    let bad_name = server.post("/api/auth/setup", None, attempt(&token, "the boss", "boss-password")).await;
    assert_eq!(bad_name.body["error"], "username_invalid");

    let created = server.post("/api/auth/setup", None, attempt(&token, "boss", "boss-password")).await;
    assert_eq!(created.status, StatusCode::OK);
    assert_eq!(created.body["user"]["role"], "admin");
    let cookie = created.cookie.unwrap();
    assert_eq!(server.get("/api/query/execute", Some(&cookie)).await.status, StatusCode::OK);
    assert!(state_without_users.users_configured.load(Ordering::Acquire));
    assert!(state_without_users.setup_token.peek().is_none());

    let again = server.post("/api/auth/setup", None, attempt(&token, "intruder", "intruder-password")).await;
    assert_eq!(again.body["error"], "setup_not_available");
}

#[tokio::test]
async fn cross_site_writes_are_rejected_before_anything_else() {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(open_state(directory.path(), |_| {}).await).await;
    let body = json!({ "username": "admin", "password": ADMIN_PASSWORD });
    let forged =
        server.send("POST", "/api/auth/login", None, Some(body.clone()), &[("sec-fetch-site", "cross-site")]).await;
    assert_eq!((forged.status, forged.body["error"].clone()), (StatusCode::FORBIDDEN, json!(CROSS_SITE_REQUEST)));
    let foreign_origin =
        server.send("POST", "/api/auth/login", None, Some(body.clone()), &[("origin", "https://evil.example")]).await;
    assert_eq!(foreign_origin.status, StatusCode::FORBIDDEN);
    let same_origin =
        server.send("POST", "/api/auth/login", None, Some(body), &[("sec-fetch-site", "same-origin")]).await;
    assert_eq!(same_origin.status, StatusCode::OK);
    let read = server.send("GET", "/api/query/execute", None, None, &[("sec-fetch-site", "cross-site")]).await;
    assert_eq!(read.body["error"], SESSION_EXPIRED);
}

#[tokio::test]
async fn api_requires_a_valid_session() {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(open_state(directory.path(), |_| {}).await).await;
    let reply = server.get("/api/query/execute", Some("dbx_session=forged")).await;
    assert_eq!((reply.status, reply.body["error"].clone()), (StatusCode::UNAUTHORIZED, json!(SESSION_EXPIRED)));
}

#[tokio::test]
async fn disabled_password_mode_skips_login_entirely() {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(open_state(directory.path(), |state| state.password_disabled = true).await).await;
    assert_eq!(server.get("/api/query/execute", None).await.body, "secret");
    let check = server.get("/api/auth/check", None).await;
    assert_eq!((check.body["authenticated"].clone(), check.body["required"].clone()), (json!(true), json!(false)));
    assert_eq!(server.login("admin", ADMIN_PASSWORD).await.body["error"], "login_not_required");
}

async fn send_method(server: &Server, method: &str, path: &str, cookie: &str) -> Reply {
    let url = format!("http://{}{path}", server.address);
    let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
    let response = server.client.request(method, url).header("cookie", cookie).json(&json!({})).send().await.unwrap();
    let status = StatusCode::from_u16(response.status().as_u16()).unwrap();
    let text = response.text().await.unwrap();
    Reply { status, cookie: None, body: serde_json::from_str(&text).unwrap_or(Value::String(text)) }
}

#[tokio::test]
async fn a_regular_user_gets_admin_required_on_every_admin_route() {
    use crate::route_policy::test_support::{concrete, registered_routes};
    use crate::route_policy::{classify, RouteClass};

    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    create_user(&state, "ana", "ana-password", false).await;
    let server = serve(state).await;
    let user = server.login("ana", "ana-password").await.cookie.unwrap();
    let admin = server.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();

    let mut checked = 0;
    for route in registered_routes() {
        if route.starts_with("/admin/") {
            continue;
        }
        let path = concrete(&route);
        for method in ["GET", "POST", "PUT", "DELETE"] {
            let parsed = axum::http::Method::from_bytes(method.as_bytes()).unwrap();
            if classify(&parsed, &path) != Some(RouteClass::Admin) {
                continue;
            }
            let denied = send_method(&server, method, &format!("/api/{path}"), &user).await;
            assert_eq!(
                (denied.status, denied.body["error"].clone()),
                (StatusCode::FORBIDDEN, json!(ADMIN_REQUIRED)),
                "{method} {route}"
            );
            let allowed = send_method(&server, method, &format!("/api/{path}"), &admin).await;
            assert_ne!(allowed.status, StatusCode::FORBIDDEN, "{method} {route}: {:?}", allowed.body);
            checked += 1;
        }
    }
    assert!(checked > 50, "only {checked} admin routes were checked");

    for path in ["list", "create", "update", "set-active", "reset-password", "delete"] {
        let denied = server.post(&format!("/api/admin/users/{path}"), Some(&user), json!({})).await;
        assert_eq!(denied.body["error"], ADMIN_REQUIRED, "{path}");
    }
    assert_eq!(server.post("/api/query/execute", Some(&user), json!({})).await.body, "written");
}

#[tokio::test]
async fn unclassified_routes_are_rejected_even_for_admins() {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(open_state(directory.path(), |_| {}).await).await;
    let admin = server.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();
    let reply = server.post("/api/brand-new/feature", Some(&admin), json!({})).await;
    assert_eq!((reply.status, reply.body["error"].clone()), (StatusCode::FORBIDDEN, json!(ROUTE_NOT_CLASSIFIED)));
}

#[tokio::test]
async fn administrators_manage_the_full_user_lifecycle() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    let server = serve(state.clone()).await;
    let admin = server.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();

    let created = server
        .post(
            "/api/admin/users/create",
            Some(&admin),
            json!({ "username": "ana", "display_name": " Ana ", "role": "user" }),
        )
        .await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.body["user"]["display_name"], "Ana");
    assert_eq!(created.body["user"]["must_change_password"], true);
    let temporary = created.body["temporary_password"].as_str().unwrap().to_string();
    let ana_id = created.body["user"]["id"].as_str().unwrap().to_string();

    let duplicate =
        server.post("/api/admin/users/create", Some(&admin), json!({ "username": "ANA", "role": "user" })).await;
    assert_eq!((duplicate.status, duplicate.body["error"].clone()), (StatusCode::CONFLICT, json!("username_taken")));
    let weak = server
        .post(
            "/api/admin/users/create",
            Some(&admin),
            json!({ "username": "bob", "role": "user", "password": "short" }),
        )
        .await;
    assert_eq!(weak.body["error"], "password_too_short");
    let chosen = server
        .post(
            "/api/admin/users/create",
            Some(&admin),
            json!({ "username": "bob", "role": "user", "password": "bob-password", "must_change_password": false }),
        )
        .await;
    assert!(chosen.body.get("temporary_password").is_none());
    assert_eq!(chosen.body["user"]["must_change_password"], false);

    let listed = server.post("/api/admin/users/list", Some(&admin), json!({})).await;
    let names: Vec<&str> =
        listed.body.as_array().unwrap().iter().map(|user| user["username"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["admin", "ana", "bob"]);

    let ana = server.login("ana", &temporary).await;
    assert_eq!(ana.body["must_change_password"], true);
    let ana_cookie = ana.cookie.unwrap();

    let promoted = server
        .post(
            "/api/admin/users/update",
            Some(&admin),
            json!({ "id": ana_id, "display_name": "Ana P.", "role": "admin" }),
        )
        .await;
    assert_eq!(promoted.body["role"], "admin");
    assert_eq!(server.get("/api/auth/check", Some(&ana_cookie)).await.body["user"]["role"], "admin");

    let disabled =
        server.post("/api/admin/users/set-active", Some(&admin), json!({ "id": ana_id, "active": false })).await;
    assert_eq!(disabled.body["active"], false);
    assert_eq!(server.get("/api/auth/check", Some(&ana_cookie)).await.body["authenticated"], false);
    assert_eq!(server.login("ana", &temporary).await.status, StatusCode::UNAUTHORIZED);
    server.post("/api/admin/users/set-active", Some(&admin), json!({ "id": ana_id, "active": true })).await;

    let reset = server.post("/api/admin/users/reset-password", Some(&admin), json!({ "id": ana_id })).await;
    let second_temporary = reset.body["temporary_password"].as_str().unwrap().to_string();
    assert_ne!(second_temporary, temporary);
    assert_eq!(server.login("ana", &temporary).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(server.login("ana", &second_temporary).await.body["must_change_password"], true);

    let deleted = server.post("/api/admin/users/delete", Some(&admin), json!({ "id": ana_id })).await;
    assert_eq!(deleted.status, StatusCode::OK);
    assert_eq!(server.login("ana", &second_temporary).await.status, StatusCode::UNAUTHORIZED);
    let missing = server.post("/api/admin/users/delete", Some(&admin), json!({ "id": ana_id })).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn administrators_cannot_lock_themselves_out() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    let server = serve(state.clone()).await;
    let admin = server.login("admin", ADMIN_PASSWORD).await;
    let admin_id = admin.body["user"]["id"].as_str().unwrap().to_string();
    let cookie = admin.cookie.unwrap();

    for (path, body) in [
        ("set-active", json!({ "id": admin_id, "active": false })),
        ("reset-password", json!({ "id": admin_id })),
        ("delete", json!({ "id": admin_id })),
        ("update", json!({ "id": admin_id, "role": "user" })),
    ] {
        let reply = server.post(&format!("/api/admin/users/{path}"), Some(&cookie), body).await;
        assert_eq!(
            (reply.status, reply.body["error"].clone()),
            (StatusCode::CONFLICT, json!("self_modification_not_allowed")),
            "{path}"
        );
    }
    let renamed = server
        .post(
            "/api/admin/users/update",
            Some(&cookie),
            json!({ "id": admin_id, "display_name": "Root", "role": "admin" }),
        )
        .await;
    assert_eq!(renamed.body["display_name"], "Root");
}

async fn save_sqlite_connection(state: &WebState, id: &str, directory: &Path) {
    let path = directory.join(format!("{id}.db"));
    let config: dbx_core::models::connection::ConnectionConfig = serde_json::from_value(json!({
        "id": id, "name": id, "db_type": "sqlite", "host": path.to_str().unwrap(),
        "port": 0, "username": "", "password": "", "database": null,
        "one_time": false, "save_password": false, "read_only": false
    }))
    .unwrap();
    let mut existing = state.app.storage.load_connections().await.unwrap();
    existing.push(config);
    state.app.storage.save_connections(&existing).await.unwrap();
}

fn connection_ids(reply: &Reply) -> Vec<String> {
    let mut ids: Vec<String> = reply
        .body
        .as_array()
        .unwrap()
        .iter()
        .map(|connection| connection["id"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn grants_managed_through_the_api_decide_which_connections_each_user_sees() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    state.app.authz.set_enforced(true);
    create_user(&state, "ana", "ana-password", false).await;
    create_user(&state, "bob", "bob-password", false).await;
    save_sqlite_connection(&state, "ventas", directory.path()).await;
    save_sqlite_connection(&state, "rrhh", directory.path()).await;
    let server = serve(state.clone()).await;
    let admin = server.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();
    let ana = server.login("ana", "ana-password").await.cookie.unwrap();
    let bob = server.login("bob", "bob-password").await.cookie.unwrap();
    let ana_id = state.app.storage.find_web_user_by_username("ana").await.unwrap().unwrap().id;

    assert_eq!(connection_ids(&server.get("/api/connection/list", Some(&admin)).await), vec!["rrhh", "ventas"]);
    assert!(connection_ids(&server.get("/api/connection/list", Some(&ana)).await).is_empty());

    let group = server.post("/api/admin/groups/create", Some(&admin), json!({ "name": "Ventas" })).await;
    let group_id = group.body["id"].as_str().unwrap().to_string();
    server.post("/api/admin/groups/set-members", Some(&admin), json!({ "id": group_id, "user_ids": [ana_id] })).await;
    let saved = server
        .post(
            "/api/admin/grants/save",
            Some(&admin),
            json!({
                "subject": { "kind": "group", "id": group_id },
                "scope": { "kind": "resource", "value": { "connectionId": "ventas" } },
                "effect": "allow",
                "role_id": "builtin:reader"
            }),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);

    assert_eq!(connection_ids(&server.get("/api/connection/list", Some(&ana)).await), vec!["ventas"]);
    assert!(connection_ids(&server.get("/api/connection/list", Some(&bob)).await).is_empty());

    let effective = server
        .post("/api/admin/grants/effective", Some(&admin), json!({ "user_id": ana_id, "connection_id": "ventas" }))
        .await;
    assert_eq!(effective.body["visible"], true);
    assert_eq!(effective.body["connection_operations"], json!(["SELECT"]));
    assert_eq!(effective.body["rules"][0]["via_group"], json!(group_id));

    let grant_id = saved.body["id"].as_str().unwrap().to_string();
    server.post("/api/admin/grants/delete", Some(&admin), json!({ "id": grant_id })).await;
    assert!(connection_ids(&server.get("/api/connection/list", Some(&ana)).await).is_empty());
}

#[tokio::test]
async fn custom_roles_and_grant_validation() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    save_sqlite_connection(&state, "ventas", directory.path()).await;
    state.app.configs.write().await.extend(
        state.app.storage.load_connections().await.unwrap().into_iter().map(|config| (config.id.clone(), config)),
    );
    let server = serve(state.clone()).await;
    let admin = server.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();

    let roles = server.post("/api/admin/roles/list", Some(&admin), json!({})).await;
    assert_eq!(roles.body.as_array().unwrap().len(), 6);
    let bad =
        server.post("/api/admin/roles/create", Some(&admin), json!({ "name": "X", "operations": ["SELEKT"] })).await;
    assert_eq!(bad.body["error"], "operation_invalid");
    let role = server
        .post("/api/admin/roles/create", Some(&admin), json!({ "name": "Auditor", "operations": ["select", "EXPORT"] }))
        .await;
    assert_eq!(role.body["operations"], json!(["SELECT", "EXPORT"]));
    let builtin = server
        .post("/api/admin/roles/update", Some(&admin), json!({ "id": "builtin:reader", "name": "x", "operations": [] }))
        .await;
    assert_eq!(builtin.body["error"], "role_builtin");

    let ghost = server
        .post(
            "/api/admin/grants/save",
            Some(&admin),
            json!({ "subject": { "kind": "user", "id": "ghost" }, "scope": { "kind": "all" }, "effect": "allow", "operations": ["SELECT"] }),
        )
        .await;
    assert_eq!(ghost.body["error"], "subject_not_found");
    let unknown_connection = server
        .post(
            "/api/admin/grants/save",
            Some(&admin),
            json!({ "subject": { "kind": "system" }, "scope": { "kind": "resource", "value": { "connectionId": "nope" } }, "effect": "allow", "operations": ["SELECT"] }),
        )
        .await;
    assert_eq!(unknown_connection.body["error"], "connection_not_found");
    let incoherent = server
        .post(
            "/api/admin/grants/save",
            Some(&admin),
            json!({ "subject": { "kind": "system" }, "scope": { "kind": "resource", "value": { "connectionId": "ventas", "schema": "s" } }, "effect": "allow", "operations": ["SELECT"] }),
        )
        .await;
    assert_eq!(incoherent.body["error"], "grant_invalid");
    let already_expired = server
        .post(
            "/api/admin/grants/save",
            Some(&admin),
            json!({ "subject": { "kind": "system" }, "scope": { "kind": "resource", "value": { "connectionId": "ventas" } }, "effect": "allow", "operations": ["SELECT"], "expires_at": now_millis() - 1000 }),
        )
        .await;
    assert_eq!(already_expired.body["error"], "grant_expiry_past");
    let system = server
        .post(
            "/api/admin/grants/save",
            Some(&admin),
            json!({ "subject": { "kind": "system" }, "scope": { "kind": "resource", "value": { "connectionId": "ventas", "database": "main" } }, "effect": "allow", "role_id": role.body["id"] }),
        )
        .await;
    assert_eq!(system.status, StatusCode::OK, "{:?}", system.body);
    let listed = server.post("/api/admin/grants/list", Some(&admin), json!({ "subject": { "kind": "system" } })).await;
    assert_eq!(listed.body.as_array().unwrap().len(), 1);
}

fn backup_schedule(id: &str, connection_id: &str, destination: &Path) -> Value {
    json!({
        "action": "save",
        "schedule": {
            "id": id, "name": "Nightly", "enabled": true, "connectionId": connection_id, "databases": ["main"],
            "destinationDirectory": destination.to_string_lossy(), "includeStructure": true, "includeData": true,
            "includeObjects": true, "frequency": "daily", "intervalHours": 1, "timeOfDay": "02:30", "weekday": 0,
            "retentionCount": 2, "timeZone": "UTC", "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-01T00:00:00Z", "nextRunAt": "2026-01-01T00:00:00Z"
        }
    })
}

#[tokio::test]
async fn scheduled_backups_need_owner_and_system_access_and_keep_their_owner() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    state.app.authz.set_enforced(true);
    save_sqlite_connection(&state, "ventas", directory.path()).await;
    state.app.configs.write().await.extend(
        state.app.storage.load_connections().await.unwrap().into_iter().map(|config| (config.id.clone(), config)),
    );
    let destination = directory.path().join("backups").join("nightly");
    std::fs::create_dir_all(&destination).unwrap();
    let server = serve(state.clone()).await;
    let admin = server.login("admin", ADMIN_PASSWORD).await;
    let admin_id = admin.body["user"]["id"].as_str().unwrap().to_string();
    let cookie = admin.cookie.unwrap();

    let denied =
        server.post("/api/database-backups", Some(&cookie), backup_schedule("nightly", "ventas", &destination)).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN, "{:?}", denied.body);
    assert!(denied.body.to_string().contains("system principal"), "{:?}", denied.body);

    server
        .post(
            "/api/admin/grants/save",
            Some(&cookie),
            json!({ "subject": { "kind": "system" }, "scope": { "kind": "resource", "value": { "connectionId": "ventas" } }, "effect": "allow", "operations": ["SELECT", "EXPORT"] }),
        )
        .await;
    let saved =
        server.post("/api/database-backups", Some(&cookie), backup_schedule("nightly", "ventas", &destination)).await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);
    assert_eq!(saved.body["ownerUserId"], json!(admin_id));

    create_user(&state, "ana", "ana-password", false).await;
    let ana_id = state.app.storage.find_web_user_by_username("ana").await.unwrap().unwrap().id;
    let reassigned = server
        .post(
            "/api/database-backups",
            Some(&cookie),
            json!({ "action": "setOwner", "id": "nightly", "ownerUserId": ana_id }),
        )
        .await;
    assert_eq!(reassigned.body["ownerUserId"], json!(ana_id));
    let missing = server
        .post(
            "/api/database-backups",
            Some(&cookie),
            json!({ "action": "setOwner", "id": "nightly", "ownerUserId": "ghost" }),
        )
        .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);

    let resaved =
        server.post("/api/database-backups", Some(&cookie), backup_schedule("nightly", "ventas", &destination)).await;
    assert_eq!(
        resaved.status,
        StatusCode::FORBIDDEN,
        "ana has no access, so the owner check must fail: {:?}",
        resaved.body
    );
    assert!(resaved.body.to_string().contains("backup owner"), "{:?}", resaved.body);

    let ana = state.app.storage.find_web_user_by_username("ana").await.unwrap().unwrap();
    state.app.storage.set_web_user_active(&ana.id, false, now_millis()).await.unwrap();
    let snapshot = crate::routes::scheduled_backup::service(&state).unwrap().store.snapshot().await.unwrap();
    assert!(snapshot.schedules[0].enabled, "disabling the owner must not pause the schedule");
}

#[tokio::test]
async fn existing_backups_are_migrated_to_system_access_once() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    save_sqlite_connection(&state, "ventas", directory.path()).await;
    let destination = directory.path().join("backups").join("nightly");
    std::fs::create_dir_all(&destination).unwrap();
    let service = crate::routes::scheduled_backup::service(&state).unwrap();
    let command: dbx_core::scheduled_backup::BackupCommand =
        serde_json::from_value(backup_schedule("nightly", "ventas", &destination)).unwrap();
    service.command(command).await.unwrap();

    crate::routes::scheduled_backup::migrate_backup_access(&state, &service).await.unwrap();
    let grants = state.app.storage.list_grants().await.unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].subject, dbx_authz::Subject::System);
    let schedule = service.store.snapshot().await.unwrap().schedules.remove(0);
    let admin = state.app.storage.find_web_user_by_username("admin").await.unwrap().unwrap();
    assert_eq!(schedule.owner_user_id, Some(admin.id));

    state.app.storage.delete_grant(&grants[0].id).await.unwrap();
    crate::routes::scheduled_backup::migrate_backup_access(&state, &service).await.unwrap();
    assert!(state.app.storage.list_grants().await.unwrap().is_empty(), "the migration runs only once");
}

#[tokio::test]
async fn connection_policies_are_validated_and_listed() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    save_sqlite_connection(&state, "ventas", directory.path()).await;
    state.app.configs.write().await.extend(
        state.app.storage.load_connections().await.unwrap().into_iter().map(|config| (config.id.clone(), config)),
    );
    let server = serve(state.clone()).await;
    let admin = server.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();
    let save = |body: Value| server.post("/api/admin/connection-policies/save", Some(&admin), body);
    let invalid =
        save(json!({ "connection_id": "ventas", "strict_function_mode": true, "function_allowlist": ["drop table;"] }))
            .await;
    assert_eq!(invalid.body["error"], "function_allowlist_invalid");
    let unknown = save(json!({ "connection_id": "nope", "strict_function_mode": true })).await;
    assert_eq!(unknown.body["error"], "connection_not_found");
    let saved = save(json!({ "connection_id": "ventas", "strict_function_mode": true, "function_allowlist": [" Sales.Score ", "sales.score", "fmt"] })).await;
    assert_eq!(saved.body["function_allowlist"], json!(["fmt", "sales.score"]));
    let listed = server.post("/api/admin/connection-policies/list", Some(&admin), json!({})).await;
    assert_eq!(listed.body[0]["strict_function_mode"], true);
    assert_eq!(
        state.app.authz.snapshot().strict_functions.get("ventas"),
        Some(&vec!["fmt".to_string(), "sales.score".to_string()])
    );
}

async fn audit_rows(state: &WebState, expected: usize) -> Vec<dbx_core::storage::AuditEntry> {
    for _ in 0..300 {
        let rows = state
            .app
            .storage
            .list_audit_events(dbx_core::storage::AuditFilter { limit: 200, ..Default::default() })
            .await
            .unwrap();
        if rows.len() >= expected {
            return rows;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("audit events were not written");
}

#[tokio::test]
async fn sign_ins_and_administrative_changes_are_audited() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    state.app.authz.set_enforced(true);
    state.app.audit.start(state.app.storage.clone(), None);
    create_user(&state, "ana", "ana-password", false).await;
    save_sqlite_connection(&state, "ventas", directory.path()).await;
    let server = serve(state.clone()).await;

    assert_eq!(server.login("ana", "wrong-password").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(server.login("nobody", "wrong-password").await.status, StatusCode::UNAUTHORIZED);
    let admin = server.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();
    let ana = server.login("ana", "ana-password").await.cookie.unwrap();
    let ana_id = state.app.storage.find_web_user_by_username("ana").await.unwrap().unwrap().id;
    server.get("/api/connection/list", Some(&admin)).await;
    let saved = server
        .post(
            "/api/admin/grants/save",
            Some(&admin),
            json!({
                "subject": { "kind": "user", "id": ana_id },
                "scope": { "kind": "resource", "value": { "connectionId": "ventas" } },
                "effect": "deny",
                "operations": ["DELETE"]
            }),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);
    server.post("/api/admin/users/create", Some(&admin), json!({ "username": "bob", "role": "user" })).await;
    let changed = server
        .post(
            "/api/auth/change-password",
            Some(&ana),
            json!({ "old_password": "ana-password", "new_password": "ana-password-2" }),
        )
        .await;
    assert_eq!(changed.status, StatusCode::OK, "{:?}", changed.body);
    assert_eq!(server.post("/api/auth/logout", Some(&ana), json!({})).await.status, StatusCode::OK);

    let rows = audit_rows(&state, 8).await;
    let find = |event: &str| rows.iter().filter(|row| row.event == event).collect::<Vec<_>>();
    let failed = find("login_failed");
    assert_eq!(failed.len(), 2, "{rows:?}");
    assert!(failed.iter().all(|row| row.reason.as_deref() == Some("invalid_credentials")));
    assert!(failed.iter().all(|row| row.ip.as_deref() == Some("127.0.0.1")));
    assert!(failed.iter().any(|row| row.username.as_deref() == Some("nobody")));
    let succeeded = find("login_succeeded");
    assert_eq!(succeeded.len(), 2);
    let admin_login = succeeded.iter().find(|row| row.username.as_deref() == Some("admin")).unwrap();
    let admin_token = admin.split_once('=').unwrap().1;
    assert_eq!(admin_login.session_ref.as_deref(), Some(&crate::sessions::hash_token(admin_token)[..16]));

    let grant = find("grant_saved");
    assert_eq!(grant.len(), 1);
    assert_eq!(grant[0].username.as_deref(), Some("admin"));
    assert_eq!(grant[0].ip.as_deref(), Some("127.0.0.1"));
    let detail: Value = serde_json::from_str(grant[0].detail.as_deref().unwrap()).unwrap();
    assert_eq!(detail["effect"], "deny");
    assert_eq!(detail["operations"], json!(["DELETE"]));
    let created = find("user_created");
    let detail: Value = serde_json::from_str(created[0].detail.as_deref().unwrap()).unwrap();
    assert_eq!(detail["username"], "bob");
    assert!(!created[0].detail.as_deref().unwrap().contains("temporary"));
    assert_eq!(find("password_changed")[0].user_id.as_deref(), Some(ana_id.as_str()));
    assert_eq!(find("logout")[0].username.as_deref(), Some("ana"));
}

fn audited_statement(user_id: &str, statement: &str, denied: bool) -> dbx_core::audit::AuditEvent {
    let principal =
        dbx_authz::Principal::User { user_id: user_id.into(), groups: Vec::new(), role: PlatformRole::User };
    let event = dbx_core::audit::AuditEvent::new("sql")
        .by(&principal)
        .connection("ventas")
        .operations(dbx_authz::Operations::UPDATE)
        .statement(statement);
    if denied {
        event.denied("Permission denied: UPDATE required on crm")
    } else {
        event.allowed()
    }
}

#[tokio::test]
async fn administrators_search_reveal_and_export_the_audit_log() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    state.app.authz.set_enforced(true);
    state.app.audit.start(state.app.storage.clone(), None);
    create_user(&state, "ana", "ana-password", false).await;
    let ana_id = state.app.storage.find_web_user_by_username("ana").await.unwrap().unwrap().id;
    state
        .app
        .storage
        .insert_audit_events(vec![
            audited_statement(&ana_id, "UPDATE accounts SET plan = 'gold'", false),
            audited_statement(&ana_id, "=HYPERLINK(\"x\")", true),
        ])
        .await
        .unwrap();
    let server = serve(state.clone()).await;
    let admin = server.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();
    let ana = server.login("ana", "ana-password").await.cookie.unwrap();

    assert_eq!(server.post("/api/admin/audit/list", Some(&ana), json!({})).await.status, StatusCode::FORBIDDEN);
    let denied = server.post("/api/admin/audit/list", Some(&admin), json!({ "decision": "deny" })).await;
    assert_eq!(denied.status, StatusCode::OK, "{:?}", denied.body);
    let entries = denied.body["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["username"], "ana");
    assert_eq!(entries[0]["operations"], json!(["UPDATE"]));
    assert_eq!(entries[0]["has_statement"], true);
    assert!(entries[0].get("statement").is_none());

    let found = server
        .post("/api/admin/audit/list", Some(&admin), json!({ "statement": "UPDATE accounts SET plan = 'gold'" }))
        .await;
    let found = found.body["entries"].as_array().unwrap().clone();
    assert_eq!(found.len(), 1);
    let event_id = found[0]["event_id"].as_str().unwrap().to_string();
    let page = server.post("/api/admin/audit/list", Some(&admin), json!({ "event": "sql", "limit": 1 })).await;
    assert_eq!(page.body["entries"].as_array().unwrap().len(), 1);
    let before = page.body["next_before_id"].as_i64().unwrap();
    let rest = server
        .post("/api/admin/audit/list", Some(&admin), json!({ "event": "sql", "limit": 1, "before_id": before }))
        .await;
    assert_ne!(rest.body["entries"][0]["id"], page.body["entries"][0]["id"]);
    let invalid = server.post("/api/admin/audit/list", Some(&admin), json!({ "decision": "maybe" })).await;
    assert_eq!(invalid.body["error"], "audit_filter_invalid");

    let revealed = server.post("/api/admin/audit/reveal", Some(&admin), json!({ "event_id": event_id })).await;
    assert_eq!(revealed.body["statement"], "UPDATE accounts SET plan = 'gold'");
    let missing = server.post("/api/admin/audit/reveal", Some(&admin), json!({ "event_id": "nope" })).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);

    let plain = server.post("/api/admin/audit/export", Some(&admin), json!({ "event": "sql" })).await;
    let plain = plain.body.as_str().unwrap().to_string();
    assert!(plain.starts_with("id,event_id,timestamp,"));
    assert_eq!(plain.lines().count(), 3);
    assert!(!plain.contains("gold"));
    let full = server
        .post("/api/admin/audit/export", Some(&admin), json!({ "event": "sql", "include_statements": true }))
        .await;
    let full = full.body.as_str().unwrap().to_string();
    assert!(full.contains("UPDATE accounts SET plan = 'gold'"));
    assert!(full.contains("\"'=HYPERLINK(\"\"x\"\")\""), "{full}");

    let rows = audit_rows(&state, 6).await;
    let revealed_events: Vec<_> = rows.iter().filter(|row| row.event == "audit_revealed").collect();
    assert_eq!(revealed_events.len(), 1);
    assert_eq!(revealed_events[0].username.as_deref(), Some("admin"));
    let exports: Vec<_> = rows.iter().filter(|row| row.event == "audit_exported").collect();
    assert_eq!(exports.len(), 2);
    assert!(exports.iter().any(|row| row.detail.as_deref().unwrap().contains("\"include_statements\":true")));
}

#[tokio::test]
async fn administrators_list_and_revoke_sessions() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    state.app.audit.start(state.app.storage.clone(), None);
    create_user(&state, "ana", "ana-password", false).await;
    let server = serve(state.clone()).await;
    let admin = server.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();
    let ana_first = server.login("ana", "ana-password").await.cookie.unwrap();
    let ana_second = server.login("ana", "ana-password").await.cookie.unwrap();
    let ana_id = state.app.storage.find_web_user_by_username("ana").await.unwrap().unwrap().id;

    let listed = server.post("/api/admin/sessions/list", Some(&admin), json!({})).await;
    let sessions = listed.body.as_array().unwrap().clone();
    assert_eq!(sessions.len(), 3);
    let own = sessions.iter().find(|session| session["current"] == true).unwrap();
    assert_eq!(own["username"], "admin");
    assert_eq!(own["ip"], "127.0.0.1");
    let own_id = own["id"].as_str().unwrap().to_string();
    assert_eq!(own["session_ref"].as_str().unwrap(), &own_id[..16]);
    let self_revoke = server.post("/api/admin/sessions/revoke", Some(&admin), json!({ "id": own_id })).await;
    assert_eq!(self_revoke.body["error"], "self_modification_not_allowed");

    let first_hash = crate::sessions::hash_token(ana_first.split_once('=').unwrap().1);
    let revoked = server.post("/api/admin/sessions/revoke", Some(&admin), json!({ "id": first_hash })).await;
    assert_eq!(revoked.body["revoked"], 1);
    assert_eq!(server.get("/api/query/execute", Some(&ana_first)).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(server.get("/api/query/execute", Some(&ana_second)).await.status, StatusCode::OK);
    let again = server.post("/api/admin/sessions/revoke", Some(&admin), json!({ "id": first_hash })).await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);

    let only_ana = server.post("/api/admin/sessions/list", Some(&admin), json!({ "user_id": ana_id })).await;
    assert_eq!(only_ana.body.as_array().unwrap().len(), 1);
    let all = server.post("/api/admin/sessions/revoke", Some(&admin), json!({ "user_id": ana_id })).await;
    assert_eq!(all.body["revoked"], 1);
    assert_eq!(server.get("/api/query/execute", Some(&ana_second)).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(server.get("/api/query/execute", Some(&admin)).await.status, StatusCode::OK);

    let rows = audit_rows(&state, 5).await;
    assert!(rows.iter().any(|row| row.event == "session_revoked"));
    assert!(rows.iter().any(|row| row.event == "user_sessions_revoked"));
}

#[tokio::test]
async fn non_sql_engines_require_the_operation_of_each_action() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    state.app.authz.set_enforced(true);
    create_user(&state, "ana", "ana-password", false).await;
    create_user(&state, "bob", "bob-password", false).await;
    create_user(&state, "eva", "eva-password", false).await;
    save_sqlite_connection(&state, "nacos", directory.path()).await;
    save_sqlite_connection(&state, "docs", directory.path()).await;
    let server = serve(state.clone()).await;
    let admin = server.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();
    let ana = server.login("ana", "ana-password").await.cookie.unwrap();
    let bob = server.login("bob", "bob-password").await.cookie.unwrap();
    let eva = server.login("eva", "eva-password").await.cookie.unwrap();
    server.get("/api/connection/list", Some(&admin)).await;
    for (user, connection, role, database) in [
        ("ana", "nacos", "builtin:reader", None),
        ("eva", "nacos", "builtin:editor", None),
        ("ana", "docs", "builtin:reader", Some("app")),
    ] {
        let id = state.app.storage.find_web_user_by_username(user).await.unwrap().unwrap().id;
        let mut value = json!({ "connectionId": connection });
        if let Some(database) = database {
            value["database"] = json!(database);
        }
        let saved = server
            .post(
                "/api/admin/grants/save",
                Some(&admin),
                json!({
                    "subject": { "kind": "user", "id": id },
                    "scope": { "kind": "resource", "value": value },
                    "effect": "allow",
                    "role_id": role
                }),
            )
            .await;
        assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);
    }
    let call = |path: &'static str, cookie: String, body: Value| {
        let server = &server;
        async move { server.post(path, Some(&cookie), body).await }
    };
    let nacos = json!({ "connectionId": "nacos", "dataId": "app.yaml" });

    assert_eq!(call("/api/nacos/configs/get", ana.clone(), nacos.clone()).await.body, "config");
    let denied = call("/api/nacos/configs/publish", ana.clone(), nacos.clone()).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert!(denied.body.to_string().contains("INSERT, UPDATE required on nacos"), "{:?}", denied.body);
    assert_eq!(call("/api/nacos/configs/publish", eva.clone(), nacos.clone()).await.body, "published");
    assert_eq!(call("/api/nacos/configs/get", bob.clone(), nacos.clone()).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        call("/api/etcd/compact", eva.clone(), json!({ "connectionId": "nacos" })).await.status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(call("/api/etcd/compact", admin.clone(), json!({ "connectionId": "nacos" })).await.body, "compacted");
    assert_eq!(call("/api/nacos/configs/get", ana.clone(), json!({})).await.status, StatusCode::FORBIDDEN);

    let docs = |database: &str| json!({ "connectionId": "docs", "database": database, "collection": "orders" });
    assert_eq!(call("/api/document-store/find-documents", ana.clone(), docs("app")).await.body, "documents");
    assert_eq!(
        call("/api/document-store/find-documents", ana.clone(), docs("billing")).await.status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn each_user_only_sees_their_own_query_history() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    state.app.authz.set_enforced(true);
    state.app.storage.enable_user_scoped_data();
    create_user(&state, "ana", "ana-password", false).await;
    create_user(&state, "bob", "bob-password", false).await;
    let server = serve(state.clone()).await;
    let admin = server.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();
    let ana = server.login("ana", "ana-password").await.cookie.unwrap();
    let bob = server.login("bob", "bob-password").await.cookie.unwrap();
    let entry = |id: &str| {
        json!({ "entry": {
            "id": id, "connection_id": "c1", "connection_name": "Sales", "database": "crm",
            "sql": format!("SELECT '{id}'"), "executed_at": format!("2026-01-01T00:00:0{}", id.len()),
            "execution_time_ms": 1, "success": true, "error": null
        } })
    };
    assert_eq!(server.post("/api/history/save", Some(&ana), entry("ana-1")).await.status, StatusCode::OK);
    assert_eq!(server.post("/api/history/save", Some(&bob), entry("bob-12")).await.status, StatusCode::OK);
    let overwrite = server.post("/api/history/save", Some(&bob), entry("ana-1")).await;
    assert_ne!(overwrite.status, StatusCode::OK);

    let ids = |reply: Reply| -> Vec<String> {
        reply.body["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["id"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(ids(server.post("/api/history/search", Some(&ana), json!({})).await), vec!["ana-1"]);
    assert_eq!(ids(server.post("/api/history/search", Some(&bob), json!({})).await), vec!["bob-12"]);
    assert!(ids(server.post("/api/history/search", Some(&admin), json!({})).await).is_empty());
}

fn totp_code(secret: &str, offset: i64) -> String {
    let key = data_encoding::BASE32_NOPAD.decode(secret.as_bytes()).unwrap();
    format!("{:06}", crate::mfa::code_at(&key, crate::mfa::step_at(now_millis()) + offset))
}

#[tokio::test]
async fn two_factor_enrollment_login_recovery_and_policy() {
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    create_user(&state, "ana", "ana-password", false).await;
    create_user(&state, "bob", "bob-password", false).await;
    let server = serve(state.clone()).await;
    let admin = server.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();
    let ana = server.login("ana", "ana-password").await.cookie.unwrap();

    let setup = server.post("/api/auth/mfa/setup", Some(&ana), json!({})).await;
    assert_eq!(setup.status, StatusCode::OK, "{:?}", setup.body);
    let secret = setup.body["secret"].as_str().unwrap().to_string();
    assert!(setup.body["otpauth_uri"].as_str().unwrap().starts_with("otpauth://totp/DBX:ana?secret="));
    let wrong = server.post("/api/auth/mfa/confirm", Some(&ana), json!({ "code": "000000" })).await;
    assert_eq!(wrong.body["error"], "mfa_code_invalid");
    let confirmed = server.post("/api/auth/mfa/confirm", Some(&ana), json!({ "code": totp_code(&secret, 0) })).await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.body);
    let recovery: Vec<String> = confirmed.body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap().to_string())
        .collect();
    assert_eq!(recovery.len(), 10);
    let status = server.post("/api/auth/mfa/status", Some(&ana), json!({})).await;
    assert_eq!(status.body["enabled"], true);
    assert_eq!(status.body["recovery_codes_left"], 10);

    let first = server.login("ana", "ana-password").await;
    assert_eq!(first.status, StatusCode::OK);
    assert!(first.cookie.is_none());
    assert_eq!(first.body["mfa_required"], true);
    let challenge = first.body["challenge"].as_str().unwrap().to_string();
    let reused = server
        .post("/api/auth/mfa/verify", None, json!({ "challenge": challenge, "code": totp_code(&secret, 0) }))
        .await;
    assert_eq!(reused.body["error"], "mfa_code_invalid");
    let verified = server
        .post("/api/auth/mfa/verify", None, json!({ "challenge": challenge, "code": totp_code(&secret, 1) }))
        .await;
    assert_eq!(verified.status, StatusCode::OK, "{:?}", verified.body);
    assert!(verified.cookie.is_some());
    let replayed = server
        .post("/api/auth/mfa/verify", None, json!({ "challenge": challenge, "code": totp_code(&secret, 1) }))
        .await;
    assert_eq!(replayed.body["error"], "mfa_challenge_expired");

    let second = server.login("ana", "ana-password").await.body["challenge"].as_str().unwrap().to_string();
    let with_recovery = server
        .post("/api/auth/mfa/verify", None, json!({ "challenge": second, "code": recovery[0].to_uppercase() }))
        .await;
    assert!(with_recovery.cookie.is_some(), "{:?}", with_recovery.body);
    let third = server.login("ana", "ana-password").await.body["challenge"].as_str().unwrap().to_string();
    let spent = server.post("/api/auth/mfa/verify", None, json!({ "challenge": third, "code": recovery[0] })).await;
    assert_eq!(spent.body["error"], "mfa_code_invalid");

    let ana_id = state.app.storage.find_web_user_by_username("ana").await.unwrap().unwrap().id;
    let bob_id = state.app.storage.find_web_user_by_username("bob").await.unwrap().unwrap().id;
    server.post("/api/admin/users/set-mfa-required", Some(&admin), json!({ "id": bob_id, "required": true })).await;
    let bob = server.login("bob", "bob-password").await;
    assert_eq!(bob.body["mfa_setup_required"], true);
    let bob = bob.cookie.unwrap();
    assert_eq!(server.get("/api/query/execute", Some(&bob)).await.body["error"], "mfa_setup_required");
    assert_eq!(server.post("/api/auth/mfa/status", Some(&bob), json!({})).await.body["setup_required"], true);

    server.post("/api/admin/users/set-mfa-required", Some(&admin), json!({ "id": ana_id, "required": true })).await;
    let blocked = server
        .post("/api/auth/mfa/disable", Some(&ana), json!({ "password": "ana-password", "code": totp_code(&secret, 0) }))
        .await;
    assert_eq!(blocked.body["error"], "mfa_required_by_policy");

    let reset = server.post("/api/admin/users/reset-mfa", Some(&admin), json!({ "id": ana_id })).await;
    assert_eq!(reset.status, StatusCode::OK, "{:?}", reset.body);
    assert_eq!(reset.body["mfa_enabled"], false);
    let after_reset = server.login("ana", "ana-password").await;
    assert_eq!(after_reset.body["mfa_setup_required"], true);
    assert!(after_reset.cookie.is_some());
    assert_eq!(verified.body["user"]["mfa_enabled"], true);
}

#[tokio::test]
async fn external_captcha_providers_are_verified_and_fall_back_to_the_built_in_one() {
    let (provider_address, recorded, provider_task) = crate::captcha_provider::test_server::spawn().await;
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |state| *state.captcha_mode.get_mut() = CaptchaMode::Always).await;
    let server = serve(state.clone()).await;
    let builtin_login = |captcha: Value| async {
        let captcha = captcha;
        let mut body = json!({ "username": "admin", "password": ADMIN_PASSWORD });
        body["captcha_id"] = captcha["id"].clone();
        let answer = state.captchas.answer_for_tests(captcha["id"].as_str().unwrap()).unwrap();
        body["captcha_code"] = json!(answer);
        server.post("/api/auth/login", None, body).await
    };
    let first_captcha = server.get("/api/auth/captcha", None).await.body;
    assert_eq!(first_captcha["provider"], "builtin");
    let admin = builtin_login(first_captcha).await.cookie.unwrap();

    let incomplete = server
        .post(
            "/api/admin/security/captcha/save",
            Some(&admin),
            json!({ "provider": "cap", "site_key": "site-1", "endpoint": "ftp://x", "secret": "s" }),
        )
        .await;
    assert_eq!(incomplete.body["error"], "captcha_endpoint_invalid");
    let saved = server
        .post(
            "/api/admin/security/captcha/save",
            Some(&admin),
            json!({ "provider": "cap", "site_key": "site-1", "endpoint": format!("http://{provider_address}/"), "secret": "cap-secret" }),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);
    assert_eq!(saved.body["has_secret"], true);
    assert!(!saved.body.to_string().contains("cap-secret"));
    assert_eq!(state.app.storage.load_web_captcha_secret().await.unwrap().as_deref(), Some("cap-secret"));

    let widget = server.get("/api/auth/captcha", None).await.body;
    assert_eq!(widget["provider"], "cap");
    assert_eq!(widget["site_key"], "site-1");
    assert_eq!(widget["endpoint"], format!("http://{provider_address}/site-1/"));
    assert!(widget.get("image").is_none());

    let login = |token: &'static str| {
        let server = &server;
        async move {
            server
                .post(
                    "/api/auth/login",
                    None,
                    json!({ "username": "admin", "password": ADMIN_PASSWORD, "captcha_token": token }),
                )
                .await
        }
    };
    assert!(login("token-good").await.cookie.is_some());
    assert_eq!(login("token-bad").await.body["error"], "captcha_invalid");
    assert_eq!(login("").await.body["error"], "captcha_invalid");
    let down = login("token-down").await;
    assert_eq!(down.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(down.body["error"], "captcha_provider_unavailable");
    assert!(recorded
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|(path, _, body)| path == "/site-1/siteverify" && body.contains("cap-secret")));

    let fallback = server.get("/api/auth/captcha", None).await.body;
    assert_eq!(fallback["provider"], "builtin");
    assert!(login("token-good").await.cookie.is_none());
    assert!(builtin_login(fallback).await.cookie.is_some());
    let settings = server.post("/api/admin/security/captcha", Some(&admin), json!({})).await;
    assert_eq!(settings.body["fallback_active"], true);

    let builtin_again =
        server.post("/api/admin/security/captcha/save", Some(&admin), json!({ "provider": "builtin" })).await;
    assert_eq!(builtin_again.body["provider"], "builtin");
    assert_eq!(builtin_again.body["has_secret"], false);
    assert!(state.app.storage.load_web_captcha_secret().await.unwrap().is_none());
    provider_task.abort();
}

fn query_param(url: &str, name: &str) -> String {
    reqwest::Url::parse(url).unwrap().query_pairs().find(|(key, _)| key == name).unwrap().1.into_owned()
}

#[tokio::test]
async fn oidc_single_sign_on_creates_links_and_rejects_accounts() {
    use crate::oidc::test_provider;
    let (_idp_address, idp, idp_task) = test_provider::spawn().await;
    let issuer = idp.issuer.lock().unwrap().clone();
    let directory = tempfile::tempdir().unwrap();
    let state = open_state(directory.path(), |_| {}).await;
    state.app.authz.set_enforced(true);
    let group = state.app.storage.create_user_group("Engineers", None, 1).await.unwrap();
    let server = serve(state.clone()).await;
    let admin = server.login("admin", ADMIN_PASSWORD).await.cookie.unwrap();
    let no_redirect = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let base = format!("http://{}", server.address);

    let saved = server
        .post(
            "/api/admin/identity-providers/save",
            Some(&admin),
            json!({
                "kind": "oidc", "name": "Keycloak", "auto_create_users": true, "default_group_id": group.id,
                "secret": test_provider::CLIENT_SECRET,
                "config": { "issuer": issuer, "client_id": test_provider::CLIENT_ID, "redirect_uri": format!("{base}/api/auth/oidc/callback") }
            }),
        )
        .await;
    assert_eq!(saved.status, StatusCode::OK, "{:?}", saved.body);
    assert_eq!(saved.body["has_secret"], true);
    assert!(!saved.body.to_string().contains(test_provider::CLIENT_SECRET));
    let provider_id = saved.body["id"].as_str().unwrap().to_string();
    let tested = server.post("/api/admin/identity-providers/test", Some(&admin), json!({ "id": provider_id })).await;
    assert_eq!(tested.body["ok"], true, "{:?}", tested.body);
    let public = server.get("/api/auth/providers", None).await;
    assert_eq!(public.body[0]["name"], "Keycloak");
    assert!(public.body[0].get("config").is_none());

    let sign_in = |subject: &'static str, claims: Value| {
        let (no_redirect, base, idp, provider_id) = (&no_redirect, &base, &idp, &provider_id);
        async move {
            let started = no_redirect.get(format!("{base}/api/auth/oidc/{provider_id}/start")).send().await.unwrap();
            let location = started.headers()["location"].to_str().unwrap().to_string();
            *idp.nonce.lock().unwrap() = query_param(&location, "nonce");
            *idp.challenge.lock().unwrap() = query_param(&location, "code_challenge");
            *idp.subject.lock().unwrap() = subject.to_string();
            *idp.claims.lock().unwrap() = claims;
            let state_param = query_param(&location, "state");
            let callback = no_redirect
                .get(format!("{base}/api/auth/oidc/callback?code=code-1&state={state_param}"))
                .send()
                .await
                .unwrap();
            let cookie = callback
                .headers()
                .get("set-cookie")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.split(';').next())
                .map(str::to_string);
            let target = callback
                .headers()
                .get("location")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            (cookie, target, state_param)
        }
    };

    let (cookie, target, used_state) =
        sign_in("kc-ana", json!({ "preferred_username": "ana.sso", "name": "Ana" })).await;
    assert_eq!(target, "/");
    let cookie = cookie.expect("session cookie");
    let check = server.get("/api/auth/check", Some(&cookie)).await;
    assert_eq!(check.body["user"]["username"], "ana.sso");
    let user = state.app.storage.find_web_user_by_username("ana.sso").await.unwrap().unwrap();
    assert_eq!(user.identity_provider, provider_id);
    assert_eq!(state.app.storage.list_user_groups().await.unwrap()[0].member_ids, vec![user.id.clone()]);
    let (second, _, _) = sign_in("kc-ana", json!({ "preferred_username": "renamed" })).await;
    assert!(second.is_some());
    assert_eq!(
        state.app.storage.find_web_user_by_external_subject(&provider_id, "kc-ana").await.unwrap().unwrap().username,
        "ana.sso"
    );

    let replay =
        no_redirect.get(format!("{base}/api/auth/oidc/callback?code=code-1&state={used_state}")).send().await.unwrap();
    assert!(replay.headers()["location"].to_str().unwrap().ends_with("/login?sso_error=sso_state_invalid"));

    let (_, taken, _) = sign_in("kc-other", json!({ "preferred_username": "admin" })).await;
    assert!(taken.ends_with("sso_error=sso_username_taken"), "{taken}");

    server
        .post(
            "/api/admin/identity-providers/save",
            Some(&admin),
            json!({ "id": provider_id, "kind": "oidc", "name": "Keycloak", "auto_create_users": false,
                    "config": { "issuer": issuer, "client_id": test_provider::CLIENT_ID, "redirect_uri": format!("{base}/api/auth/oidc/callback") } }),
        )
        .await;
    let (_, not_provisioned, _) = sign_in("kc-bob", json!({ "preferred_username": "bob" })).await;
    assert!(not_provisioned.ends_with("sso_error=sso_user_not_provisioned"), "{not_provisioned}");

    state.app.storage.set_web_user_active(&user.id, false, now_millis()).await.unwrap();
    let (_, disabled, _) = sign_in("kc-ana", json!({})).await;
    assert!(disabled.ends_with("sso_error=sso_user_disabled"), "{disabled}");
    assert_eq!(server.login("ana.sso", "!external").await.status, StatusCode::UNAUTHORIZED);
    idp_task.abort();
}
