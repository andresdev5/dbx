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
        .route("/api/connection/list", get(crate::routes::connection::load_connections))
        .route("/api/database-backups", post(crate::routes::scheduled_backup::command))
        .fallback(|| async { "handled" })
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
    let invalid = save(json!({ "connection_id": "ventas", "strict_function_mode": true, "function_allowlist": ["drop table;"] })).await;
    assert_eq!(invalid.body["error"], "function_allowlist_invalid");
    let unknown = save(json!({ "connection_id": "nope", "strict_function_mode": true })).await;
    assert_eq!(unknown.body["error"], "connection_not_found");
    let saved = save(json!({ "connection_id": "ventas", "strict_function_mode": true, "function_allowlist": [" Sales.Score ", "sales.score", "fmt"] })).await;
    assert_eq!(saved.body["function_allowlist"], json!(["fmt", "sales.score"]));
    let listed = server.post("/api/admin/connection-policies/list", Some(&admin), json!({})).await;
    assert_eq!(listed.body[0]["strict_function_mode"], true);
    assert_eq!(state.app.authz.snapshot().strict_functions.get("ventas"), Some(&vec!["fmt".to_string(), "sales.score".to_string()]));
}
