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
        .route("/api/protected", get(|| async { "secret" }).post(|| async { "written" }))
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

    assert_eq!(server.get("/api/protected", Some(&cookie)).await.body, "secret");
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
    assert_eq!(restarted.get("/api/protected", Some(&cookie)).await.status, StatusCode::OK);
    assert_eq!(restarted.post("/api/auth/logout", Some(&cookie), json!({})).await.status, StatusCode::OK);
    let after = restarted.get("/api/protected", Some(&cookie)).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    assert_eq!(after.body["error"], SESSION_EXPIRED);
    drop(restarted);

    let again = serve(open_state(directory.path(), |_| {}).await).await;
    assert_eq!(again.get("/api/protected", Some(&cookie)).await.status, StatusCode::UNAUTHORIZED);
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

    let blocked = server.get("/api/protected", Some(&current)).await;
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

    assert_eq!(server.get("/api/protected", Some(&current)).await.status, StatusCode::OK);
    assert_eq!(server.get("/api/protected", Some(&other)).await.status, StatusCode::UNAUTHORIZED);
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

    assert_eq!(server.get("/api/protected", None).await.body["error"], SETUP_REQUIRED);
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
    assert_eq!(server.get("/api/protected", Some(&cookie)).await.status, StatusCode::OK);
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
    let read = server.send("GET", "/api/protected", None, None, &[("sec-fetch-site", "cross-site")]).await;
    assert_eq!(read.body["error"], SESSION_EXPIRED);
}

#[tokio::test]
async fn api_requires_a_valid_session() {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(open_state(directory.path(), |_| {}).await).await;
    let reply = server.get("/api/protected", Some("dbx_session=forged")).await;
    assert_eq!((reply.status, reply.body["error"].clone()), (StatusCode::UNAUTHORIZED, json!(SESSION_EXPIRED)));
}

#[tokio::test]
async fn disabled_password_mode_skips_login_entirely() {
    let directory = tempfile::tempdir().unwrap();
    let server = serve(open_state(directory.path(), |state| state.password_disabled = true).await).await;
    assert_eq!(server.get("/api/protected", None).await.body, "secret");
    let check = server.get("/api/auth/check", None).await;
    assert_eq!((check.body["authenticated"].clone(), check.body["required"].clone()), (json!(true), json!(false)));
    assert_eq!(server.login("admin", ADMIN_PASSWORD).await.body["error"], "login_not_required");
}
