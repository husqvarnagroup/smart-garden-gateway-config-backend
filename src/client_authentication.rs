// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::app::AppState;
use crate::gateway_info::GATEWAY_ID;
use axum::middleware::Next;
use axum::Json;
use std::path::{Path, PathBuf};

use crate::utils;
use anyhow::{Context, Error};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use lazy_static::lazy_static;
use openssl::base64;
use pbkdf2::pbkdf2_hmac;
use rand::random;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

const SESSION_LIFETIME: Duration = Duration::from_secs(15 * 60);
const MIN_CUSTOM_PASSWORD_LEN: usize = 8;
const MAX_CUSTOM_PASSWORD_LEN: usize = 50;
const PASSWORD_HASH_ITERATIONS: u32 = 2048;
const CONFIG_BACKEND_PASSWORD_FILE_PATH: &str = "/etc/gateway-config-interface/password";

lazy_static! {
    pub(crate) static ref SESSION_TOKEN_STORE: Arc<Mutex<SessionTokenStore>> =
        Arc::new(Mutex::new(SessionTokenStore::new(SESSION_LIFETIME)));
}

// Ensures that a login can't authenticate against a password that a concurrent change is about to
// replace and then create a session after that password change has already destroyed all sessions.
lazy_static! {
    static ref PASSWORD_AUTH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::new(());
}

fn get_password_file_path() -> PathBuf {
    let path_str = if cfg!(feature = "nongwhw") {
        std::env::var("TEST_PASSWORD_FILE")
            .unwrap_or_else(|_| CONFIG_BACKEND_PASSWORD_FILE_PATH.to_string())
    } else {
        CONFIG_BACKEND_PASSWORD_FILE_PATH.to_string()
    };

    let mut path_buf = PathBuf::new();
    path_buf.push(path_str);
    path_buf
}

#[derive(Serialize)]
pub(crate) struct SessionIdentifier {
    session: String,
}

#[derive(Deserialize)]
pub struct Login {
    password: String,
}

#[derive(Deserialize)]
pub struct PasswordChange {
    current_password: String,
    password: String,
}

#[derive(Deserialize)]
pub struct CurrentPassword {
    current_password: String,
}

#[derive(Clone)]
pub struct ClientAuthentication {
    allowed_paths: HashSet<String>,
}

impl ClientAuthentication {
    pub fn new_with_allowed(allowed: &[&str]) -> Self {
        Self {
            allowed_paths: Self::allowed_paths(allowed),
        }
    }

    fn allowed_paths(allowed: &[&str]) -> HashSet<String> {
        let mut paths = HashSet::new();
        allowed.iter().for_each(|path| {
            paths.insert(path.to_string());
        });

        paths
    }
}

fn check_authorization(headers: HeaderMap) -> Result<(), (StatusCode, String)> {
    if let Ok(session_token) = get_session_token(&headers) {
        let token_store = &SESSION_TOKEN_STORE;

        let mut token_store = match token_store.lock() {
            Ok(guard) => guard,
            Err(_) => {
                error!("Cant access session token store");
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to acquire session token store lock.".to_string(),
                ));
            }
        };

        match token_store.verify_and_refresh_session(session_token) {
            Ok(_) => {
                debug!("Session validated and refreshed");
                Ok(())
            }
            // The 'old' config-backend returned an empty body if unauthorized.
            // Keeping the same behavior here.
            Err(_) => {
                debug!("Session token verification failed");
                Err((StatusCode::UNAUTHORIZED, "".to_string()))
            }
        }
    } else {
        debug!("No session token received in request");
        Err((
            StatusCode::UNAUTHORIZED,
            "No session token received.".to_string(),
        ))
    }
}

pub(crate) async fn client_authentication<B>(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request<B>,
    next: Next<B>,
) -> Response {
    let path = request.uri().path().to_string();
    if is_allowed_path(path.clone(), state.client_authenticator) {
        debug!("Path {path} is allowed without authentication");
        return next.run(request).await;
    }

    if let Err(resp) = check_authorization(headers) {
        resp.into_response()
    } else {
        next.run(request).await
    }
}

fn is_allowed_path(path: String, client_authentication: ClientAuthentication) -> bool {
    debug!("Checking if path {path} is allowed without authentication");
    for allowed_path in &client_authentication.allowed_paths {
        if path == *allowed_path
            || (allowed_path.ends_with('*')
                && path.starts_with(&allowed_path[..allowed_path.len() - 1]))
        {
            return true;
        }
    }
    false
}

pub(crate) struct SessionTokenStore {
    session_lifetime: Duration,
    authenticated_session_tokens: HashMap<String, Instant>,
}

impl SessionTokenStore {
    pub fn new(session_lifetime: Duration) -> Self {
        Self {
            session_lifetime,
            authenticated_session_tokens: HashMap::new(),
        }
    }

    fn new_session(&mut self) -> String {
        let session_token = format!("{:x}", random::<u128>());
        debug!("Session token generated: {session_token}");
        // remove expired tokens
        let lifetime = self.session_lifetime;
        self.authenticated_session_tokens
            .retain(|_, time| time.elapsed() <= lifetime);
        // add new token
        debug!("Add session token: {session_token}");
        self.authenticated_session_tokens
            .insert(session_token.clone(), Instant::now());
        session_token
    }

    fn destroy_session(&mut self, session_token: &str) {
        debug!("Destroy session with token: {session_token}");
        self.authenticated_session_tokens.remove(session_token);
    }

    fn destroy_all_sessions(&mut self) {
        debug!("destroy all sessions");
        self.authenticated_session_tokens.clear();
    }

    fn verify_and_refresh_session(&mut self, session_token: &str) -> Result<(), String> {
        // verify token is in store
        self.authenticated_session_tokens
            .get(session_token)
            .ok_or("Session not authorized.")
            .and_then(|time| {
                if time.elapsed() > self.session_lifetime {
                    debug!("Session token {session_token} expired");
                    return Err("Session expired.");
                }
                Ok(())
            })?;
        // refresh session time
        self.authenticated_session_tokens
            .insert(session_token.to_string(), Instant::now());
        debug!("Session token {session_token} refreshed");
        Ok(())
    }

    pub fn has_active_sessions(&self) -> bool {
        for time in self.authenticated_session_tokens.values() {
            if time.elapsed() > self.session_lifetime {
                // expired
                continue;
            }

            return true;
        }

        false
    }
}

pub struct RateLimiter {
    count_max: u32,
    refill_interval: Duration,
    count_available: u32,
    last_fill: Instant,
}

impl RateLimiter {
    pub fn new(count: u32, refill_interval: Duration) -> Self {
        Self {
            count_max: count,
            refill_interval,
            count_available: count,
            last_fill: Instant::now(),
        }
    }

    fn check(&mut self) -> bool {
        // refill
        while self.count_available < self.count_max
            && self.last_fill.elapsed() >= self.refill_interval
        {
            self.count_available += 1;
            self.last_fill += self.refill_interval;
        }
        if self.count_available == self.count_max {
            self.last_fill = Instant::now();
        }

        debug!("Number of active sessions: {}", self.count_available);
        self.count_available != 0
    }

    fn check_and_count(&mut self) -> bool {
        if !self.check() {
            return false;
        }
        self.count_available -= 1;
        true
    }
}

fn get_session_token(headers: &HeaderMap) -> Result<&str, Error> {
    headers
        .get("X-Session")
        .context("Missing session header")?
        .to_str()
        .context("Invalid session header value")
}

pub async fn login(
    State(state): State<AppState>,
    login: Json<Login>,
) -> Result<Json<SessionIdentifier>, StatusCode> {
    let _password_auth_guard = PASSWORD_AUTH_LOCK.lock().await;

    // Checked after acquiring the lock, so concurrent logins can't all see
    // budget available before any of them records a failure.
    if !state.login_rate_limiter.lock().unwrap().check() {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let password_is_valid = check_password(&login.password, &get_password_file_path())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if password_is_valid {
        debug!("login password is valid");
        // The store is locked after the password check, so the lock is never
        // held across an await
        let mut session_token_store = SESSION_TOKEN_STORE
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(Json(SessionIdentifier {
            session: session_token_store.new_session(),
        }))
    } else {
        debug!("Login password is not valid");
        state.login_rate_limiter.lock().unwrap().check_and_count();
        Err(StatusCode::UNAUTHORIZED)
    }
}

pub async fn logout(headers: HeaderMap) -> StatusCode {
    match get_session_token(&headers) {
        Ok(session_token) => {
            if let Ok(session_token_store) = &mut SESSION_TOKEN_STORE.lock() {
                info!("Logout session with token: {session_token}");
                session_token_store.destroy_session(session_token);
                StatusCode::NO_CONTENT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
        _ => StatusCode::BAD_REQUEST,
    }
}

async fn check_password(password: &str, pw_file: &Path) -> anyhow::Result<bool> {
    match tokio::fs::read_to_string(pw_file).await {
        Ok(hash_from_file) => Ok(check_custom_password(&hash_from_file, password)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok(check_default_password(password))
        }
        // Any other error must not fall back to the default password
        Err(err) => Err(err).context("Can't read custom password file"),
    }
}

fn check_custom_password(hash_from_file: &str, password: &str) -> bool {
    let hash_from_request = calculate_password_hash(password);
    // `memcmp::eq` panics on slices of different length
    let authenticated = hash_from_file.len() == hash_from_request.len()
        && openssl::memcmp::eq(hash_from_file.as_bytes(), hash_from_request.as_bytes());
    authenticated
}

fn check_default_password(password: &str) -> bool {
    password.to_lowercase() == GATEWAY_ID[..8]
}

// The gateway ID is unique per device, so it is used as salt.
// Using `pbkdf2_hmac` like for Wi-Fi PSK derivation from passphrase but
// with less iteration (trading a bit of security for speed on our old hardware).
fn calculate_password_hash(password: &str) -> String {
    const PASSWORD_HASH_LEN: usize = 20; // SHA1 output length in bytes
    let mut digest = [0u8; PASSWORD_HASH_LEN];
    pbkdf2_hmac::<Sha1>(
        password.as_bytes(),
        GATEWAY_ID.as_bytes(),
        PASSWORD_HASH_ITERATIONS,
        &mut digest,
    );
    base64::encode_block(&digest)
}

pub(crate) async fn set_custom_password(
    State(state): State<AppState>,
    request: Json<PasswordChange>,
) -> StatusCode {
    debug!("received request to set a custom password");
    if let Err(status) = ensure_custom_password_length(&request.password) {
        return status;
    }
    let _password_auth_guard = PASSWORD_AUTH_LOCK.lock().await;
    if let Err(status) = verify_current_password(&state, &request.current_password).await {
        return status;
    }
    if let Err(status) = destroy_all_sessions() {
        return status;
    }
    match set_password(&get_password_file_path(), &request.password).await {
        Ok(()) => {
            debug!("custom password set");
            StatusCode::NO_CONTENT
        }
        Err(err) => {
            error!("failed to set custom password: {err:?}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn set_password(pw_file: &Path, password: &str) -> anyhow::Result<()> {
    let digest = calculate_password_hash(password);
    Ok(utils::save_file_atomic(
        pw_file
            .to_str()
            .context("can't convert password file path")?,
        digest,
    )
    .await?)
}

pub(crate) async fn delete_custom_password(
    State(state): State<AppState>,
    request: Json<CurrentPassword>,
) -> StatusCode {
    debug!("received request to delete the custom password");
    let _password_auth_guard = PASSWORD_AUTH_LOCK.lock().await;
    if let Err(status) = verify_current_password(&state, &request.current_password).await {
        return status;
    }
    if let Err(status) = destroy_all_sessions() {
        return status;
    }
    match tokio::fs::remove_file(get_password_file_path()).await {
        Ok(()) => {
            info!("custom password deleted");
            StatusCode::NO_CONTENT
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            info!("no custom password is set, nothing to delete");
            StatusCode::BAD_REQUEST
        }
        Err(err) => {
            error!("failed to delete custom password: {err:?}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn ensure_custom_password_length(password: &str) -> Result<(), StatusCode> {
    let length = password.chars().count();
    if length < MIN_CUSTOM_PASSWORD_LEN {
        debug!("rejected custom password: shorter than {MIN_CUSTOM_PASSWORD_LEN} characters");
        return Err(StatusCode::BAD_REQUEST);
    }
    if length > MAX_CUSTOM_PASSWORD_LEN {
        debug!("rejected custom password: longer than {MAX_CUSTOM_PASSWORD_LEN} characters");
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

// A valid session is not enough to change or remove the password. Without this
// check a hijacked session could lock the owner out of the gateway. The check
// shares the login rate limiter, so a hijacked session can't be used to
// brute-force the current password either.
async fn verify_current_password(state: &AppState, password: &str) -> Result<(), StatusCode> {
    if !state
        .login_rate_limiter
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .check()
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    match check_password(password, &get_password_file_path()).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            warn!("current password is not valid");
            state
                .login_rate_limiter
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .check_and_count();
            Err(StatusCode::FORBIDDEN)
        }
        Err(err) => {
            error!("failed to check the current password: {err:?}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// Changing or removing the password invalidates every existing session, since
// sessions established under the old password should not outlive it.
fn destroy_all_sessions() -> Result<(), StatusCode> {
    destroy_all_sessions_in(&SESSION_TOKEN_STORE)
}

fn destroy_all_sessions_in(store: &Mutex<SessionTokenStore>) -> Result<(), StatusCode> {
    match store.lock() {
        Ok(mut token_store) => {
            token_store.destroy_all_sessions();
            Ok(())
        }
        Err(_) => {
            error!("can't access session token store to destroy all sessions");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::app::{create_app, AppState};
    use crate::client_authentication::{check_custom_password, check_password, StatusCode};
    use crate::client_authentication::{
        destroy_all_sessions_in, login, set_custom_password, ClientAuthentication, Login,
        PasswordChange, RateLimiter, SessionTokenStore, PASSWORD_AUTH_LOCK, SESSION_LIFETIME,
    };
    use crate::client_authentication::{ensure_custom_password_length, set_password};
    use axum::extract::State;
    use axum::Json;
    use axum_test::TestServer;
    use std::fs;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tempdir::TempDir;

    const DUMMY_CUSTOM_PASSWORD_FILE: &str = "password";

    #[tokio::test]
    async fn test_login_deny() -> Result<(), Box<dyn ::std::error::Error>> {
        let app = create_app();
        let server = TestServer::new(app.into_make_service());

        let response = server
            .post_fail(
                "/login",
                &serde_json::json!({ "password": "wrong_password" }).to_string(),
            )
            .await;

        response.assert_status(StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_login_allow() -> Result<(), Box<dyn ::std::error::Error>> {
        let app = create_app();
        let server = TestServer::new(app.into_make_service());

        let response = server
            .post(
                "/login",
                &serde_json::json!({ "password": "7155a0b7" }).to_string(),
            )
            .await;

        response.assert_status(StatusCode::OK);

        Ok(())
    }

    #[test]
    fn test_ensure_custom_password_length_ok() {
        assert!(ensure_custom_password_length("12345678").is_ok());
        assert!(ensure_custom_password_length(&"a".repeat(50)).is_ok());
    }

    #[test]
    fn test_ensure_custom_password_length_too_short() {
        assert!(ensure_custom_password_length("1234567").is_err());
    }

    #[test]
    fn test_ensure_custom_password_length_too_long() {
        assert!(ensure_custom_password_length(&"a".repeat(51)).is_err());
    }

    #[test]
    fn test_ensure_custom_password_length_counts_characters() {
        let short_password = "äöüéèàçñ";
        assert_eq!(short_password.chars().count(), 8);
        assert_eq!(short_password.len(), 16);
        assert!(ensure_custom_password_length(short_password).is_ok());

        assert!(ensure_custom_password_length(&"ä".repeat(7)).is_err());

        let long_password = "é".repeat(50);
        assert_eq!(long_password.chars().count(), 50);
        assert_eq!(long_password.len(), 100);
        assert!(ensure_custom_password_length(&long_password).is_ok());

        assert!(ensure_custom_password_length(&"é".repeat(51)).is_err());
    }

    fn test_app_state_with_rate_limit(count: u32) -> AppState {
        AppState {
            client_authenticator: ClientAuthentication::new_with_allowed(&[]),
            login_rate_limiter: Arc::new(Mutex::new(RateLimiter::new(
                count,
                Duration::from_secs(15 * 60),
            ))),
        }
    }

    #[tokio::test]
    async fn test_set_custom_password_rate_limited_after_failed_attempts() {
        let state = test_app_state_with_rate_limit(2);
        let wrong_attempt = || {
            Json(PasswordChange {
                current_password: "wrong-password".to_string(),
                password: "a-new-password".to_string(),
            })
        };

        let first = set_custom_password(State(state.clone()), wrong_attempt()).await;
        assert_eq!(first, StatusCode::FORBIDDEN);
        let second = set_custom_password(State(state.clone()), wrong_attempt()).await;
        assert_eq!(second, StatusCode::FORBIDDEN);
        let third = set_custom_password(State(state.clone()), wrong_attempt()).await;
        assert_eq!(third, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_login_blocks_while_password_change_holds_the_lock() {
        // A password change holds PASSWORD_AUTH_LOCK while it checks the
        // current password and destroys sessions. A concurrent login must
        // wait for that lock, so it can't authenticate against a password
        // that is being replaced. Simulate the held lock directly, since
        // driving a real race deterministically is not possible.
        let guard = PASSWORD_AUTH_LOCK.lock().await;

        let state = test_app_state_with_rate_limit(20);
        let login_future = login(
            State(state),
            Json(Login {
                password: "7155a0b7".to_string(),
            }),
        );
        tokio::pin!(login_future);

        let timed_out = tokio::time::timeout(Duration::from_millis(50), &mut login_future).await;
        assert!(
            timed_out.is_err(),
            "login must block while a password change holds the lock"
        );

        drop(guard);

        let result = tokio::time::timeout(Duration::from_millis(50), login_future)
            .await
            .expect("login must proceed once the lock is released");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_login_rate_limit_enforced_under_concurrent_attempts() {
        // The rate limit must be checked and counted as one atomic step per
        // login. Otherwise concurrent attempts can all see budget available
        // before any of them records a failure, letting more attempts
        // through than the configured limit.
        let state = test_app_state_with_rate_limit(1);
        let wrong_login = || {
            Json(Login {
                password: "wrong-password".to_string(),
            })
        };

        let (first, second) = tokio::join!(
            login(State(state.clone()), wrong_login()),
            login(State(state.clone()), wrong_login()),
        );

        let to_status = |result: Result<_, StatusCode>| match result {
            Ok(_) => panic!("expected login with a wrong password to fail"),
            Err(status) => status,
        };
        let mut statuses = [to_status(first), to_status(second)];
        statuses.sort_by_key(|status| status.as_u16());
        assert_eq!(
            statuses,
            [StatusCode::UNAUTHORIZED, StatusCode::TOO_MANY_REQUESTS]
        );
    }

    #[test]
    fn test_destroy_all_sessions_in_reports_a_poisoned_lock() {
        let store = Mutex::new(SessionTokenStore::new(SESSION_LIFETIME));
        let poison_result = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = store.lock().unwrap();
                    panic!("poison the lock on purpose");
                })
                .join()
        });
        assert!(poison_result.is_err());

        assert_eq!(
            destroy_all_sessions_in(&store),
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        );
    }

    #[tokio::test]
    async fn test_set_custom_password_checks_length_before_current_password() {
        // Checking the new password's length is cheap and in-memory, unlike
        // verifying the current password (a file read plus a password hash).
        // The cheap check should run first, so a malformed request is
        // rejected without doing the expensive check.
        let state = test_app_state_with_rate_limit(20);
        let request = Json(PasswordChange {
            current_password: "wrong-password".to_string(),
            password: "short".to_string(),
        });

        let status = set_custom_password(State(state), request).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_set_password() {
        let password = "my-custom-password";
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_password_file = temp_dir.path().join(DUMMY_CUSTOM_PASSWORD_FILE);
        assert!(!dummy_password_file.exists());

        set_password(&dummy_password_file, password).await.unwrap();
        assert!(dummy_password_file.exists());
        let actual = fs::read_to_string(dummy_password_file).unwrap();

        let expected = "l3j9DWQO9KO8r1bCpVbqttnuQ1w=";
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_check_custom_password_success() {
        let password = "my-custom-password";
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_password_file = temp_dir.path().join(DUMMY_CUSTOM_PASSWORD_FILE);

        set_password(&dummy_password_file, password).await.unwrap();

        let result = check_password(password, &dummy_password_file).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_check_custom_password_fail() {
        let password = "my-custom-password";
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_password_file = temp_dir.path().join(DUMMY_CUSTOM_PASSWORD_FILE);

        set_password(&dummy_password_file, "other-password")
            .await
            .unwrap();

        let hash_from_file = fs::read_to_string(&dummy_password_file).unwrap();
        let result = check_custom_password(&hash_from_file, password);
        assert!(!result);
    }

    #[tokio::test]
    async fn test_check_custom_password_not_set() {
        let result = check_custom_password("", "some-password");
        assert!(!result);
    }

    #[tokio::test]
    async fn test_check_custom_password_with_unexpected_hash_length() {
        let password = "my-custom-password";
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_password_file = temp_dir.path().join(DUMMY_CUSTOM_PASSWORD_FILE);
        set_password(&dummy_password_file, password).await.unwrap();
        // a trailing newline, e.g. from manual editing of the file
        let mut content = fs::read_to_string(&dummy_password_file).unwrap();
        content.push('\n');
        fs::write(&dummy_password_file, content).unwrap();

        let hash_from_file = fs::read_to_string(&dummy_password_file).unwrap();
        let result = check_custom_password(&hash_from_file, password);
        assert!(!result);
    }

    #[tokio::test]
    async fn test_check_custom_password_unreadable_file() {
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_password_file = temp_dir.path().join(DUMMY_CUSTOM_PASSWORD_FILE);
        fs::write(&dummy_password_file, [0xff, 0xfe]).unwrap();

        let result = check_password("some-password", &dummy_password_file).await;
        assert!(result.is_err());
    }
}
