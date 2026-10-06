// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::access_point::get_ap;
use crate::client_authentication::{
    client_authentication, delete_custom_password, set_custom_password, ClientAuthentication,
    RateLimiter,
};
use crate::client_authentication::{login, logout};
use crate::cloudadapter::{enable_cloudadapter, is_cloudadapter_enabled};
use crate::consent::{
    get_support_bundle_consent, get_telemetry_consent, set_support_bundle_consent,
    set_telemetry_consent,
};
use crate::gateway_info::get_gateway_version;
use crate::ssh_access::{add_ssh_credentials, is_ssh_access_enabled, set_ssh_access};
use crate::timezone::get_timezone_list;
use crate::timezone::{get_timezone, set_timezone};
use crate::websocket::{enable_websocket_api, is_websocket_api_enabled};
use crate::wifiapi::delete_homekit_pairings;
use crate::wifiapi::get_wifi_list;
use crate::wifiapi::{delete_wifi_settings, get_wifi_settings, set_wifi_settings};
use axum::http::StatusCode;
use axum::response::Redirect;
use axum::routing::{delete, get, get_service, post, put};
use axum::{middleware, Router};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

#[derive(Clone)]
pub struct AppState {
    pub client_authenticator: ClientAuthentication,
    pub login_rate_limiter: Arc<Mutex<RateLimiter>>,
}

const LOGIN_FAILED_RATE_LIMIT_COUNT: u32 = 20;
const LOGIN_FAILED_RATE_LIMIT_REFILL_INTERVAL: Duration = Duration::from_secs(15 * 60);

// URI locations that are allowed without authentication
const ALLOWED_PATHS: &[&str] = &[
    "/",
    "/assets/*",
    "/favicon-*",
    "/fonts/*",
    "/index.html",
    "/licenses",
    "/licenses/*",
    "/login",
    "/logout",
    "/main",
    "/robots.txt",
    "/simple.html",
    "/version",
];

impl AppState {
    fn new() -> Self {
        Self {
            client_authenticator: ClientAuthentication::new_with_allowed(ALLOWED_PATHS),
            login_rate_limiter: Arc::new(Mutex::new(RateLimiter::new(
                LOGIN_FAILED_RATE_LIMIT_COUNT,
                LOGIN_FAILED_RATE_LIMIT_REFILL_INTERVAL,
            ))),
        }
    }
}

pub(crate) fn create_app() -> Router {
    let state = AppState::new();

    let cors = CorsLayer::new().allow_methods(Any).allow_origin(Any);

    Router::new()
        .layer(cors)
        .route("/version", get(get_gateway_version))
        .route("/ap", get(get_ap))
        .route(
            "/cloud_connection",
            get(is_cloudadapter_enabled).put(enable_cloudadapter),
        )
        .route(
            "/consent_telemetry",
            get(get_telemetry_consent).put(set_telemetry_consent),
        )
        .route(
            "/consent_support_bundle",
            get(get_support_bundle_consent).put(set_support_bundle_consent),
        )
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route(
            "/password",
            put(set_custom_password).delete(delete_custom_password),
        )
        .route("/timezone", get(get_timezone).put(set_timezone))
        .route("/timezone_list", get(get_timezone_list))
        .route("/ssh_access_credentials", post(add_ssh_credentials))
        .route(
            "/ssh_access_enable",
            get(is_ssh_access_enabled).put(set_ssh_access),
        )
        .route(
            "/websocket_api",
            get(is_websocket_api_enabled).put(enable_websocket_api),
        )
        .route(
            "/wifi",
            get(get_wifi_settings)
                .put(set_wifi_settings)
                .delete(delete_wifi_settings),
        )
        .route("/wifi_list", get(get_wifi_list))
        .route("/homekit", delete(delete_homekit_pairings))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            client_authentication,
        ))
        .route(
            // This path is currently used by the frontend. Redirect so browsers save the download as licenses.tar.xz
            // instead of deriving a name (without extension or just .xz) from the URI.
            "/licenses",
            get(|| async { Redirect::permanent("/licenses/licenses.tar.xz") }),
        )
        .nest_service(
            "/licenses/licenses.tar.xz",
            get_service(ServeFile::new("/usr/share/common-licenses/licenses.tar.xz")),
        )
        .fallback_service(
            get_service(ServeDir::new("www"))
                .handle_error(|_| async move { StatusCode::INTERNAL_SERVER_ERROR }),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_test::TestServer;

    #[tokio::test]
    async fn test_serve_static_file_ok() {
        let app = create_app();
        let app = app.into_make_service();
        let server = TestServer::new(app);
        let response = server.get("/simple.html").await;
        let response = response.assert_status_ok();
        let contents = response.contents();
        assert!(contents.contains("<title>GARDENA smart Gateway</title>"));
    }

    #[tokio::test]
    async fn test_licenses_redirect() {
        let app = create_app();
        let app = app.into_make_service();
        let server = TestServer::new(app);
        let response = server.get_fail("/licenses").await;
        response.assert_status(StatusCode::PERMANENT_REDIRECT);
    }

    #[tokio::test]
    async fn test_serve_static_file_not_found() {
        let app = create_app();
        let app = app.into_make_service();
        let server = TestServer::new(app);
        let response = server.get_fail("/non_existing_file").await;
        let response = response.assert_status_not_found();
        assert!(response.contents().is_empty());
    }
}
