// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::http::header;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{middleware, Router};
use axum_server::Handle;
use axum_server::Server;
use std::net::{SocketAddr, TcpListener};
use tracing::debug;
use tracing::info;
use tracing::log::warn;

pub(crate) fn http_port() -> i32 {
    if cfg!(feature = "nongwhw") {
        8080
    } else {
        // use default port
        80
    }
}

async fn redirect_http_to_https<B>(
    headers: HeaderMap,
    request: Request<B>,
    _next: Next<B>,
) -> Response {
    let hostname = headers.get(header::HOST).and_then(|h| h.to_str().ok());

    if let Some(hostname) = hostname {
        debug!("Hostname of request: {hostname}");
        let hostname = hostname.replacen("http://", "", 1);
        let uri = request.uri().to_string();
        let url = format!("https://{}{}", hostname, uri);

        debug!("Moved URL: {url}");
        return Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header(header::LOCATION, url)
            .body(axum::body::boxed(axum::body::Empty::new()))
            .unwrap_or_else(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to construct HTTPS URL: {}", e),
                )
                    .into_response()
            });
    }

    warn!("No hostname header in request");

    (
        StatusCode::BAD_REQUEST,
        "Failed to retrieve hostname from request".to_string(),
    )
        .into_response()
}

async fn bind_http_server(listener: Option<TcpListener>) -> Server {
    if let Some(listener) = listener {
        info!(
            "starting server with socket activation on listener {}",
            listener.local_addr().unwrap()
        );
        axum_server::from_tcp(listener)
    } else {
        let http_port = http_port();
        let addr: SocketAddr = format!("[::]:{http_port}").parse().unwrap();
        info!("starting server on {addr}");
        axum_server::bind(addr)
    }
}

pub(crate) async fn start_http_server(listener: Option<TcpListener>, shutdown_handle: Handle) {
    let app = Router::new().layer(middleware::from_fn(redirect_http_to_https));

    let server = bind_http_server(listener).await;

    server
        .handle(shutdown_handle)
        .serve(app.into_make_service())
        .await
        .expect("unable to start HTTP server");
}
