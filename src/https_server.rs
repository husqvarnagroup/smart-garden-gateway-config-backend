// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::app;
use axum_server::tls_openssl::OpenSSLAcceptor;
use axum_server::tls_openssl::OpenSSLConfig;
use axum_server::Handle;
use axum_server::Server;
use openssl::ssl::SslAcceptor;
use openssl::ssl::SslFiletype;
use openssl::ssl::SslMethod;
use std::net::{SocketAddr, TcpListener};
use tracing::debug;
use tracing::info;

const SSL_CERT_FILE: &str = "cert.pem";
const SSL_KEY_FILE: &str = "key.pem";

fn https_port() -> i32 {
    if cfg!(feature = "nongwhw") {
        8888
    } else {
        // use default port
        443
    }
}

fn cert_path() -> &'static str {
    if cfg!(feature = "nongwhw") {
        "test-fixtures/"
    } else {
        ""
    }
}

fn build_ssl_config() -> OpenSSLConfig {
    let cert_path = cert_path();
    debug!("using certificate path: {cert_path}");

    let mut ssl_builder =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("failed to load openssl");
    ssl_builder
        .set_private_key_file(format!("{cert_path}{SSL_KEY_FILE}"), SslFiletype::PEM)
        .expect("failed to load SSL key file");
    ssl_builder
        .set_certificate_chain_file(format!("{cert_path}{SSL_CERT_FILE}"))
        .expect("failed to load SSL certificate file");
    ssl_builder
        .check_private_key()
        .expect("SSL key does not match certificate");

    OpenSSLConfig::try_from(ssl_builder).expect("failed to create OpenSSL config")
}

async fn bind_https_server(listener: Option<TcpListener>) -> Server<OpenSSLAcceptor> {
    let config = build_ssl_config();

    if let Some(listener) = listener {
        info!(
            "starting server with socket activation on listener {}",
            listener.local_addr().unwrap()
        );
        axum_server::from_tcp(listener).acceptor(OpenSSLAcceptor::new(config))
    } else {
        let https_port = https_port();
        let addr: SocketAddr = format!("[::]:{https_port}").parse().unwrap();
        info!("starting server on {addr}");
        axum_server::bind_openssl(addr, config)
    }
}

pub(crate) async fn start_https_server(listener: Option<TcpListener>, shutdown_handle: Handle) {
    let app = app::create_app();
    let server = bind_https_server(listener).await;

    server
        .handle(shutdown_handle)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
