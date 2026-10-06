// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::client_authentication::SESSION_TOKEN_STORE;
use crate::gateway_info::{GATEWAY_ID, GATEWAY_VERSION};
use crate::https_server::start_https_server;
use crate::inactivity_timer::inactivity_timer;
use crate::redirect_https::start_http_server;
use crate::timezone::TIMEZONES;
use axum_server::Handle;
use listenfd::ListenFd;
use std::net::TcpListener;
use tokio::task::JoinSet;
use tracing::error;
use tracing::info;

mod access_point;
mod app;
mod client_authentication;
mod cloudadapter;
mod command;
mod consent;
mod dbus_helper;
mod gateway_info;
mod https_server;
mod inactivity_timer;
mod redirect_https;
mod ssh_access;
mod timezone;
mod utils;
mod websocket;
mod wifiapi;

fn initialize_static_values() {
    // load static values early, so that a potential panic does not go unnoticed in a thread
    lazy_static::initialize(&GATEWAY_ID);
    lazy_static::initialize(&GATEWAY_VERSION);
    lazy_static::initialize(&SESSION_TOKEN_STORE);
    lazy_static::initialize(&TIMEZONES);
}

fn take_socket_activated_listeners() -> (Option<TcpListener>, Option<TcpListener>) {
    /* Handling socket activation needs to be done in the main thread/task. */
    let mut listenfd = ListenFd::from_env();

    /* The index of the listener corresponds to the position of `ListenStream` under `[Socket]` in
    the systemd socket file for this service. See the file `gateway-config-backend.socket` in the
    `smart-garden-gateway-yocto-meta-gardena` repository.
    ```
    [Socket]
    ListenStream=80
    ListenStream=443
    ```
    */

    let http_listener = listenfd
        .take_tcp_listener(0)
        .expect("can't take listener0 for HTTP");

    let https_listener = listenfd
        .take_tcp_listener(1)
        .expect("can't take listener1 for HTTPS");

    (http_listener, https_listener)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    gardenalog::init_tracing();
    initialize_static_values();

    let (http_listener, https_listener) = take_socket_activated_listeners();

    let shutdown_handle = Handle::new();

    tokio::spawn(inactivity_timer(shutdown_handle.clone()));

    let mut servers = JoinSet::new();
    servers.spawn(start_http_server(http_listener, shutdown_handle.clone()));
    servers.spawn(start_https_server(https_listener, shutdown_handle));

    while let Some(server) = servers.join_next().await {
        if let Err(e) = server {
            error!("server task failed: {:?}", e)
        }
    }

    info!("shutting down");
}
