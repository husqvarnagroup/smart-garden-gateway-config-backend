// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::client_authentication::SESSION_TOKEN_STORE;
use axum_server::Handle;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

const INACTIVITY_TIMER_INTERVAL: Duration = Duration::from_secs(60);
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_millis(500);

async fn has_activity(handle: Handle) -> bool {
    if handle.connection_count() == 0 {
        debug!("no active connections, checking for active sessions");
        if let Ok(sessions) = SESSION_TOKEN_STORE.clone().lock() {
            if !sessions.has_active_sessions() {
                return false;
            }
        }
    }
    true
}

/* Task that checks regularly if no connections and sessions are available and shut down the
service if it is currently not used.
Inspired by: https://docs.rs/axum-server/latest/src/graceful_shutdown/graceful_shutdown.rs.html#42 */
pub(crate) async fn inactivity_timer(handle: Handle) {
    loop {
        sleep(INACTIVITY_TIMER_INTERVAL).await;
        if !has_activity(handle.clone()).await {
            handle.graceful_shutdown(Some(SHUTDOWN_GRACE_PERIOD));
        }
    }
}
