// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::command::run_command;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use std::time::Duration;
use tokio::time::timeout;
use tracing::debug;

#[derive(Serialize)]
pub struct Ap {
    active: bool,
}

async fn is_hostapd_running() -> anyhow::Result<bool, StatusCode> {
    debug!("checking if hostapd is running");

    let status = run_command("/usr/bin/pgrep", &["hostapd"])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .status;

    if !status.success() {
        debug!("hostapd is not running");
        return Ok(false);
    }

    debug!("hostapd is running");
    Ok(true)
}

pub(crate) async fn get_ap() -> Result<Json<Ap>, StatusCode> {
    timeout(Duration::from_secs(60), is_hostapd_running())
        .await
        .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
        .map(|is_running| Json(Ap { active: is_running }))
}
