// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::command::run_command;
use anyhow::Context;
use axum::http::StatusCode;
use axum::Json;
use lazy_static::lazy_static;
use std::process::Command as StdCommand;
use std::time::Duration;
use tokio::fs::read_link;
use tokio::time::timeout;
use tracing::{debug, error};

lazy_static! {
    /* This is initialized at the beginning of `main`. Therefore, it is guaranteed to be initialized
    before any request is handled. */
    pub(crate) static ref TIMEZONES: Vec<String> = {
        let output = StdCommand::new("/usr/bin/timedatectl")
            .args(["list-timezones"])
            .output()
            .expect("failed to get list of available timezones")
            .stdout;

        String::from_utf8_lossy(&output)
            .lines()
            .filter(|x| !x.is_empty())
            .map(String::from)
            .collect()
    };
}

pub async fn get_timezone() -> Result<Json<String>, StatusCode> {
    let localtime_path = read_link("/etc/localtime")
        .await
        .context("failed to read /etc/localtime path")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_str()
        .unwrap_or_default()
        .to_string();

    debug!("Localtime path: {localtime_path}");
    let mut localtime = localtime_path.rsplit("share/zoneinfo/");
    let localtime = localtime
        .next()
        .context("failed to parse timezone file")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .to_string();
    debug!("Localtime: {localtime}");
    Ok(Json(localtime))
}

async fn set_timezone_with_timedatectl(timezone: String) -> Result<Json<String>, StatusCode> {
    debug!("Setting timezone {timezone}");
    let status = run_command("/usr/bin/timedatectl", &["set-timezone", &timezone])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .status;

    if !status.success() {
        error!("timedatectl command failed with {status}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    debug!("Setting timezone to {timezone}");
    Ok(Json(timezone))
}

pub async fn set_timezone(timezone: Json<String>) -> Result<Json<String>, StatusCode> {
    let timezone = timezone.parse().unwrap_or_default();
    if !TIMEZONES.contains(&timezone) {
        error!("provided time zone is invalid: {timezone}");
        return Err(StatusCode::BAD_REQUEST);
    }

    timeout(
        Duration::from_secs(60),
        set_timezone_with_timedatectl(timezone),
    )
    .await
    .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
}

pub async fn get_timezone_list() -> Json<&'static Vec<String>> {
    Json(&TIMEZONES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_timezone_get() {
        let timezone = get_timezone().await.expect("failed to get timezone");
        // expecting that tests run on a system with Europe/Zurich timezone
        assert_eq!(timezone.to_string(), "Europe/Zurich".to_string());
    }

    #[tokio::test]
    async fn test_timezone_list() {
        let timezones = get_timezone_list().await;
        let timezones = timezones.to_vec();
        // Expecting that there are a lot of timezones available
        assert!(timezones.len() > 100);
        assert!(timezones.contains(&"Europe/Zurich".to_string()));
        assert!(timezones.contains(&"America/Detroit".to_string()));
        assert!(timezones.contains(&"Asia/Shanghai".to_string()));
    }
}
