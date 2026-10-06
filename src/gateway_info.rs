// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use axum::Json;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::warn;

lazy_static! {
    pub static ref GATEWAY_VERSION: String = gateway_version();
    pub static ref GATEWAY_ID: String = get_gateway_id();
}

#[derive(Deserialize, Serialize, PartialEq, Debug)]
pub(crate) struct GatewayVersion {
    gateway_version: String,
}

pub(crate) async fn get_gateway_version() -> Json<GatewayVersion> {
    let gw_version = GatewayVersion {
        gateway_version: GATEWAY_VERSION.clone(),
    };
    Json(gw_version)
}

fn gateway_version() -> String {
    if cfg!(feature = "nongwhw") {
        warn!("Using development variant of gateway-config-backend");
        return "1.0".to_string();
    }

    let file =
        ::std::fs::read_to_string("/etc/os-release").expect("failed to read os-release file");
    let version_line = file
        .split('\n')
        .find(|l| {
            let l = l.trim();
            l.starts_with("VERSION_ID=\"") && l.ends_with('"')
        })
        .expect("failed to parse os-release file");
    version_line[12..version_line.len() - 1].to_string()
}

fn get_gateway_id() -> String {
    if cfg!(feature = "nongwhw") {
        warn!("Using development variant of gateway-config-backend");
        return "7155a0b7-86ee-4fc9-bee7-a1daaf64f7c4".to_string();
    }

    let output = Command::new("/sbin/fw_printenv")
        .args(["-n", "gatewayid"])
        .output()
        .expect("failed to get gateway ID")
        .stdout;
    let gateway_id = String::from_utf8_lossy(&output).trim().to_lowercase();
    if gateway_id.len() != 36 {
        panic!("Gateway ID does not seem valid.");
    }
    gateway_id
}

#[cfg(test)]
mod tests {
    use crate::app::create_app;
    use crate::gateway_info::GatewayVersion;
    use axum::http::StatusCode;
    use axum_test::TestServer;

    #[tokio::test]
    async fn test_get_gateway_version() {
        let app = create_app();
        let app = app.into_make_service();
        let server = TestServer::new(app);
        let response = server.get("/version").await;

        response
            .assert_status(StatusCode::OK)
            .assert_json(&GatewayVersion {
                gateway_version: "1.0".to_string(),
            });
    }
}
