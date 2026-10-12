// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::command::restart_service_checked;
use crate::utils::{create_file, is_file_present, remove_file};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

const ENABLE_WEBSOCKETD_FILE: &str = "/etc/enable-websocketd";

#[derive(Debug, Deserialize, Serialize)]
pub struct WebSocketApi {
    /* Previously the field was named `enable`. This is counterintuitive for a getter
    so it is renamed, but setting (deserializing) with the old name is still allowed. */
    #[serde(alias = "enable")]
    pub enabled: bool,
}

pub(crate) async fn enable_websocket_api(
    settings: Json<WebSocketApi>,
) -> Result<StatusCode, StatusCode> {
    run_websocket_activation(settings.enabled)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn is_websocket_api_enabled() -> Json<WebSocketApi> {
    Json(WebSocketApi {
        enabled: is_file_present(ENABLE_WEBSOCKETD_FILE).await,
    })
}

async fn run_websocket_activation(enable: bool) -> Result<StatusCode, StatusCode> {
    configure_websocketd(enable, ENABLE_WEBSOCKETD_FILE).await;

    restart_service_checked("websocketd").await?;
    restart_service_checked("firewall").await?;

    Ok(StatusCode::NO_CONTENT)
}

async fn configure_websocketd(enable: bool, file_name: &str) {
    if enable {
        create_file(file_name).await;
    } else {
        remove_file(file_name).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    const DUMMY_ENABLE_WEBSOCKETD_FILE: &str = "enable-websocketd";

    #[tokio::test]
    async fn test_configure_websocketd() {
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_enable_websocketd_file = temp_dir.path().join(DUMMY_ENABLE_WEBSOCKETD_FILE);
        assert!(!dummy_enable_websocketd_file.exists());

        configure_websocketd(true, dummy_enable_websocketd_file.to_str().unwrap()).await;
        assert!(dummy_enable_websocketd_file.exists());

        configure_websocketd(false, dummy_enable_websocketd_file.to_str().unwrap()).await;
        assert!(!dummy_enable_websocketd_file.exists());
    }
}
