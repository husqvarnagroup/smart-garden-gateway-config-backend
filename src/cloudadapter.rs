// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::command::restart_service_checked;
use crate::utils::is_file_present;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

const DISABLE_CLOUDADAPTER_FILE: &str = "/etc/disable-cloudadapter";

#[derive(Debug, Deserialize, Serialize)]
pub struct CloudAdapter {
    pub enabled: bool,
}

pub(crate) async fn enable_cloudadapter(
    settings: Json<CloudAdapter>,
) -> Result<StatusCode, StatusCode> {
    run_cloudadapter_activation(settings.enabled).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn is_cloudadapter_enabled() -> Json<CloudAdapter> {
    Json(CloudAdapter {
        enabled: !is_file_present(DISABLE_CLOUDADAPTER_FILE).await,
    })
}

async fn run_cloudadapter_activation(enabled: bool) -> Result<(), StatusCode> {
    configure_cloudadapter_disable_file(DISABLE_CLOUDADAPTER_FILE, enabled).await;

    restart_service_checked("cloudadapter").await?;

    Ok(())
}

async fn configure_cloudadapter_disable_file(file_name: &str, enabled: bool) {
    // Note: the logic here is that the cloudadapter is disabled when the
    // file is present. That is inverted to other cases (i.e., local SSH access
    // or websocketd).
    if enabled {
        crate::utils::remove_file(file_name).await;
    } else {
        crate::utils::create_file(file_name).await;
    }
}

#[cfg(test)]
mod tests {
    use tempdir::TempDir;

    const DUMMY_DISABLE_CLOUDADAPTER_FILE: &str = "disable-cloudadapter";

    #[tokio::test]
    async fn test_configure_cloudadapter_disable_file() {
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_disable_file = temp_dir.path().join(DUMMY_DISABLE_CLOUDADAPTER_FILE);
        assert!(!dummy_disable_file.exists());

        super::configure_cloudadapter_disable_file(dummy_disable_file.to_str().unwrap(), false)
            .await;
        assert!(dummy_disable_file.exists());

        super::configure_cloudadapter_disable_file(dummy_disable_file.to_str().unwrap(), true)
            .await;
        assert!(!dummy_disable_file.exists());
    }
}
