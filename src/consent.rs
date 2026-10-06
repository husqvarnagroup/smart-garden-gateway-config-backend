// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::command::run_command_checked;
use crate::utils::is_file_present;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

const CONSENT_TELEMETRY_FILE: &str = "/etc/consent-to-telemetry";
const CONSENT_SUPPORT_BUNDLE_FILE: &str = "/etc/consent-to-support-bundle";

#[derive(Debug, Deserialize, Serialize)]
pub struct Consent {
    pub enabled: bool,
}

pub(crate) async fn get_telemetry_consent() -> Json<Consent> {
    Json(Consent {
        enabled: is_file_present(CONSENT_TELEMETRY_FILE).await,
    })
}

pub(crate) async fn set_telemetry_consent(
    consent: Json<Consent>,
) -> Result<StatusCode, StatusCode> {
    run_telemetry_consent_activation(CONSENT_TELEMETRY_FILE, consent.enabled).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn get_support_bundle_consent() -> Json<Consent> {
    Json(Consent {
        enabled: is_file_present(CONSENT_SUPPORT_BUNDLE_FILE).await,
    })
}

pub(crate) async fn set_support_bundle_consent(
    consent: Json<Consent>,
) -> Result<StatusCode, StatusCode> {
    configure_consent_file(CONSENT_SUPPORT_BUNDLE_FILE, consent.enabled).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn configure_consent_file(file_name: &str, allow: bool) {
    if allow {
        crate::utils::create_file(file_name).await;
    } else {
        crate::utils::remove_file(file_name).await;
    }
}

async fn run_telemetry_consent_activation(file_name: &str, allow: bool) -> Result<(), StatusCode> {
    configure_consent_file(file_name, allow).await;

    if allow {
        run_command_checked("systemctl", &["start", "-q", "--no-block", "syslog.socket"]).await?;
        run_command_checked("systemctl", &["start", "-q", "--no-block", "syslog"]).await?;
    } else {
        run_command_checked("systemctl", &["stop", "-q", "--no-block", "syslog"]).await?;
        run_command_checked("systemctl", &["stop", "-q", "--no-block", "syslog.socket"]).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempdir::TempDir;

    const DUMMY_CONSENT_FILE: &str = "consent-to-support-bundle";

    #[tokio::test]
    async fn test_configure_consent_file() {
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_consent_file = temp_dir.path().join(DUMMY_CONSENT_FILE);
        assert!(!dummy_consent_file.exists());

        super::configure_consent_file(dummy_consent_file.to_str().unwrap(), true).await;
        assert!(dummy_consent_file.exists());

        super::configure_consent_file(dummy_consent_file.to_str().unwrap(), false).await;
        assert!(!dummy_consent_file.exists());
    }
}
