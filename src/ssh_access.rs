// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::command::restart_service_checked;
use crate::utils::{create_file, is_file_present, remove_file, save_file_atomic};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

const AUTHORIZED_KEYS_FILE: &str = "/root/.ssh/authorized_keys";
const SYSUPGRADE_CONF_FILE: &str = "/etc/sysupgrade.conf";
const FIREWALL_ALLOW_SSH_FILE: &str = "/etc/allow-local-ssh";

#[derive(Debug, Deserialize)]
pub struct SshCredentials {
    pub key: String,
}

pub async fn add_ssh_credentials(
    credentials: Json<SshCredentials>,
) -> Result<StatusCode, StatusCode> {
    add_public_key_and_protect_for_sysupgrade(&credentials.key)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

async fn add_public_key_and_protect_for_sysupgrade(public_key: &str) -> std::io::Result<()> {
    add_public_key(AUTHORIZED_KEYS_FILE, public_key).await?;
    protect_authorized_keys_for_sysupgrade(SYSUPGRADE_CONF_FILE).await?;
    Ok(())
}

async fn add_public_key(file_name: &str, public_key: &str) -> std::io::Result<()> {
    let mut authorized_keys_content = tokio::fs::read_to_string(file_name).await?;

    let public_key = public_key.trim();
    authorized_keys_content.push_str("\n# Added by gateway-config-backend:\n");
    authorized_keys_content.push_str(public_key);
    authorized_keys_content.push('\n');
    save_file_atomic(file_name, authorized_keys_content).await
}

async fn protect_authorized_keys_for_sysupgrade(conf_file: &str) -> std::io::Result<()> {
    let mut conf_file_content = tokio::fs::read_to_string(conf_file)
        .await
        .unwrap_or_else(|_| String::new());

    let protection_entry = format!(
        "# `authorized_keys` protected by `gateway-config-backend`:\n{AUTHORIZED_KEYS_FILE}\n"
    );
    if conf_file_content.contains(&protection_entry) {
        return Ok(());
    }

    conf_file_content.push_str(&protection_entry);
    save_file_atomic(conf_file, conf_file_content).await
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SshAccess {
    /* Previously the field was named `enable`. This is counterintuitive for a getter
    so it is renamed, but setting (deserializing) with the old name is still allowed. */
    #[serde(alias = "enable")]
    pub enabled: bool,
}

pub async fn set_ssh_access(settings: Json<SshAccess>) -> Result<StatusCode, StatusCode> {
    run_ssh_activation(settings.enabled).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn is_ssh_access_enabled() -> Json<SshAccess> {
    Json(SshAccess {
        enabled: is_file_present(FIREWALL_ALLOW_SSH_FILE).await,
    })
}

async fn run_ssh_activation(enable: bool) -> Result<(), StatusCode> {
    configure_ssh_access(enable, FIREWALL_ALLOW_SSH_FILE).await;

    restart_service_checked("firewall").await?;

    Ok(())
}

async fn configure_ssh_access(enable: bool, file_name: &str) {
    if enable {
        create_file(file_name).await;
    } else {
        remove_file(file_name).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use tempdir::TempDir;
    use tokio::io::AsyncWriteExt;

    const DUMMY_AUTHORIZED_KEYS_FILE: &str = "authorized_keys";
    const DUMMY_SYSUPGRADE_CONF_FILE: &str = "sysupgrade.conf";
    const DUMMY_FIREWALL_ALLOW_SSH_FILE: &str = "allow-local-ssh";

    async fn create_test_authorized_keys_file(temp_dir: &TempDir) -> std::path::PathBuf {
        let dummy_authorized_keys_file = temp_dir.path().join(DUMMY_AUTHORIZED_KEYS_FILE);
        let mut f = tokio::fs::File::create(&dummy_authorized_keys_file)
            .await
            .unwrap();
        f.write_all(
            b"# Existing authorized keys\nssh-dummy AAAAB3NzaC1yc2EAAAABIwAAAQEArD1 testing\n",
        )
        .await
        .unwrap();
        f.sync_all().await.unwrap();
        dummy_authorized_keys_file
    }

    #[tokio::test]
    async fn test_add_public_key() {
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let authorized_key_file = create_test_authorized_keys_file(&temp_dir).await;

        add_public_key(
            authorized_key_file.to_str().unwrap(),
            "ssh-dummy AaBbCc1234 just for testing",
        )
        .await
        .unwrap();

        let mut expected_authorized_keys_file_content = String::from_str(
            "# Existing authorized keys\nssh-dummy AAAAB3NzaC1yc2EAAAABIwAAAQEArD1 testing\n",
        )
        .unwrap();
        expected_authorized_keys_file_content.push_str(
            "\n# Added by gateway-config-backend:\nssh-dummy AaBbCc1234 just for testing\n",
        );

        let authorized_keys_content = tokio::fs::read_to_string(authorized_key_file)
            .await
            .unwrap();
        assert_eq!(
            expected_authorized_keys_file_content,
            authorized_keys_content
        );
    }

    #[tokio::test]
    async fn test_protect_authorized_keys_for_sysupgrade_file_not_exists() {
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_sysupgrade_conf_file = temp_dir.path().join(DUMMY_SYSUPGRADE_CONF_FILE);
        protect_authorized_keys_for_sysupgrade(dummy_sysupgrade_conf_file.to_str().unwrap())
            .await
            .unwrap();

        let expected_sysupgrade_conf_file_content = String::from_str(
            "# `authorized_keys` protected by `gateway-config-backend`:\n/root/.ssh/authorized_keys\n").unwrap();

        let sysupgrade_conf_content = tokio::fs::read_to_string(dummy_sysupgrade_conf_file)
            .await
            .unwrap();
        assert_eq!(
            expected_sysupgrade_conf_file_content,
            sysupgrade_conf_content
        );
    }

    #[tokio::test]
    async fn test_protect_authorized_keys_for_sysupgrade_file_exists() {
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_sysupgrade_conf_file = temp_dir.path().join(DUMMY_SYSUPGRADE_CONF_FILE);

        let mut f = tokio::fs::File::create(&dummy_sysupgrade_conf_file)
            .await
            .unwrap();
        f.write_all(b"# Existing sysupgrade config\n/tmp/some_other_file\n")
            .await
            .unwrap();
        f.sync_all().await.unwrap();

        protect_authorized_keys_for_sysupgrade(dummy_sysupgrade_conf_file.to_str().unwrap())
            .await
            .unwrap();

        let expected_sysupgrade_conf_file_content = String::from_str(
            "# Existing sysupgrade config\n/tmp/some_other_file\n# `authorized_keys` protected by `gateway-config-backend`:\n/root/.ssh/authorized_keys\n").unwrap();

        let sysupgrade_conf_content = tokio::fs::read_to_string(DUMMY_SYSUPGRADE_CONF_FILE)
            .await
            .unwrap();
        assert_eq!(
            expected_sysupgrade_conf_file_content,
            sysupgrade_conf_content
        );
    }

    #[tokio::test]
    async fn test_protect_authorized_keys_for_sysupgrade_entry_already_present() {
        let existing_content =
            "# Existing sysupgrade config\n/tmp/some_other_file\n# `authorized_keys` protected by `gateway-config-backend`:\n/root/.ssh/authorized_keys\n";
        tokio::fs::write(DUMMY_SYSUPGRADE_CONF_FILE, existing_content)
            .await
            .unwrap();

        protect_authorized_keys_for_sysupgrade(DUMMY_SYSUPGRADE_CONF_FILE)
            .await
            .unwrap();

        let sysupgrade_conf_content = tokio::fs::read_to_string(DUMMY_SYSUPGRADE_CONF_FILE)
            .await
            .unwrap();
        assert_eq!(existing_content, sysupgrade_conf_content);
    }

    #[tokio::test]
    async fn test_enable_ssh_access() {
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_firewall_allow_ssh_file = temp_dir.path().join(DUMMY_FIREWALL_ALLOW_SSH_FILE);
        assert!(!dummy_firewall_allow_ssh_file.exists());

        configure_ssh_access(true, dummy_firewall_allow_ssh_file.to_str().unwrap()).await;
        assert!(dummy_firewall_allow_ssh_file.exists());
    }

    #[tokio::test]
    async fn test_enable_ssh_access_file_exists() {
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_firewall_allow_ssh_file = temp_dir.path().join(DUMMY_FIREWALL_ALLOW_SSH_FILE);
        assert!(!dummy_firewall_allow_ssh_file.exists());

        configure_ssh_access(true, dummy_firewall_allow_ssh_file.to_str().unwrap()).await;
        assert!(dummy_firewall_allow_ssh_file.exists());

        configure_ssh_access(true, dummy_firewall_allow_ssh_file.to_str().unwrap()).await;
        assert!(dummy_firewall_allow_ssh_file.exists());
    }

    #[tokio::test]
    async fn test_disable_ssh_access() {
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_firewall_allow_ssh_file = temp_dir.path().join(DUMMY_FIREWALL_ALLOW_SSH_FILE);

        // make sure the file exists before disabling
        configure_ssh_access(true, dummy_firewall_allow_ssh_file.to_str().unwrap()).await;
        assert!(dummy_firewall_allow_ssh_file.exists());

        configure_ssh_access(false, dummy_firewall_allow_ssh_file.to_str().unwrap()).await;
        assert!(!dummy_firewall_allow_ssh_file.exists());
    }
    #[tokio::test]
    async fn test_disable_ssh_access_file_doesnt_exist() {
        let temp_dir = TempDir::new("config-backend-tests").unwrap();
        let dummy_firewall_allow_ssh_file = temp_dir.path().join(DUMMY_FIREWALL_ALLOW_SSH_FILE);

        assert!(!dummy_firewall_allow_ssh_file.exists());

        configure_ssh_access(false, dummy_firewall_allow_ssh_file.to_str().unwrap()).await;
        assert!(!dummy_firewall_allow_ssh_file.exists());
    }
}
