// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Context;
use axum::http::StatusCode;
use std::process::Output;
use std::time::Duration;
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;
use tracing::{debug, error};

/// Restart a systemd service, applying a 30 second timeout and turning a
/// missing/non-zero exit status into an appropriate `StatusCode`.
pub(crate) async fn restart_service_checked(service_name: &str) -> Result<(), StatusCode> {
    run_command_checked("systemctl", &["restart", service_name]).await?;
    Ok(())
}

pub(crate) async fn run_command_checked(
    command: &str,
    args: &[&str],
) -> Result<Output, StatusCode> {
    let output = timeout(Duration::from_secs(30), run_command(command, args))
        .await
        .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !output.status.success() {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(output)
}

pub(crate) async fn run_command(command: &str, args: &[&str]) -> anyhow::Result<Output> {
    let output = TokioCommand::new(command)
        .args(args)
        .kill_on_drop(true)
        .output()
        .await
        .with_context(|| format!("Failed to run command: {} {}", command, args.join(" ")))?;

    // Log stdout/stderr here, so that output from the child process is not lost
    if output.status.success() {
        debug!(
            "Command `{command} {}` finished with {}, stdout: {:?}, stderr: {:?}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        error!(
            "Command `{command} {}` failed with {}, stdout: {:?}, stderr: {:?}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_command() {
        let output = run_command("echo", &["Hello, world!"])
            .await
            .expect("Failed to run command");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout, "Hello, world!\n");
    }

    #[tokio::test]
    async fn test_run_failing_command() {
        let output = run_command("/bin/false", &[])
            .await
            .expect("Failed to run command");
        assert!(!output.status.success());
    }
}
