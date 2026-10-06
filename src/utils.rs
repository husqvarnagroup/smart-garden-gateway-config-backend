// SPDX-FileCopyrightText: GARDENA GmbH
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::ops::Add;
use tokio::io::AsyncWriteExt;
use tracing::debug;

pub(crate) async fn is_file_present(file_path: &str) -> bool {
    tokio::fs::metadata(file_path)
        .await
        .is_ok_and(|metadata| metadata.is_file())
}

pub(crate) async fn remove_file(file_path: &str) {
    if let Err(error) = tokio::fs::remove_file(file_path).await {
        debug!("Failed to remove file {file_path}: {error}");
    }
}

pub(crate) async fn create_file(file_path: &str) {
    if let Err(error) = tokio::fs::File::create(file_path).await.map(|_| ()) {
        debug!("Failed to create file {file_path}: {error}");
    }
}

/// Create name of temporary file when writing atomically to
/// the filesystem. The name includes a random suffix, so concurrent
/// writers to the same file_path don't share, and clobber, one temporary
/// file.
fn temp_file_path(file_path: &str) -> String {
    let mut temp_file_path = file_path.to_string();
    temp_file_path = temp_file_path.add(&format!(".{:x}.tmp", rand::random::<u32>()));
    temp_file_path
}

/// Write file content into a temporary file first and move it then to the final
/// destination. This guarantees that the file content is complete in the final file because
/// moving a file on the filesystem is atomic (in contrast to writing to a file).
/// This step is important for embedded Linux.
pub async fn save_file_atomic(file_path: &str, content: String) -> std::io::Result<()> {
    let temp_file_path = temp_file_path(file_path);
    let mut file = tokio::fs::File::create(temp_file_path.clone()).await?;
    file.write_all(content.as_ref()).await?;
    file.sync_all().await?;
    tokio::fs::rename(temp_file_path, file_path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn test_temp_file_path_is_unique_per_call() {
        // Two concurrent save_file_atomic() calls for the same file_path must
        // not share a temporary file, or one call's write can be clobbered by
        // the other before either gets to rename its result into place.
        let first = temp_file_path("password");
        let second = temp_file_path("password");
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn test_create_and_remove_file() {
        let temp_dir = TempDir::new("test_create_and_remove_file").unwrap();
        let file_path = temp_dir.path().join("test_file.txt");
        let file_path_str = file_path.to_str().unwrap();

        // Test creating a file
        create_file(file_path_str).await;
        assert!(is_file_present(file_path_str).await);

        // Test removing the file
        remove_file(file_path_str).await;
        assert!(!is_file_present(file_path_str).await);
    }

    #[tokio::test]
    async fn test_create_file_multiple_times() {
        let temp_dir = TempDir::new("test_create_file_multiple_times").unwrap();
        let file_path = temp_dir.path().join("test_file.txt");
        let file_path_str = file_path.to_str().unwrap();

        // Test creating a file
        create_file(file_path_str).await;
        assert!(is_file_present(file_path_str).await);

        // Test creating the file again (should not fail)
        create_file(file_path_str).await;
        assert!(is_file_present(file_path_str).await);

        // Clean up by removing the file
        remove_file(file_path_str).await;
        assert!(!is_file_present(file_path_str).await);
    }

    #[tokio::test]
    async fn test_remove_file_multiple_times() {
        let temp_dir = TempDir::new("test_remove_file_multiple_times").unwrap();
        let file_path = temp_dir.path().join("test_file.txt");
        let file_path_str = file_path.to_str().unwrap();

        // Test removing a file
        remove_file(file_path_str).await;
        assert!(!is_file_present(file_path_str).await);

        // Test removing the file again (should not fail)
        remove_file(file_path_str).await;
        assert!(!is_file_present(file_path_str).await);
    }
}
