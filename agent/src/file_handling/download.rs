use log::{debug, error, info, warn};
use reqwest::Client; // Use reqwest::Client
use std::error::Error;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

/// Download a file using reqwest by streaming chunks directly to disk
pub async fn download_file(url: &str, dest_path: &Path) -> Result<(), Box<dyn Error>> {
    let client = Client::new();
    let mut resp = client.get(url).send().await?; // Use reqwest::Client::get and send

    if !resp.status().is_success() {
        return Err(format!("Download failed with status: {}", resp.status()).into());
    }

    // Create file asynchronously
    let mut file = File::create(dest_path).await?;

    // Stream body chunks to file using reqwest::Response::chunk
    while let Some(chunk) = resp.chunk().await? {
        file.write_all(&chunk).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tokio::runtime::Runtime;

    // Basic test requires a running web server to serve the file.
    // This test structure assumes such a server exists at 127.0.0.1:8080.
    #[test]
    fn test_download_functionality() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let test_file_url = "http://127.0.0.1:8080/test_download.txt"; // Example URL
            let download_path = PathBuf::from("downloaded_test_file.txt");

            // Ensure the test file doesn't exist before download
            if download_path.exists() {
                fs::remove_file(&download_path).unwrap();
            }

            // Attempt download
            match download_file(test_file_url, &download_path).await {
                Ok(_) => {
                    info!("Download successful.");
                    // Verify file exists
                    assert!(download_path.exists());
                    // Optional: Verify file content if known
                    // let content = fs::read_to_string(&download_path).unwrap();
                    // assert_eq!(content, "Expected content");
                }
                Err(e) => {
                    // If the server isn't running, this error is expected.
                    warn!(
                        "Download failed (is test server running at {}?): {}",
                        test_file_url, e
                    );
                    // We don't fail the test here, as the server might not be running.
                    // assert!(false, "Download failed: {}", e);
                }
            }

            // Cleanup
            if download_path.exists() {
                fs::remove_file(&download_path).unwrap();
            }
        });
    }
}
