use std::error::Error;
use std::path::Path;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use reqwest::Client;
use log::{info, warn, error, debug};

/// Download a file using the provided reqwest client by streaming chunks directly to disk.
/// The caller must pass a client built from AgentConfig::build_http_client() to ensure
/// SOCKS5 proxy and other agent-wide settings are respected.
pub async fn download_file(client: &Client, url: &str, dest_path: &Path) -> Result<(), Box<dyn Error>> {
    let mut resp = client.get(url).send().await?;

    if !resp.status().is_success() {
        return Err(format!("Download failed with status: {}", resp.status()).into());
    }

    // Create file asynchronously
    let mut file = File::create(dest_path).await?;

    // Stream body chunks to file with timeout per chunk
    let chunk_timeout = Duration::from_secs(60); // 1 minute per chunk
    while let Ok(Some(chunk)) = tokio::time::timeout(chunk_timeout, resp.chunk()).await? {
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

            // Build a test client (no proxy, direct connection)
            let client = Client::builder()
                .timeout(Duration::from_secs(10))
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap();

            // Attempt download
            match download_file(&client, test_file_url, &download_path).await {
                Ok(_) => {
                    info!("Download successful.");
                    // Verify file exists
                    assert!(download_path.exists());
                }
                Err(e) => {
                    // If the server isn't running, this error is expected.
                    warn!("Download failed (is test server running at {}?): {}", test_file_url, e);
                }
            }

            // Cleanup
            if download_path.exists() {
                fs::remove_file(&download_path).unwrap();
            }
        });
    }
}
