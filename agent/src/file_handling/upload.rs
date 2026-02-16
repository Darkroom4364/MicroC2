use std::error::Error;
use reqwest::Client;

/// Uploads a file to the given URL via HTTP POST using the provided reqwest client.
/// The caller must pass a client built from AgentConfig::build_http_client() to ensure
/// SOCKS5 proxy and other agent-wide settings are respected.
pub async fn upload_file_to_url(client: &Client, file_path: &str, upload_url: &str) -> Result<String, Box<dyn Error>> {
    let file_content = tokio::fs::read(file_path).await?;

    let response = client
        .post(upload_url)
        .header("Content-Type", "application/octet-stream")
        .body(file_content)
        .send()
        .await?;

    if response.status().is_success() {
        Ok(format!("File uploaded successfully: {}", response.status()))
    } else {
        Err(format!("Upload failed with status: {}", response.status()).into())
    }
}
