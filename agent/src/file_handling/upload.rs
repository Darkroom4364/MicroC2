use crate::config::validate_http_url;
use reqwest::{Client, Method};
use std::error::Error;
use std::fs;

/// Uploads a file to the given URL via HTTP POST using reqwest.
pub async fn upload_file_to_url(
    file_path: &str,
    upload_url: &str,
) -> Result<String, Box<dyn Error>> {
    let file_content = fs::read(file_path)?;
    let upload_url = validate_http_url(upload_url).map_err(|e| -> Box<dyn Error> { e.into() })?;

    let client = Client::new();
    let response = client
        .request(Method::POST, upload_url)
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
