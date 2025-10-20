use std::fs;
use std::error::Error;
use std::time::Duration;
use reqwest::Client;
use obfstr::obfstr;

/// Uploads a file to the given URL via HTTP POST using reqwest.
/// Includes timeout protection to prevent hanging on stalled connections
pub async fn upload_file_to_url(file_path: &str, upload_url: &str) -> Result<String, Box<dyn Error>> {
    let file_content = fs::read(file_path)?;
    
    let client = Client::builder()
        .timeout(Duration::from_secs(300)) // 5 minute total timeout
        .connect_timeout(Duration::from_secs(30)) // 30 second connect timeout
        .build()?;
        
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
