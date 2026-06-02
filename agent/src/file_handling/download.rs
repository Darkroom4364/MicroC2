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
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn downloads_successful_response_to_disk() {
        let url = spawn_one_response_server("200 OK", b"downloaded body").await;
        let download_path = unique_temp_path("download-success.txt");

        if let Err(err) = download_file(&url, &download_path).await {
            panic!("download should succeed: {}", err);
        }

        let content = must(fs::read_to_string(&download_path), "read downloaded file");
        assert_eq!(content, "downloaded body");
        let _ = fs::remove_file(download_path);
    }

    #[tokio::test]
    async fn returns_error_for_unsuccessful_response() {
        let url = spawn_one_response_server("404 Not Found", b"missing").await;
        let download_path = unique_temp_path("download-missing.txt");

        let err = match download_file(&url, &download_path).await {
            Ok(()) => panic!("download should fail for 404 response"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("404"));
        assert!(!download_path.exists());
    }

    async fn spawn_one_response_server(status: &'static str, body: &'static [u8]) -> String {
        let listener = must(TcpListener::bind("127.0.0.1:0").await, "bind test server");
        let addr = must(listener.local_addr(), "read test server address");
        tokio::spawn(async move {
            let (mut stream, _) = must(listener.accept().await, "accept test request");
            let mut request = [0_u8; 1024];
            let _ = must(stream.read(&mut request).await, "read test request");
            let headers = format!(
                "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                status,
                body.len()
            );
            must(
                stream.write_all(headers.as_bytes()).await,
                "write test response headers",
            );
            must(stream.write_all(body).await, "write test response body");
        });
        format!("http://{}", addr)
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = must(
            SystemTime::now().duration_since(UNIX_EPOCH),
            "read system time",
        )
        .as_nanos();
        std::env::temp_dir().join(format!("microc2-{}-{}-{}", std::process::id(), nanos, name))
    }

    fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{}: {}", context, err),
        }
    }
}
