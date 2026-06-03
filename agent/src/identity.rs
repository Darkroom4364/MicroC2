use crate::config::AgentConfig;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const AGENT_ID_FILE: &str = "agent_id";

pub fn resolve_runtime_agent_id(config: &AgentConfig) -> String {
    if let Some(agent_id) = configured_agent_id(&config.agent_id) {
        return agent_id;
    }

    match runtime_identity_dir() {
        Some(config_dir) => load_or_create_runtime_agent_id(&config_dir, &config.payload_id),
        None => generate_runtime_agent_id(&config.payload_id),
    }
}

pub fn generate_runtime_agent_id(payload_id: &str) -> String {
    let payload_component = identity_component(payload_id);
    format!(
        "agent-{}-{:032x}",
        payload_component,
        rand::random::<u128>()
    )
}

fn configured_agent_id(agent_id: &str) -> Option<String> {
    let trimmed = agent_id.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn runtime_identity_dir() -> Option<PathBuf> {
    match env::current_exe() {
        Ok(exe_path) => exe_path.parent().map(|parent| parent.join(".config")),
        Err(_) => None,
    }
}

fn load_or_create_runtime_agent_id(config_dir: &Path, payload_id: &str) -> String {
    let id_path = config_dir.join(AGENT_ID_FILE);
    if let Some(agent_id) = read_runtime_agent_id(&id_path) {
        return agent_id;
    }

    let agent_id = generate_runtime_agent_id(payload_id);
    if fs::create_dir_all(config_dir).is_ok() {
        let _ = fs::write(&id_path, agent_id.as_bytes());
    }
    agent_id
}

fn read_runtime_agent_id(id_path: &Path) -> Option<String> {
    match fs::read_to_string(id_path) {
        Ok(content) => configured_agent_id(&content),
        Err(_) => None,
    }
}

fn identity_component(raw: &str) -> String {
    let component: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect();
    if component.is_empty() {
        "runtime".to_string()
    } else {
        component
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn generated_agent_ids_are_distinct_from_payload_id() {
        let payload_id = "payload-one";
        let first = generate_runtime_agent_id(payload_id);
        let second = generate_runtime_agent_id(payload_id);

        assert_ne!(first, payload_id);
        assert_ne!(first, second);
        assert!(first.starts_with("agent-payloado-"));
        assert!(first.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    }

    #[test]
    fn explicit_agent_id_wins() {
        let config = AgentConfig {
            payload_id: "payload-one".to_string(),
            agent_id: " configured-agent ".to_string(),
            ..Default::default()
        };

        assert_eq!(resolve_runtime_agent_id(&config), "configured-agent");
    }

    #[test]
    fn runtime_agent_id_is_persisted_in_config_dir() {
        let config_dir = unique_temp_dir("identity");
        let first = load_or_create_runtime_agent_id(&config_dir, "payload-one");
        let second = load_or_create_runtime_agent_id(&config_dir, "payload-one");

        assert_eq!(first, second);
        assert_ne!(first, "payload-one");

        let id_path = config_dir.join(AGENT_ID_FILE);
        assert!(id_path.exists());
        let _ = fs::remove_file(id_path);
        let _ = fs::remove_dir_all(config_dir);
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos(),
            Err(err) => panic!("read system time: {}", err),
        };
        env::temp_dir().join(format!("microc2-{}-{}-{}", std::process::id(), nanos, name))
    }
}
