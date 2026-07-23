use crate::config::AgentConfig;
use crate::tasks::{validate_identifier, TaskValidationError};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const AGENT_ID_FILE: &str = "agent_id";

pub fn resolve_runtime_agent_id(config: &AgentConfig) -> Result<String, TaskValidationError> {
    if let Some(agent_id) = configured_agent_id(&config.agent_id)? {
        return Ok(agent_id);
    }

    Ok(match runtime_identity_dir() {
        Some(config_dir) => load_or_create_runtime_agent_id(&config_dir, &config.payload_id),
        None => generate_runtime_agent_id(&config.payload_id),
    })
}

pub fn generate_runtime_agent_id(payload_id: &str) -> String {
    let payload_component = identity_component(payload_id);
    format!(
        "agent-{}-{:032x}",
        payload_component,
        rand::random::<u128>()
    )
}

fn configured_agent_id(agent_id: &str) -> Result<Option<String>, TaskValidationError> {
    if agent_id.is_empty() {
        return Ok(None);
    }
    validate_identifier("agent_id", agent_id)?;
    Ok(Some(agent_id.to_string()))
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
        Ok(content) => configured_agent_id(&content).ok().flatten(),
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
            agent_id: "configured-agent".to_string(),
            ..Default::default()
        };

        assert_eq!(
            resolve_runtime_agent_id(&config).expect("valid configured identity"),
            "configured-agent"
        );
    }

    #[test]
    fn invalid_explicit_agent_id_fails_fast() {
        let config = AgentConfig {
            payload_id: "payload-one".to_string(),
            agent_id: "invalid agent/id".to_string(),
            ..Default::default()
        };

        let error = resolve_runtime_agent_id(&config).expect_err("invalid configured identity");
        assert!(error.to_string().contains("unsupported characters"));
    }

    #[test]
    fn explicit_agent_id_is_not_silently_trimmed() {
        let config = AgentConfig {
            payload_id: "payload-one".to_string(),
            agent_id: " configured-agent ".to_string(),
            ..Default::default()
        };

        assert!(resolve_runtime_agent_id(&config).is_err());
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

    #[test]
    fn invalid_persisted_agent_id_is_replaced() {
        let config_dir = unique_temp_dir("invalid-identity");
        fs::create_dir_all(&config_dir).expect("create identity dir");
        let id_path = config_dir.join(AGENT_ID_FILE);
        fs::write(&id_path, "invalid agent/id").expect("write invalid identity");

        let resolved = load_or_create_runtime_agent_id(&config_dir, "payload-one");
        assert_ne!(resolved, "invalid agent/id");
        validate_identifier("agent_id", &resolved).expect("replacement identifier");
        assert_eq!(
            fs::read_to_string(&id_path).expect("read replacement identity"),
            resolved
        );

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
