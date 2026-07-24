use crate::config::AgentConfig;
use crate::tasks::validate_identifier;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const AGENT_ID_FILE: &str = "agent_id";
const APPLICATION_STATE_DIRECTORY: &str = "microc2";
const AGENT_STATE_DIRECTORY: &str = "agent";

pub fn resolve_runtime_agent_id(config: &AgentConfig) -> io::Result<String> {
    if let Some(agent_id) = configured_agent_id(&config.agent_id)? {
        return Ok(agent_id);
    }

    let config_dir = runtime_identity_dir(config)?;
    load_or_create_runtime_agent_id(&config_dir, &config.payload_id)
}

pub fn generate_runtime_agent_id(payload_id: &str) -> String {
    let payload_component = identity_component(payload_id);
    format!(
        "agent-{}-{:032x}",
        payload_component,
        rand::random::<u128>()
    )
}

fn configured_agent_id(agent_id: &str) -> io::Result<Option<String>> {
    if agent_id.is_empty() {
        return Ok(None);
    }
    validate_identifier("agent_id", agent_id)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    Ok(Some(agent_id.to_string()))
}

pub(crate) fn runtime_identity_dir(config: &AgentConfig) -> io::Result<PathBuf> {
    validate_identifier("listener_id", &config.listener_id)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    validate_identifier("payload_id", &config.payload_id)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    Ok(runtime_state_root()?
        .join(scoped_component(&config.listener_id))
        .join(scoped_component(&config.payload_id)))
}

pub(crate) fn runtime_session_dir(config: &AgentConfig, agent_id: &str) -> io::Result<PathBuf> {
    validate_identifier("agent_id", agent_id)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    Ok(runtime_identity_dir(config)?.join(scoped_component(agent_id)))
}

fn runtime_state_root() -> io::Result<PathBuf> {
    platform_state_root().map(|root| {
        root.join(APPLICATION_STATE_DIRECTORY)
            .join(AGENT_STATE_DIRECTORY)
    })
}

#[cfg(windows)]
fn platform_state_root() -> io::Result<PathBuf> {
    if let Some(path) = absolute_environment_path("LOCALAPPDATA") {
        return Ok(path);
    }
    if let Some(profile) = absolute_environment_path("USERPROFILE") {
        return Ok(profile.join("AppData").join("Local"));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "cannot resolve per-user agent state directory",
    ))
}

#[cfg(target_os = "macos")]
fn platform_state_root() -> io::Result<PathBuf> {
    absolute_environment_path("HOME")
        .map(|home| home.join("Library").join("Application Support"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "cannot resolve per-user agent state directory",
            )
        })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_state_root() -> io::Result<PathBuf> {
    if let Some(path) = absolute_environment_path("XDG_STATE_HOME") {
        return Ok(path);
    }
    absolute_environment_path("HOME")
        .map(|home| home.join(".local").join("state"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "cannot resolve per-user agent state directory",
            )
        })
}

#[cfg(not(any(unix, windows)))]
fn platform_state_root() -> io::Result<PathBuf> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "per-user agent state is unsupported on this platform",
    ))
}

fn absolute_environment_path(name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env::var_os(name)?);
    path.is_absolute().then_some(path)
}

fn scoped_component(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(value.as_bytes())
}

pub(crate) fn ensure_private_directory(path: &Path) -> io::Result<()> {
    if path.exists() {
        if fs::symlink_metadata(path)?.file_type().is_symlink() || !path.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "agent state path is not a private directory",
            ));
        }
    } else {
        fs::create_dir_all(path)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn load_or_create_runtime_agent_id(config_dir: &Path, payload_id: &str) -> io::Result<String> {
    ensure_private_directory(config_dir)?;
    let id_path = config_dir.join(AGENT_ID_FILE);
    if id_path.exists() && fs::symlink_metadata(&id_path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime agent identity file must not be a symbolic link",
        ));
    }
    if let Some(agent_id) = read_runtime_agent_id(&id_path) {
        return Ok(agent_id);
    }

    let agent_id = generate_runtime_agent_id(payload_id);
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&id_path)?;
    file.write_all(agent_id.as_bytes())?;
    file.flush()?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&id_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(agent_id)
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
        let first =
            load_or_create_runtime_agent_id(&config_dir, "payload-one").expect("create identity");
        let second =
            load_or_create_runtime_agent_id(&config_dir, "payload-one").expect("reload identity");

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

        let resolved = load_or_create_runtime_agent_id(&config_dir, "payload-one")
            .expect("replace invalid identity");
        assert_ne!(resolved, "invalid agent/id");
        validate_identifier("agent_id", &resolved).expect("replacement identifier");
        assert_eq!(
            fs::read_to_string(&id_path).expect("read replacement identity"),
            resolved
        );

        let _ = fs::remove_file(id_path);
        let _ = fs::remove_dir_all(config_dir);
    }

    #[test]
    fn runtime_state_is_scoped_to_listener_payload_and_agent() {
        let config = AgentConfig {
            listener_id: "listener:one".to_string(),
            payload_id: "payload.one".to_string(),
            ..Default::default()
        };
        let identity_dir = runtime_identity_dir(&config).expect("identity directory");
        let session_dir = runtime_session_dir(&config, "agent-one").expect("session directory");

        assert!(identity_dir.ends_with(
            PathBuf::from(scoped_component("listener:one")).join(scoped_component("payload.one"))
        ));
        assert_eq!(
            session_dir,
            identity_dir.join(scoped_component("agent-one"))
        );
        for component in [
            scoped_component("listener:one"),
            scoped_component("payload.one"),
            scoped_component("agent-one"),
        ] {
            assert!(!component.contains(['/', '\\', ':']));
        }
    }

    #[cfg(unix)]
    #[test]
    fn runtime_identity_uses_private_unix_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let config_dir = unique_temp_dir("identity-permissions");
        load_or_create_runtime_agent_id(&config_dir, "payload-one").expect("create identity");

        let directory_mode = fs::metadata(&config_dir)
            .expect("identity directory metadata")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::metadata(config_dir.join(AGENT_ID_FILE))
            .expect("identity file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);

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
