use crate::config::AgentConfig;
use crate::tasks::validate_identifier;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use zeroize::{Zeroize, Zeroizing};

const SESSION_STATE_FILE: &str = "session.json";
const SESSION_STATE_SCHEMA_VERSION: u32 = 2;
const MAX_SESSION_STATE_BYTES: u64 = 16 * 1024;
const RAW_CREDENTIAL_BYTES: usize = 32;
const RAW_CREDENTIAL_ENCODED_BYTES: usize = 43;
const MAX_SESSION_CREDENTIAL_BYTES: usize = 160;

/// A bearer credential whose formatting never reveals the underlying secret.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct SecretCredential(String);

impl SecretCredential {
    pub fn new_bootstrap(raw: impl Into<String>) -> io::Result<Self> {
        let raw = raw.into();
        validate_bootstrap_credential(&raw)?;
        Ok(Self(raw))
    }

    pub fn new_session(raw: impl Into<String>) -> io::Result<Self> {
        let raw = raw.into();
        validate_session_credential(&raw)?;
        Ok(Self(raw))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Drop for SecretCredential {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> Deserialize<'de> for SecretCredential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

fn decode_canonical_raw_url(raw: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    if raw.len() != RAW_CREDENTIAL_ENCODED_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential field is not a 32-byte unpadded base64url value",
        ));
    }
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(raw).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential field is not canonical unpadded base64url",
        )
    })?);
    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(&*decoded));
    if decoded.len() != RAW_CREDENTIAL_BYTES || canonical.as_str() != raw {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "credential field is not canonical unpadded base64url",
        ));
    }
    Ok(decoded)
}

fn validate_bootstrap_credential(raw: &str) -> io::Result<()> {
    decode_canonical_raw_url(raw).map(|_| ())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedSessionCredential<'a> {
    session_id: &'a str,
    generation: i64,
}

fn parse_session_credential(raw: &str) -> io::Result<ParsedSessionCredential<'_>> {
    if raw.len() > MAX_SESSION_CREDENTIAL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session credential exceeds the supported size",
        ));
    }
    let mut parts = raw.split('.');
    let version = parts.next();
    let session_id = parts.next();
    let generation = parts.next();
    let mac = parts.next();
    if version != Some("s1")
        || session_id.is_none()
        || generation.is_none()
        || mac.is_none()
        || parts.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session credential has an invalid structure",
        ));
    }
    let session_id = session_id.unwrap_or_default();
    decode_canonical_raw_url(session_id)?;
    decode_canonical_raw_url(mac.unwrap_or_default())?;

    let generation = generation.unwrap_or_default();
    if generation.is_empty()
        || generation.len() > 19
        || !generation.as_bytes()[0].is_ascii_digit()
        || generation.as_bytes()[0] == b'0'
        || !generation.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session credential generation is not a canonical positive integer",
        ));
    }
    let parsed_generation = generation.parse::<i64>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "session credential generation is outside the supported range",
        )
    })?;
    if parsed_generation < 1 || parsed_generation.to_string() != generation {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session credential generation is not a canonical positive integer",
        ));
    }
    Ok(ParsedSessionCredential {
        session_id,
        generation: parsed_generation,
    })
}

fn validate_session_credential(raw: &str) -> io::Result<()> {
    parse_session_credential(raw).map(|_| ())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialSource {
    Bootstrap,
    Session,
}

#[derive(Clone)]
pub struct CredentialUse {
    pub source: CredentialSource,
    pub credential: SecretCredential,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CredentialProtection {
    UnixPermissions,
    WindowsDpapiCurrentUser,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SessionState {
    schema_version: u32,
    listener_id: String,
    payload_id: String,
    agent_id: String,
    credential_protection: CredentialProtection,
    protected_session_credential: String,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.protected_session_credential.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SessionBinding {
    listener_id: String,
    payload_id: String,
    agent_id: String,
}

#[derive(Clone, Copy)]
enum SessionResponseContext<'a> {
    Authenticated,
    Bootstrap {
        expected_prior_session: Option<&'a SecretCredential>,
    },
}

/// Runtime authentication state shared by all C2 request paths.
///
/// The bootstrap credential remains embedded in the payload. A session
/// credential, once enrolled, is stored in per-user state scoped to the
/// complete listener/payload/runtime-agent tuple. Windows protects the bearer
/// with current-user DPAPI; Unix relies on private directory and file modes.
#[derive(Clone)]
pub struct AgentAuth {
    bootstrap_credential: SecretCredential,
    binding: SessionBinding,
    state_path: PathBuf,
    session_credential: Arc<RwLock<Option<SecretCredential>>>,
}

impl fmt::Debug for AgentAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentAuth")
            .field("bootstrap_credential", &"[REDACTED]")
            .field("binding", &self.binding)
            .field("state_path", &self.state_path)
            .field("has_session", &self.has_session())
            .finish()
    }
}

impl AgentAuth {
    pub fn for_runtime(config: &AgentConfig, agent_id: &str) -> io::Result<Self> {
        let state_dir = crate::identity::runtime_session_dir(config, agent_id)?;
        Self::from_dir(config, agent_id, &state_dir)
    }

    pub fn from_dir(config: &AgentConfig, agent_id: &str, state_dir: &Path) -> io::Result<Self> {
        let bootstrap_credential =
            SecretCredential::new_bootstrap(config.enrollment_credential.expose().to_string())?;
        for (name, value) in [
            ("listener_id", config.listener_id.as_str()),
            ("payload_id", config.payload_id.as_str()),
            ("agent_id", agent_id),
        ] {
            validate_identifier(name, value)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        }

        crate::identity::ensure_private_directory(state_dir)?;
        let binding = SessionBinding {
            listener_id: config.listener_id.clone(),
            payload_id: config.payload_id.clone(),
            agent_id: agent_id.to_string(),
        };
        let state_path = state_dir.join(SESSION_STATE_FILE);
        let session_credential = load_bound_session(&state_path, &binding)?;

        Ok(Self {
            bootstrap_credential,
            binding,
            state_path,
            session_credential: Arc::new(RwLock::new(session_credential)),
        })
    }

    pub fn active_credential(&self) -> io::Result<CredentialUse> {
        match self.session_credential() {
            Some(credential) => Ok(credential),
            None => self.bootstrap_credential(),
        }
    }

    pub fn session_credential(&self) -> Option<CredentialUse> {
        self.session_credential
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .map(|credential| CredentialUse {
                source: CredentialSource::Session,
                credential,
            })
    }

    pub fn bootstrap_credential(&self) -> io::Result<CredentialUse> {
        validate_bootstrap_credential(self.bootstrap_credential.expose())?;
        Ok(CredentialUse {
            source: CredentialSource::Bootstrap,
            credential: self.bootstrap_credential.clone(),
        })
    }

    pub fn persist_session(&self, raw_credential: String) -> io::Result<()> {
        self.persist_session_response(raw_credential, SessionResponseContext::Authenticated)
    }

    pub(crate) fn persist_bootstrap_session(
        &self,
        raw_credential: String,
        expected_prior_session: Option<&SecretCredential>,
    ) -> io::Result<()> {
        self.persist_session_response(
            raw_credential,
            SessionResponseContext::Bootstrap {
                expected_prior_session,
            },
        )
    }

    fn persist_session_response(
        &self,
        raw_credential: String,
        context: SessionResponseContext<'_>,
    ) -> io::Result<()> {
        let session_credential = SecretCredential::new_session(raw_credential)?;
        let incoming = parse_session_credential(session_credential.expose())?;
        let mut current = self
            .session_credential
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(existing_credential) = current.as_ref() {
            if existing_credential.expose() == session_credential.expose() {
                return Ok(());
            }

            let existing = parse_session_credential(existing_credential.expose())?;
            if existing.session_id == incoming.session_id {
                if incoming.generation < existing.generation {
                    return Ok(());
                }
                if incoming.generation == existing.generation {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "conflicting credential for the current session generation",
                    ));
                }
            } else {
                let expected_prior_session = match context {
                    SessionResponseContext::Bootstrap {
                        expected_prior_session: Some(expected),
                    } => expected,
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "session identity changed outside explicit bootstrap re-enrollment",
                        ));
                    }
                };
                if expected_prior_session.expose() != existing_credential.expose() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "bootstrap re-enrollment response no longer matches the active session",
                    ));
                }
            }
        } else if matches!(
            context,
            SessionResponseContext::Bootstrap {
                expected_prior_session: Some(_)
            }
        ) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "bootstrap re-enrollment response has no matching prior session",
            ));
        }

        let (credential_protection, protected_session_credential) =
            protect_session_credential(&self.binding, &session_credential)?;
        let state = SessionState {
            schema_version: SESSION_STATE_SCHEMA_VERSION,
            listener_id: self.binding.listener_id.clone(),
            payload_id: self.binding.payload_id.clone(),
            agent_id: self.binding.agent_id.clone(),
            credential_protection,
            protected_session_credential,
        };
        persist_state_atomically(&self.state_path, &state)?;
        *current = Some(session_credential);
        Ok(())
    }

    pub fn has_session(&self) -> bool {
        self.session_credential
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }
}

fn load_bound_session(
    state_path: &Path,
    binding: &SessionBinding,
) -> io::Result<Option<SecretCredential>> {
    if state_path.exists() && fs::symlink_metadata(state_path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session state file must not be a symbolic link",
        ));
    }
    let file = match File::open(state_path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_SESSION_STATE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SESSION_STATE_BYTES {
        return Ok(None);
    }
    let state: SessionState = match serde_json::from_slice(&bytes) {
        Ok(state) => state,
        Err(_) => return Ok(None),
    };
    if state.schema_version != SESSION_STATE_SCHEMA_VERSION
        || state.listener_id != binding.listener_id
        || state.payload_id != binding.payload_id
        || state.agent_id != binding.agent_id
    {
        return Ok(None);
    }
    unprotect_session_credential(
        binding,
        state.credential_protection,
        &state.protected_session_credential,
    )
    .map(Some)
}

#[cfg(windows)]
fn session_binding_entropy(binding: &SessionBinding) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        format!(
            "microc2-agent-session-state-v2\0{}\0{}\0{}",
            binding.listener_id, binding.payload_id, binding.agent_id
        )
        .into_bytes(),
    )
}

#[cfg(not(windows))]
fn protect_session_credential(
    _binding: &SessionBinding,
    credential: &SecretCredential,
) -> io::Result<(CredentialProtection, String)> {
    Ok((
        CredentialProtection::UnixPermissions,
        credential.expose().to_string(),
    ))
}

#[cfg(not(windows))]
fn unprotect_session_credential(
    _binding: &SessionBinding,
    protection: CredentialProtection,
    protected: &str,
) -> io::Result<SecretCredential> {
    if protection != CredentialProtection::UnixPermissions {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "session credential protection is unsupported on this platform",
        ));
    }
    SecretCredential::new_session(protected.to_string())
}

#[cfg(windows)]
fn protect_session_credential(
    binding: &SessionBinding,
    credential: &SecretCredential,
) -> io::Result<(CredentialProtection, String)> {
    use std::ptr;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::dpapi::{CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN};
    use winapi::um::winbase::LocalFree;
    use winapi::um::wincrypt::DATA_BLOB;

    let mut plaintext = Zeroizing::new(credential.expose().as_bytes().to_vec());
    let mut entropy = session_binding_entropy(binding);
    let mut input = DATA_BLOB {
        cbData: DWORD::try_from(plaintext.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "session credential is too large",
            )
        })?,
        pbData: plaintext.as_mut_ptr(),
    };
    let mut optional_entropy = DATA_BLOB {
        cbData: DWORD::try_from(entropy.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "session binding is too large")
        })?,
        pbData: entropy.as_mut_ptr(),
    };
    let mut output = DATA_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: all input blobs borrow live mutable byte buffers for the duration
    // of the call, output is initialized for DPAPI allocation, and UI is
    // explicitly disabled. No machine-scope flag is used, so the current user
    // is part of DPAPI's protection boundary.
    // foxguard: ignore[rs/unsafe-block]
    let result = unsafe {
        CryptProtectData(
            &mut input,
            ptr::null(),
            &mut optional_entropy,
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if result == 0 {
        let error = io::Error::last_os_error();
        if !output.pbData.is_null() {
            // SAFETY: any DPAPI output buffer is allocated with LocalAlloc.
            // foxguard: ignore[rs/unsafe-block]
            unsafe {
                LocalFree(output.pbData.cast());
            }
        }
        return Err(error);
    }
    if output.pbData.is_null() || output.cbData == 0 {
        if !output.pbData.is_null() {
            // SAFETY: DPAPI allocated output.pbData with LocalAlloc.
            // foxguard: ignore[rs/unsafe-block]
            unsafe {
                LocalFree(output.pbData.cast());
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DPAPI returned an empty protected credential",
        ));
    }
    let protected = {
        // SAFETY: successful DPAPI output is valid for output.cbData bytes until
        // released with LocalFree.
        // foxguard: ignore[rs/unsafe-block]
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() }
    };
    // SAFETY: DPAPI allocated output.pbData with LocalAlloc.
    // foxguard: ignore[rs/unsafe-block]
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok((
        CredentialProtection::WindowsDpapiCurrentUser,
        URL_SAFE_NO_PAD.encode(protected),
    ))
}

#[cfg(windows)]
fn unprotect_session_credential(
    binding: &SessionBinding,
    protection: CredentialProtection,
    protected: &str,
) -> io::Result<SecretCredential> {
    use std::ptr;
    use winapi::shared::minwindef::DWORD;
    use winapi::um::dpapi::{CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN};
    use winapi::um::winbase::LocalFree;
    use winapi::um::wincrypt::DATA_BLOB;

    if protection != CredentialProtection::WindowsDpapiCurrentUser {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows session state is not protected with current-user DPAPI",
        ));
    }
    let mut ciphertext = Zeroizing::new(URL_SAFE_NO_PAD.decode(protected).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DPAPI session credential is not valid base64url",
        )
    })?);
    let mut entropy = session_binding_entropy(binding);
    let mut input = DATA_BLOB {
        cbData: DWORD::try_from(ciphertext.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DPAPI state is too large"))?,
        pbData: ciphertext.as_mut_ptr(),
    };
    let mut optional_entropy = DATA_BLOB {
        cbData: DWORD::try_from(entropy.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "session binding is too large")
        })?,
        pbData: entropy.as_mut_ptr(),
    };
    let mut output = DATA_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: input and entropy blobs borrow live mutable buffers, output is
    // initialized for DPAPI allocation, and UI is explicitly disabled.
    // foxguard: ignore[rs/unsafe-block]
    let result = unsafe {
        CryptUnprotectData(
            &mut input,
            ptr::null_mut(),
            &mut optional_entropy,
            ptr::null_mut(),
            ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if result == 0 {
        let error = io::Error::last_os_error();
        if !output.pbData.is_null() {
            // SAFETY: any DPAPI plaintext output is writable for cbData bytes
            // and allocated with LocalAlloc.
            // foxguard: ignore[rs/unsafe-block]
            unsafe {
                if output.cbData != 0 {
                    ptr::write_bytes(output.pbData, 0, output.cbData as usize);
                }
                LocalFree(output.pbData.cast());
            }
        }
        return Err(error);
    }
    if output.pbData.is_null() || output.cbData == 0 {
        if !output.pbData.is_null() {
            // SAFETY: DPAPI allocated output.pbData with LocalAlloc.
            // foxguard: ignore[rs/unsafe-block]
            unsafe {
                LocalFree(output.pbData.cast());
            }
        }
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DPAPI returned an empty session credential",
        ));
    }
    // SAFETY: successful DPAPI output is valid for output.cbData bytes until
    // it is zeroed and released with LocalFree.
    // foxguard: ignore[rs/unsafe-block]
    let plaintext = unsafe {
        Zeroizing::new(std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec())
    };
    // SAFETY: output.pbData is writable DPAPI-owned memory of output.cbData
    // bytes and is released immediately afterward.
    // foxguard: ignore[rs/unsafe-block]
    unsafe {
        ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData.cast());
    }
    let credential = std::str::from_utf8(&plaintext).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DPAPI session credential is not UTF-8",
        )
    })?;
    SecretCredential::new_session(credential.to_string())
}

fn persist_state_atomically(state_path: &Path, state: &SessionState) -> io::Result<()> {
    let parent = state_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "session state path has no parent directory",
        )
    })?;
    crate::identity::ensure_private_directory(parent)?;

    let bytes = Zeroizing::new(
        serde_json::to_vec(state).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
    );
    let temp_path = parent.join(format!(
        ".{}.{}.{:032x}.tmp",
        SESSION_STATE_FILE,
        std::process::id(),
        rand::random::<u128>()
    ));
    let write_result = (|| -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp_path)?;
        file.write_all(&bytes)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        atomic_replace(&temp_path, state_path)?;
        sync_parent_directory(parent)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

#[cfg(not(windows))]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::winbase::{MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH};

    let source: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: source and destination are live, NUL-terminated UTF-16 buffers
    // for this synchronous call; both paths are generated inside the private
    // session-state directory and the return value is checked before success.
    // foxguard: ignore[rs/unsafe-block]
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::process::Command;
    use std::sync::{Arc, Barrier};
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_BOOTSTRAP_CREDENTIAL: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";
    const TEST_SESSION_ID: &str = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE";
    const TEST_OTHER_SESSION_ID: &str = "REREREREREREREREREREREREREREREREREREREREREQ";
    const TEST_SESSION_MAC: &str = "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M";
    const TEST_OTHER_SESSION_MAC: &str = "RUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUU";

    fn test_session_credential(generation: i64) -> String {
        test_session_credential_for(TEST_SESSION_ID, generation, TEST_SESSION_MAC)
    }

    fn test_session_credential_for(session_id: &str, generation: i64, mac: &str) -> String {
        format!("s1.{session_id}.{generation}.{mac}")
    }

    fn test_config() -> AgentConfig {
        AgentConfig {
            listener_id: "listener-one".to_string(),
            payload_id: "payload-one".to_string(),
            enrollment_credential: SecretCredential::new_bootstrap(TEST_BOOTSTRAP_CREDENTIAL)
                .expect("bootstrap credential"),
            ..Default::default()
        }
    }

    #[test]
    fn credential_debug_output_is_redacted() {
        let secret = SecretCredential::new_bootstrap(TEST_BOOTSTRAP_CREDENTIAL)
            .expect("bootstrap credential");
        let output = format!("{secret:?}");
        assert!(!output.contains(TEST_BOOTSTRAP_CREDENTIAL));
        assert!(output.contains("REDACTED"));

        let config = AgentConfig {
            enrollment_credential: secret,
            ..Default::default()
        };
        assert!(!format!("{config:?}").contains(TEST_BOOTSTRAP_CREDENTIAL));
    }

    #[test]
    fn bootstrap_and_session_credentials_use_distinct_strict_contracts() {
        assert!(SecretCredential::new_bootstrap(TEST_BOOTSTRAP_CREDENTIAL).is_ok());
        assert!(SecretCredential::new_session(test_session_credential(7)).is_ok());

        for invalid in [
            "",
            "bootstrap-secret",
            "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=",
            "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJ",
        ] {
            assert!(
                SecretCredential::new_bootstrap(invalid).is_err(),
                "accepted invalid bootstrap credential {invalid:?}"
            );
        }

        for invalid in [
            "",
            TEST_BOOTSTRAP_CREDENTIAL,
            "s2.QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE.7.Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M",
            "s1.QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE.0.Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M",
            "s1.QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE.07.Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M",
            "s1.QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE.+7.Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M",
            "s1.QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE.9223372036854775808.Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M",
            "s1.QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE.7.Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M=",
        ] {
            assert!(
                SecretCredential::new_session(invalid).is_err(),
                "accepted invalid session credential {invalid:?}"
            );
        }
    }

    #[test]
    fn agent_auth_rejects_noncanonical_bootstrap_before_network_use() {
        let state_dir = unique_temp_dir("invalid-bootstrap");
        let config = AgentConfig {
            listener_id: "listener-one".to_string(),
            payload_id: "payload-one".to_string(),
            enrollment_credential: serde_json::from_str(r#""bootstrap-secret""#)
                .expect("deserialize weak fixture"),
            ..Default::default()
        };

        let error = AgentAuth::from_dir(&config, "agent-one", &state_dir)
            .expect_err("weak bootstrap credential must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!state_dir.exists());
    }

    #[test]
    fn session_is_persisted_and_reloaded_for_the_same_tuple() {
        let state_dir = unique_temp_dir("session-restart");
        let config = test_config();
        let auth = AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("auth state");
        assert_eq!(
            auth.active_credential().expect("credential").source,
            CredentialSource::Bootstrap
        );

        let session_credential = test_session_credential(1);
        auth.persist_session(session_credential.clone())
            .expect("persist session");
        let restarted =
            AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("reloaded auth state");
        let credential = restarted.active_credential().expect("session credential");
        assert_eq!(credential.source, CredentialSource::Session);
        assert_eq!(credential.credential.expose(), session_credential);

        let _ = fs::remove_dir_all(state_dir);
    }

    #[test]
    fn concurrent_out_of_order_rotations_preserve_the_highest_generation_on_disk() {
        let state_dir = unique_temp_dir("session-monotonic");
        let config = test_config();
        let auth =
            Arc::new(AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("auth state"));
        auth.persist_session(test_session_credential(1))
            .expect("persist initial session");

        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for generation in [2, 3] {
            let auth = auth.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                auth.persist_session(test_session_credential(generation))
                    .expect("persist rotated session");
            }));
        }
        barrier.wait();
        for worker in workers {
            worker.join().expect("rotation worker");
        }

        let expected = test_session_credential(3);
        assert_eq!(
            auth.session_credential()
                .expect("active session")
                .credential
                .expose(),
            expected
        );
        let restarted =
            AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("reload auth state");
        assert_eq!(
            restarted
                .session_credential()
                .expect("persisted session")
                .credential
                .expose(),
            expected
        );

        let _ = fs::remove_dir_all(state_dir);
    }

    #[test]
    fn same_generation_conflicts_and_ordinary_session_identity_changes_are_rejected() {
        let state_dir = unique_temp_dir("session-conflicts");
        let config = test_config();
        let auth = AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("auth state");
        let current = test_session_credential(2);
        auth.persist_session(current.clone())
            .expect("persist current session");

        let conflicting_mac =
            test_session_credential_for(TEST_SESSION_ID, 2, TEST_OTHER_SESSION_MAC);
        assert!(auth.persist_session(conflicting_mac).is_err());

        let different_session =
            test_session_credential_for(TEST_OTHER_SESSION_ID, 1, TEST_SESSION_MAC);
        assert!(auth.persist_session(different_session).is_err());
        assert_eq!(
            auth.session_credential()
                .expect("unchanged session")
                .credential
                .expose(),
            current
        );

        let _ = fs::remove_dir_all(state_dir);
    }

    #[test]
    fn bootstrap_session_change_requires_the_exact_prior_session() {
        let state_dir = unique_temp_dir("session-reenrollment");
        let config = test_config();
        let auth = AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("auth state");
        let current = test_session_credential(2);
        auth.persist_session(current.clone())
            .expect("persist current session");
        let expected_prior =
            SecretCredential::new_session(current).expect("expected prior session");
        let replacement = test_session_credential_for(TEST_OTHER_SESSION_ID, 1, TEST_SESSION_MAC);

        auth.persist_bootstrap_session(replacement.clone(), Some(&expected_prior))
            .expect("explicit re-enrollment may change the session identity");
        assert_eq!(
            auth.session_credential()
                .expect("replacement session")
                .credential
                .expose(),
            replacement
        );

        let _ = fs::remove_dir_all(state_dir);
    }

    #[test]
    fn delayed_reenrollment_response_cannot_replace_a_newer_session_or_disk_state() {
        let state_dir = unique_temp_dir("session-delayed-reenrollment");
        let config = test_config();
        let auth = AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("auth state");
        let prior = test_session_credential(1);
        auth.persist_session(prior.clone())
            .expect("persist prior session");
        let expected_prior = SecretCredential::new_session(prior).expect("expected prior session");

        let newer = test_session_credential(2);
        auth.persist_session(newer.clone())
            .expect("persist newer session");
        let delayed_replacement =
            test_session_credential_for(TEST_OTHER_SESSION_ID, 1, TEST_SESSION_MAC);
        assert!(auth
            .persist_bootstrap_session(delayed_replacement, Some(&expected_prior))
            .is_err());
        assert_eq!(
            auth.session_credential()
                .expect("newer session remains active")
                .credential
                .expose(),
            newer
        );

        let restarted =
            AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("reload auth state");
        assert_eq!(
            restarted
                .session_credential()
                .expect("newer session remains on disk")
                .credential
                .expose(),
            newer
        );

        let _ = fs::remove_dir_all(state_dir);
    }

    #[test]
    fn tuple_mismatch_never_reuses_a_session() {
        let state_dir = unique_temp_dir("session-binding");
        let config = test_config();
        let auth = AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("auth state");
        auth.persist_session(test_session_credential(1))
            .expect("persist session");

        let mut wrong_listener = config.clone();
        wrong_listener.listener_id = "listener-two".to_string();
        let mut wrong_payload = config.clone();
        wrong_payload.payload_id = "payload-two".to_string();
        for (candidate, agent_id) in [
            (&wrong_listener, "agent-one"),
            (&wrong_payload, "agent-one"),
            (&config, "agent-two"),
        ] {
            let mismatched =
                AgentAuth::from_dir(candidate, agent_id, &state_dir).expect("mismatched auth");
            assert_eq!(
                mismatched.active_credential().expect("credential").source,
                CredentialSource::Bootstrap
            );
            assert!(!mismatched.has_session());
        }

        let _ = fs::remove_dir_all(state_dir);
    }

    #[test]
    fn oversized_session_state_is_ignored_before_parsing() {
        let state_dir = unique_temp_dir("oversized-session");
        fs::create_dir_all(&state_dir).expect("create state directory");
        fs::write(
            state_dir.join(SESSION_STATE_FILE),
            vec![b'x'; MAX_SESSION_STATE_BYTES as usize + 1],
        )
        .expect("write oversized state");

        let auth =
            AgentAuth::from_dir(&test_config(), "agent-one", &state_dir).expect("load auth state");
        assert!(!auth.has_session());
        assert_eq!(
            auth.active_credential().expect("credential").source,
            CredentialSource::Bootstrap
        );

        let _ = fs::remove_dir_all(state_dir);
    }

    #[test]
    fn malformed_session_response_is_never_persisted() {
        let state_dir = unique_temp_dir("malformed-session");
        let auth =
            AgentAuth::from_dir(&test_config(), "agent-one", &state_dir).expect("auth state");

        assert!(auth.persist_session("session-secret".to_string()).is_err());
        assert!(!auth.has_session());
        assert!(!state_dir.join(SESSION_STATE_FILE).exists());

        let _ = fs::remove_dir_all(state_dir);
    }

    #[cfg(unix)]
    #[test]
    fn build_sidecars_and_output_never_contain_the_bootstrap_secret() {
        use std::os::unix::fs::PermissionsExt;

        let workspace = unique_temp_dir("build-redaction");
        let fake_bin = workspace.join("bin");
        let output_dir = workspace.join("payload");
        let cargo_target_dir = workspace.join("private-cargo-target");
        fs::create_dir_all(&fake_bin).expect("create fake tool directory");
        let fake_cargo = fake_bin.join("cargo");
        fs::write(
            &fake_cargo,
            "#!/bin/sh\ncargo_target_dir=${CARGO_TARGET_DIR:-target}\nmkdir -p \"$cargo_target_dir/x86_64-unknown-linux-gnu/debug\"\nprintf fake > \"$cargo_target_dir/x86_64-unknown-linux-gnu/debug/agent\"\n",
        )
        .expect("write fake cargo");
        fs::set_permissions(&fake_cargo, fs::Permissions::from_mode(0o700))
            .expect("make fake cargo executable");
        let fake_strip = fake_bin.join("strip");
        fs::write(&fake_strip, "#!/bin/sh\nexit 0\n").expect("write fake strip");
        fs::set_permissions(&fake_strip, fs::Permissions::from_mode(0o700))
            .expect("make fake strip executable");

        let secret = TEST_BOOTSTRAP_CREDENTIAL;
        let inherited_path = std::env::var("PATH").unwrap_or_default();
        let output = Command::new("/bin/bash")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/build.sh"))
            .args([
                "--target",
                "x86_64-unknown-linux-gnu",
                "--output",
                output_dir.to_str().expect("UTF-8 output path"),
                "--build-type",
                "debug",
                "--format",
                "linux_elf",
                "--listener-host",
                "127.0.0.1",
                "--listener-port",
                "8080",
                "--payload-id",
                "payload-one",
                "--protocol",
                "http",
            ])
            .current_dir(&workspace)
            .env("PATH", format!("{}:{inherited_path}", fake_bin.display()))
            .env("CARGO_TARGET_DIR", &cargo_target_dir)
            .env("LISTENER_ID", "listener-one")
            .env("ENROLLMENT_CREDENTIAL", secret)
            .env("ALLOW_INSECURE_ISOLATED_LAB", "true")
            .output()
            .expect("run build script");
        assert!(
            output.status.success(),
            "build script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
        assert!(output_dir.join("agent").exists());
        assert!(cargo_target_dir
            .join("x86_64-unknown-linux-gnu")
            .join("debug")
            .join("agent")
            .exists());

        for config_path in [
            workspace.join(".config/config.json"),
            output_dir.join(".config/config.json"),
        ] {
            let projected = fs::read_to_string(&config_path).expect("read projected config");
            assert!(
                !projected.contains(secret),
                "{} contains the bootstrap credential",
                config_path.display()
            );
            assert!(projected.contains(r#""enrollment_credential": """#));
        }

        let _ = fs::remove_dir_all(workspace);
    }

    #[cfg(unix)]
    #[test]
    fn durable_session_state_uses_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let state_dir = unique_temp_dir("session-permissions");
        let auth =
            AgentAuth::from_dir(&test_config(), "agent-one", &state_dir).expect("auth state");
        auth.persist_session(test_session_credential(1))
            .expect("persist session");

        let dir_mode = fs::metadata(&state_dir)
            .expect("state directory metadata")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::metadata(state_dir.join(SESSION_STATE_FILE))
            .expect("state file metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);

        let _ = fs::remove_dir_all(state_dir);
    }

    #[cfg(windows)]
    #[test]
    fn durable_session_state_is_dpapi_protected_for_the_current_user() {
        let state_dir = unique_temp_dir("session-dpapi");
        let session_credential = test_session_credential(1);
        let auth =
            AgentAuth::from_dir(&test_config(), "agent-one", &state_dir).expect("auth state");
        auth.persist_session(session_credential.clone())
            .expect("persist session");

        let stored = fs::read_to_string(state_dir.join(SESSION_STATE_FILE))
            .expect("read protected session state");
        assert!(!stored.contains(&session_credential));
        assert!(stored.contains("windows_dpapi_current_user"));

        let restarted =
            AgentAuth::from_dir(&test_config(), "agent-one", &state_dir).expect("reload state");
        assert_eq!(
            restarted
                .active_credential()
                .expect("active session")
                .credential
                .expose(),
            session_credential
        );

        let _ = fs::remove_dir_all(state_dir);
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "microc2-auth-{}-{}-{}",
            std::process::id(),
            nanos,
            name
        ))
    }
}
