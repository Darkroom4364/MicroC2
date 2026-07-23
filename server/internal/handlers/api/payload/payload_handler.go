package payload

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"microc2/server/internal/listeners"
	"microc2/server/internal/persistence"
)

const (
	payloadStateBuilding    = "building"
	payloadStateCompleted   = "completed"
	payloadStateFailed      = "failed"
	payloadStateInterrupted = "interrupted"
	payloadStateMissing     = "missing"
	payloadStateCorrupt     = "corrupt"

	payloadFailedDetail      = "payload build failed before completion"
	payloadInterruptedDetail = "server restarted before payload build completed"
)

type payloadBuildRecord struct {
	ID             string
	PayloadID      string
	ListenerID     string
	MutationSeed   string
	Filename       string
	RelativePath   string
	Size           int64
	SHA256         string
	CreatedAt      string
	State          string
	StateDetail    string
	ProvenanceJSON []byte
}

// NewPayloadHandler is the compatibility constructor for callers that do not
// yet provide durable storage. It derives the legacy listeners directory from
// payloadsDir instead of relying on the process working directory.
func NewPayloadHandler(payloadsDir, agentSourceDir string) *PayloadHandler {
	lookup := filesystemListenerLookup{
		listenersDir: filepath.Join(filepath.Dir(payloadsDir), "listeners"),
	}
	handler, err := newPayloadHandler(payloadsDir, agentSourceDir, lookup, nil)
	if err == nil {
		return handler
	}
	log.Printf("[ERROR] Failed to initialize payload handler: %v", err)
	return &PayloadHandler{
		payloadsDir:    payloadsDir,
		agentSourceDir: agentSourceDir,
		listenerLookup: lookup,
		initErr:        err,
		payloads:       make(map[string]PayloadResult),
	}
}

// NewPayloadHandlerWithPersistence constructs a payload handler backed by the
// shared server database and reconciles every stored artifact before serving.
func NewPayloadHandlerWithPersistence(
	payloadsDir string,
	agentSourceDir string,
	lookup ListenerLookup,
	database *persistence.Database,
) (*PayloadHandler, error) {
	if database == nil {
		return nil, errors.New("payload persistence database is required")
	}
	handler, err := newPayloadHandler(payloadsDir, agentSourceDir, lookup, database)
	if err != nil {
		return nil, err
	}
	if err := handler.reconcilePayloads(); err != nil {
		return nil, fmt.Errorf("reconcile payload metadata: %w", err)
	}
	return handler, nil
}

func newPayloadHandler(
	payloadsDir string,
	agentSourceDir string,
	lookup ListenerLookup,
	database *persistence.Database,
) (*PayloadHandler, error) {
	if lookup == nil {
		return nil, errors.New("listener lookup is required")
	}
	absolutePayloadsDir, err := filepath.Abs(payloadsDir)
	if err != nil {
		return nil, fmt.Errorf("resolve payload directory: %w", err)
	}
	for _, dir := range []string{
		absolutePayloadsDir,
		filepath.Join(absolutePayloadsDir, "debug"),
		filepath.Join(absolutePayloadsDir, "release"),
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("create payload directory %s: %w", dir, err)
		}
	}
	return &PayloadHandler{
		payloadsDir:    absolutePayloadsDir,
		agentSourceDir: agentSourceDir,
		listenerLookup: lookup,
		database:       database,
		payloads:       make(map[string]PayloadResult),
	}, nil
}

type filesystemListenerLookup struct {
	listenersDir string
}

func (lookup filesystemListenerLookup) LookupListener(listenerID string) (listeners.ListenerConfig, error) {
	entries, err := os.ReadDir(lookup.listenersDir)
	if err != nil {
		return listeners.ListenerConfig{}, fmt.Errorf("read listeners directory: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		configPath := filepath.Join(lookup.listenersDir, entry.Name(), "config.json")
		configData, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}
		var config listeners.ListenerConfig
		if err := json.Unmarshal(configData, &config); err != nil {
			continue
		}
		if config.ID == listenerID {
			return config, nil
		}
	}
	return listeners.ListenerConfig{}, fmt.Errorf("listener %s not found", listenerID)
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
	if h.initErr != nil {
		http.Error(w, "Payload handler is unavailable", http.StatusInternalServerError)
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

	if h.database == nil {
		// Compatibility mode remains process-local. Production construction
		// always supplies the durable database.
		h.mutex.Lock()
		h.payloads[result.ID] = result
		h.mutex.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	response := result
	// The operator only needs the artifact path relative to the configured
	// payload root. Never disclose the server host's absolute filesystem path.
	response.Path = result.relativePath
	json.NewEncoder(w).Encode(response)
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
	if h.initErr != nil {
		http.Error(w, "Payload handler is unavailable", http.StatusInternalServerError)
		return
	}

	// Extract payload ID from URL path
	id := strings.TrimPrefix(r.URL.Path, "/api/payload/download/")
	if id == "" {
		http.Error(w, "Payload ID is required", http.StatusBadRequest)
		return
	}
	if !validPayloadID(id) {
		http.Error(w, "Invalid payload ID", http.StatusBadRequest)
		return
	}

	record, err := h.lookupPayload(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Payload not found", http.StatusNotFound)
			return
		}
		log.Print("[ERROR] Failed to load payload metadata")
		http.Error(w, "Failed to load payload metadata", http.StatusInternalServerError)
		return
	}

	switch record.State {
	case payloadStateBuilding, payloadStateFailed, payloadStateInterrupted:
		http.Error(w, "Payload artifact is unavailable", http.StatusGone)
		return
	}

	file, state, detail, actualHash := h.openVerifiedPayload(record)
	if file != nil {
		defer file.Close()
	}
	if h.database != nil {
		if err := h.updatePayloadState(record, state, detail, actualHash); err != nil {
			log.Print("[ERROR] Failed to update payload state")
			http.Error(w, "Failed to update payload metadata", http.StatusInternalServerError)
			return
		}
	}
	if state != payloadStateCompleted {
		http.Error(w, "Payload artifact is unavailable", http.StatusGone)
		return
	}
	if h.afterVerified != nil {
		h.afterVerified()
	}

	// Set appropriate headers
	disposition := mime.FormatMediaType("attachment", map[string]string{"filename": record.Filename})
	if disposition == "" {
		http.Error(w, "Payload metadata is corrupt", http.StatusGone)
		return
	}
	w.Header().Set("Content-Disposition", disposition)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(record.Size, 10))

	// Stream file to response
	if _, err := io.Copy(w, file); err != nil {
		log.Print("[ERROR] Failed to stream payload file")
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
func (h *PayloadHandler) GeneratePayload(
	config PayloadConfig,
) (result PayloadResult, returnErr error) {
	var durableBuildID string
	durableBuildStarted := false
	durableBuildCompleted := false
	defer func() {
		if h.database == nil ||
			!durableBuildStarted ||
			durableBuildCompleted ||
			returnErr == nil {
			return
		}
		if err := h.failPayloadBuild(durableBuildID); err != nil {
			returnErr = errors.Join(
				returnErr,
				fmt.Errorf("persist failed payload state: %w", err),
			)
		}
	}()

	if h.initErr != nil {
		return PayloadResult{}, h.initErr
	}
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
	buildStartedAt := time.Now().UTC()
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

	payloadFileName := payloadFilename(config.Format)
	log.Printf("[INFO] Payload filename: %s", payloadFileName)

	// Create a directory for build artifacts
	outputDir := filepath.Join(h.payloadsDir, buildType, payloadID)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Printf("[ERROR] Failed to create output directory %s: %v", outputDir, err)
		return PayloadResult{}, fmt.Errorf("failed to create output directory: %w", err)
	}
	log.Printf("[INFO] Created output directory: %s", outputDir)
	payloadPath := filepath.Join(outputDir, payloadFileName)

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

	plannedRelativePath, err := h.plannedRelativeArtifactPath(payloadPath)
	if err != nil {
		return PayloadResult{}, err
	}
	if h.database != nil {
		if err := h.beginPayloadBuild(payloadBuildRecord{
			ID:             payloadID,
			PayloadID:      payloadID,
			ListenerID:     listener.ID,
			MutationSeed:   mutationSeed,
			Filename:       payloadFileName,
			RelativePath:   plannedRelativePath,
			Size:           0,
			SHA256:         "",
			CreatedAt:      buildStartedAt.Format(time.RFC3339Nano),
			State:          payloadStateBuilding,
			StateDetail:    "",
			ProvenanceJSON: []byte("{}"),
		}); err != nil {
			return PayloadResult{}, fmt.Errorf("persist building payload state: %w", err)
		}
		durableBuildID = payloadID
		durableBuildStarted = true
	}

	log.Printf("[INFO] Starting build process...")
	// Execute build command
	var output []byte
	if h.runBuild != nil {
		output, err = h.runBuild(cmd)
	} else {
		output, err = cmd.CombinedOutput()
	}
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

	// Find the generated payload
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

	completedAt := time.Now().UTC()

	// Persist build provenance next to the artifact so any payload is
	// reproducible from (git revision, seed) (issue #99).
	provenance := map[string]interface{}{
		"mutation_seed":            mutationSeed,
		"seed_generated_by_server": seedGenerated,
		"git_revision":             gitRevision(h.agentSourceDir),
		"target":                   buildTarget,
		"built_at":                 completedAt.Format(time.RFC3339Nano),
		"config_sha256":            fmt.Sprintf("%x", sha256.Sum256(configJSON)),
		"mutation_flags":           []string{"config-xor-key", "junk-code", "surface-strings"},
	}
	if err := writeProvenance(filepath.Dir(payloadPath), provenance); err != nil {
		log.Printf("[WARNING] Failed to write build provenance: %v", err)
	}
	provenanceJSON, err := json.Marshal(provenance)
	if err != nil {
		return PayloadResult{}, fmt.Errorf("marshal payload provenance: %w", err)
	}
	relativePath, err := h.relativeArtifactPath(payloadPath)
	if err != nil {
		return PayloadResult{}, err
	}
	artifactHash, err := hashArtifact(payloadPath)
	if err != nil {
		return PayloadResult{}, fmt.Errorf("hash payload artifact: %w", err)
	}

	// Create the result
	result = PayloadResult{
		ID:           payloadID,
		PayloadID:    payloadID,
		ListenerID:   listener.ID,
		MutationSeed: mutationSeed,
		Filename:     payloadFileName,
		Path:         payloadPath,
		Size:         fileInfo.Size(),
		Created:      completedAt.Format(time.RFC3339Nano),
		relativePath: relativePath,
		sha256:       artifactHash,
		provenanceJSON: append(
			json.RawMessage(nil),
			provenanceJSON...,
		),
	}
	if durableBuildStarted {
		if err := h.completePayloadBuild(result); err != nil {
			return PayloadResult{}, fmt.Errorf("persist completed payload state: %w", err)
		}
		durableBuildCompleted = true
	}

	log.Printf("[INFO] Successfully generated payload: %s (%s, %d bytes)",
		result.Filename, buildType, result.Size)

	return result, nil
}

// loadListenerConfig resolves a listener through the injected authoritative
// lookup. Production uses ListenerManager; only the compatibility constructor
// uses a filesystem adapter.
func (h *PayloadHandler) loadListenerConfig(listenerID string) (listeners.ListenerConfig, error) {
	return h.listenerLookup.LookupListener(listenerID)
}

func (h *PayloadHandler) beginPayloadBuild(record payloadBuildRecord) error {
	if h.database == nil {
		return errors.New("payload persistence database is unavailable")
	}
	if record.State != payloadStateBuilding {
		return fmt.Errorf("initial payload state must be %q", payloadStateBuilding)
	}
	if len(record.ProvenanceJSON) == 0 || !json.Valid(record.ProvenanceJSON) {
		return errors.New("initial payload provenance is invalid")
	}

	_, err := h.database.SQL().Exec(
		`INSERT INTO payload_builds (
			id, payload_id, listener_id, mutation_seed, filename,
			relative_path, size, sha256, created_at, state,
			state_detail, provenance_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID,
		record.PayloadID,
		record.ListenerID,
		record.MutationSeed,
		record.Filename,
		record.RelativePath,
		record.Size,
		record.SHA256,
		record.CreatedAt,
		record.State,
		record.StateDetail,
		record.ProvenanceJSON,
	)
	if err != nil {
		return fmt.Errorf("insert building payload metadata: %w", err)
	}
	return nil
}

func (h *PayloadHandler) completePayloadBuild(result PayloadResult) error {
	if h.database == nil {
		return errors.New("payload persistence database is unavailable")
	}
	if result.relativePath == "" ||
		result.sha256 == "" ||
		len(result.provenanceJSON) == 0 ||
		!json.Valid(result.provenanceJSON) {
		return errors.New("completed payload metadata is incomplete")
	}
	sqlResult, err := h.database.SQL().Exec(
		`UPDATE payload_builds
		 SET relative_path = ?,
		     size = ?,
		     sha256 = ?,
		     created_at = ?,
		     state = ?,
		     state_detail = '',
		     provenance_json = ?
		 WHERE id = ? AND state = ?`,
		result.relativePath,
		result.Size,
		result.sha256,
		result.Created,
		payloadStateCompleted,
		result.provenanceJSON,
		result.ID,
		payloadStateBuilding,
	)
	if err != nil {
		return fmt.Errorf("transition payload to completed: %w", err)
	}
	affected, err := sqlResult.RowsAffected()
	if err != nil {
		return fmt.Errorf("read completed payload transition result: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("completed payload transition affected %d rows, want 1", affected)
	}
	return nil
}

func (h *PayloadHandler) failPayloadBuild(payloadID string) error {
	if h.database == nil {
		return nil
	}
	sqlResult, err := h.database.SQL().Exec(
		`UPDATE payload_builds
		 SET state = ?, state_detail = ?
		 WHERE id = ? AND state = ?`,
		payloadStateFailed,
		payloadFailedDetail,
		payloadID,
		payloadStateBuilding,
	)
	if err != nil {
		return fmt.Errorf("transition payload to failed: %w", err)
	}
	affected, err := sqlResult.RowsAffected()
	if err != nil {
		return fmt.Errorf("read failed payload transition result: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("failed payload transition affected %d rows, want 1", affected)
	}
	return nil
}

func (h *PayloadHandler) interruptPayloadBuild(payloadID string) error {
	if h.database == nil {
		return nil
	}
	sqlResult, err := h.database.SQL().Exec(
		`UPDATE payload_builds
		 SET state = ?, state_detail = ?
		 WHERE id = ? AND state = ?`,
		payloadStateInterrupted,
		payloadInterruptedDetail,
		payloadID,
		payloadStateBuilding,
	)
	if err != nil {
		return fmt.Errorf("transition payload to interrupted: %w", err)
	}
	affected, err := sqlResult.RowsAffected()
	if err != nil {
		return fmt.Errorf("read interrupted payload transition result: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("interrupted payload transition affected %d rows, want 1", affected)
	}
	return nil
}

func (h *PayloadHandler) lookupPayload(id string) (payloadBuildRecord, error) {
	if h.database == nil {
		h.mutex.Lock()
		result, exists := h.payloads[id]
		h.mutex.Unlock()
		if !exists {
			return payloadBuildRecord{}, sql.ErrNoRows
		}
		record := payloadBuildRecord{
			ID:             result.ID,
			PayloadID:      result.PayloadID,
			ListenerID:     result.ListenerID,
			MutationSeed:   result.MutationSeed,
			Filename:       result.Filename,
			RelativePath:   result.relativePath,
			Size:           result.Size,
			SHA256:         result.sha256,
			CreatedAt:      result.Created,
			State:          payloadStateCompleted,
			ProvenanceJSON: append([]byte(nil), result.provenanceJSON...),
		}
		if record.RelativePath == "" {
			relativePath, err := h.relativeArtifactPath(result.Path)
			if err != nil {
				return payloadBuildRecord{}, err
			}
			record.RelativePath = relativePath
		}
		if record.SHA256 == "" {
			hash, err := hashArtifact(result.Path)
			if err != nil {
				return payloadBuildRecord{}, err
			}
			record.SHA256 = hash
		}
		return record, nil
	}

	record := payloadBuildRecord{}
	err := h.database.SQL().QueryRow(
		`SELECT
			id, payload_id, listener_id, mutation_seed, filename,
			relative_path, size, sha256, created_at, state,
			state_detail, provenance_json
		FROM payload_builds
		WHERE id = ?`,
		id,
	).Scan(
		&record.ID,
		&record.PayloadID,
		&record.ListenerID,
		&record.MutationSeed,
		&record.Filename,
		&record.RelativePath,
		&record.Size,
		&record.SHA256,
		&record.CreatedAt,
		&record.State,
		&record.StateDetail,
		&record.ProvenanceJSON,
	)
	if err != nil {
		return payloadBuildRecord{}, err
	}
	return record, nil
}

func (h *PayloadHandler) reconcilePayloads() error {
	records, err := h.listPayloadRecords()
	if err != nil {
		return err
	}
	for _, record := range records {
		switch record.State {
		case payloadStateBuilding:
			if err := h.interruptPayloadBuild(record.ID); err != nil {
				return fmt.Errorf("interrupt payload %s after restart: %w", record.ID, err)
			}
			continue
		case payloadStateFailed, payloadStateInterrupted:
			continue
		}
		_, state, detail, actualHash := h.revalidatePayload(record)
		if err := h.updatePayloadState(record, state, detail, actualHash); err != nil {
			return fmt.Errorf("reconcile payload %s: %w", record.ID, err)
		}
	}
	return nil
}

func (h *PayloadHandler) listPayloadRecords() ([]payloadBuildRecord, error) {
	rows, err := h.database.SQL().Query(
		`SELECT
			id, payload_id, listener_id, mutation_seed, filename,
			relative_path, size, sha256, created_at, state,
			state_detail, provenance_json
		FROM payload_builds
		ORDER BY id`,
	)
	if err != nil {
		return nil, fmt.Errorf("list payload metadata: %w", err)
	}
	defer rows.Close()

	records := make([]payloadBuildRecord, 0)
	for rows.Next() {
		record := payloadBuildRecord{}
		if err := rows.Scan(
			&record.ID,
			&record.PayloadID,
			&record.ListenerID,
			&record.MutationSeed,
			&record.Filename,
			&record.RelativePath,
			&record.Size,
			&record.SHA256,
			&record.CreatedAt,
			&record.State,
			&record.StateDetail,
			&record.ProvenanceJSON,
		); err != nil {
			return nil, fmt.Errorf("scan payload metadata: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate payload metadata: %w", err)
	}
	return records, nil
}

func (h *PayloadHandler) updatePayloadState(
	record payloadBuildRecord,
	state string,
	detail string,
	actualHash string,
) error {
	if h.database == nil {
		return nil
	}
	if state != payloadStateCompleted &&
		state != payloadStateMissing &&
		state != payloadStateCorrupt {
		return fmt.Errorf("unsupported reconciled payload state %q", state)
	}
	hash := record.SHA256
	if state == payloadStateCompleted && hash == "" {
		hash = actualHash
	}
	_, err := h.database.SQL().Exec(
		`UPDATE payload_builds
		 SET state = ?, state_detail = ?, sha256 = ?
		 WHERE id = ?`,
		state,
		detail,
		hash,
		record.ID,
	)
	if err != nil {
		return fmt.Errorf("update payload state: %w", err)
	}
	return nil
}

func (h *PayloadHandler) revalidatePayload(
	record payloadBuildRecord,
) (artifactPath string, state string, detail string, actualHash string) {
	file, state, detail, actualHash := h.openVerifiedPayload(record)
	if file == nil {
		return "", state, detail, actualHash
	}
	artifactPath = file.Name()
	if err := file.Close(); err != nil {
		return "", payloadStateCorrupt, "artifact cannot be closed after verification", ""
	}
	return artifactPath, state, detail, actualHash
}

func (h *PayloadHandler) openVerifiedPayload(
	record payloadBuildRecord,
) (file *os.File, state string, detail string, actualHash string) {
	if len(record.ProvenanceJSON) == 0 || !json.Valid(record.ProvenanceJSON) {
		return nil, payloadStateCorrupt, "payload provenance is invalid", ""
	}
	if !validPayloadFilename(record.Filename) {
		return nil, payloadStateCorrupt, "payload filename is invalid", ""
	}
	artifactPath, err := h.resolveArtifactPath(record.RelativePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, payloadStateMissing, "artifact is missing", ""
		}
		return nil, payloadStateCorrupt, err.Error(), ""
	}
	if filepath.Base(artifactPath) != record.Filename {
		return nil, payloadStateCorrupt, "artifact filename does not match metadata", ""
	}

	file, err = openPayloadArtifact(artifactPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, payloadStateMissing, "artifact is missing", ""
		}
		return nil, payloadStateCorrupt, "artifact cannot be opened", ""
	}
	closeAsCorrupt := func(detail string) (*os.File, string, string, string) {
		_ = file.Close()
		return nil, payloadStateCorrupt, detail, ""
	}

	info, err := file.Stat()
	if err != nil {
		return closeAsCorrupt("artifact cannot be inspected")
	}
	if !info.Mode().IsRegular() {
		return closeAsCorrupt("artifact is not a regular file")
	}
	if info.Size() != record.Size {
		return closeAsCorrupt("artifact size does not match metadata")
	}
	actualHash, err = hashOpenArtifact(file)
	if err != nil {
		return closeAsCorrupt("artifact cannot be hashed")
	}
	if record.SHA256 != "" && actualHash != record.SHA256 {
		_ = file.Close()
		return nil, payloadStateCorrupt, "artifact SHA-256 does not match metadata", actualHash
	}
	infoAfterHash, err := file.Stat()
	if err != nil ||
		!infoAfterHash.Mode().IsRegular() ||
		infoAfterHash.Size() != record.Size {
		return closeAsCorrupt("artifact changed during verification")
	}
	return file, payloadStateCompleted, "", actualHash
}

func payloadFilename(format string) string {
	switch format {
	case "windows_exe":
		return "agent.exe"
	case "windows_dll":
		return "agent.dll"
	case "windows_service":
		return "agent_service.exe"
	case "windows_shellcode":
		return "shellcode.bin"
	default:
		return "agent"
	}
}

func (h *PayloadHandler) plannedRelativeArtifactPath(artifactPath string) (string, error) {
	absoluteArtifactPath, err := filepath.Abs(artifactPath)
	if err != nil {
		return "", fmt.Errorf("resolve planned artifact path: %w", err)
	}
	relativePath, err := filepath.Rel(h.payloadsDir, absoluteArtifactPath)
	if err != nil || !isContainedRelativePath(relativePath) {
		return "", errors.New("planned payload artifact is outside the configured payload root")
	}
	resolvedRoot, err := filepath.EvalSymlinks(h.payloadsDir)
	if err != nil {
		return "", fmt.Errorf("resolve payload root: %w", err)
	}
	resolvedParent, err := filepath.EvalSymlinks(filepath.Dir(absoluteArtifactPath))
	if err != nil {
		return "", fmt.Errorf("resolve planned artifact directory: %w", err)
	}
	resolvedRelative, err := filepath.Rel(resolvedRoot, resolvedParent)
	if err != nil || (resolvedRelative != "." && !isContainedRelativePath(resolvedRelative)) {
		return "", errors.New("planned payload artifact resolves outside the configured payload root")
	}
	return filepath.ToSlash(relativePath), nil
}

func (h *PayloadHandler) relativeArtifactPath(artifactPath string) (string, error) {
	absoluteArtifactPath, err := filepath.Abs(artifactPath)
	if err != nil {
		return "", fmt.Errorf("resolve artifact path: %w", err)
	}
	relativePath, err := filepath.Rel(h.payloadsDir, absoluteArtifactPath)
	if err != nil || !isContainedRelativePath(relativePath) {
		return "", errors.New("payload artifact is outside the configured payload root")
	}
	resolvedRoot, err := filepath.EvalSymlinks(h.payloadsDir)
	if err != nil {
		return "", fmt.Errorf("resolve payload root: %w", err)
	}
	resolvedArtifact, err := filepath.EvalSymlinks(absoluteArtifactPath)
	if err != nil {
		return "", fmt.Errorf("resolve payload artifact: %w", err)
	}
	resolvedRelative, err := filepath.Rel(resolvedRoot, resolvedArtifact)
	if err != nil || !isContainedRelativePath(resolvedRelative) {
		return "", errors.New("payload artifact resolves outside the configured payload root")
	}
	return filepath.ToSlash(relativePath), nil
}

func (h *PayloadHandler) resolveArtifactPath(relativePath string) (string, error) {
	if relativePath == "" || filepath.IsAbs(relativePath) {
		return "", errors.New("artifact path is not a contained relative path")
	}
	nativeRelativePath := filepath.FromSlash(relativePath)
	if !isContainedRelativePath(nativeRelativePath) {
		return "", errors.New("artifact path is not a contained relative path")
	}
	artifactPath := filepath.Join(h.payloadsDir, nativeRelativePath)
	lexicalRelative, err := filepath.Rel(h.payloadsDir, artifactPath)
	if err != nil || !isContainedRelativePath(lexicalRelative) {
		return "", errors.New("artifact path escapes the configured payload root")
	}
	resolvedRoot, err := filepath.EvalSymlinks(h.payloadsDir)
	if err != nil {
		return "", fmt.Errorf("resolve payload root: %w", err)
	}
	resolvedArtifact, err := filepath.EvalSymlinks(artifactPath)
	if err != nil {
		return "", err
	}
	resolvedRelative, err := filepath.Rel(resolvedRoot, resolvedArtifact)
	if err != nil || !isContainedRelativePath(resolvedRelative) {
		return "", errors.New("artifact path resolves outside the configured payload root")
	}
	return resolvedArtifact, nil
}

func isContainedRelativePath(path string) bool {
	if path == "" || path == "." || filepath.IsAbs(path) || path == ".." {
		return false
	}
	return !strings.HasPrefix(path, ".."+string(filepath.Separator))
}

func validPayloadFilename(filename string) bool {
	return filename != "" &&
		filename == filepath.Base(filename) &&
		!strings.ContainsAny(filename, "\r\n\x00")
}

func validPayloadID(id string) bool {
	if id == "" || len(id) > 128 || id != strings.TrimSpace(id) {
		return false
	}
	for _, character := range id {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func hashArtifact(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	return hashOpenArtifact(file)
}

func hashOpenArtifact(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func openPayloadArtifact(path string) (*os.File, error) {
	return os.Open(filepath.Clean(path))
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
