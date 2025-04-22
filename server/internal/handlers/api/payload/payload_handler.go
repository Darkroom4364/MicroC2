package payload

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PayloadConfig defines the structure for payload generation configuration
type PayloadConfig struct {
	AgentType       string `json:"agentType"`
	ListenerID      string `json:"listener"`
	Architecture    string `json:"architecture"`
	Format          string `json:"format"`
	Sleep           int    `json:"sleep"`
	IndirectSyscall bool   `json:"indirectSyscall"`
	SleepTechnique  string `json:"sleepTechnique"`
	DllSideloading  bool   `json:"dllSideloading"`
	SideloadDll     string `json:"sideloadDll,omitempty"`
	ExportName      string `json:"exportName,omitempty"`
}

// PayloadResult contains information about a generated payload
type PayloadResult struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Created  string `json:"created"`
}

// TLSConfig holds TLS configuration for secure listeners
type TLSConfig struct {
	CertFile          string `json:"cert_file"`
	KeyFile           string `json:"key_file"`
	RequireClientCert bool   `json:"requireClientCert"`
}

// PayloadHandler manages payload generation operations
type PayloadHandler struct {
	payloadsDir    string
	agentSourceDir string
	mutex          sync.Mutex
	payloads       map[string]PayloadResult
}

// ListenerConfig represents the configuration of a listener
type ListenerConfig struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Protocol     string            `json:"protocol"`
	BindHost     string            `json:"host"`
	Port         int               `json:"port"`
	Headers      map[string]string `json:"headers,omitempty"`
	UserAgent    string            `json:"user_agent,omitempty"`
	HostRotation string            `json:"host_rotation,omitempty"`
	Hosts        []string          `json:"hosts,omitempty"`
	TLSConfig    *TLSConfig        `json:"tls_config,omitempty"`
}

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
	log.Printf("[INFO] Using listener: %s (%s) at %s:%d", listener.Name, listener.Protocol, listener.BindHost, listener.Port)

	// Use listener ID for the payload
	payloadID := listener.ID
	log.Printf("[INFO] Using listener ID as payload ID: %s", payloadID)

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

	// Determine the protocol prefix and full server URL
	protocolPrefix := "http://"
	if listener.Protocol == "https" {
		protocolPrefix = "https://"
	}

	// Use BindHost by default, override with the first entry in Hosts if provided
	serverUrl := fmt.Sprintf("%s%s:%d", protocolPrefix, listener.BindHost, listener.Port)
	if len(listener.Hosts) > 0 {
		serverUrl = fmt.Sprintf("%s%s:%d", protocolPrefix, listener.Hosts[0], listener.Port)
	}

	agentConfig := map[string]interface{}{
		"server_url":     serverUrl,
		"sleep_interval": config.Sleep,
		"jitter":         2,           // Default jitter value
		"payload_id":     listener.ID, // Use listener ID as payload ID
		"protocol":       listener.Protocol,
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
		"--listener-host", listener.BindHost, // Add listener host argument
		"--listener-port", fmt.Sprintf("%d", listener.Port), // Add listener port argument
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
		// fmt.Sprintf("LISTENER_HOST=%s", listener.BindHost),
		// fmt.Sprintf("LISTENER_PORT=%d", listener.Port),
		fmt.Sprintf("SLEEP_INTERVAL=%d", config.Sleep),
	)
	// log.Printf("[INFO] Environment variables set: TARGET=%s, OUTPUT_DIR=%s, BUILD_TYPE=%s, LISTENER_HOST=%s, LISTENER_PORT=%d, SLEEP_INTERVAL=%d",
	//	buildTarget, outputDir, buildType, listener.BindHost, listener.Port, config.Sleep)

	log.Printf("[INFO] Environment variables set: TARGET=%s, OUTPUT_DIR=%s, BUILD_TYPE=%s, SLEEP_INTERVAL=%d",
		buildTarget, outputDir, buildType, config.Sleep)

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
	maxLogLines := 10
	for i, line := range outputLines {
		if line != "" {
			if i < maxLogLines {
				log.Printf("[INFO] Build output: %s", line)
			} else {
				log.Printf("[INFO] Skipping remaining %d lines of output...", len(outputLines)-maxLogLines)
				break
			}
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

	// Create the result
	result := PayloadResult{
		ID:       payloadID,
		Filename: payloadFileName,
		Path:     payloadPath,
		Size:     fileInfo.Size(),
		Created:  time.Now().Format(time.RFC3339),
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
			log.Printf("[DEBUG] Skipping directory %s: %v", entry.Name(), err)
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

// SetupRoutes registers all payload-related routes
//
// Pre-conditions:
//   - HTTP server is initialized and ready to accept route registrations
//
// Post-conditions:
//   - Routes for payload generation and download are registered
//   - Requests to these routes will be handled by the appropriate methods
func (h *PayloadHandler) SetupRoutes() {
	http.HandleFunc("/api/payload/generate", h.HandleGeneratePayload)
	http.HandleFunc("/api/payload/download/", h.HandleDownloadPayload)
}
