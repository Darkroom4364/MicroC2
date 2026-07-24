// This file will be moved to the new 'behaviour' folder as 'static_polling.go'.
package behaviour

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"microc2/server/internal/common"
	"microc2/server/internal/enrollment"
	"microc2/server/internal/filestore"
	"microc2/server/internal/persistence"
	"microc2/server/internal/tasks"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HTTPPollingProtocol struct {
	config      common.BaseProtocolConfig
	mux         *http.ServeMux
	taskStore   taskStateStore
	database    *persistence.Database
	listenerID  string
	enrollment  *enrollment.Store
	requireAuth bool
	results     struct {
		sync.Mutex
		history map[string][]CommandResult // AgentID -> []CommandResult
	}
	agents struct {
		sync.Mutex
		list           map[string]*Agent
		activeThisBoot map[string]bool
	}
}

type taskStateStore interface {
	Create(agentID string, request tasks.CreateRequest) (tasks.Task, error)
	CreateLegacyShell(agentID, command string) (tasks.Task, error)
	List(agentID string) ([]tasks.Task, error)
	Get(agentID, taskID string) (tasks.Task, error)
	DispatchNext(agentID string) (tasks.Task, bool, error)
	DispatchNextLegacy(agentID string) (tasks.Task, bool, error)
	MarkRunning(agentID, taskID string, update tasks.StatusUpdate) (tasks.Task, error)
	CompleteWithInfo(agentID string, result tasks.Result) (tasks.Task, tasks.CompletionInfo, error)
	Cancel(agentID, taskID string) (tasks.Task, error)
	CompleteLegacy(agentID, command, output string) (tasks.Task, bool, error)
}

type durableLegacyResultPager interface {
	GetLegacyResultsPage(
		agentID string,
		offset, limit, maxEncodedBytes int,
	) ([]tasks.LegacyResult, int, bool, error)
}

type taskSummaryPager interface {
	ListTaskSummariesPage(
		agentID string,
		offset, limit int,
	) ([]tasks.TaskSummary, int, error)
}

type CommandResult struct {
	Command   string `json:"command"`
	Output    string `json:"output"`
	Timestamp string `json:"timestamp"`
}

const maxAgentHeartbeatBodyBytes = 64 << 10

const maxAgentAuthorizationHeaderBytes = 256

var (
	errAgentHeartbeatPersistence = errors.New("agent heartbeat persistence failed")
)

type Agent struct {
	ID         string    `json:"id"`
	ListenerID string    `json:"listener_id,omitempty"`
	PayloadID  string    `json:"payload_id,omitempty"`
	OS         string    `json:"os"`
	Hostname   string    `json:"hostname"`
	IP         string    `json:"ip"`
	IPList     []string  `json:"ip_list,omitempty"`
	LastSeen   time.Time `json:"last_seen"`
	Commands   []string  `json:"last_commands"`
}

// NewHTTPPollingProtocol creates a new HTTP polling protocol instance
func NewHTTPPollingProtocol(config common.BaseProtocolConfig) *HTTPPollingProtocol {
	return newHTTPPollingProtocol(config, tasks.NewStore(), nil, "")
}

// NewHTTPPollingProtocolWithPersistence loads listener-scoped durable agents,
// tasks, results, and dispatch lease state. listenerID is supplied by the
// server-side listener configuration and never trusted from heartbeat data.
func NewHTTPPollingProtocolWithPersistence(
	config common.BaseProtocolConfig,
	database *persistence.Database,
	listenerID string,
) (*HTTPPollingProtocol, error) {
	if database == nil {
		return nil, errors.New("durable polling protocol requires a database")
	}
	if err := tasks.ValidateIdentifier("listener_id", listenerID); err != nil {
		return nil, err
	}
	taskStore, err := tasks.NewDurableStore(database, listenerID, time.Now)
	if err != nil {
		return nil, err
	}
	p := newHTTPPollingProtocol(config, taskStore, database, listenerID)
	if err := p.loadPersistedAgents(); err != nil {
		return nil, err
	}
	return p, nil
}

// NewAuthenticatedHTTPPollingProtocolWithPersistence constructs the
// production polling protocol. It starts with no process-local active agents:
// durable rows remain available to the operator API, but every agent must
// authenticate a fresh heartbeat after server restart before it can receive
// tasking.
func NewAuthenticatedHTTPPollingProtocolWithPersistence(
	config common.BaseProtocolConfig,
	database *persistence.Database,
	listenerID string,
) (*HTTPPollingProtocol, error) {
	if database == nil {
		return nil, errors.New("authenticated polling protocol requires a database")
	}
	if err := tasks.ValidateIdentifier("listener_id", listenerID); err != nil {
		return nil, err
	}
	taskStore, err := tasks.NewDurableStore(database, listenerID, time.Now)
	if err != nil {
		return nil, err
	}
	enrollmentStore, err := enrollment.NewStore(context.Background(), database)
	if err != nil {
		return nil, fmt.Errorf("initialize enrollment store: %w", err)
	}
	p := newHTTPPollingProtocol(config, taskStore, database, listenerID)
	p.enrollment = enrollmentStore
	p.requireAuth = true
	return p, nil
}

func newHTTPPollingProtocol(
	config common.BaseProtocolConfig,
	taskStore taskStateStore,
	database *persistence.Database,
	listenerID string,
) *HTTPPollingProtocol {
	p := &HTTPPollingProtocol{
		config:     config,
		mux:        http.NewServeMux(),
		taskStore:  taskStore,
		database:   database,
		listenerID: listenerID,
		agents: struct {
			sync.Mutex
			list           map[string]*Agent
			activeThisBoot map[string]bool
		}{
			list:           make(map[string]*Agent),
			activeThisBoot: make(map[string]bool),
		},
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

// RequiresAgentAuthentication reports whether this protocol rejects all
// agent lifecycle requests until a durable enrollment session is established.
func (p *HTTPPollingProtocol) RequiresAgentAuthentication() bool {
	return p != nil && p.requireAuth && p.enrollment != nil
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
	if p.requireAuth {
		w.Header().Set("Cache-Control", "no-store")
		if action != "heartbeat" {
			if err := p.authenticateAgentRequest(r, agentID); err != nil {
				p.writeAgentAuthenticationError(w, err)
				return
			}
			if !p.agentActiveThisBoot(agentID) {
				p.writeAgentAuthenticationError(w, enrollment.ErrUnauthorized)
				return
			}
		}
	}
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

func (p *HTTPPollingProtocol) authenticateAgentRequest(
	r *http.Request,
	agentID string,
) error {
	if p.enrollment == nil {
		return errors.New("agent enrollment store is unavailable")
	}
	credential, ok := agentBearerCredential(r)
	if !ok {
		return enrollment.ErrUnauthorized
	}
	_, err := p.enrollment.Authenticate(
		r.Context(),
		p.listenerID,
		agentID,
		credential,
	)
	return err
}

func (p *HTTPPollingProtocol) agentActiveThisBoot(agentID string) bool {
	p.agents.Lock()
	defer p.agents.Unlock()
	return p.agents.activeThisBoot[agentID]
}

func agentBearerCredential(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 ||
		len(values[0]) == 0 ||
		len(values[0]) > maxAgentAuthorizationHeaderBytes {
		return "", false
	}
	scheme, credential, found := strings.Cut(values[0], " ")
	if !found ||
		!strings.EqualFold(scheme, "Bearer") ||
		credential == "" ||
		strings.ContainsAny(credential, " \t\r\n") {
		return "", false
	}
	return credential, true
}

func (p *HTTPPollingProtocol) writeAgentAuthenticationError(
	w http.ResponseWriter,
	err error,
) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case errors.Is(err, enrollment.ErrUnauthorized):
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	case errors.Is(err, enrollment.ErrEnrollmentCapacity):
		http.Error(w, "Agent enrollment capacity reached", http.StatusConflict)
	default:
		log.Printf("[ERROR] Agent authentication state unavailable: %v", err)
		http.Error(w, "Agent authentication unavailable", http.StatusInternalServerError)
	}
}

func (p *HTTPPollingProtocol) handleAgentHeartbeat(
	w http.ResponseWriter,
	r *http.Request,
	agentID string,
) {
	p.enableCors(w, r)

	// Handle preflight OPTIONS request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		// net/http rejects methods that are not RFC tokens before dispatch, so
		// r.Method cannot contain the control characters needed to forge a log.
		// foxguard: ignore[go/taint-log-injection]
		log.Printf("[ERROR] Invalid method %s for agent heartbeat", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	credential := ""
	if p.requireAuth {
		var ok bool
		credential, ok = agentBearerCredential(r)
		if !ok {
			p.writeAgentAuthenticationError(w, enrollment.ErrUnauthorized)
			return
		}
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAgentHeartbeatBodyBytes))
	if err != nil {
		// The server-owned request reader returns fixed net/http or I/O errors;
		// request body bytes are never included in this error string.
		// foxguard: ignore[go/taint-log-injection]
		log.Printf("[ERROR] Failed to read bounded agent heartbeat body: %v", err)
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			http.Error(w, "Heartbeat request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		return
	}

	agent, err := decodeAgentHeartbeat(body, agentID)
	if err != nil {
		http.Error(w, "Invalid agent heartbeat", http.StatusBadRequest)
		return
	}

	sessionCredential := ""
	if p.requireAuth {
		if p.enrollment == nil {
			p.writeAgentAuthenticationError(
				w,
				errors.New("agent enrollment store is unavailable"),
			)
			return
		}
		if agent.ListenerID != p.listenerID || agent.PayloadID == "" {
			p.writeAgentAuthenticationError(w, enrollment.ErrUnauthorized)
			return
		}
		authentication, authErr := p.enrollment.Authenticate(
			r.Context(),
			p.listenerID,
			agentID,
			credential,
		)
		switch {
		case authErr == nil:
			if authentication.PayloadBuildID != agent.PayloadID {
				p.writeAgentAuthenticationError(w, enrollment.ErrUnauthorized)
				return
			}
			sessionCredential = authentication.ReplacementCredential
		case errors.Is(authErr, enrollment.ErrUnauthorized):
			enrolled, enrollErr := p.enrollment.Enroll(
				r.Context(),
				enrollment.EnrollRequest{
					ListenerID:     p.listenerID,
					AgentID:        agentID,
					PayloadBuildID: agent.PayloadID,
					Bootstrap:      credential,
				},
			)
			if enrollErr != nil {
				p.writeAgentAuthenticationError(w, enrollErr)
				return
			}
			sessionCredential = enrolled.Credential
		default:
			p.writeAgentAuthenticationError(w, authErr)
			return
		}
	}

	if err := p.recordAgentHeartbeat(agent); err != nil {
		// recordAgentHeartbeat returns only fixed validation or persistence
		// errors; decoded heartbeat field values are never formatted into err.
		// foxguard: ignore[go/taint-log-injection]
		log.Printf("[ERROR] Failed to record authenticated agent heartbeat: %v", err)
		if errors.Is(err, errAgentHeartbeatPersistence) {
			http.Error(w, "Failed to persist agent heartbeat", http.StatusInternalServerError)
			return
		}
		http.Error(w, "Invalid agent heartbeat", http.StatusBadRequest)
		return
	}

	if p.requireAuth {
		log.Printf("[INFO] Successfully processed authenticated heartbeat for agent %s", agentID)
	} else {
		log.Printf("[INFO] Successfully processed heartbeat for agent %s", agentID)
	}
	response := map[string]string{
		"status": "connected",
		"time":   time.Now().UTC().Format(time.RFC3339),
	}
	if sessionCredential != "" {
		response["session_credential"] = sessionCredential
	}
	respBytes, err := json.Marshal(response)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal agent heartbeat response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(respBytes)))
	if _, err := w.Write(respBytes); err != nil {
		log.Printf("[ERROR] Failed to write agent heartbeat response: %v", err)
	}
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
	if _, durable := p.taskStore.(durableLegacyResultPager); !durable &&
		completion.LegacyOrigin && completion.Applied {
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
	} else if _, durable := p.taskStore.(durableLegacyResultPager); matched && !durable {
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
	agent, err := decodeAgentHeartbeat(agentData, expectedAgentID)
	if err != nil {
		return err
	}
	return p.recordAgentHeartbeat(agent)
}

func decodeAgentHeartbeat(agentData []byte, expectedAgentID string) (Agent, error) {
	var agent Agent
	if err := json.Unmarshal(agentData, &agent); err != nil {
		log.Printf("[ERROR] Failed to unmarshal agent heartbeat: %v", err)
		return Agent{}, fmt.Errorf("failed to unmarshal agent data: %w", err)
	}
	if strings.TrimSpace(agent.ID) == "" {
		return Agent{}, fmt.Errorf("agent id is required")
	}
	if expectedAgentID != "" && agent.ID != expectedAgentID {
		return Agent{}, fmt.Errorf("agent id mismatch")
	}
	if err := validateAgentHeartbeat(agent); err != nil {
		return Agent{}, err
	}
	return agent, nil
}

func (p *HTTPPollingProtocol) recordAgentHeartbeat(agent Agent) error {
	p.agents.Lock()
	defer p.agents.Unlock()
	_, alreadyPresent := p.agents.list[agent.ID]
	agent.ListenerID = p.listenerID
	agent.LastSeen = time.Now().UTC().Round(0)
	if err := p.persistAgent(agent); err != nil {
		return fmt.Errorf("%w: %w", errAgentHeartbeatPersistence, err)
	}
	if !alreadyPresent && len(p.agents.list) >= enrollment.MaxListenerSessions {
		p.evictOldestRuntimeAgentLocked()
	}
	p.agents.list[agent.ID] = &agent
	p.agents.activeThisBoot[agent.ID] = true
	log.Printf("[DEBUG] Agent %s added/updated in list. Total agents: %d", agent.ID, len(p.agents.list))
	return nil
}

// evictOldestRuntimeAgentLocked bounds process-local presence without deleting
// durable history. The evicted session remains valid, but must heartbeat again
// before it can receive tasking in this process. Caller must hold agents.Lock.
func (p *HTTPPollingProtocol) evictOldestRuntimeAgentLocked() {
	oldestID := ""
	var oldestSeen time.Time
	for agentID, agent := range p.agents.list {
		lastSeen := time.Time{}
		if agent != nil {
			lastSeen = agent.LastSeen
		}
		if oldestID == "" ||
			lastSeen.Before(oldestSeen) ||
			lastSeen.Equal(oldestSeen) && agentID < oldestID {
			oldestID = agentID
			oldestSeen = lastSeen
		}
	}
	if oldestID == "" {
		return
	}
	delete(p.agents.list, oldestID)
	delete(p.agents.activeThisBoot, oldestID)
	log.Printf(
		"[INFO] Evicted least-recently-seen runtime agent %s; durable history retained",
		oldestID,
	)
}

// Restore the interface method for Protocol compatibility
func (p *HTTPPollingProtocol) HandleAgentHeartbeat(agentData []byte) error {
	if p.requireAuth {
		return errors.New(
			"authenticated heartbeats must use the HTTP enrollment path",
		)
	}
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
	w.Header().Set(
		"Access-Control-Allow-Headers",
		"Authorization, Content-Type, X-Filename, X-Command",
	)
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
	if !p.agents.activeThisBoot[agentID] {
		// Persisted agents are historical after restart. A fresh heartbeat is
		// required before operator dispatch; durable enrollment state does not
		// prove that the runtime is active in this process lifetime.
		return time.Time{}, true
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

// QueueLegacyShellTaskContext preserves the authenticated operator actor for
// durable audit records while retaining the legacy adapter surface.
func (p *HTTPPollingProtocol) QueueLegacyShellTaskContext(
	ctx context.Context,
	agentID, command string,
) (tasks.Task, error) {
	if store, ok := p.taskStore.(interface {
		CreateLegacyShellContext(
			context.Context,
			string,
			string,
		) (tasks.Task, error)
	}); ok {
		return store.CreateLegacyShellContext(ctx, agentID, command)
	}
	return p.taskStore.CreateLegacyShell(agentID, command)
}

func (p *HTTPPollingProtocol) CreateTask(agentID string, createRequest tasks.CreateRequest) (tasks.Task, error) {
	return p.taskStore.Create(agentID, createRequest)
}

// CreateTaskContext preserves the authenticated operator actor for durable
// task queue audit records.
func (p *HTTPPollingProtocol) CreateTaskContext(
	ctx context.Context,
	agentID string,
	createRequest tasks.CreateRequest,
) (tasks.Task, error) {
	if store, ok := p.taskStore.(interface {
		CreateContext(
			context.Context,
			string,
			tasks.CreateRequest,
		) (tasks.Task, error)
	}); ok {
		return store.CreateContext(ctx, agentID, createRequest)
	}
	return p.taskStore.Create(agentID, createRequest)
}

func (p *HTTPPollingProtocol) ListTasks(agentID string) ([]tasks.Task, error) {
	return p.taskStore.List(agentID)
}

// ListTaskSummariesPage uses the durable metadata-only query when available.
// The in-memory fallback preserves the same newest-first operator contract for
// focused tests and legacy callers.
func (p *HTTPPollingProtocol) ListTaskSummariesPage(
	agentID string,
	offset, limit int,
) ([]tasks.TaskSummary, int, error) {
	if pager, ok := p.taskStore.(taskSummaryPager); ok {
		return pager.ListTaskSummariesPage(agentID, offset, limit)
	}
	history, err := p.taskStore.List(agentID)
	if err != nil {
		return nil, 0, err
	}
	sort.Slice(history, func(i, j int) bool {
		if history[i].CreatedAt.Equal(history[j].CreatedAt) {
			return history[i].ID > history[j].ID
		}
		return history[i].CreatedAt.After(history[j].CreatedAt)
	})
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
	if limit > total-offset {
		limit = total - offset
	}
	summaries := make([]tasks.TaskSummary, 0, limit)
	for _, task := range history[offset : offset+limit] {
		summaries = append(summaries, tasks.Summarize(task))
	}
	return summaries, total, nil
}

func (p *HTTPPollingProtocol) CancelTask(agentID, taskID string) (tasks.Task, error) {
	return p.taskStore.Cancel(agentID, taskID)
}

// CancelTaskContext preserves the authenticated operator actor for durable
// task cancellation audit records.
func (p *HTTPPollingProtocol) CancelTaskContext(
	ctx context.Context,
	agentID, taskID string,
) (tasks.Task, error) {
	if store, ok := p.taskStore.(interface {
		CancelContext(
			context.Context,
			string,
			string,
		) (tasks.Task, error)
	}); ok {
		return store.CancelContext(ctx, agentID, taskID)
	}
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
	results, _ := p.GetResultsPage(AgentID, 0, tasks.MaxTaskHistoryPerAgent)
	return results
}

// ListLegacyResultsPage returns compatibility results within an encoded JSON
// body budget. Durable stores apply the budget while SQLite rows are stepped;
// the in-memory fallback applies the identical accounting to its resident data.
func (p *HTTPPollingProtocol) ListLegacyResultsPage(
	agentID string,
	offset, limit, maxEncodedBytes int,
) ([]tasks.LegacyResult, int, bool, error) {
	if pager, ok := p.taskStore.(durableLegacyResultPager); ok {
		return pager.GetLegacyResultsPage(
			agentID,
			offset,
			limit,
			maxEncodedBytes,
		)
	}

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
	if limit > total-offset {
		limit = total - offset
	}

	results := make([]tasks.LegacyResult, 0, limit)
	truncated := false
	encodedSize := len("[]\n")
	if limit > 0 && maxEncodedBytes < encodedSize {
		return results, total, true, nil
	}
	for _, result := range history[offset : offset+limit] {
		legacyResult := tasks.LegacyResult{
			Command:   result.Command,
			Output:    result.Output,
			Timestamp: result.Timestamp,
		}
		encoded, err := json.Marshal(legacyResult)
		if err != nil {
			return nil, 0, false, fmt.Errorf("measure legacy result: %w", err)
		}
		separatorSize := 0
		if len(results) > 0 {
			separatorSize = 1
		}
		used := encodedSize + separatorSize
		if used > maxEncodedBytes || len(encoded) > maxEncodedBytes-used {
			truncated = true
			break
		}
		results = append(results, legacyResult)
		encodedSize = used + len(encoded)
	}
	return results, total, truncated, nil
}

// GetResultsPage retains the legacy no-error interface for compatibility.
// Operator APIs use ListLegacyResultsPage directly so storage failures become
// 5xx responses instead of plausible empty history.
func (p *HTTPPollingProtocol) GetResultsPage(
	agentID string,
	offset int,
	limit int,
) ([]map[string]interface{}, int) {
	page, total, _, err := p.ListLegacyResultsPage(
		agentID,
		offset,
		limit,
		tasks.MaxLegacyResultPageBytes,
	)
	if err != nil {
		log.Printf("[ERROR] Failed to load legacy results: %v", err)
		return []map[string]interface{}{}, 0
	}
	results := make([]map[string]interface{}, 0, len(page))
	for _, result := range page {
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
