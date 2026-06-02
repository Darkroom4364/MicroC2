package api

import (
	"encoding/json"
	"log" // Updated from `networking`

	// Updated from `networking`

	"microc2/server/pkg/communication"
	"net/http"
	"strings"
)

func NewAPIHandler(manager *communication.ServerManager) *APIHandler {
	return &APIHandler{
		serverManager: manager,
	}
}

func (h *APIHandler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	// log.Printf("[DEBUG] HandleRequest called: %s %s", r.Method, r.URL.Path)
	if r.URL.Path == "/api/agents/list" {
		h.handleListAgents(w, r)
		return
	}

	if r.Method == http.MethodPost && r.URL.Path == "/api/agents/command" {
		h.handleQueueAgentCommandFromBody(w, r)
		return
	}

	// Handle POST /api/agents/{AgentID}/command
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/agents/") && strings.HasSuffix(r.URL.Path, "/command") {
		trimmed := strings.TrimPrefix(r.URL.Path, "/api/agents/")
		AgentID := strings.TrimSuffix(trimmed, "/command")
		AgentID = strings.TrimSuffix(AgentID, "/") // Remove trailing slash if present
		h.handleQueueAgentCommand(w, r, AgentID)
		return
	}

	// Add GET /api/agents/{AgentID}/results endpoint
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/agents/") && strings.HasSuffix(r.URL.Path, "/results") {
		trimmed := strings.TrimPrefix(r.URL.Path, "/api/agents/")
		AgentID := strings.TrimSuffix(trimmed, "/results")
		AgentID = strings.TrimSuffix(AgentID, "/")
		h.handleGetAgentResults(w, AgentID)
		return
	}

	// Default handler for API requests
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"unknown operator API route"}`))
}

func (h *APIHandler) handleListAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Aggregate agents from all listeners
	agents := h.serverManager.GetListenerManager().AllAgents()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agents)
}

type queueCommandRequest struct {
	AgentID string `json:"agent_id,omitempty"`
	Command string `json:"command"`
}

func (h *APIHandler) handleQueueAgentCommandFromBody(w http.ResponseWriter, r *http.Request) {
	var req queueCommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" || req.Command == "" {
		log.Printf("[DEBUG] Invalid command request")
		http.Error(w, "Invalid command request", http.StatusBadRequest)
		return
	}

	h.queueAgentCommandResponse(w, req.AgentID, req.Command)
}

// handleQueueAgentCommand handles POST /api/agents/{AgentID}/command
func (h *APIHandler) handleQueueAgentCommand(w http.ResponseWriter, r *http.Request, AgentID string) {
	// log.Printf("[DEBUG] handleQueueAgentCommand entered for AgentID=%s", AgentID)
	var req queueCommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Command == "" {
		log.Printf("[DEBUG] Invalid path-based command request")
		http.Error(w, "Invalid command", http.StatusBadRequest)
		return
	}
	// log.Printf("[DEBUG] handleQueueAgentCommand: AgentID=%s, command=%s", AgentID, req.Command)

	h.queueAgentCommandResponse(w, AgentID, req.Command)
}

func (h *APIHandler) queueAgentCommandResponse(w http.ResponseWriter, AgentID, command string) {
	// Find the listener/protocol for this agent
	listenerMgr := h.serverManager.GetListenerManager()
	var queued bool
	for _, listener := range listenerMgr.ListListeners() {
		if listener.Protocol != nil {
			if agenter, ok := listener.Protocol.(interface{ GetAllAgents() map[string]interface{} }); ok {
				agents := agenter.GetAllAgents()
				// log.Printf("[DEBUG] Listener %s has agents: %v", listener.Config.ID, reflect.ValueOf(agents).MapKeys())
				if _, exists := agents[AgentID]; exists {
					if commander, ok := listener.Protocol.(interface {
						QueueCommand(AgentID, cmd string)
					}); ok {
						commander.QueueCommand(AgentID, command)
						queued = true
						break
					}
				}
			}
		}
	}

	// log.Printf("[DEBUG] Command queued for agent %s: %s (queued=%v)", AgentID, command, queued)

	if queued {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"queued"}`))
	} else {
		http.Error(w, "Failed to queue command for agent", http.StatusInternalServerError)
	}
}

// Add handler for agent results
func (h *APIHandler) handleGetAgentResults(w http.ResponseWriter, AgentID string) {
	// log.Printf("[DEBUG] handleGetAgentResults called for AgentID=%s", AgentID)
	listenerMgr := h.serverManager.GetListenerManager()
	for _, listener := range listenerMgr.ListListeners() {
		if listener.Protocol != nil {
			if agenter, ok := listener.Protocol.(interface{ GetAllAgents() map[string]interface{} }); ok {
				agents := agenter.GetAllAgents()
				// log.Printf("[DEBUG] Available agent IDs: %v", reflect.ValueOf(agents).MapKeys())
				if _, exists := agents[AgentID]; exists {
					if resultGetter, ok := listener.Protocol.(interface {
						GetResults(AgentID string) []map[string]interface{}
					}); ok {
						// Add debug: print keys in results.history
						// if hp, ok := listener.Protocol.(*behaviour.HTTPPollingProtocol); ok {
						// keys := hp.GetResultsHistoryKeys()
						// log.Printf("[DEBUG] Results history keys: %v", keys)
						// }
						results := resultGetter.GetResults(AgentID)
						// log.Printf("[DEBUG] Results for AgentID=%s: %+v", AgentID, results)
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(results)
						return
					}
				}
			}
		}
	}
	http.Error(w, "Agent or results not found", http.StatusNotFound)
}
