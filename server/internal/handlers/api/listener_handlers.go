package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"microc2/server/internal/enrollment"
	"microc2/server/internal/listeners" // Updated from `networking`
	"microc2/server/internal/tasks"
	"net/http"
	"strings"
)

const maxListenerCreateRequestBytes = 64 << 10

// NewListenerHandlers creates a new listener handlers instance
func NewListenerHandlers(manager *listeners.ListenerManager) *ListenerHandlers {
	handler := &ListenerHandlers{manager: manager}
	if manager != nil && manager.Database() != nil {
		handler.enrollment, handler.enrollmentErr = enrollment.NewStore(
			context.Background(),
			manager.Database(),
		)
	}
	return handler
}

// HandleCreateListener handles requests to create a new listener
func (h *ListenerHandlers) HandleCreateListener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var config listeners.ListenerConfig
	if err := decodeStrictJSON(
		w,
		r,
		&config,
		maxListenerCreateRequestBytes,
	); err != nil {
		writeJSONDecodeError(w, "Invalid request body", err)
		return
	}

	listener, err := h.manager.CreateListenerWithContext(r.Context(), config)
	if err != nil {
		if listeners.IsListenerConfigValidationError(err) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"status": "success",
		"listener": map[string]interface{}{
			"id":       listener.Config.ID,
			"name":     listener.Config.Name,
			"protocol": listener.Config.Protocol,
			"host":     listener.Config.BindHost,
			"port":     listener.Config.Port,
			"status":   listener.Status,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleListListeners handles requests to list all listeners
func (h *ListenerHandlers) HandleListListeners(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	listeners := h.manager.ListListeners()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(listeners)
}

// HandleGetListener handles requests to get a specific listener
func (h *ListenerHandlers) HandleGetListener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/listeners/")
	listener, err := h.manager.GetListener(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(listener)
}

// HandleListListenerEvents returns the durable, append-only lifecycle history
// for a listener. History remains queryable after the runtime listener is
// deleted.
func (h *ListenerHandlers) HandleListListenerEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/listeners/")
	id = strings.TrimSuffix(id, "/events")
	if id == "" || strings.Contains(id, "/") {
		sendJSONError(w, "Listener ID is required", http.StatusBadRequest)
		return
	}
	events, err := h.manager.ListListenerEvents(id)
	if err != nil {
		sendJSONError(w, "Failed to load listener events", http.StatusInternalServerError)
		return
	}
	sendJSONResponse(w, events)
}

// HandleStopListener handles requests to stop a listener
func (h *ListenerHandlers) HandleStopListener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/listeners/")
	id = strings.TrimSuffix(id, "/stop")

	if id == "" {
		sendJSONError(w, "Listener ID is required", http.StatusBadRequest)
		return
	}

	if err := h.manager.StopListenerWithContext(r.Context(), id); err != nil {
		sendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONResponse(w, map[string]string{"status": "success"})
}

// HandleDeleteListener handles requests to delete a listener
func (h *ListenerHandlers) HandleDeleteListener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/listeners/")

	if id == "" {
		sendJSONError(w, "Listener ID is required", http.StatusBadRequest)
		return
	}

	// Now using DeleteListener which completely removes the listener
	if err := h.manager.DeleteListenerWithContext(r.Context(), id); err != nil {
		sendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONResponse(w, map[string]string{"status": "success", "message": "Listener deleted successfully"})
}

// HandleStartListener handles requests to start a stopped listener
func (h *ListenerHandlers) HandleStartListener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/listeners/")
	id = strings.TrimSuffix(id, "/start")

	if id == "" {
		sendJSONError(w, "Listener ID is required", http.StatusBadRequest)
		return
	}

	// Get the listener to verify it exists and is in a stopped state
	listener, err := h.manager.GetListener(id)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusNotFound)
		return
	}

	// Check if it's already running
	if listener.GetStatus() == listeners.StatusActive {
		sendJSONResponse(w, map[string]string{"status": "success", "message": "Listener is already active"})
		return
	}

	// Start the listener
	if err := h.manager.StartListenerWithContext(r.Context(), id); err != nil {
		sendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sendJSONResponse(w, map[string]string{"status": "success", "message": "Listener started successfully"})
}

// Helper functions for consistent JSON responses
func sendJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func sendJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func parseListenerAgentSessionRoute(
	path string,
) (matched, valid bool, listenerID, agentID, action string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 4 ||
		parts[0] != "api" ||
		parts[1] != "listeners" ||
		parts[3] != "agents" {
		return false, false, "", "", ""
	}
	if len(parts) != 7 ||
		parts[5] != "session" ||
		(parts[6] != "rotate" &&
			parts[6] != "revoke" &&
			parts[6] != "re-enroll") ||
		tasks.ValidateIdentifier("listener_id", parts[2]) != nil ||
		tasks.ValidateIdentifier("agent_id", parts[4]) != nil {
		return true, false, "", "", ""
	}
	return true, true, parts[2], parts[4], parts[6]
}

func (h *ListenerHandlers) handleAgentSessionManagement(
	w http.ResponseWriter,
	r *http.Request,
	listenerID string,
	agentID string,
	action string,
) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "Query parameters are not supported", http.StatusBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 2))
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if len(body) != 0 {
		http.Error(w, "Request body must be empty", http.StatusBadRequest)
		return
	}
	if h.enrollmentErr != nil {
		log.Printf("[ERROR] Agent enrollment management unavailable: %v", h.enrollmentErr)
		http.Error(w, "Agent enrollment management unavailable", http.StatusServiceUnavailable)
		return
	}
	if h.enrollment == nil {
		http.Error(w, "Agent enrollment management unavailable", http.StatusServiceUnavailable)
		return
	}

	response := map[string]interface{}{
		"listener_id": listenerID,
		"agent_id":    agentID,
	}
	switch action {
	case "rotate":
		rotation, err := h.enrollment.Rotate(
			r.Context(),
			listenerID,
			agentID,
		)
		if err != nil {
			writeEnrollmentManagementError(w, err)
			return
		}
		response["status"] = "rotation_pending"
		response["pending_generation"] = rotation.PendingGeneration
		response["already_pending"] = rotation.AlreadyPending
	case "revoke":
		if err := h.enrollment.RevokeSession(
			r.Context(),
			listenerID,
			agentID,
		); err != nil {
			writeEnrollmentManagementError(w, err)
			return
		}
		response["status"] = "revoked"
	case "re-enroll":
		if err := h.enrollment.RequireReenrollment(
			r.Context(),
			listenerID,
			agentID,
		); err != nil {
			writeEnrollmentManagementError(w, err)
			return
		}
		response["status"] = "reenrollment_required"
	default:
		http.Error(w, "Unknown session action", http.StatusNotFound)
		return
	}
	sendJSONResponse(w, response)
}

func writeEnrollmentManagementError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, enrollment.ErrNotFound):
		http.Error(w, "Agent enrollment session not found", http.StatusNotFound)
	case errors.Is(err, enrollment.ErrConflict),
		errors.Is(err, enrollment.ErrGenerationExhausted),
		errors.Is(err, enrollment.ErrEnrollmentCapacity):
		http.Error(w, "Agent enrollment state conflict", http.StatusConflict)
	case errors.Is(err, enrollment.ErrInvalidArgument):
		http.Error(w, "Invalid agent enrollment request", http.StatusBadRequest)
	default:
		log.Printf("[ERROR] Agent enrollment management failed: %v", err)
		http.Error(w, "Agent enrollment management failed", http.StatusInternalServerError)
	}
}

// RegisterRoutes registers all listener-related routes on the provided mux.
func (h *ListenerHandlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/listeners/create", h.HandleCreateListener)
	mux.HandleFunc("/api/listeners/list", h.HandleListListeners)
	mux.HandleFunc("/api/listeners/", func(w http.ResponseWriter, r *http.Request) {
		if matched, valid, listenerID, agentID, action :=
			parseListenerAgentSessionRoute(r.URL.Path); matched {
			if !valid {
				http.Error(
					w,
					"Invalid agent session management path",
					http.StatusBadRequest,
				)
				return
			}
			h.handleAgentSessionManagement(
				w,
				r,
				listenerID,
				agentID,
				action,
			)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/listeners/")
		if strings.HasSuffix(path, "/events") {
			h.HandleListListenerEvents(w, r)
			return
		}
		if strings.HasSuffix(path, "/stop") {
			h.HandleStopListener(w, r)
			return
		}
		if strings.HasSuffix(path, "/start") {
			h.HandleStartListener(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			h.HandleGetListener(w, r)
		case http.MethodDelete:
			h.HandleDeleteListener(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

// SetupRoutes registers listener routes on the default mux for legacy callers.
func (h *ListenerHandlers) SetupRoutes() {
	h.RegisterRoutes(http.DefaultServeMux)
}
