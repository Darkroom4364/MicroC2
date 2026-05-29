package api

import (
	"encoding/json"
	"microc2/server/internal/listeners" // Updated from `networking`
	"net/http"
	"strings"
)

// NewListenerHandlers creates a new listener handlers instance
func NewListenerHandlers(manager *listeners.ListenerManager) *ListenerHandlers {
	return &ListenerHandlers{
		manager: manager,
	}
}

// HandleCreateListener handles requests to create a new listener
func (h *ListenerHandlers) HandleCreateListener(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var config listeners.ListenerConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Trim whitespace from bind host to avoid invalid addresses
	config.BindHost = strings.TrimSpace(config.BindHost)

	listener, err := h.manager.CreateListener(config)
	if err != nil {
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

	if err := h.manager.StopListener(id); err != nil {
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
	if err := h.manager.DeleteListener(id); err != nil {
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
	if err := h.manager.StartListener(id); err != nil {
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

// SetupRoutes registers all listener-related routes
func (h *ListenerHandlers) SetupRoutes() {
	http.HandleFunc("/api/listeners/create", h.HandleCreateListener)
	http.HandleFunc("/api/listeners/list", h.HandleListListeners)
	http.HandleFunc("/api/listeners/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/listeners/")
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
