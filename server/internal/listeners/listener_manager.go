// This file will be moved to the new 'listeners' folder as 'listener_management.go'.
package listeners

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	behaviour "microc2/server/internal/behaviour"
	"microc2/server/internal/common"

	"github.com/google/uuid"
)

// Define missing types
// BaseProtocolConfig is a placeholder for the actual implementation
// Removed local definition of BaseProtocolConfig

// Define missing Protocol interface
// Protocol defines the interface that all communication protocols must implement
type Protocol interface {
	Initialize() error
	HandleCommand(cmd string) error
	HandleFileUpload(filename string, fileData io.Reader) error
	HandleFileDownload(filename string) (io.Reader, error)
	HandleAgentHeartbeat(agentData []byte) error
	GetRoutes() map[string]http.HandlerFunc
	GetHTTPHandler() http.Handler
}

// ListenerManager handles the creation, management, and tracking of protocol listeners.
// It maintains a thread-safe registry of all active and stopped listeners.
type ListenerManager struct {
	listeners map[string]*Listener
	protocol  Protocol // Add field to hold the main protocol instance
	mu        sync.RWMutex
}

// NewListenerManager creates a new listener manager instance
func NewListenerManager(proto Protocol) *ListenerManager { // Accept protocol instance
	manager := &ListenerManager{
		listeners: make(map[string]*Listener),
		protocol:  proto, // Store the protocol instance
	}

	// Load saved listener configurations
	listenersDir := filepath.Join("static", "listeners")
	entries, err := os.ReadDir(listenersDir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[WARNING] Failed to read listeners directory: %v", err)
		}
		return manager
	}

	// Pass the manager itself to NewListener when loading saved configs
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check for config file
		configPath := filepath.Join(listenersDir, entry.Name(), "config.json")
		configData, err := os.ReadFile(configPath)
		if err != nil {
			log.Printf("[WARNING] Failed to read config for listener %s: %v", entry.Name(), err)
			continue
		}

		var config ListenerConfig
		if err := json.Unmarshal(configData, &config); err != nil {
			log.Printf("[WARNING] Failed to parse config for listener %s: %v", entry.Name(), err)
			continue
		}

		// Create a new listener instance with STOPPED status, passing the manager
		listener, err := NewListener(config) // Updated function signature
		if err != nil {
			log.Printf("[WARNING] Failed to create listener instance for %s: %v", config.Name, err)
			continue
		}

		// Add to manager without starting
		manager.listeners[config.ID] = listener
		log.Printf("[INFO] Loaded saved configuration for listener: %s (ID: %s)", config.Name, config.ID)
	}

	return manager
}

// GetProtocol returns the protocol instance associated with the manager
func (m *ListenerManager) GetProtocol() Protocol {
	return m.protocol
}

// CreateListener creates and starts a new listener with the given configuration
//
// Pre-conditions:
//   - config is a valid ListenerConfig instance
//
// Post-conditions:
//   - A new listener is created, started, and added to the manager
//   - Returns error if the configuration is invalid or the port is already in use
func (m *ListenerManager) CreateListener(config ListenerConfig) (*Listener, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	config.ID = uuid.New().String()
	if err := m.validateListenerConfig(config); err != nil {
		return nil, err
	}

	// HTTP polling uses a dedicated HTTP server
	if config.Protocol == "http" {
		// Prepare listener directory and save config.json
		listenerDir := filepath.Join("static", "listeners", config.Name)
		if err := os.MkdirAll(listenerDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create listener directory: %w", err)
		}
		cfgPath := filepath.Join(listenerDir, "config.json")
		cfgBytes, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal listener config: %w", err)
		}
		if err := os.WriteFile(cfgPath, cfgBytes, 0644); err != nil {
			return nil, fmt.Errorf("failed to save listener config: %w", err)
		}
		// Setup upload directory inside listener
		uploadDir := filepath.Join(listenerDir, "uploads")
		protoConfig := common.BaseProtocolConfig{UploadDir: uploadDir, Port: fmt.Sprintf("%d", config.Port)}
		httpProto := behaviour.NewHTTPPollingProtocol(protoConfig)
		// Use config.BindHost if provided, otherwise default to 0.0.0.0
		bindHost := config.BindHost
		if bindHost == "" {
			bindHost = "0.0.0.0"
		}
		bindAddr := fmt.Sprintf("%s:%d", bindHost, config.Port)
		handler := httpProto.GetHTTPHandler()
		if handler == nil {
			log.Fatalf("[FATAL] HTTPPollingProtocol.GetHTTPHandler() returned nil for listener %s on %s", config.Name, bindAddr)
			panic("HTTPPollingProtocol.GetHTTPHandler() returned nil")
		}
		log.Printf("[INFO] Starting HTTP server for listener %s on %s with handler type: %T", config.Name, bindAddr, handler)
		go func() {
			if config.TLSConfig != nil {
				log.Printf("[INFO] Starting HTTPS polling listener %s on %s", config.Name, bindAddr)
				http.ListenAndServeTLS(bindAddr, config.TLSConfig.CertFile, config.TLSConfig.KeyFile, handler)
			} else {
				log.Printf("[INFO] Starting HTTP polling listener %s on %s", config.Name, bindAddr)
				http.ListenAndServe(bindAddr, handler)
			}
		}()
		l := &Listener{Config: config, Status: StatusActive, StartTime: time.Now(), Protocol: httpProto}
		m.listeners[config.ID] = l
		return l, nil
	}

	// Fallback: use raw TCP listener for other protocols
	listener, err := NewListener(config)
	if err != nil {
		return nil, err
	}
	if err := listener.Start(); err != nil {
		return nil, err
	}
	m.listeners[config.ID] = listener
	return listener, nil
}

// AddListener adds a new listener to the manager
//
// Pre-conditions:
//   - listener is a properly initialized Listener instance
//   - listener has a unique ID not already in use
//
// Post-conditions:
//   - Listener is added to the manager's registry
//   - Returns error if a listener with the same ID already exists
func (m *ListenerManager) AddListener(listener *Listener) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[listener.Config.ID]; exists {
		return fmt.Errorf("listener with ID %s already exists", listener.Config.ID)
	}

	m.listeners[listener.Config.ID] = listener
	return nil
}

// GetListener retrieves a listener by its ID
//
// Pre-conditions:
//   - id is a valid listener identifier string
//
// Post-conditions:
//   - Returns the requested listener if found
//   - Returns error if the listener doesn't exist
func (m *ListenerManager) GetListener(id string) (*Listener, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	listener, exists := m.listeners[id]
	if !exists {
		return nil, fmt.Errorf("listener %s not found", id)
	}
	return listener, nil
}

// ListListeners returns a list of all registered listeners
//
// Pre-conditions:
//   - None
//
// Post-conditions:
//   - Returns a slice containing all listeners in the manager
//   - Safe for concurrent access
func (m *ListenerManager) ListListeners() []*Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := make([]*Listener, 0, len(m.listeners))
	for _, listener := range m.listeners {
		list = append(list, listener)
	}
	return list
}

// RemoveListener removes a listener from the manager
//
// Pre-conditions:
//   - id is a valid listener identifier string
//   - Listener with the given ID exists
//
// Post-conditions:
//   - Listener is removed from the registry
//   - Listener is stopped if it was running
//   - Returns error if the listener doesn't exist
func (m *ListenerManager) RemoveListener(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	listener, exists := m.listeners[id]
	if !exists {
		return fmt.Errorf("listener %s not found", id)
	}

	// Stop the listener if it's running
	if listener.Status == StatusActive {
		if err := listener.Stop(); err != nil {
			log.Printf("[WARNING] Failed to stop listener %s: %v", id, err)
		}
	}

	delete(m.listeners, id)
	return nil
}

// StopListener stops a running listener
//
// Pre-conditions:
//   - id is a valid listener identifier string
//   - Listener with the given ID exists
//
// Post-conditions:
//   - Listener is stopped if it was running
//   - Listener remains in the registry but with stopped status
//   - Returns error if the listener doesn't exist or can't be stopped
func (m *ListenerManager) StopListener(id string) error {
	m.mu.Lock()
	listener, exists := m.listeners[id]
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("listener not found: %s", id)
	}

	if listener.Status == StatusStopped {
		return nil // Already stopped
	}

	if err := listener.Stop(); err != nil {
		return fmt.Errorf("failed to stop listener: %w", err)
	}

	return nil
}

// StartListener starts a previously stopped listener
//
// Pre-conditions:
//   - id is a valid listener identifier string
//   - Listener with the given ID exists and is in stopped state
//
// Post-conditions:
//   - Listener is started and its status updated to active
//   - Returns error if the listener doesn't exist or can't be started
func (m *ListenerManager) StartListener(id string) error {
	m.mu.Lock()
	listener, exists := m.listeners[id]
	m.mu.Unlock()

	if !exists {
		return fmt.Errorf("listener not found: %s", id)
	}

	if listener.Status == StatusActive {
		return nil // Already running
	}

	// Create a new stop channel since the old one was closed
	listener.stopChan = make(chan struct{})

	// Start the listener
	if err := listener.Start(); err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	return nil
}

// DeleteListener stops (if running) and removes a listener from the manager
//
// Pre-conditions:
//   - id is a valid listener identifier string
//   - Listener with the given ID exists
//
// Post-conditions:
//   - Listener is removed from the registry
//   - Listener is stopped if it was running
//   - Returns error if the listener doesn't exist
func (m *ListenerManager) DeleteListener(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	listener, exists := m.listeners[id]
	if !exists {
		return fmt.Errorf("listener %s not found", id)
	}

	// If listener is active, stop it first
	if listener.Status == StatusActive {
		if err := listener.Stop(); err != nil {
			return fmt.Errorf("failed to stop listener before deletion: %v", err)
		}
	}

	// Clean up listener directory
	listenerDir := filepath.Join("static", "listeners", listener.Config.Name)
	if err := os.RemoveAll(listenerDir); err != nil {
		log.Printf("[WARNING] Failed to cleanup listener directory %s: %v", listenerDir, err)
	}

	// Remove from listeners map
	delete(m.listeners, id)
	log.Printf("[INFO] Deleted listener %s and cleaned up directory %s", id, listenerDir)
	return nil
}

// StopAll stops all active listeners but keeps them in the manager
//
// Pre-conditions:
//   - None
//
// Post-conditions:
//   - All active listeners are stopped
//   - Returns a list of errors for listeners that couldn't be stopped
func (m *ListenerManager) StopAll() []error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errors []error
	for id, listener := range m.listeners {
		if listener.Status == StatusActive {
			if err := listener.Stop(); err != nil {
				errors = append(errors, fmt.Errorf("failed to stop listener %s: %v", id, err))
			}
		}
	}
	return errors
}

// DeleteAll stops and removes all listeners
//
// Pre-conditions:
//   - None
//
// Post-conditions:
//   - All listeners are removed from the registry
//   - Active listeners are stopped before removal
//   - Returns a list of errors for listeners that couldn't be stopped
func (m *ListenerManager) DeleteAll() []error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errors []error
	for id, listener := range m.listeners {
		if listener.Status == StatusActive {
			if err := listener.Stop(); err != nil {
				errors = append(errors, fmt.Errorf("failed to stop listener %s: %v", id, err))
				continue // Skip deletion if stopping fails
			}
		}
		delete(m.listeners, id)
	}
	return errors
}

// validateListenerConfig checks if the listener configuration is valid
//
// Pre-conditions:
//   - config is a ListenerConfig instance
//
// Post-conditions:
//   - Returns error if the configuration is invalid
func (m *ListenerManager) validateListenerConfig(config ListenerConfig) error {
	if config.Name == "" {
		log.Printf("[ERROR] Listener validation failed: name is required")
		return fmt.Errorf("listener name is required")
	}

	if config.Protocol == "" {
		log.Printf("[ERROR] Listener validation failed: protocol is required")
		return fmt.Errorf("protocol is required")
	}

	if config.Port < 1 || config.Port > 65535 {
		log.Printf("[ERROR] Listener validation failed: invalid port number %d", config.Port)
		return fmt.Errorf("invalid port number: %d", config.Port)
	}

	if config.BindHost == "" {
		log.Printf("[INFO] BindHost not provided, defaulting to 0.0.0.0")
		config.BindHost = "0.0.0.0" // Set default bind address
	}

	// Validate TLS configuration if provided
	if config.TLSConfig != nil {
		if config.TLSConfig.CertFile == "" || config.TLSConfig.KeyFile == "" {
			log.Printf("[ERROR] Listener validation failed: both certificate and key files are required for TLS")
			return fmt.Errorf("both certificate and key files are required for TLS")
		}
	}

	log.Printf("[INFO] Listener configuration validated successfully: %+v", config)
	return nil
}

// hasPortConflict checks if the given port is already in use by another *active* listener
//
// Pre-conditions:
//   - config is a ListenerConfig instance
//
// Post-conditions:
//   - Returns true if the port is in use by an active listener, false otherwise
func (m *ListenerManager) hasPortConflict(config ListenerConfig) bool {
	for id, l := range m.listeners {
		// Check against other listeners (not itself if config.ID is provided and matches)
		if l.Config.Port == config.Port && l.Status == StatusActive && id != config.ID {
			log.Printf("[WARN] Port conflict detected: Port %d is already used by active listener %s (%s)", config.Port, l.Config.Name, id)
			return true
		}
	}
	return false
}

// CleanupInactive removes listeners that have been stopped for longer than the specified duration
//
// Pre-conditions:
//   - threshold is a valid time.Duration instance
//
// Post-conditions:
//   - Removes listeners that have been stopped for longer than the threshold
func (m *ListenerManager) CleanupInactive(threshold time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for id, listener := range m.listeners {
		if listener.Status == StatusStopped && !listener.StopTime.IsZero() {
			if now.Sub(listener.StopTime) > threshold {
				delete(m.listeners, id)
			}
		}
	}
}

// LoadSavedListener loads a saved listener configuration from disk
func (m *ListenerManager) LoadSavedListener(configPath string) (*Listener, error) {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config ListenerConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	listener, err := NewListener(config) // Updated function signature
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %v", err)
	}

	return listener, nil
}

// AllAgents returns a combined map of all agents from all listeners
func (m *ListenerManager) AllAgents() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	allAgents := make(map[string]interface{})
	for _, listener := range m.listeners {
		if listener.Protocol != nil {
			if agenter, ok := listener.Protocol.(interface{ GetAllAgents() map[string]interface{} }); ok {
				for id, agent := range agenter.GetAllAgents() {
					allAgents[id] = agent
				}
			}
		}
	}
	return allAgents
}
