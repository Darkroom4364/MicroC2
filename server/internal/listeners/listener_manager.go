package listeners

import (
	"encoding/json"
	"fmt"
	"log"
	"microc2/server/internal/common"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ListenerManager handles the creation, management, and tracking of protocol listeners.
// It maintains a thread-safe registry of all active and stopped listeners.
type ListenerManager struct {
	listeners map[string]*Listener
	protocol  common.Protocol
	mu        sync.RWMutex
}

// NewListenerManager creates a new listener manager instance
func NewListenerManager(proto common.Protocol) *ListenerManager {
	manager := &ListenerManager{
		listeners: make(map[string]*Listener),
		protocol:  proto,
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

		listener, err := NewListener(config)
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
func (m *ListenerManager) GetProtocol() common.Protocol {
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
	if config.BindHost == "" {
		config.BindHost = "0.0.0.0"
	}
	config.Protocol = strings.ToLower(config.Protocol)
	if err := m.validateListenerConfig(config); err != nil {
		return nil, err
	}
	if m.hasNameConflict(config) {
		return nil, fmt.Errorf("listener name %q is already registered", config.Name)
	}
	if m.hasPortConflict(config) {
		return nil, fmt.Errorf("port %d is already used by an active listener", config.Port)
	}

	listener, err := NewListener(config)
	if err != nil {
		return nil, err
	}
	if err := listener.Start(); err != nil {
		listenerDir := filepath.Join("static", "listeners", config.Name)
		if cleanupErr := os.RemoveAll(listenerDir); cleanupErr != nil {
			log.Printf("[WARNING] Failed to cleanup listener directory %s after start failure: %v", listenerDir, cleanupErr)
		}
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
	if listener.GetStatus() == StatusActive || listener.GetStatus() == StatusError {
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
	defer m.mu.Unlock()

	listener, exists := m.listeners[id]

	if !exists {
		return fmt.Errorf("listener not found: %s", id)
	}

	if listener.GetStatus() == StatusStopped {
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
	defer m.mu.Unlock()

	listener, exists := m.listeners[id]

	if !exists {
		return fmt.Errorf("listener not found: %s", id)
	}

	status := listener.GetStatus()
	if status == StatusActive {
		return nil // Already running
	}
	if status == StatusError {
		if err := listener.Stop(); err != nil {
			return fmt.Errorf("failed to cleanup errored listener before restart: %w", err)
		}
	}

	conflict := m.hasPortConflict(listener.Config)
	if conflict {
		return fmt.Errorf("port %d is already used by an active listener", listener.Config.Port)
	}

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
	if listener.GetStatus() == StatusActive || listener.GetStatus() == StatusError {
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
		if listener.GetStatus() == StatusActive || listener.GetStatus() == StatusError {
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
		if listener.GetStatus() == StatusActive || listener.GetStatus() == StatusError {
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
	protocol := strings.ToLower(config.Protocol)
	switch protocol {
	case "http", "https":
	case "dns", "dnsoverhttps":
		return fmt.Errorf("DNSoverHTTPS protocol is not implemented yet")
	default:
		return fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}

	if config.Port < 1 || config.Port > 65535 {
		log.Printf("[ERROR] Listener validation failed: invalid port number %d", config.Port)
		return fmt.Errorf("invalid port number: %d", config.Port)
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
		status := l.GetStatus()
		if l.Config.Port == config.Port && (status == StatusActive || status == StatusError) && id != config.ID {
			log.Printf("[WARN] Port conflict detected: Port %d is already used by active listener %s (%s)", config.Port, l.Config.Name, id)
			return true
		}
	}
	return false
}

func (m *ListenerManager) hasNameConflict(config ListenerConfig) bool {
	for id, l := range m.listeners {
		if l.Config.Name == config.Name && id != config.ID {
			log.Printf("[WARN] Name conflict detected: listener %q is already registered as %s", config.Name, id)
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
		listener.mu.RLock()
		status := listener.Status
		stopTime := listener.StopTime
		listener.mu.RUnlock()
		if status == StatusStopped && !stopTime.IsZero() {
			if now.Sub(stopTime) > threshold {
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

	config.Protocol = strings.ToLower(config.Protocol)
	listener, err := NewListener(config)
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
