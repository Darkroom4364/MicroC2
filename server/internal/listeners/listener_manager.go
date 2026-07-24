package listeners

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"microc2/server/internal/behaviour"
	"microc2/server/internal/common"
	"microc2/server/internal/persistence"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const scopedAgentKeyDelimiter = "/"

// ListenerManager handles the creation, management, and tracking of protocol listeners.
// It maintains a thread-safe registry of all active and stopped listeners.
type ListenerManager struct {
	listeners        map[string]*Listener
	protocol         common.Protocol
	listenersDir     string
	database         *persistence.Database
	transportPolicy  common.AgentTransportPolicy
	requireAgentAuth bool
	now              func() time.Time
	mu               sync.RWMutex
}

// Database returns the immutable process-wide persistence handle used by this
// manager. Callers must not change its connection-pool or durability settings.
func (m *ListenerManager) Database() *persistence.Database {
	if m == nil {
		return nil
	}
	return m.database
}

// NewListenerManager creates a non-durable manager with the production-safe
// transport policy. Focused tests that require plaintext HTTP must explicitly
// call NewListenerManagerForIsolatedLab.
func NewListenerManager(proto common.Protocol) *ListenerManager {
	manager, err := newListenerManager(
		proto,
		filepath.Join("static", "listeners"),
		nil,
		common.AgentTransportPolicy{},
		true,
		time.Now,
	)
	if err != nil {
		log.Printf("[WARNING] Failed to load listener configurations: %v", err)
		return &ListenerManager{
			listeners:        make(map[string]*Listener),
			protocol:         proto,
			listenersDir:     filepath.Join("static", "listeners"),
			transportPolicy:  common.AgentTransportPolicy{},
			requireAgentAuth: true,
			now:              time.Now,
		}
	}
	return manager
}

// NewListenerManagerForIsolatedLab creates a non-durable manager whose policy
// explicitly permits plaintext HTTP agent listeners.
func NewListenerManagerForIsolatedLab(proto common.Protocol) *ListenerManager {
	manager, err := newListenerManager(
		proto,
		filepath.Join("static", "listeners"),
		nil,
		common.IsolatedLabAgentTransportPolicy(),
		false,
		time.Now,
	)
	if err != nil {
		log.Printf("[WARNING] Failed to load listener configurations: %v", err)
		return &ListenerManager{
			listeners:        make(map[string]*Listener),
			protocol:         proto,
			listenersDir:     filepath.Join("static", "listeners"),
			transportPolicy:  common.IsolatedLabAgentTransportPolicy(),
			requireAgentAuth: false,
			now:              time.Now,
		}
	}
	return manager
}

// NewListenerManagerWithPersistence constructs a durable manager with the
// production-safe transport policy. Focused tests that require plaintext HTTP
// must explicitly call NewListenerManagerWithPersistenceForIsolatedLab.
func NewListenerManagerWithPersistence(
	proto common.Protocol,
	listenersDir string,
	database *persistence.Database,
) (*ListenerManager, error) {
	return newListenerManager(
		proto,
		listenersDir,
		database,
		common.AgentTransportPolicy{},
		true,
		time.Now,
	)
}

// NewListenerManagerWithPersistenceForIsolatedLab constructs a durable
// manager whose policy explicitly permits plaintext HTTP agent listeners.
func NewListenerManagerWithPersistenceForIsolatedLab(
	proto common.Protocol,
	listenersDir string,
	database *persistence.Database,
) (*ListenerManager, error) {
	return newListenerManager(
		proto,
		listenersDir,
		database,
		common.IsolatedLabAgentTransportPolicy(),
		false,
		time.Now,
	)
}

// NewProductionListenerManager constructs a listener manager with an explicit
// production transport policy. Its zero-value policy rejects plaintext HTTP.
func NewProductionListenerManager(
	proto common.Protocol,
	listenersDir string,
	database *persistence.Database,
	transportPolicy common.AgentTransportPolicy,
) (*ListenerManager, error) {
	return newListenerManager(
		proto,
		listenersDir,
		database,
		transportPolicy,
		true,
		time.Now,
	)
}

func newListenerManager(
	proto common.Protocol,
	listenersDir string,
	database *persistence.Database,
	transportPolicy common.AgentTransportPolicy,
	requireAgentAuth bool,
	now func() time.Time,
) (*ListenerManager, error) {
	if listenersDir == "" {
		listenersDir = filepath.Join("static", "listeners")
	}
	if now == nil {
		now = time.Now
	}
	manager := &ListenerManager{
		listeners:        make(map[string]*Listener),
		protocol:         proto,
		listenersDir:     listenersDir,
		database:         database,
		transportPolicy:  transportPolicy,
		requireAgentAuth: requireAgentAuth,
		now:              now,
	}

	if err := ensurePrivateDirectory(listenersDir); err != nil {
		return nil, fmt.Errorf("prepare listeners directory: %w", err)
	}

	durableConfigs, tombstonedIDs, tombstonedNames, err :=
		manager.loadAndRecoverDurableListeners()
	if err != nil {
		return nil, fmt.Errorf("load durable listeners: %w", err)
	}
	for _, config := range durableConfigs {
		if _, duplicate := manager.listeners[config.ID]; duplicate {
			return nil, fmt.Errorf("duplicate durable listener ID %q", config.ID)
		}
		if manager.hasNameConflict(config) {
			return nil, fmt.Errorf(
				"durable listener name %q is registered more than once",
				config.Name,
			)
		}

		listener, err := newListener(
			config,
			listenersDir,
			database,
			manager.transportPolicy,
			manager.requireAgentAuth,
			false,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"create durable listener runtime %s: %w",
				config.ID,
				err,
			)
		}
		if err := writeListenerConfigProjection(
			listenersDir,
			config,
			true,
		); err != nil {
			return nil, fmt.Errorf(
				"write durable listener projection %s: %w",
				config.ID,
				err,
			)
		}
		manager.attachListenerCallbacks(listener)
		manager.listeners[config.ID] = listener
		log.Printf(
			"[INFO] Loaded durable listener: %s (ID: %s)",
			config.Name,
			config.ID,
		)
	}

	// Import only valid configurations that are not already represented by an
	// authoritative durable row.
	entries, err := os.ReadDir(listenersDir)
	if err != nil {
		return nil, fmt.Errorf("read listeners directory: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check for config file
		configPath := filepath.Join(listenersDir, entry.Name(), "config.json")
		configData, err := readListenerConfigProjection(configPath)
		if err != nil {
			log.Printf("[WARNING] Failed to read config for listener %s: %v", entry.Name(), err)
			continue
		}

		var config ListenerConfig
		if err := json.Unmarshal(configData, &config); err != nil {
			log.Printf("[WARNING] Failed to parse config for listener %s: %v", entry.Name(), err)
			continue
		}
		config.Protocol = strings.ToLower(config.Protocol)
		if err := validateListenerIdentity(config); err != nil {
			if database != nil {
				return nil, fmt.Errorf(
					"saved listener identity in %s is unsafe: %w",
					configPath,
					err,
				)
			}
			log.Printf("[WARNING] Saved listener %s has an unsafe identity; skipping", entry.Name())
			continue
		}
		if err := manager.validateListenerConfig(config); err != nil {
			if errors.Is(err, common.ErrInsecureHTTPAgentTransport) ||
				errors.Is(err, common.ErrClientCertificateValidationUnavailable) {
				return nil, fmt.Errorf(
					"saved listener %s violates agent transport policy: %w",
					config.ID,
					err,
				)
			}
			log.Print("[WARNING] Saved listener configuration is invalid; skipping")
			continue
		}
		if entry.Name() != config.Name {
			if database != nil {
				return nil, fmt.Errorf(
					"saved listener directory %q does not match config name %q",
					entry.Name(),
					config.Name,
				)
			}
			log.Print("[WARNING] Saved listener directory does not match its config name; skipping")
			continue
		}
		if _, tombstoned := tombstonedIDs[config.ID]; tombstoned {
			log.Print("[INFO] Ignoring tombstoned listener configuration")
			continue
		}
		if _, tombstoned := tombstonedNames[strings.ToLower(config.Name)]; tombstoned {
			log.Print("[INFO] Ignoring listener configuration with a tombstoned name")
			continue
		}
		if _, duplicate := manager.listeners[config.ID]; duplicate {
			log.Print("[INFO] Ignoring compatibility projection for a durable listener")
			continue
		}
		if manager.hasNameConflict(config) {
			log.Print("[WARNING] Duplicate saved listener name; skipping")
			continue
		}

		listener, err := newListener(
			config,
			listenersDir,
			database,
			manager.transportPolicy,
			manager.requireAgentAuth,
			false,
		)
		if err != nil {
			log.Printf("[WARNING] Failed to create listener instance for %s: %v", config.Name, err)
			continue
		}
		if database != nil {
			if err := manager.recordListenerImported(config); err != nil {
				return nil, fmt.Errorf("import listener %s: %w", config.ID, err)
			}
			if err := writeListenerConfigProjection(
				listenersDir,
				config,
				true,
			); err != nil {
				return nil, fmt.Errorf(
					"write imported listener projection %s: %w",
					config.ID,
					err,
				)
			}
		}
		manager.attachListenerCallbacks(listener)

		// Add to manager without starting
		manager.listeners[config.ID] = listener
		log.Printf("[INFO] Loaded saved configuration for listener: %s (ID: %s)", config.Name, config.ID)
	}

	return manager, nil
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

	listener, err := newListener(
		config,
		m.listenersDir,
		m.database,
		m.transportPolicy,
		m.requireAgentAuth,
		m.database == nil,
	)
	if err != nil {
		return nil, err
	}
	m.attachListenerCallbacks(listener)
	if err := m.recordListenerCreated(config); err != nil {
		m.cleanupListenerConfig(config.Name)
		return nil, fmt.Errorf("persist listener creation: %w", err)
	}
	// Once the durable row commits, keep the runtime registered until the
	// listener either starts successfully or that row is tombstoned. This
	// prevents any cleanup failure from leaving a hidden nondeleted listener
	// that a same-name retry could duplicate.
	m.listeners[config.ID] = listener
	if m.database != nil {
		if err := writeListenerConfigProjection(
			m.listenersDir,
			config,
			true,
		); err != nil {
			return nil, m.failCreatedListener(
				listener,
				fmt.Errorf("write listener compatibility projection: %w", err),
			)
		}
	}
	if err := listener.Start(); err != nil {
		return nil, m.failCreatedListener(listener, err)
	}
	if err := m.recordListenerState(config.ID, StatusActive, "started", "", false); err != nil {
		if stopErr := listener.Stop(); stopErr != nil {
			log.Printf("[WARNING] Failed to stop listener after persistence error: %v", stopErr)
		}
		return nil, m.failCreatedListener(
			listener,
			fmt.Errorf("persist listener start: %w", err),
		)
	}
	return listener, nil
}

// failCreatedListener compensates for a failure after the initial durable
// creation record committed. If the tombstone cannot be committed, the
// runtime deliberately remains registered so another create cannot hide or
// duplicate the durable row.
//
// The caller must hold m.mu.
func (m *ListenerManager) failCreatedListener(
	listener *Listener,
	cause error,
) error {
	if listener == nil {
		return cause
	}

	if m.database != nil {
		if err := m.recordListenerState(
			listener.Config.ID,
			StatusError,
			"creation_failed",
			cause.Error(),
			true,
		); err != nil {
			listener.mu.Lock()
			listener.Status = StatusError
			listener.Error = cause.Error()
			listener.mu.Unlock()
			return fmt.Errorf(
				"%w; failed to tombstone durable listener: %v",
				cause,
				err,
			)
		}
	}

	delete(m.listeners, listener.Config.ID)
	m.cleanupListenerConfig(listener.Config.Name)
	return cause
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

	if listener == nil {
		return fmt.Errorf("listener is required")
	}
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.Status != StatusStopped {
		return fmt.Errorf(
			"listener %s must be stopped before it can be added",
			listener.Config.ID,
		)
	}
	config := listener.Config
	if err := m.validateListenerConfig(config); err != nil {
		return err
	}
	if _, exists := m.listeners[config.ID]; exists {
		return fmt.Errorf("listener with ID %s already exists", config.ID)
	}
	if m.requireAgentAuth {
		httpProtocol, ok := listener.Protocol.(*behaviour.HTTPPollingProtocol)
		if !listener.requireAgentAuth ||
			!ok ||
			!httpProtocol.RequiresAgentAuthentication() {
			return errors.New(
				"listener does not enforce authenticated agent enrollment",
			)
		}
	}

	listener.transportPolicy = m.transportPolicy
	listener.requireAgentAuth = m.requireAgentAuth
	m.listeners[config.ID] = listener
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
	sort.Slice(list, func(i, j int) bool {
		return list[i].Config.ID < list[j].Config.ID
	})
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
		} else if err := m.recordListenerState(id, StatusStopped, "stopped", "", false); err != nil {
			return fmt.Errorf("persist stopped listener: %w", err)
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
	if err := m.recordListenerState(id, StatusStopped, "stopped", "", false); err != nil {
		return fmt.Errorf("persist stopped listener: %w", err)
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
		if persistErr := m.recordListenerState(
			id,
			StatusError,
			"error",
			err.Error(),
			false,
		); persistErr != nil {
			log.Printf("[WARNING] Failed to persist listener start error: %v", persistErr)
		}
		return fmt.Errorf("failed to start listener: %w", err)
	}
	if err := m.recordListenerState(id, StatusActive, "started", "", false); err != nil {
		if stopErr := listener.Stop(); stopErr != nil {
			log.Printf("[WARNING] Failed to stop listener after persistence error: %v", stopErr)
		}
		return fmt.Errorf("persist started listener: %w", err)
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
		if err := m.recordListenerState(id, StatusStopped, "stopped", "", false); err != nil {
			return fmt.Errorf("persist stopped listener before deletion: %w", err)
		}
	}

	if err := m.recordListenerState(id, StatusStopped, "deleted", "", true); err != nil {
		return fmt.Errorf("persist deleted listener: %w", err)
	}
	// Clean up listener directory after the tombstone commits. If filesystem
	// cleanup fails, startup reconciliation still refuses to resurrect it.
	listenerDir := filepath.Join(m.listenersDir, listener.Config.Name)
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
			} else if err := m.recordListenerState(id, StatusStopped, "stopped", "", false); err != nil {
				errors = append(errors, fmt.Errorf("persist stopped listener %s: %v", id, err))
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
			if err := m.recordListenerState(id, StatusStopped, "stopped", "", false); err != nil {
				errors = append(errors, fmt.Errorf("persist stopped listener %s: %v", id, err))
				continue
			}
		}
		if err := m.recordListenerState(id, StatusStopped, "deleted", "", true); err != nil {
			errors = append(errors, fmt.Errorf("persist deleted listener %s: %v", id, err))
			continue
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
	if err := validateListenerIdentity(config); err != nil {
		log.Printf("[ERROR] Listener identity validation failed")
		return err
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
	if err := validateListenerTLSProtocol(protocol, config.TLSConfig); err != nil {
		return err
	}
	if err := m.transportPolicy.ValidateListener(
		protocol,
		config.TLSConfig != nil && config.TLSConfig.RequireClientCert,
	); err != nil {
		return err
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

	log.Print("[INFO] Listener configuration validated successfully")
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
		if strings.EqualFold(l.Config.Name, config.Name) && id != config.ID {
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
	if m.database != nil {
		// Keep stopped durable listeners available for operator lifecycle
		// actions and authoritative payload-build configuration lookup.
		return
	}

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
	configData, err := readListenerConfigProjection(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config ListenerConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	config.Protocol = strings.ToLower(config.Protocol)
	listener, err := newListener(
		config,
		m.listenersDir,
		m.database,
		m.transportPolicy,
		m.requireAgentAuth,
		false,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %v", err)
	}
	m.attachListenerCallbacks(listener)

	return listener, nil
}

func (m *ListenerManager) attachListenerCallbacks(listener *Listener) {
	if listener == nil || m.database == nil {
		return
	}
	listenerID := listener.Config.ID
	listener.mu.Lock()
	listener.onError = func(listenerErr error) {
		message := "unknown listener error"
		if listenerErr != nil {
			message = listenerErr.Error()
		}
		if err := m.recordListenerState(
			listenerID,
			StatusError,
			"error",
			message,
			false,
		); err != nil {
			log.Printf(
				"[WARNING] Failed to persist listener %s error: %v",
				listenerID,
				err,
			)
		}
	}
	listener.mu.Unlock()
}

// AllAgents returns a combined map of all agents from all listeners
func (m *ListenerManager) AllAgents() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	type scopedAgent struct {
		listenerID string
		agentID    string
		value      interface{}
	}
	listenerIDs := make([]string, 0, len(m.listeners))
	for listenerID := range m.listeners {
		listenerIDs = append(listenerIDs, listenerID)
	}
	sort.Strings(listenerIDs)
	var collected []scopedAgent
	counts := make(map[string]int)
	for _, listenerID := range listenerIDs {
		listener := m.listeners[listenerID]
		if listener.Protocol != nil {
			if agenter, ok := listener.Protocol.(interface{ GetAllAgents() map[string]interface{} }); ok {
				for id, agent := range agenter.GetAllAgents() {
					counts[id]++
					collected = append(collected, scopedAgent{
						listenerID: listenerID,
						agentID:    id,
						value:      agent,
					})
				}
			}
		}
	}
	allAgents := make(map[string]interface{}, len(collected))
	for _, agent := range collected {
		key := agent.agentID
		if counts[key] > 1 {
			key = agent.listenerID + scopedAgentKeyDelimiter + agent.agentID
		}
		allAgents[key] = agent.value
	}
	return allAgents
}
