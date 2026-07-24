package listeners

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	behaviour "microc2/server/internal/behaviour"
	"microc2/server/internal/common"
	"microc2/server/internal/persistence"
	"microc2/server/internal/tasks"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ListenerStatus represents the current operational state of a listener
type ListenerStatus string

const (
	listenerDirectoryMode = 0o700
	listenerConfigMode    = 0o600

	// StatusActive indicates the listener is running and accepting connections
	StatusActive ListenerStatus = "ACTIVE"

	// StatusStopped indicates the listener is not running
	StatusStopped ListenerStatus = "STOPPED"

	// StatusError indicates the listener encountered an error
	StatusError ListenerStatus = "ERROR"
)

// ListenerConfig holds the configuration for a C2 listener
type ListenerConfig struct {
	ID           string                `json:"id"`
	Name         string                `json:"name"`
	Protocol     string                `json:"protocol"`
	BindHost     string                `json:"host"`
	Port         int                   `json:"port"`
	URIs         []string              `json:"uris,omitempty"`
	Headers      map[string]string     `json:"headers,omitempty"`
	UserAgent    string                `json:"user_agent,omitempty"`
	HostRotation string                `json:"host_rotation,omitempty"`
	Hosts        []string              `json:"hosts,omitempty"`
	Proxy        *ProxyConfig          `json:"proxy,omitempty"`
	TLSConfig    *TLSConfig            `json:"tls_config,omitempty"`
	SOCKS5Config *SOCKS5ListenerConfig `json:"socks5_config,omitempty"`
}

// ProxyConfig holds proxy-related configuration
type ProxyConfig struct {
	Type     string `json:"type"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// TLSConfig holds TLS configuration for secure listeners
type TLSConfig struct {
	CertFile          string `json:"cert_file"`
	KeyFile           string `json:"key_file"`
	RequireClientCert bool   `json:"requireClientCert"`
}

// SOCKS5ListenerConfig holds SOCKS5-specific listener configuration
type SOCKS5ListenerConfig struct {
	RequireAuth     bool     `json:"require_auth"`
	AllowedIPs      []string `json:"allowed_ips,omitempty"`
	DisallowedPorts []int    `json:"disallowed_ports,omitempty"`
	IdleTimeout     int      `json:"idle_timeout,omitempty"` // Timeout in seconds
}

// Listener represents a communication protocol listener that agents connect to
// It manages the lifecycle of the listening service and tracks its operational state.
type Listener struct {
	Config           ListenerConfig    `json:"config"`
	Status           ListenerStatus    `json:"status"`
	Error            string            `json:"error,omitempty"`
	StartTime        time.Time         `json:"start_time"`
	StopTime         time.Time         `json:"stop_time,omitempty"`
	Stats            ListenerStats     `json:"stats"`
	URIs             []string          `json:"uris,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	UserAgent        string            `json:"user_agent,omitempty"`
	mu               sync.RWMutex
	listener         net.Listener
	server           *http.Server
	protocolHandler  http.Handler // HTTP handler for http
	Protocol         common.Protocol
	transportPolicy  common.AgentTransportPolicy
	requireAgentAuth bool
	onError          func(error)
}

// ListenerStats tracks operational statistics for a listener
type ListenerStats struct {
	TotalConnections  int64     `json:"total_connections"`
	ActiveConnections int64     `json:"active_connections"`
	LastConnection    time.Time `json:"last_connection,omitempty"`
	BytesReceived     int64     `json:"bytes_received"`
	BytesSent         int64     `json:"bytes_sent"`
	FailedConnections int64     `json:"failed_connections"`
}

type ListenerSnapshot struct {
	Config    ListenerConfig    `json:"config"`
	Status    ListenerStatus    `json:"status"`
	Error     string            `json:"error,omitempty"`
	StartTime time.Time         `json:"start_time"`
	StopTime  time.Time         `json:"stop_time,omitempty"`
	Stats     ListenerStats     `json:"stats"`
	URIs      []string          `json:"uris,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	UserAgent string            `json:"user_agent,omitempty"`
}

func (l *Listener) Snapshot() ListenerSnapshot {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return ListenerSnapshot{
		Config:    l.Config,
		Status:    l.Status,
		Error:     l.Error,
		StartTime: l.StartTime,
		StopTime:  l.StopTime,
		Stats:     l.Stats,
		URIs:      append([]string(nil), l.URIs...),
		Headers:   cloneStringMap(l.Headers),
		UserAgent: l.UserAgent,
	}
}

func (l *Listener) MarshalJSON() ([]byte, error) {
	snapshot := l.Snapshot()
	return json.Marshal(snapshot)
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// NewListener creates a listener with the production-safe transport policy.
//
// Pre-conditions:
//   - config is a valid ListenerConfig instance
//   - Protocol specified in config must be supported
//
// Post-conditions:
//   - Returns an initialized Listener instance with appropriate protocol handler
//   - Listener is in stopped state
//   - Returns error if the protocol is not supported or configuration is invalid
func NewListener(config ListenerConfig) (*Listener, error) {
	return newListener(
		config,
		filepath.Join("static", "listeners"),
		nil,
		common.AgentTransportPolicy{},
		true,
		true,
	)
}

// NewListenerForIsolatedLab creates a listener with the explicit compatibility
// policy that permits plaintext HTTP. Production code must construct listeners
// through a ListenerManager carrying the configured AgentTransportPolicy.
func NewListenerForIsolatedLab(config ListenerConfig) (*Listener, error) {
	return newListener(
		config,
		filepath.Join("static", "listeners"),
		nil,
		common.IsolatedLabAgentTransportPolicy(),
		false,
		true,
	)
}

func newListener(
	config ListenerConfig,
	listenersDir string,
	database *persistence.Database,
	transportPolicy common.AgentTransportPolicy,
	requireAgentAuth bool,
	saveConfig bool,
) (*Listener, error) {
	config.Protocol = strings.ToLower(config.Protocol)
	if err := validateListenerIdentity(config); err != nil {
		return nil, err
	}
	if err := transportPolicy.ValidateListener(
		config.Protocol,
		config.TLSConfig != nil && config.TLSConfig.RequireClientCert,
	); err != nil {
		return nil, err
	}
	if err := validateListenerTLSProtocol(config.Protocol, config.TLSConfig); err != nil {
		return nil, err
	}
	if listenersDir == "" {
		listenersDir = filepath.Join("static", "listeners")
	}
	if err := ensurePrivateDirectory(listenersDir); err != nil {
		return nil, fmt.Errorf("failed to prepare listeners directory: %v", err)
	}

	listenerDir := filepath.Join(listenersDir, config.Name)
	if err := ensurePrivateDirectory(listenerDir); err != nil {
		return nil, fmt.Errorf("failed to create listener directory: %v", err)
	}

	if saveConfig {
		if err := writeListenerConfigProjection(
			listenersDir,
			config,
			database != nil,
		); err != nil {
			return nil, err
		}
	}

	// Initialize protocol handler based on config
	var protoHandler http.Handler
	var proto common.Protocol
	switch config.Protocol {
	case "http", "https":
		protoConfig := common.BaseProtocolConfig{
			UploadDir: filepath.Join(listenerDir, "uploads"),
			Port:      fmt.Sprintf("%d", config.Port),
		}
		var httpProto *behaviour.HTTPPollingProtocol
		switch {
		case requireAgentAuth && database == nil:
			return nil, errors.New(
				"authenticated agent listener requires durable storage",
			)
		case requireAgentAuth:
			var err error
			httpProto, err =
				behaviour.NewAuthenticatedHTTPPollingProtocolWithPersistence(
					protoConfig,
					database,
					config.ID,
				)
			if err != nil {
				return nil, fmt.Errorf(
					"load authenticated protocol state for listener %s: %w",
					config.ID,
					err,
				)
			}
		case database == nil:
			httpProto = behaviour.NewHTTPPollingProtocol(protoConfig)
		default:
			var err error
			httpProto, err = behaviour.NewHTTPPollingProtocolWithPersistence(
				protoConfig,
				database,
				config.ID,
			)
			if err != nil {
				return nil, fmt.Errorf(
					"load durable protocol state for listener %s: %w",
					config.ID,
					err,
				)
			}
		}
		protoHandler = httpProto.GetHTTPHandler()
		proto = httpProto
		// Ensure upload directory exists
		if err := ensurePrivateDirectory(protoConfig.UploadDir); err != nil {
			return nil, fmt.Errorf("create listener upload directory: %w", err)
		}
	case "dns", "dnsoverhttps":
		// DNSoverHTTPS logic (may be implemented later)
		return nil, fmt.Errorf("DNSoverHTTPS protocol is not implemented yet")
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}

	// Construct listener instance
	l := &Listener{
		Config:           config,
		Status:           StatusStopped,
		Stats:            ListenerStats{},
		protocolHandler:  protoHandler,
		Protocol:         proto,
		transportPolicy:  transportPolicy,
		requireAgentAuth: requireAgentAuth,
	}
	return l, nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, listenerDirectoryMode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("path is not a private directory")
	}
	if err := os.Chmod(path, listenerDirectoryMode); err != nil {
		return err
	}
	return nil
}

func writeListenerConfigProjection(
	listenersDir string,
	config ListenerConfig,
	redactSecrets bool,
) (returnErr error) {
	if err := validateListenerIdentity(config); err != nil {
		return err
	}
	if redactSecrets {
		config = redactedListenerConfig(config)
	}
	configJSON, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal listener config: %w", err)
	}

	if err := ensurePrivateDirectory(listenersDir); err != nil {
		return fmt.Errorf("secure listeners directory: %w", err)
	}
	listenerDir := filepath.Join(listenersDir, config.Name)
	if err := ensurePrivateDirectory(listenerDir); err != nil {
		return fmt.Errorf("secure listener directory: %w", err)
	}
	configPath := filepath.Join(listenerDir, "config.json")
	temp, err := os.CreateTemp(listenerDir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create listener config temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		if returnErr != nil {
			_ = temp.Close()
		}
		_ = os.Remove(tempPath)
	}()

	if err := temp.Chmod(listenerConfigMode); err != nil {
		return fmt.Errorf("secure listener config temporary file: %w", err)
	}
	if _, err := temp.Write(configJSON); err != nil {
		return fmt.Errorf("write listener config temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync listener config temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close listener config temporary file: %w", err)
	}
	if err := os.Rename(tempPath, configPath); err != nil {
		return fmt.Errorf("replace listener config atomically: %w", err)
	}
	if err := os.Chmod(configPath, listenerConfigMode); err != nil {
		return fmt.Errorf("secure listener config: %w", err)
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(listenerDir)
		if err != nil {
			return fmt.Errorf("open listener directory for sync: %w", err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return fmt.Errorf("sync listener directory: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close listener directory after sync: %w", closeErr)
		}
	}
	return nil
}

func readListenerConfigProjection(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("listener config is not a regular file")
	}
	if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("secure listener directory: %w", err)
	}
	if err := os.Chmod(path, listenerConfigMode); err != nil {
		return nil, fmt.Errorf("secure listener config: %w", err)
	}
	return os.ReadFile(path)
}

func redactedListenerConfig(config ListenerConfig) ListenerConfig {
	if config.Proxy == nil {
		return config
	}
	proxy := *config.Proxy
	proxy.Password = ""
	config.Proxy = &proxy
	return config
}

func validateListenerIdentity(config ListenerConfig) error {
	if err := tasks.ValidateIdentifier("listener id", config.ID); err != nil {
		return err
	}
	name := config.Name
	if name == "" {
		return errors.New("listener name is required")
	}
	if name != strings.TrimSpace(name) {
		return errors.New("listener name must not contain surrounding whitespace")
	}
	if len(name) > 128 {
		return errors.New("listener name must be at most 128 bytes")
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character < 0x20 || character > 0x7e {
			return errors.New(
				"listener name must contain only printable ASCII characters",
			)
		}
		if strings.ContainsRune(`<>:"/\|?*`, rune(character)) {
			return errors.New(
				"listener name contains a character that is not portable across filesystems",
			)
		}
	}
	if strings.HasSuffix(name, ".") {
		return errors.New("listener name must not end with a period")
	}
	if isReservedWindowsListenerName(name) {
		return errors.New("listener name is reserved on Windows")
	}
	return nil
}

func isReservedWindowsListenerName(name string) bool {
	stem := name
	if dot := strings.IndexByte(stem, '.'); dot >= 0 {
		stem = stem[:dot]
	}
	upper := strings.ToUpper(strings.TrimRight(stem, " ."))
	switch upper {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	return len(upper) == 4 &&
		(upper[:3] == "COM" || upper[:3] == "LPT") &&
		upper[3] >= '1' && upper[3] <= '9'
}

// Start initiates the listener
//
// Pre-conditions:
//   - Listener is in stopped state
//   - Required resources (ports, etc.) are available
//
// Post-conditions:
//   - Listener is started and accepting connections
//   - Status is updated to Active
//   - StartTime is updated
//   - Returns error if the listener can't be started
func (l *Listener) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.transportPolicy.ValidateListener(
		l.Config.Protocol,
		l.Config.TLSConfig != nil && l.Config.TLSConfig.RequireClientCert,
	); err != nil {
		return err
	}
	if err := validateListenerTLSProtocol(
		l.Config.Protocol,
		l.Config.TLSConfig,
	); err != nil {
		return err
	}
	if l.requireAgentAuth {
		httpProtocol, ok := l.Protocol.(*behaviour.HTTPPollingProtocol)
		if !ok || !httpProtocol.RequiresAgentAuthentication() {
			return errors.New(
				"listener protocol does not enforce authenticated agent enrollment",
			)
		}
	}
	if l.Status == StatusActive {
		return fmt.Errorf("listener %s is already running", l.Config.Name)
	}
	if l.protocolHandler == nil {
		return fmt.Errorf("listener %s has no protocol handler for %s", l.Config.Name, l.Config.Protocol)
	}

	l.Error = ""
	if l.Config.BindHost == "" {
		l.Config.BindHost = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", l.Config.BindHost, l.Config.Port)

	var tlsConfig *tls.Config
	if l.usesTLS() {
		certFile, keyFile := l.tlsCertFiles()
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			l.Error = err.Error()
			return fmt.Errorf("failed to load TLS certificate for listener %s: %w", l.Config.Name, err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           l.protocolHandler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		l.Error = err.Error()
		return fmt.Errorf("failed to bind listener %s on %s: %w", l.Config.Name, addr, err)
	}

	l.listener = tcpListener
	l.server = server
	l.Status = StatusActive
	l.StartTime = time.Now()
	l.StopTime = time.Time{}

	go func() {
		var err error
		if l.usesTLS() {
			// log.Printf("[DEBUG] Loading TLS configuration from %s and %s", certFile, keyFile)
			// log.Printf("[DEBUG] Starting HTTPS server on %s", addr)
			err = server.ServeTLS(tcpListener, "", "")
		} else {
			// log.Printf("[DEBUG] Starting HTTP server on %s", addr)
			err = server.Serve(tcpListener)
		}
		if err != nil && err != http.ErrServerClosed {
			log.Printf("[ERROR] HTTP server error: %v", err)
			_ = tcpListener.Close()
			l.SetError(err)
		}
	}()

	return nil
}

func (l *Listener) usesTLS() bool {
	return strings.EqualFold(strings.TrimSpace(l.Config.Protocol), "https")
}

func validateListenerTLSProtocol(protocol string, tlsConfig *TLSConfig) error {
	if strings.EqualFold(strings.TrimSpace(protocol), "http") &&
		tlsConfig != nil {
		return errors.New(
			`listener TLS configuration requires protocol "https"`,
		)
	}
	return nil
}

func (l *Listener) tlsCertFiles() (string, string) {
	if l.Config.TLSConfig != nil {
		return l.Config.TLSConfig.CertFile, l.Config.TLSConfig.KeyFile
	}
	return "certs/server.crt", "certs/server.key"
}

// Stop halts the listener operation
//
// Pre-conditions:
//   - Listener is in active state
//
// Post-conditions:
//   - Listener is stopped and no longer accepting connections
//   - Status is updated to Stopped
//   - StopTime is updated
//   - Resources are released
//   - Returns error if the listener can't be stopped cleanly
func (l *Listener) Stop() error {
	l.mu.Lock()
	if l.Status != StatusActive && l.Status != StatusError {
		l.mu.Unlock()
		return fmt.Errorf("listener %s is not running", l.Config.Name)
	}

	server := l.server
	tcpListener := l.listener

	l.Status = StatusStopped
	l.StopTime = time.Now()
	l.server = nil
	l.listener = nil
	l.mu.Unlock()

	if server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil && err != http.ErrServerClosed && !errors.Is(err, net.ErrClosed) {
			if tcpListener != nil {
				_ = tcpListener.Close()
			}
			l.mu.Lock()
			l.Error = err.Error()
			l.mu.Unlock()
			return fmt.Errorf("error stopping listener: %v", err)
		}
		if tcpListener != nil {
			_ = tcpListener.Close()
		}
	} else if tcpListener != nil {
		if err := tcpListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			l.mu.Lock()
			l.Error = err.Error()
			l.mu.Unlock()
			return fmt.Errorf("error stopping listener: %v", err)
		}
	}

	log.Printf("[INFO] Stopped listener %s", l.Config.Name)
	return nil
}

// GetStatus returns the current status of the listener
//
// Pre-conditions:
//   - None
//
// Post-conditions:
//   - Returns the current listener status in a thread-safe manner
func (l *Listener) GetStatus() ListenerStatus {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.Status
}

// GetError returns any error encountered by the listener
//
// Pre-conditions:
//   - None
//
// Post-conditions:
//   - Returns the current error message in a thread-safe manner
//   - Returns empty string if no error
func (l *Listener) GetError() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.Error
}

// SetError sets an error state for the listener
//
// Pre-conditions:
//   - Error message is meaningful and describes the issue
//
// Post-conditions:
//   - Listener status is updated to Error
//   - Error message is stored
func (l *Listener) SetError(err error) {
	l.mu.Lock()
	if l.Status == StatusStopped && (err == http.ErrServerClosed || errors.Is(err, net.ErrClosed)) {
		l.mu.Unlock()
		return
	}
	l.Status = StatusError
	if err != nil {
		l.Error = err.Error()
	} else {
		l.Error = "Unknown error"
	}
	onError := l.onError
	l.mu.Unlock()
	if onError != nil {
		onError(err)
	}
}
