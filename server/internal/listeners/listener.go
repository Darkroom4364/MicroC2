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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ListenerStatus represents the current operational state of a listener
type ListenerStatus string

const (
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
	Config          ListenerConfig    `json:"config"`
	Status          ListenerStatus    `json:"status"`
	Error           string            `json:"error,omitempty"`
	StartTime       time.Time         `json:"start_time"`
	StopTime        time.Time         `json:"stop_time,omitempty"`
	Stats           ListenerStats     `json:"stats"`
	URIs            []string          `json:"uris,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	UserAgent       string            `json:"user_agent,omitempty"`
	mu              sync.RWMutex
	listener        net.Listener
	server          *http.Server
	protocolHandler http.Handler // HTTP handler for http
	Protocol        common.Protocol
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

// NewListener creates a new listener instance with the given configuration
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
	config.Protocol = strings.ToLower(config.Protocol)

	// Create listener-specific directory in static/listeners
	listenerDir := filepath.Join("static", "listeners", config.Name)
	if err := os.MkdirAll(listenerDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create listener directory: %v", err)
	}

	// Save configuration to file
	configJson, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal listener config: %v", err)
	}

	configPath := filepath.Join(listenerDir, "config.json")
	if err := os.WriteFile(configPath, configJson, 0644); err != nil {
		return nil, fmt.Errorf("failed to save listener config: %v", err)
	}

	// Initialize protocol handler based on config
	var protoHandler http.Handler
	var proto common.Protocol
	switch config.Protocol {
	case "http", "https":
		protoConfig := common.BaseProtocolConfig{
			UploadDir: filepath.Join("static", "listeners", config.Name, "uploads"),
			Port:      fmt.Sprintf("%d", config.Port),
		}
		httpProto := behaviour.NewHTTPPollingProtocol(protoConfig)
		protoHandler = httpProto.GetHTTPHandler()
		proto = httpProto
		// Ensure upload directory exists
		os.MkdirAll(protoConfig.UploadDir, 0755)
	case "dns", "dnsoverhttps":
		// DNSoverHTTPS logic (may be implemented later)
		return nil, fmt.Errorf("DNSoverHTTPS protocol is not implemented yet")
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}

	// Construct listener instance
	l := &Listener{
		Config:          config,
		Status:          StatusStopped,
		Stats:           ListenerStats{},
		protocolHandler: protoHandler,
		Protocol:        proto,
	}
	return l, nil
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
		Addr:      addr,
		Handler:   l.protocolHandler,
		TLSConfig: tlsConfig,
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
	return l.Config.Protocol == "https" || l.Config.TLSConfig != nil
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
	defer l.mu.Unlock()

	if l.Status == StatusStopped && (err == http.ErrServerClosed || errors.Is(err, net.ErrClosed)) {
		return
	}
	l.Status = StatusError
	if err != nil {
		l.Error = err.Error()
	} else {
		l.Error = "Unknown error"
	}
}
