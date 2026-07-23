package common

import (
	"io"
	"net/http"
	"time"
)

// ListenerConfig holds the configuration for a C2 listener
type ListenerConfig struct {
	ID           string
	Name         string
	Protocol     string
	BindHost     string
	Port         int
	URIs         []string
	Headers      map[string]string
	UserAgent    string
	HostRotation string
	Hosts        []string
	Proxy        *ProxyConfig
	TLSConfig    *TLSConfig
	SOCKS5Config *SOCKS5ListenerConfig
}

// ProxyConfig holds proxy-related configuration
type ProxyConfig struct {
	Type     string
	Host     string
	Port     int
	Username string
	Password string
}

// TLSConfig holds TLS configuration for secure listeners
type TLSConfig struct {
	CertFile          string
	KeyFile           string
	RequireClientCert bool
}

// SOCKS5ListenerConfig holds SOCKS5-specific listener configuration
type SOCKS5ListenerConfig struct {
	RequireAuth     bool
	AllowedIPs      []string
	DisallowedPorts []int
	IdleTimeout     int
}

// BaseProtocolConfig contains common configuration for all protocols
type BaseProtocolConfig struct {
	UploadDir string
	Port      string
	// AllowedOrigins lists browser origins permitted by CORS on polling
	// routes. Empty means no cross-origin access; "*" is an explicit,
	// documented escape hatch that restores wildcard behavior.
	AllowedOrigins []string
}

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

// Listener represents a communication protocol listener that agents connect to
type Listener struct {
	Config    ListenerConfig
	Status    ListenerStatus
	Error     string
	StartTime time.Time
	StopTime  time.Time
	Stats     ListenerStats
	Protocol  Protocol
}

// ListenerStatus represents the current operational state of a listener
type ListenerStatus string

const (
	StatusActive  ListenerStatus = "ACTIVE"
	StatusStopped ListenerStatus = "STOPPED"
	StatusError   ListenerStatus = "ERROR"
)

// ListenerStats tracks operational statistics for a listener
type ListenerStats struct {
	TotalConnections  int64
	ActiveConnections int64
	LastConnection    time.Time
	BytesReceived     int64
	BytesSent         int64
	FailedConnections int64
}
