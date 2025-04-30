package payload

import "sync"

// PayloadConfig defines the structure for payload generation configuration
type PayloadConfig struct {
	AgentType       string `json:"agentType"`
	ListenerID      string `json:"listener"`
	Architecture    string `json:"architecture"`
	Format          string `json:"format"`
	Sleep           int    `json:"sleep"`
	IndirectSyscall bool   `json:"indirectSyscall"`
	SleepTechnique  string `json:"sleepTechnique"`
	DllSideloading  bool   `json:"dllSideloading"`
	SideloadDll     string `json:"sideloadDll,omitempty"`
	ExportName      string `json:"exportName,omitempty"`
	Socks5Enabled   bool   `json:"socks5_enabled"`
	Socks5Host      string `json:"socks5_host"`
	Socks5Port      int    `json:"socks5_port"`
}

// PayloadResult contains information about a generated payload
type PayloadResult struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Created  string `json:"created"`
}

// TLSConfig holds TLS configuration for secure listeners
type TLSConfig struct {
	CertFile          string `json:"cert_file"`
	KeyFile           string `json:"key_file"`
	RequireClientCert bool   `json:"requireClientCert"`
}

// PayloadHandler manages payload generation operations
type PayloadHandler struct {
	payloadsDir    string
	agentSourceDir string
	mutex          sync.Mutex
	payloads       map[string]PayloadResult
}

// ListenerConfig represents the configuration of a listener
type ListenerConfig struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Protocol     string            `json:"protocol"`
	BindHost     string            `json:"host"`
	Port         int               `json:"port"`
	Headers      map[string]string `json:"headers,omitempty"`
	UserAgent    string            `json:"user_agent,omitempty"`
	HostRotation string            `json:"host_rotation,omitempty"`
	Hosts        []string          `json:"hosts,omitempty"`
	TLSConfig    *TLSConfig        `json:"tls_config,omitempty"`
}
