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

	// OPSEC Configuration
	ProcScanIntervalSecs              int     `json:"proc_scan_interval_secs"`
	BaseThresholdEnterFullOpsec       float64 `json:"base_threshold_enter_full_opsec"`
	BaseThresholdExitFullOpsec        float64 `json:"base_threshold_exit_full_opsec"` // Will be mapped or ignored based on agent logic
	BaseThresholdEnterReducedActivity float64 `json:"base_threshold_enter_reduced_activity"`
	BaseThresholdExitReducedActivity  float64 `json:"base_threshold_exit_reduced_activity"` // Will be mapped or ignored
	MinDurationFullOpsecSecs          int     `json:"min_duration_full_opsec_secs"`
	MinDurationReducedActivitySecs    int     `json:"min_duration_reduced_activity_secs"`
	MinDurationBackgroundOpsecSecs    int     `json:"min_duration_background_opsec_secs"`
	ReducedActivitySleepSecs          int     `json:"reduced_activity_sleep_secs"`
	BaseMaxConsecutiveC2Failures      int     `json:"base_max_consecutive_c2_failures"`
	C2FailureThresholdIncreaseFactor  float64 `json:"c2_failure_threshold_increase_factor"`
	C2FailureThresholdDecreaseFactor  float64 `json:"c2_failure_threshold_decrease_factor"`
	C2ThresholdAdjustIntervalSecs     int     `json:"c2_threshold_adjust_interval_secs"`
	C2DynamicThresholdMaxMultiplier   float64 `json:"c2_dynamic_threshold_max_multiplier"`
}

// PayloadResult contains information about a generated payload
type PayloadResult struct {
	ID         string `json:"id"`
	PayloadID  string `json:"payload_id,omitempty"`
	ListenerID string `json:"listener_id,omitempty"`
	Filename   string `json:"filename"`
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	Created    string `json:"created"`
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
