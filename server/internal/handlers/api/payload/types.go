package payload

import (
	"encoding/json"
	"os/exec"
	"sync"

	"microc2/server/internal/audit"
	"microc2/server/internal/enrollment"
	"microc2/server/internal/listeners"
	"microc2/server/internal/persistence"
)

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
	// MaxSessions bounds the active runtime identities that may enroll from
	// this payload build. Zero selects the secure default of one.
	MaxSessions int `json:"max_sessions,omitempty"`

	// MutationSeed optionally pins the hex u64 seed for the source mutation
	// engine; a random seed is generated when empty (issue #67).
	MutationSeed string `json:"mutation_seed,omitempty"`

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
	ID           string `json:"id"`
	PayloadID    string `json:"payload_id,omitempty"`
	ListenerID   string `json:"listener_id,omitempty"`
	MutationSeed string `json:"mutation_seed,omitempty"`
	Filename     string `json:"filename"`
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	Created      string `json:"created"`

	relativePath              string
	sha256                    string
	provenanceJSON            json.RawMessage
	createdAuditEventSequence int64
}

// ListenerLookup resolves the authoritative listener configuration used for a
// build. Production wiring supplies the listener manager through a small
// adapter; payload generation never scans listener files itself.
type ListenerLookup interface {
	LookupListener(listenerID string) (listeners.ListenerConfig, error)
}

// PayloadHandler manages payload generation operations
type PayloadHandler struct {
	payloadsDir              string
	agentSourceDir           string
	listenerLookup           ListenerLookup
	database                 *persistence.Database
	audit                    *audit.Store
	enrollment               *enrollment.Store
	allowInsecureIsolatedLab bool
	initErr                  error
	runBuild                 func(*exec.Cmd) ([]byte, error)
	afterVerified            func()
	buildMutex               sync.Mutex
	mutex                    sync.Mutex
	payloads                 map[string]PayloadResult
}
