package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"microc2/server/internal/behaviour"
	"microc2/server/internal/listeners"
	"microc2/server/internal/persistence"
)

// Health states reported by the operator telemetry endpoints. The semantics
// are deliberately small and deterministic so external tooling can alert on
// them without parsing logs:
//
//   - healthy: the component works as configured and shows no recent failure
//     indicators.
//   - degraded: the component still serves, but recent task or payload build
//     failures were recorded inside the telemetry failure window.
//   - failing: the component cannot serve its purpose right now (listener in
//     ERROR state, storage unavailable, or telemetry itself unreadable).
const (
	HealthStateHealthy  = "healthy"
	HealthStateDegraded = "degraded"
	HealthStateFailing  = "failing"
)

// Listener error classes. Raw listener error strings can contain filesystem
// paths, bind addresses, and TLS library internals, so telemetry only ever
// exposes these fixed categories.
const (
	listenerErrorClassBindFailed           = "bind_failed"
	listenerErrorClassTLSConfigInvalid     = "tls_config_invalid"
	listenerErrorClassRuntimeError         = "runtime_error"
	listenerErrorClassTelemetryUnavailable = "telemetry_unavailable"
)

// Storage states shared by the readiness and telemetry responses.
const (
	storageStateOK          = "ok"
	storageStateDisabled    = "disabled"
	storageStateUnavailable = "unavailable"
)

// telemetryFailureWindow bounds "recent" task and build failure indicators.
// Counters inside the window restart from zero once failures age out, so a
// resolved incident stops degrading the server without operator action.
const telemetryFailureWindow = time.Hour

// buildFailureWindowLayout truncates the recent-build-failure comparison to
// whole seconds. payload_builds.created_at values are UTC RFC3339Nano
// strings, so a second-precision lower bound compares correctly against them
// while a nanosecond bound could mismatch variable-width fractions.
const buildFailureWindowLayout = "2006-01-02T15:04:05"

// HealthHandlers serves the machine-readable operator health surface:
// liveness, readiness, and runtime telemetry. All routes are registered on
// the operator mux, so they sit behind the same loopback-or-operator-token
// guard as every other operator API.
type HealthHandlers struct {
	manager   *listeners.ListenerManager
	database  *persistence.Database
	startedAt time.Time
	now       func() time.Time
}

// NewHealthHandlers creates the health handler set over the existing
// listener manager and durable state handle. Both may be nil: a nil manager
// reports zero listeners, and a nil database reports storage as disabled.
func NewHealthHandlers(
	manager *listeners.ListenerManager,
	database *persistence.Database,
) *HealthHandlers {
	return newHealthHandlersWithClock(manager, database, time.Now)
}

func newHealthHandlersWithClock(
	manager *listeners.ListenerManager,
	database *persistence.Database,
	now func() time.Time,
) *HealthHandlers {
	if now == nil {
		now = time.Now
	}
	return &HealthHandlers{
		manager:   manager,
		database:  database,
		startedAt: now().UTC(),
		now:       now,
	}
}

// RegisterRoutes registers all health routes on the provided mux.
func (h *HealthHandlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/health", h.HandleHealth)
	mux.HandleFunc("/api/ready", h.HandleReady)
	mux.HandleFunc("/api/telemetry", h.HandleTelemetry)
}

// HandleHealth is the liveness probe. It answers 200 whenever the process
// can serve HTTP; it performs no I/O beyond encoding the response, so it
// stays deterministic and inexpensive under load.
func (h *HealthHandlers) HandleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sendJSONResponse(w, map[string]interface{}{
		"status":         "ok",
		"uptime_seconds": h.uptimeSeconds(),
	})
}

// HandleReady is the readiness probe. It reports 200 only when every
// configured dependency answers a trivial check; today that is a single
// `SELECT 1` against durable storage. A server without configured storage is
// ready with storage reported as disabled.
func (h *HealthHandlers) HandleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	storage := h.storageState()
	status := "ready"
	code := http.StatusOK
	if storage == storageStateUnavailable {
		status = "not_ready"
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status": status,
		"checks": map[string]string{"storage": storage},
	}); err != nil {
		log.Printf("[ERROR] Failed to encode readiness response: %v", err)
	}
}

type listenerTelemetry struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Protocol            string `json:"protocol"`
	Port                int    `json:"port"`
	Status              string `json:"status"`
	Health              string `json:"health"`
	LastErrorClass      string `json:"last_error_class,omitempty"`
	ActiveAgents        int    `json:"active_agents"`
	QueueDepth          int    `json:"queue_depth"`
	RecentTaskFailures  int    `json:"recent_task_failures"`
	RecentBuildFailures int    `json:"recent_build_failures"`
}

type buildTelemetry struct {
	RecentFailures int `json:"recent_failures"`
}

type telemetryResponse struct {
	Status        string              `json:"status"`
	GeneratedAt   string              `json:"generated_at"`
	UptimeSeconds int64               `json:"uptime_seconds"`
	Storage       string              `json:"storage"`
	Listeners     []listenerTelemetry `json:"listeners"`
	Builds        buildTelemetry      `json:"builds"`
}

// HandleTelemetry reports the operator server runtime summary: per-listener
// status, sanitized last-error class, active agent count, queue depth, and
// recent task/build failure indicators, plus the aggregate server health.
// Responses never contain agent identifiers, filesystem paths, secrets, or
// raw error strings.
func (h *HealthHandlers) HandleTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := h.now().UTC()
	windowStart := now.Add(-telemetryFailureWindow)

	storage := h.storageState()
	buildFailures, totalBuildFailures, buildsErr := h.recentBuildFailures(windowStart)
	if buildsErr != nil {
		// The build table lives in the same database as the readiness probe;
		// surface its failure as a storage problem instead of fabricating
		// plausible-looking zero counters.
		log.Printf("[ERROR] Failed to load recent build failures: %v", buildsErr)
		storage = storageStateUnavailable
	}

	response := telemetryResponse{
		Status:        HealthStateHealthy,
		GeneratedAt:   now.Format(time.RFC3339),
		UptimeSeconds: h.uptimeSeconds(),
		Storage:       storage,
		Listeners:     []listenerTelemetry{},
		Builds:        buildTelemetry{RecentFailures: totalBuildFailures},
	}
	if storage == storageStateUnavailable {
		response.Status = HealthStateFailing
	}
	if h.manager != nil {
		for _, listener := range h.manager.ListListeners() {
			entry := h.summarizeListener(listener, windowStart, buildFailures)
			response.Listeners = append(response.Listeners, entry)
			response.Status = worstHealth(response.Status, entry.Health)
		}
	}
	sendJSONResponse(w, response)
}

func (h *HealthHandlers) summarizeListener(
	listener *listeners.Listener,
	windowStart time.Time,
	buildFailures map[string]int,
) listenerTelemetry {
	snapshot := listener.Snapshot()
	entry := listenerTelemetry{
		ID:             snapshot.Config.ID,
		Name:           snapshot.Config.Name,
		Protocol:       snapshot.Config.Protocol,
		Port:           snapshot.Config.Port,
		Status:         string(snapshot.Status),
		Health:         HealthStateHealthy,
		LastErrorClass: classifyListenerError(snapshot.Error),
	}

	statsAvailable := false
	provider, ok := listener.Protocol.(interface {
		RuntimeStats(failedSince time.Time) (behaviour.RuntimeStats, error)
	})
	if ok {
		stats, err := provider.RuntimeStats(windowStart)
		if err != nil {
			log.Printf("[ERROR] Failed to load listener runtime stats: %v", err)
			entry.LastErrorClass = listenerErrorClassTelemetryUnavailable
		} else {
			statsAvailable = true
			entry.ActiveAgents = stats.ActiveAgents
			entry.QueueDepth = stats.PendingTasks
			entry.RecentTaskFailures = stats.RecentFailedTasks
		}
	}
	entry.RecentBuildFailures = buildFailures[snapshot.Config.ID]

	switch {
	case snapshot.Status == listeners.StatusError:
		entry.Health = HealthStateFailing
	case ok && !statsAvailable:
		// Telemetry for this listener could not be read; treat it as failing
		// rather than reporting unverifiable zeros.
		entry.Health = HealthStateFailing
	case snapshot.Status == listeners.StatusActive &&
		(entry.RecentTaskFailures > 0 || entry.RecentBuildFailures > 0):
		entry.Health = HealthStateDegraded
	}
	return entry
}

// recentBuildFailures counts failed and interrupted payload builds per
// listener since windowStart. Completed builds whose artifacts later fail
// reconciliation (missing/corrupt) are not build failures and stay out of
// this indicator.
func (h *HealthHandlers) recentBuildFailures(
	windowStart time.Time,
) (map[string]int, int, error) {
	counts := make(map[string]int)
	if h.database == nil || h.database.SQL() == nil {
		return counts, 0, nil
	}
	rows, err := h.database.SQL().Query(
		`SELECT listener_id, COUNT(*)
		 FROM payload_builds
		 WHERE state IN ('failed', 'interrupted') AND created_at >= ?
		 GROUP BY listener_id`,
		windowStart.UTC().Format(buildFailureWindowLayout),
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	total := 0
	for rows.Next() {
		var listenerID string
		var count int
		if err := rows.Scan(&listenerID, &count); err != nil {
			return nil, 0, err
		}
		counts[listenerID] = count
		total += count
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return counts, total, nil
}

// storageState performs the cheapest possible durable-storage check. It runs
// on every readiness and telemetry request, so it must stay a trivial
// constant-time probe rather than a schema or content scan.
func (h *HealthHandlers) storageState() string {
	if h.database == nil || h.database.SQL() == nil {
		return storageStateDisabled
	}
	var one int
	if err := h.database.SQL().QueryRow("SELECT 1").Scan(&one); err != nil {
		log.Printf("[ERROR] Durable storage readiness probe failed: %v", err)
		return storageStateUnavailable
	}
	return storageStateOK
}

func (h *HealthHandlers) uptimeSeconds() int64 {
	uptime := h.now().UTC().Sub(h.startedAt)
	if uptime < 0 {
		return 0
	}
	return int64(uptime / time.Second)
}

// classifyListenerError maps a raw listener error string to a fixed category.
// Raw errors can embed certificate paths, bind addresses, and TLS library
// internals, none of which may leave the process through telemetry.
func classifyListenerError(raw string) string {
	if raw == "" {
		return ""
	}
	lowered := strings.ToLower(raw)
	switch {
	case strings.Contains(lowered, "bind"),
		strings.Contains(lowered, "address already in use"),
		strings.Contains(lowered, "listen tcp"):
		return listenerErrorClassBindFailed
	case strings.Contains(lowered, "certificate"),
		strings.Contains(lowered, "tls"),
		strings.Contains(lowered, "x509"):
		return listenerErrorClassTLSConfigInvalid
	default:
		return listenerErrorClassRuntimeError
	}
}

func worstHealth(current, next string) string {
	rank := map[string]int{
		HealthStateHealthy:  0,
		HealthStateDegraded: 1,
		HealthStateFailing:  2,
	}
	if rank[next] > rank[current] {
		return next
	}
	return current
}
