package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"microc2/server/internal/behaviour"
	"microc2/server/internal/listeners"
	"microc2/server/internal/persistence"
	"microc2/server/internal/tasks"
)

func TestHealthEndpointReportsLiveness(t *testing.T) {
	clock := healthTestClock()
	handler := newHealthHandlersWithClock(nil, nil, clock)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	response := serveHealthRequest(mux, http.MethodGet, "/api/health")
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d: %s", response.Code, response.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("health status field = %#v, want ok", body["status"])
	}
	if body["uptime_seconds"] != float64(0) {
		t.Fatalf("uptime_seconds = %#v, want 0 with a frozen clock", body["uptime_seconds"])
	}

	response = serveHealthRequest(mux, http.MethodPost, "/api/health")
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/health status = %d, want 405", response.Code)
	}
}

func TestReadyEndpointStorageStates(t *testing.T) {
	t.Run("no storage configured", func(t *testing.T) {
		handler := newHealthHandlersWithClock(nil, nil, time.Now)
		response := serveHealthRequest(healthTestMux(handler), http.MethodGet, "/api/ready")
		assertReadyResponse(t, response, http.StatusOK, "ready", storageStateDisabled)
	})

	t.Run("healthy storage", func(t *testing.T) {
		database := openHealthTestDatabase(t)
		handler := newHealthHandlersWithClock(nil, database, time.Now)
		response := serveHealthRequest(healthTestMux(handler), http.MethodGet, "/api/ready")
		assertReadyResponse(t, response, http.StatusOK, "ready", storageStateOK)
	})

	t.Run("unavailable storage", func(t *testing.T) {
		database := openHealthTestDatabase(t)
		if err := database.Close(); err != nil {
			t.Fatalf("close database: %v", err)
		}
		handler := newHealthHandlersWithClock(nil, database, time.Now)
		response := serveHealthRequest(healthTestMux(handler), http.MethodGet, "/api/ready")
		assertReadyResponse(
			t,
			response,
			http.StatusServiceUnavailable,
			"not_ready",
			storageStateUnavailable,
		)
	})

	t.Run("rejects non-GET methods", func(t *testing.T) {
		handler := newHealthHandlersWithClock(nil, nil, time.Now)
		response := serveHealthRequest(healthTestMux(handler), http.MethodPost, "/api/ready")
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST /api/ready status = %d, want 405", response.Code)
		}
	})
}

func TestTelemetryHealthyActiveListener(t *testing.T) {
	manager := newHealthTestManager(t)
	listener, proto := addHealthTestListener(t, manager, "listener-one", 49101)
	heartbeatHealthTestAgent(t, proto, "agent-health-one")
	listener.Status = listeners.StatusActive
	createHealthTestTask(t, proto, "agent-health-one", "whoami")

	handler := newHealthHandlersWithClock(manager, nil, time.Now)
	response := serveHealthRequest(healthTestMux(handler), http.MethodGet, "/api/telemetry")
	if response.Code != http.StatusOK {
		t.Fatalf("telemetry status = %d: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "agent-health-one") {
		t.Fatalf("telemetry leaked an agent identifier: %s", response.Body.String())
	}

	body := decodeTelemetryResponse(t, response)
	if body.Status != HealthStateHealthy {
		t.Fatalf("server health = %q, want healthy", body.Status)
	}
	if body.Storage != storageStateDisabled {
		t.Fatalf("storage = %q, want disabled", body.Storage)
	}
	if body.Builds.RecentFailures != 0 {
		t.Fatalf("recent build failures = %d, want 0", body.Builds.RecentFailures)
	}
	if len(body.Listeners) != 1 {
		t.Fatalf("listeners = %#v, want exactly one", body.Listeners)
	}
	entry := body.Listeners[0]
	if entry.ID != "listener-one" || entry.Status != string(listeners.StatusActive) {
		t.Fatalf("unexpected listener entry: %#v", entry)
	}
	if entry.Health != HealthStateHealthy {
		t.Fatalf("listener health = %q, want healthy", entry.Health)
	}
	if entry.ActiveAgents != 1 {
		t.Fatalf("active agents = %d, want 1", entry.ActiveAgents)
	}
	if entry.QueueDepth != 1 {
		t.Fatalf("queue depth = %d, want 1 queued task", entry.QueueDepth)
	}
	if entry.RecentTaskFailures != 0 || entry.RecentBuildFailures != 0 {
		t.Fatalf("unexpected failure counters: %#v", entry)
	}
	if entry.LastErrorClass != "" {
		t.Fatalf("last error class = %q, want empty", entry.LastErrorClass)
	}
}

func TestTelemetryErroredListenerFailsAndSanitizesError(t *testing.T) {
	manager := newHealthTestManager(t)
	listener, _ := addHealthTestListener(t, manager, "listener-two", 49102)
	listener.SetError(errors.New(
		"failed to load TLS certificate for listener listener-two: " +
			"open /etc/private/certs/listener.pem: no such file or directory",
	))

	handler := newHealthHandlersWithClock(manager, nil, time.Now)
	response := serveHealthRequest(healthTestMux(handler), http.MethodGet, "/api/telemetry")
	if response.Code != http.StatusOK {
		t.Fatalf("telemetry status = %d: %s", response.Code, response.Body.String())
	}
	for _, leaked := range []string{
		"/etc/private/certs/listener.pem",
		"no such file or directory",
	} {
		if strings.Contains(response.Body.String(), leaked) {
			t.Fatalf("telemetry leaked raw error internals %q: %s", leaked, response.Body.String())
		}
	}

	body := decodeTelemetryResponse(t, response)
	if body.Status != HealthStateFailing {
		t.Fatalf("server health = %q, want failing", body.Status)
	}
	if len(body.Listeners) != 1 {
		t.Fatalf("listeners = %#v, want exactly one", body.Listeners)
	}
	entry := body.Listeners[0]
	if entry.Health != HealthStateFailing {
		t.Fatalf("listener health = %q, want failing", entry.Health)
	}
	if entry.Status != string(listeners.StatusError) {
		t.Fatalf("listener status = %q, want ERROR", entry.Status)
	}
	if entry.LastErrorClass != listenerErrorClassTLSConfigInvalid {
		t.Fatalf("last error class = %q, want tls_config_invalid", entry.LastErrorClass)
	}
}

func TestTelemetryDegradedListenerWithQueueAndRecentTaskFailure(t *testing.T) {
	manager := newHealthTestManager(t)
	listener, proto := addHealthTestListener(t, manager, "listener-three", 49103)
	heartbeatHealthTestAgent(t, proto, "agent-health-three")
	listener.Status = listeners.StatusActive

	failedTask := createHealthTestTask(t, proto, "agent-health-three", "id")
	createHealthTestTask(t, proto, "agent-health-three", "uname -a")
	failHealthTestTask(t, proto, failedTask)

	handler := newHealthHandlersWithClock(manager, nil, time.Now)
	response := serveHealthRequest(healthTestMux(handler), http.MethodGet, "/api/telemetry")
	if response.Code != http.StatusOK {
		t.Fatalf("telemetry status = %d: %s", response.Code, response.Body.String())
	}

	body := decodeTelemetryResponse(t, response)
	if body.Status != HealthStateDegraded {
		t.Fatalf("server health = %q, want degraded", body.Status)
	}
	if len(body.Listeners) != 1 {
		t.Fatalf("listeners = %#v, want exactly one", body.Listeners)
	}
	entry := body.Listeners[0]
	if entry.Health != HealthStateDegraded {
		t.Fatalf("listener health = %q, want degraded", entry.Health)
	}
	if entry.QueueDepth != 1 {
		t.Fatalf("queue depth = %d, want 1 remaining queued task", entry.QueueDepth)
	}
	if entry.RecentTaskFailures != 1 {
		t.Fatalf("recent task failures = %d, want 1", entry.RecentTaskFailures)
	}
}

func TestTelemetryRecentBuildFailures(t *testing.T) {
	database := openHealthTestDatabase(t)
	manager := newHealthTestManager(t)
	listener, proto := addHealthTestListener(t, manager, "listener-builds", 49104)
	heartbeatHealthTestAgent(t, proto, "agent-health-builds")
	listener.Status = listeners.StatusActive

	now := time.Now().UTC()
	insertHealthTestPayloadBuild(t, database, "build-recent-failed", "listener-builds",
		"failed", now.Add(-30*time.Minute))
	insertHealthTestPayloadBuild(t, database, "build-old-failed", "listener-builds",
		"failed", now.Add(-2*time.Hour))
	insertHealthTestPayloadBuild(t, database, "build-recent-completed", "listener-builds",
		"completed", now.Add(-10*time.Minute))

	handler := newHealthHandlersWithClock(manager, database, time.Now)
	response := serveHealthRequest(healthTestMux(handler), http.MethodGet, "/api/telemetry")
	if response.Code != http.StatusOK {
		t.Fatalf("telemetry status = %d: %s", response.Code, response.Body.String())
	}

	body := decodeTelemetryResponse(t, response)
	if body.Status != HealthStateDegraded {
		t.Fatalf("server health = %q, want degraded", body.Status)
	}
	if body.Storage != storageStateOK {
		t.Fatalf("storage = %q, want ok", body.Storage)
	}
	if body.Builds.RecentFailures != 1 {
		t.Fatalf("recent build failures = %d, want 1 inside the window", body.Builds.RecentFailures)
	}
	if len(body.Listeners) != 1 {
		t.Fatalf("listeners = %#v, want exactly one", body.Listeners)
	}
	entry := body.Listeners[0]
	if entry.RecentBuildFailures != 1 {
		t.Fatalf("listener recent build failures = %d, want 1", entry.RecentBuildFailures)
	}
	if entry.Health != HealthStateDegraded {
		t.Fatalf("listener health = %q, want degraded", entry.Health)
	}
}

func TestTelemetryUnavailableStorageMarksServerFailing(t *testing.T) {
	database := openHealthTestDatabase(t)
	if err := database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	handler := newHealthHandlersWithClock(nil, database, time.Now)
	response := serveHealthRequest(healthTestMux(handler), http.MethodGet, "/api/telemetry")
	if response.Code != http.StatusOK {
		t.Fatalf("telemetry status = %d: %s", response.Code, response.Body.String())
	}
	body := decodeTelemetryResponse(t, response)
	if body.Status != HealthStateFailing {
		t.Fatalf("server health = %q, want failing", body.Status)
	}
	if body.Storage != storageStateUnavailable {
		t.Fatalf("storage = %q, want unavailable", body.Storage)
	}
}

func TestTelemetryRejectsNonGetMethods(t *testing.T) {
	handler := newHealthHandlersWithClock(nil, nil, time.Now)
	response := serveHealthRequest(healthTestMux(handler), http.MethodPost, "/api/telemetry")
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /api/telemetry status = %d, want 405", response.Code)
	}
}

func TestClassifyListenerError(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"empty", "", ""},
		{
			"bind conflict",
			"failed to bind listener lab on 0.0.0.0:8080: listen tcp 0.0.0.0:8080: bind: address already in use",
			listenerErrorClassBindFailed,
		},
		{
			"tls certificate path",
			"failed to load TLS certificate for listener lab: open /srv/certs/lab.pem: no such file or directory",
			listenerErrorClassTLSConfigInvalid,
		},
		{
			"tls x509 internals",
			"tls: failed to parse certificate: x509: malformed certificate",
			listenerErrorClassTLSConfigInvalid,
		},
		{
			"unknown runtime error",
			"HTTP server error: unexpected EOF",
			listenerErrorClassRuntimeError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyListenerError(tc.raw); got != tc.want {
				t.Fatalf("classifyListenerError(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func healthTestClock() func() time.Time {
	frozen := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return frozen }
}

func healthTestMux(handler *HealthHandlers) *http.ServeMux {
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	return mux
}

func serveHealthRequest(mux *http.ServeMux, method, path string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
	return recorder
}

func assertReadyResponse(
	t *testing.T,
	response *httptest.ResponseRecorder,
	wantCode int,
	wantStatus string,
	wantStorage string,
) {
	t.Helper()
	if response.Code != wantCode {
		t.Fatalf("ready status = %d, want %d: %s", response.Code, wantCode, response.Body.String())
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode readiness response: %v", err)
	}
	if body.Status != wantStatus {
		t.Fatalf("readiness status = %q, want %q", body.Status, wantStatus)
	}
	if body.Checks["storage"] != wantStorage {
		t.Fatalf("storage check = %q, want %q", body.Checks["storage"], wantStorage)
	}
}

func decodeTelemetryResponse(
	t *testing.T,
	response *httptest.ResponseRecorder,
) telemetryResponse {
	t.Helper()
	var body telemetryResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode telemetry response: %v", err)
	}
	return body
}

func openHealthTestDatabase(t *testing.T) *persistence.Database {
	t.Helper()
	database, err := persistence.Open(filepath.Join(t.TempDir(), "microc2.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() {
		_ = database.Close()
	})
	return database
}

// newHealthTestManager creates a non-durable isolated-lab listener manager.
// The compatibility constructors resolve static/listeners relative to the
// working directory, so tests run inside a temporary directory.
func newHealthTestManager(t *testing.T) *listeners.ListenerManager {
	t.Helper()
	tempDir := t.TempDir()
	oldCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("switch to temp cwd: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldCwd); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})
	return listeners.NewListenerManagerForIsolatedLab(nil)
}

func addHealthTestListener(
	t *testing.T,
	manager *listeners.ListenerManager,
	listenerID string,
	port int,
) (*listeners.Listener, *behaviour.HTTPPollingProtocol) {
	t.Helper()
	listener, err := listeners.NewListenerForIsolatedLab(listeners.ListenerConfig{
		ID:       listenerID,
		Name:     listenerID,
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     port,
	})
	if err != nil {
		t.Fatalf("create listener %s: %v", listenerID, err)
	}
	proto, ok := listener.Protocol.(*behaviour.HTTPPollingProtocol)
	if !ok {
		t.Fatalf("listener %s protocol = %T, want HTTP polling", listenerID, listener.Protocol)
	}
	if err := manager.AddListener(listener); err != nil {
		t.Fatalf("add listener %s: %v", listenerID, err)
	}
	return listener, proto
}

func heartbeatHealthTestAgent(
	t *testing.T,
	proto *behaviour.HTTPPollingProtocol,
	agentID string,
) {
	t.Helper()
	heartbeat := []byte(
		`{"id":"` + agentID + `","os":"linux","hostname":"workstation","ip":"127.0.0.1"}`,
	)
	if err := proto.HandleAgentHeartbeat(heartbeat); err != nil {
		t.Fatalf("register agent heartbeat: %v", err)
	}
}

func createHealthTestTask(
	t *testing.T,
	proto *behaviour.HTTPPollingProtocol,
	agentID string,
	command string,
) tasks.Task {
	t.Helper()
	expiresIn := 300
	task, err := proto.CreateTask(agentID, tasks.CreateRequest{
		SchemaVersion:    tasks.SchemaVersion,
		Type:             tasks.TypeShell,
		Arguments:        tasks.ShellArguments{Command: command},
		TimeoutSeconds:   30,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("create task %q: %v", command, err)
	}
	return task
}

// failHealthTestTask drives one task through dispatch and running into the
// failed terminal state, mirroring completeTypedTask with a failed outcome.
func failHealthTestTask(
	t *testing.T,
	proto *behaviour.HTTPPollingProtocol,
	task tasks.Task,
) {
	t.Helper()
	handler := proto.GetHTTPHandler()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/agent/"+task.AgentID+"/tasks",
		nil,
	)
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("dispatch task: %d: %s", recorder.Code, recorder.Body.String())
	}
	var dispatched tasks.Task
	if err := json.Unmarshal(recorder.Body.Bytes(), &dispatched); err != nil {
		t.Fatalf("decode dispatched task: %v", err)
	}
	if dispatched.ID != task.ID || dispatched.DispatchedAt == nil {
		t.Fatalf("dispatched task = %#v, want %q", dispatched, task.ID)
	}

	startedAt := dispatched.DispatchedAt.Add(time.Second)
	statusBody, err := json.Marshal(tasks.StatusUpdate{
		SchemaVersion: tasks.SchemaVersion,
		TaskID:        task.ID,
		AgentID:       task.AgentID,
		Status:        tasks.StatusRunning,
		Timestamp:     startedAt,
	})
	if err != nil {
		t.Fatalf("marshal running update: %v", err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(
		http.MethodPost,
		"/api/agent/"+task.AgentID+"/tasks/"+task.ID+"/status",
		bytes.NewReader(statusBody),
	)
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("mark task running: %d: %s", recorder.Code, recorder.Body.String())
	}

	resultBody, err := json.Marshal(tasks.Result{
		SchemaVersion: tasks.SchemaVersion,
		TaskID:        task.ID,
		AgentID:       task.AgentID,
		Outcome:       tasks.OutcomeFailed,
		StartedAt:     startedAt,
		CompletedAt:   startedAt.Add(time.Second),
		Error:         "simulated task failure",
	})
	if err != nil {
		t.Fatalf("marshal failed result: %v", err)
	}
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(
		http.MethodPost,
		"/api/agent/"+task.AgentID+"/results",
		bytes.NewReader(resultBody),
	)
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("fail task: %d: %s", recorder.Code, recorder.Body.String())
	}
}

func insertHealthTestPayloadBuild(
	t *testing.T,
	database *persistence.Database,
	payloadID string,
	listenerID string,
	state string,
	createdAt time.Time,
) {
	t.Helper()
	if _, err := database.SQL().Exec(
		`INSERT INTO payload_builds (
			id, payload_id, listener_id, mutation_seed, filename,
			relative_path, size, sha256, created_at, state,
			state_detail, provenance_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		payloadID,
		payloadID,
		listenerID,
		"0123456789abcdef",
		"agent",
		"release/"+payloadID+"/agent",
		0,
		"",
		createdAt.UTC().Format(time.RFC3339Nano),
		state,
		"",
		[]byte("{}"),
	); err != nil {
		t.Fatalf("insert payload build %s: %v", payloadID, err)
	}
}
