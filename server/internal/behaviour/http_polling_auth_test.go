package behaviour

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"microc2/server/internal/common"
	"microc2/server/internal/enrollment"
	"microc2/server/internal/persistence"
	"microc2/server/internal/tasks"
)

func TestAuthenticatedPollingProtectsTaskLifecycle(t *testing.T) {
	fixture := newPollingAuthFixture(t)
	bootstrap := fixture.addPayload(t, "listener-one", "payload-one", 1)
	protocol := fixture.protocol(t, "listener-one")
	handler := protocol.GetHTTPHandler()

	expiresIn := 300
	queued, err := protocol.CreateTask("agent-one", tasks.CreateRequest{
		SchemaVersion:    tasks.SchemaVersion,
		Type:             tasks.TypeShell,
		Arguments:        tasks.ShellArguments{Command: "whoami"},
		TimeoutSeconds:   30,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("queue task: %v", err)
	}

	response := serveAgentRequest(
		handler,
		http.MethodGet,
		"/api/agent/agent-one/tasks",
		"",
		nil,
	)
	assertAgentStatus(t, response, http.StatusUnauthorized)
	if task, err := protocol.GetTask("agent-one", queued.ID); err != nil {
		t.Fatalf("read protected queued task: %v", err)
	} else if task.Status != tasks.StatusQueued {
		t.Fatalf("unauthorized poll changed task status to %q", task.Status)
	}

	response = serveHeartbeat(
		t,
		handler,
		"listener-one",
		"payload-one",
		"agent-one",
		"wrong-bootstrap",
	)
	assertAgentStatus(t, response, http.StatusUnauthorized)
	if len(protocol.GetAllAgents()) != 0 {
		t.Fatalf("unauthorized heartbeat registered an agent: %#v", protocol.GetAllAgents())
	}

	response = serveHeartbeat(
		t,
		handler,
		"listener-one",
		"payload-one",
		"agent-one",
		bootstrap.Public,
	)
	assertAgentStatus(t, response, http.StatusOK)
	session := heartbeatSessionCredential(t, response)
	if session == "" || session == bootstrap.Public {
		t.Fatal("bootstrap heartbeat did not return a distinct session credential")
	}
	if strings.Contains(response.Body.String(), bootstrap.Public) {
		t.Fatal("heartbeat response reflected the bootstrap credential")
	}

	response = serveHeartbeat(
		t,
		handler,
		"listener-one",
		"payload-two",
		"agent-one",
		session,
	)
	assertAgentStatus(t, response, http.StatusUnauthorized)

	response = serveAgentRequest(
		handler,
		http.MethodGet,
		"/api/agent/agent-two/tasks",
		session,
		nil,
	)
	assertAgentStatus(t, response, http.StatusUnauthorized)

	response = serveAgentRequest(
		handler,
		http.MethodGet,
		"/api/agent/agent-one/tasks",
		session,
		nil,
	)
	assertAgentStatus(t, response, http.StatusOK)
	var dispatched tasks.Task
	if err := json.Unmarshal(response.Body.Bytes(), &dispatched); err != nil {
		t.Fatalf("decode dispatched task: %v", err)
	}

	startedAt := dispatched.DispatchedAt.Add(time.Second)
	statusBody := marshalAgentJSON(t, tasks.StatusUpdate{
		SchemaVersion: tasks.SchemaVersion,
		TaskID:        dispatched.ID,
		AgentID:       "agent-one",
		Status:        tasks.StatusRunning,
		Timestamp:     startedAt,
	})
	response = serveAgentRequest(
		handler,
		http.MethodPost,
		"/api/agent/agent-one/tasks/"+dispatched.ID+"/status",
		"wrong-session",
		statusBody,
	)
	assertAgentStatus(t, response, http.StatusUnauthorized)
	if task, err := protocol.GetTask("agent-one", queued.ID); err != nil {
		t.Fatalf("read task after forged status: %v", err)
	} else if task.Status != tasks.StatusDispatched {
		t.Fatalf("forged status changed task status to %q", task.Status)
	}

	response = serveAgentRequest(
		handler,
		http.MethodPost,
		"/api/agent/agent-one/tasks/"+dispatched.ID+"/status",
		session,
		statusBody,
	)
	assertAgentStatus(t, response, http.StatusOK)

	exitCode := 0
	resultBody := marshalAgentJSON(t, tasks.Result{
		SchemaVersion: tasks.SchemaVersion,
		TaskID:        dispatched.ID,
		AgentID:       "agent-one",
		Outcome:       tasks.OutcomeCompleted,
		StartedAt:     startedAt,
		CompletedAt:   startedAt.Add(time.Second),
		ExitCode:      &exitCode,
		Output:        tasks.Output{Stdout: "operator\n"},
	})
	response = serveAgentRequest(
		handler,
		http.MethodPost,
		"/api/agent/agent-one/results",
		"",
		resultBody,
	)
	assertAgentStatus(t, response, http.StatusUnauthorized)
	if task, err := protocol.GetTask("agent-one", queued.ID); err != nil {
		t.Fatalf("read task after forged result: %v", err)
	} else if task.Status != tasks.StatusRunning {
		t.Fatalf("forged result changed task status to %q", task.Status)
	}

	response = serveAgentRequest(
		handler,
		http.MethodPost,
		"/api/agent/agent-one/results",
		session,
		resultBody,
	)
	assertAgentStatus(t, response, http.StatusOK)
}

func TestAuthenticatedPollingRejectsEveryLifecycleRouteWithoutBearer(t *testing.T) {
	fixture := newPollingAuthFixture(t)
	fixture.addPayload(t, "listener-one", "payload-one", 1)
	handler := fixture.protocol(t, "listener-one").GetHTTPHandler()

	requests := []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{
			name:   "task poll",
			method: http.MethodGet,
			path:   "/api/agent/agent-one/tasks",
		},
		{
			name:   "running acknowledgement",
			method: http.MethodPost,
			path:   "/api/agent/agent-one/tasks/task-one/status",
			body:   []byte(`{}`),
		},
		{
			name:   "typed result",
			method: http.MethodPost,
			path:   "/api/agent/agent-one/results",
			body:   []byte(`{}`),
		},
		{
			name:   "legacy command poll",
			method: http.MethodGet,
			path:   "/api/agent/agent-one/command",
		},
		{
			name:   "legacy result",
			method: http.MethodPost,
			path:   "/api/agent/agent-one/result",
			body:   []byte(`{}`),
		},
	}
	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			response := serveAgentRequest(
				handler,
				request.method,
				request.path,
				"",
				request.body,
			)
			assertAgentStatus(t, response, http.StatusUnauthorized)
			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}

func TestAuthenticatedPollingRotationRevocationAndReenrollment(t *testing.T) {
	fixture := newPollingAuthFixture(t)
	bootstrap := fixture.addPayload(t, "listener-one", "payload-one", 1)
	protocol := fixture.protocol(t, "listener-one")
	handler := protocol.GetHTTPHandler()
	current := enrollTestAgent(
		t,
		handler,
		"listener-one",
		"payload-one",
		"agent-one",
		bootstrap.Public,
	)

	rotation, err := fixture.store.Rotate(
		context.Background(),
		"listener-one",
		"agent-one",
	)
	if err != nil {
		t.Fatalf("rotate session: %v", err)
	}
	if rotation.PendingGeneration != 2 || rotation.AlreadyPending {
		t.Fatalf("unexpected rotation metadata: %#v", rotation)
	}

	response := serveHeartbeat(
		t,
		handler,
		"listener-one",
		"payload-one",
		"agent-one",
		current,
	)
	assertAgentStatus(t, response, http.StatusOK)
	replacement := heartbeatSessionCredential(t, response)
	if replacement == "" || replacement == current {
		t.Fatal("rotation heartbeat did not deliver a replacement credential")
	}

	response = serveAgentRequest(
		handler,
		http.MethodGet,
		"/api/agent/agent-one/tasks",
		current,
		nil,
	)
	assertAgentStatus(t, response, http.StatusNoContent)

	response = serveHeartbeat(
		t,
		handler,
		"listener-one",
		"payload-one",
		"agent-one",
		replacement,
	)
	assertAgentStatus(t, response, http.StatusOK)
	if got := heartbeatSessionCredential(t, response); got != "" {
		t.Fatalf("promoted heartbeat returned another credential: %q", got)
	}

	response = serveAgentRequest(
		handler,
		http.MethodGet,
		"/api/agent/agent-one/tasks",
		current,
		nil,
	)
	assertAgentStatus(t, response, http.StatusUnauthorized)

	if err := fixture.store.RevokeSession(
		context.Background(),
		"listener-one",
		"agent-one",
	); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	for name, credential := range map[string]string{
		"revoked session":    replacement,
		"consumed bootstrap": bootstrap.Public,
	} {
		t.Run(name, func(t *testing.T) {
			response := serveHeartbeat(
				t,
				handler,
				"listener-one",
				"payload-one",
				"agent-one",
				credential,
			)
			assertAgentStatus(t, response, http.StatusUnauthorized)
		})
	}

	if err := fixture.store.RequireReenrollment(
		context.Background(),
		"listener-one",
		"agent-one",
	); err != nil {
		t.Fatalf("require re-enrollment: %v", err)
	}
	response = serveHeartbeat(
		t,
		handler,
		"listener-one",
		"payload-one",
		"agent-one",
		bootstrap.Public,
	)
	assertAgentStatus(t, response, http.StatusOK)
	reenrolled := heartbeatSessionCredential(t, response)
	if reenrolled == "" || reenrolled == replacement || reenrolled == current {
		t.Fatal("explicit re-enrollment did not replace the revoked session")
	}
}

func TestAuthenticatedPollingIsolatesListenersAndBoundsEnrollment(t *testing.T) {
	fixture := newPollingAuthFixture(t)
	firstBootstrap := fixture.addPayload(t, "listener-one", "payload-one", 1)
	secondBootstrap := fixture.addPayload(t, "listener-two", "payload-two", 1)
	first := fixture.protocol(t, "listener-one")
	second := fixture.protocol(t, "listener-two")

	firstSession := enrollTestAgent(
		t,
		first.GetHTTPHandler(),
		"listener-one",
		"payload-one",
		"duplicate-agent",
		firstBootstrap.Public,
	)
	secondSession := enrollTestAgent(
		t,
		second.GetHTTPHandler(),
		"listener-two",
		"payload-two",
		"duplicate-agent",
		secondBootstrap.Public,
	)
	if firstSession == secondSession {
		t.Fatal("duplicate runtime IDs across listeners shared a session")
	}

	response := serveHeartbeat(
		t,
		second.GetHTTPHandler(),
		"listener-two",
		"payload-two",
		"duplicate-agent",
		firstSession,
	)
	assertAgentStatus(t, response, http.StatusUnauthorized)

	response = serveHeartbeat(
		t,
		first.GetHTTPHandler(),
		"listener-one",
		"payload-one",
		"second-agent",
		firstBootstrap.Public,
	)
	assertAgentStatus(t, response, http.StatusConflict)
	if !strings.Contains(response.Body.String(), "capacity") {
		t.Fatalf("capacity response was not actionable: %q", response.Body.String())
	}
}

func TestAuthenticatedPollingEvictsOldestRuntimePresenceAtCapacity(
	t *testing.T,
) {
	fixture := newPollingAuthFixture(t)
	bootstrap := fixture.addPayload(t, "listener-one", "payload-one", 1)
	protocol := fixture.protocol(t, "listener-one")
	oldestID := fillRuntimeAgentCache(t, protocol)
	protocol.agents.Lock()
	oldest := *protocol.agents.list[oldestID]
	protocol.agents.Unlock()
	if err := protocol.persistAgent(oldest); err != nil {
		t.Fatalf("persist oldest runtime history: %v", err)
	}

	response := serveHeartbeat(
		t,
		protocol.GetHTTPHandler(),
		"listener-one",
		"payload-one",
		"new-agent",
		bootstrap.Public,
	)
	assertAgentStatus(t, response, http.StatusOK)
	session := heartbeatSessionCredential(t, response)
	if session == "" {
		t.Fatal("capacity-bound enrollment omitted its session credential")
	}

	protocol.agents.Lock()
	cacheSize := len(protocol.agents.list)
	_, oldestRetained := protocol.agents.list[oldestID]
	_, newcomerRetained := protocol.agents.list["new-agent"]
	_, oldestActive := protocol.agents.activeThisBoot[oldestID]
	newcomerActive := protocol.agents.activeThisBoot["new-agent"]
	protocol.agents.Unlock()
	if cacheSize != enrollment.MaxListenerSessions {
		t.Fatalf(
			"runtime cache size = %d, want %d",
			cacheSize,
			enrollment.MaxListenerSessions,
		)
	}
	if oldestRetained || oldestActive {
		t.Fatalf("oldest runtime agent %q was not fully evicted", oldestID)
	}
	if !newcomerRetained || !newcomerActive {
		t.Fatal("authenticated newcomer was not retained as active")
	}
	var durableOldest int
	if err := fixture.database.SQL().QueryRow(
		`SELECT COUNT(*)
		 FROM agents
		 WHERE listener_id = ?
		   AND agent_id = ?`,
		"listener-one",
		oldestID,
	).Scan(&durableOldest); err != nil {
		t.Fatalf("read evicted durable history: %v", err)
	}
	if durableOldest != 1 {
		t.Fatalf("eviction removed durable history for %q", oldestID)
	}

	response = serveAgentRequest(
		protocol.GetHTTPHandler(),
		http.MethodGet,
		"/api/agent/new-agent/tasks",
		session,
		nil,
	)
	assertAgentStatus(t, response, http.StatusNoContent)
}

func TestAuthenticatedPollingRejectsDirectHeartbeatCompatibilityPath(
	t *testing.T,
) {
	fixture := newPollingAuthFixture(t)
	protocol := fixture.protocol(t, "listener-one")
	body := marshalAgentJSON(t, Agent{
		ID:         "agent-one",
		ListenerID: "listener-one",
		PayloadID:  "payload-one",
		OS:         "linux",
		Hostname:   "test-host",
		IP:         "127.0.0.1",
	})

	err := protocol.HandleAgentHeartbeat(body)
	if err == nil ||
		!strings.Contains(err.Error(), "HTTP enrollment path") {
		t.Fatalf("direct authenticated heartbeat error = %v", err)
	}
	if len(protocol.GetAllAgents()) != 0 {
		t.Fatal("direct compatibility heartbeat changed authenticated state")
	}
}

func TestAuthenticatedPollingRequiresFreshHeartbeatAfterRestart(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "microc2.db")
	database, err := persistence.Open(databasePath)
	if err != nil {
		t.Fatalf("open first database: %v", err)
	}
	fixture := &pollingAuthFixture{
		database: database,
		store:    newEnrollmentStore(t, database),
	}
	bootstrap := fixture.addPayload(t, "listener-one", "payload-one", 1)
	first := fixture.protocol(t, "listener-one")
	session := enrollTestAgent(
		t,
		first.GetHTTPHandler(),
		"listener-one",
		"payload-one",
		"agent-one",
		bootstrap.Public,
	)
	if err := database.Close(); err != nil {
		t.Fatalf("close first database: %v", err)
	}

	reopened, err := persistence.Open(databasePath)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened database: %v", err)
		}
	})
	restarted, err := NewAuthenticatedHTTPPollingProtocolWithPersistence(
		common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"},
		reopened,
		"listener-one",
	)
	if err != nil {
		t.Fatalf("create restarted authenticated protocol: %v", err)
	}

	response := serveAgentRequest(
		restarted.GetHTTPHandler(),
		http.MethodGet,
		"/api/agent/agent-one/tasks",
		session,
		nil,
	)
	assertAgentStatus(t, response, http.StatusUnauthorized)

	response = serveAgentRequest(
		restarted.GetHTTPHandler(),
		http.MethodPost,
		"/api/agent/agent-one/heartbeat",
		session,
		marshalAgentJSON(t, Agent{
			ID:         "agent-one",
			ListenerID: "listener-one",
			PayloadID:  "payload-one",
			OS:         "linux",
			Hostname:   "test-host",
			IP:         "127.0.0.1",
			IPList:     []string{"127.0.0.1"},
			Commands:   []string{},
			ModuleIDs:  []string{"agent.capability_inventory.v1"},
		}),
	)
	assertAgentStatus(t, response, http.StatusOK)
	expiresIn := 120
	queued, err := restarted.CreateModuleTask("agent-one", tasks.ModuleCreateRequest{
		SchemaVersion:    tasks.SchemaVersion,
		ModuleID:         "agent.capability_inventory.v1",
		Input:            json.RawMessage(`{}`),
		TimeoutSeconds:   5,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("create module task after fresh authenticated heartbeat: %v", err)
	}
	response = serveAgentRequest(
		restarted.GetHTTPHandler(),
		http.MethodGet,
		"/api/agent/agent-one/tasks",
		session,
		nil,
	)
	assertAgentStatus(t, response, http.StatusOK)
	var dispatched tasks.Task
	if err := json.Unmarshal(response.Body.Bytes(), &dispatched); err != nil ||
		dispatched.ID != queued.ID || dispatched.Type != tasks.TypeModule {
		t.Fatalf("fresh heartbeat did not restore module lease: task=%#v err=%v", dispatched, err)
	}
}

func fillRuntimeAgentCache(
	t *testing.T,
	protocol *HTTPPollingProtocol,
) string {
	t.Helper()
	base := time.Date(2026, time.July, 23, 0, 0, 0, 0, time.UTC)
	protocol.agents.Lock()
	defer protocol.agents.Unlock()
	for index := 0; index < enrollment.MaxListenerSessions; index++ {
		agentID := fmt.Sprintf("cached-agent-%04d", index)
		protocol.agents.list[agentID] = &Agent{
			ID:         agentID,
			ListenerID: protocol.listenerID,
			LastSeen:   base.Add(time.Duration(index) * time.Second),
		}
		protocol.agents.activeThisBoot[agentID] = true
	}
	return "cached-agent-0000"
}

type pollingAuthFixture struct {
	database *persistence.Database
	store    *enrollment.Store
}

func newPollingAuthFixture(t *testing.T) *pollingAuthFixture {
	t.Helper()
	database, err := persistence.Open(filepath.Join(t.TempDir(), "microc2.db"))
	if err != nil {
		t.Fatalf("open enrollment database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close enrollment database: %v", err)
		}
	})
	return &pollingAuthFixture{
		database: database,
		store:    newEnrollmentStore(t, database),
	}
}

func newEnrollmentStore(
	t *testing.T,
	database *persistence.Database,
) *enrollment.Store {
	t.Helper()
	store, err := enrollment.NewStore(context.Background(), database)
	if err != nil {
		t.Fatalf("create enrollment store: %v", err)
	}
	return store
}

func (fixture *pollingAuthFixture) addPayload(
	t *testing.T,
	listenerID string,
	payloadID string,
	maxSessions int,
) enrollment.BootstrapCredential {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := fixture.database.SQL().Exec(
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
		1,
		strings.Repeat("a", 64),
		now,
		"completed",
		"",
		[]byte("{}"),
	); err != nil {
		t.Fatalf("insert completed payload: %v", err)
	}
	bootstrap, err := enrollment.GenerateBootstrapCredential()
	if err != nil {
		t.Fatalf("generate bootstrap credential: %v", err)
	}
	if err := fixture.store.ActivatePayloadCredential(
		context.Background(),
		enrollment.PayloadCredentialActivation{
			PayloadBuildID:  payloadID,
			ListenerID:      listenerID,
			BootstrapSHA256: bootstrap.SHA256,
			MaxSessions:     maxSessions,
		},
	); err != nil {
		t.Fatalf("activate payload credential: %v", err)
	}
	return bootstrap
}

func (fixture *pollingAuthFixture) protocol(
	t *testing.T,
	listenerID string,
) *HTTPPollingProtocol {
	t.Helper()
	protocol, err := NewAuthenticatedHTTPPollingProtocolWithPersistence(
		common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"},
		fixture.database,
		listenerID,
	)
	if err != nil {
		t.Fatalf("create authenticated polling protocol: %v", err)
	}
	return protocol
}

func enrollTestAgent(
	t *testing.T,
	handler http.Handler,
	listenerID string,
	payloadID string,
	agentID string,
	bootstrap string,
) string {
	t.Helper()
	response := serveHeartbeat(
		t,
		handler,
		listenerID,
		payloadID,
		agentID,
		bootstrap,
	)
	assertAgentStatus(t, response, http.StatusOK)
	session := heartbeatSessionCredential(t, response)
	if session == "" {
		t.Fatal("enrollment heartbeat omitted session credential")
	}
	return session
}

func serveHeartbeat(
	t *testing.T,
	handler http.Handler,
	listenerID string,
	payloadID string,
	agentID string,
	credential string,
) *httptest.ResponseRecorder {
	t.Helper()
	body := marshalAgentJSON(t, Agent{
		ID:         agentID,
		ListenerID: listenerID,
		PayloadID:  payloadID,
		OS:         "linux",
		Hostname:   "test-host",
		IP:         "127.0.0.1",
		IPList:     []string{"127.0.0.1"},
		Commands:   []string{},
	})
	return serveAgentRequest(
		handler,
		http.MethodPost,
		"/api/agent/"+agentID+"/heartbeat",
		credential,
		body,
	)
}

func serveAgentRequest(
	handler http.Handler,
	method string,
	path string,
	credential string,
	body []byte,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if credential != "" {
		request.Header.Set("Authorization", "Bearer "+credential)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func heartbeatSessionCredential(
	t *testing.T,
	response *httptest.ResponseRecorder,
) string {
	t.Helper()
	var body struct {
		SessionCredential string `json:"session_credential"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode heartbeat response: %v", err)
	}
	return body.SessionCredential
}

func marshalAgentJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal agent request: %v", err)
	}
	return body
}

func assertAgentStatus(
	t *testing.T,
	response *httptest.ResponseRecorder,
	want int,
) {
	t.Helper()
	if response.Code != want {
		t.Fatalf(
			"agent response status = %d, want %d: %s",
			response.Code,
			want,
			response.Body.String(),
		)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}
