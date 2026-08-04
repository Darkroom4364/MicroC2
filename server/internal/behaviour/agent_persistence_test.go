package behaviour

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"microc2/server/internal/common"
	"microc2/server/internal/persistence"
	"microc2/server/internal/tasks"
)

func TestPersistedAgentHistoryRequiresFreshHeartbeatAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	database, err := persistence.Open(path)
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	protocol, err := NewHTTPPollingProtocolWithPersistence(
		common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"},
		database,
		"listener-one",
	)
	if err != nil {
		t.Fatalf("create durable protocol: %v", err)
	}
	heartbeat := []byte(
		`{"id":"agent-one","listener_id":"attacker-scope","payload_id":"payload-one",` +
			`"os":"linux","hostname":"host-one","ip":"127.0.0.1",` +
			`"ip_list":["127.0.0.1"],"last_commands":["whoami"]}`,
	)
	if err := protocol.HandleAgentHeartbeat(heartbeat); err != nil {
		t.Fatalf("persist heartbeat: %v", err)
	}
	if _, known := protocol.AgentLastSeen("agent-one"); !known {
		t.Fatal("fresh heartbeat was not active")
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close first database: %v", err)
	}

	database, err = persistence.Open(path)
	if err != nil {
		t.Fatalf("reopen persistence database: %v", err)
	}
	defer database.Close()
	restarted, err := NewHTTPPollingProtocolWithPersistence(
		common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"},
		database,
		"listener-one",
	)
	if err != nil {
		t.Fatalf("reload durable protocol: %v", err)
	}
	agents := restarted.GetAllAgents()
	value, ok := agents["agent-one"]
	if !ok {
		t.Fatalf("persisted agent history missing after restart: %#v", agents)
	}
	agent, ok := value.(*Agent)
	if !ok {
		t.Fatalf("persisted agent has unexpected type %T", value)
	}
	if agent.ListenerID != "listener-one" {
		t.Fatalf(
			"heartbeat-selected listener scope was trusted: got %q",
			agent.ListenerID,
		)
	}
	if lastSeen, known := restarted.AgentLastSeen("agent-one"); !known || !lastSeen.IsZero() {
		t.Fatalf(
			"persisted agent should be known but inactive: last_seen=%v known=%t",
			lastSeen,
			known,
		)
	}

	if err := restarted.HandleAgentHeartbeat(heartbeat); err != nil {
		t.Fatalf("refresh heartbeat after restart: %v", err)
	}
	if lastSeen, known := restarted.AgentLastSeen("agent-one"); !known || lastSeen.IsZero() {
		t.Fatalf(
			"fresh post-restart heartbeat was not active: last_seen=%v known=%t",
			lastSeen,
			known,
		)
	}
}

func TestPersistedModuleEligibilityRequiresFreshHeartbeat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	database, err := persistence.Open(path)
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	protocol, err := NewHTTPPollingProtocolWithPersistence(
		common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"},
		database,
		"listener-one",
	)
	if err != nil {
		t.Fatalf("create durable protocol: %v", err)
	}
	heartbeat := []byte(
		`{"id":"agent-one","os":"linux","hostname":"host-one","ip":"127.0.0.1",` +
			`"module_ids":["agent.capability_inventory.v1"]}`,
	)
	if err := protocol.HandleAgentHeartbeat(heartbeat); err != nil {
		t.Fatalf("record module heartbeat: %v", err)
	}
	expiresIn := 120
	queued, err := protocol.CreateModuleTask("agent-one", tasks.ModuleCreateRequest{
		SchemaVersion:    tasks.SchemaVersion,
		ModuleID:         "agent.capability_inventory.v1",
		Input:            json.RawMessage(`{}`),
		TimeoutSeconds:   5,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("queue module task: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close first database: %v", err)
	}

	database, err = persistence.Open(path)
	if err != nil {
		t.Fatalf("reopen persistence database: %v", err)
	}
	defer database.Close()
	restarted, err := NewHTTPPollingProtocolWithPersistence(
		common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"},
		database,
		"listener-one",
	)
	if err != nil {
		t.Fatalf("reload durable protocol: %v", err)
	}
	if _, err := restarted.CreateModuleTask("agent-one", tasks.ModuleCreateRequest{
		SchemaVersion:    tasks.SchemaVersion,
		ModuleID:         "agent.capability_inventory.v1",
		Input:            json.RawMessage(`{}`),
		TimeoutSeconds:   5,
		ExpiresInSeconds: &expiresIn,
	}); err == nil {
		t.Fatal("created module from persisted heartbeat eligibility")
	}
	recorder := httptest.NewRecorder()
	restarted.GetHTTPHandler().ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodGet, "/api/agent/agent-one/tasks", nil),
	)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("persisted module dispatched before fresh heartbeat: %d: %s", recorder.Code, recorder.Body.String())
	}
	history, err := restarted.ListTasks("agent-one")
	if err != nil || len(history) != 1 || history[0].ID != queued.ID ||
		history[0].Status != tasks.StatusCancelled {
		t.Fatalf("persisted module quarantine history=%#v err=%v", history, err)
	}
}

func TestPersistedAgentsRemainListenerScoped(t *testing.T) {
	database, err := persistence.Open(filepath.Join(t.TempDir(), "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer database.Close()

	first, err := NewHTTPPollingProtocolWithPersistence(
		common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"},
		database,
		"listener-one",
	)
	if err != nil {
		t.Fatalf("create first protocol: %v", err)
	}
	second, err := NewHTTPPollingProtocolWithPersistence(
		common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"},
		database,
		"listener-two",
	)
	if err != nil {
		t.Fatalf("create second protocol: %v", err)
	}
	for protocol, hostname := range map[*HTTPPollingProtocol]string{
		first:  "first-host",
		second: "second-host",
	} {
		body, err := json.Marshal(Agent{
			ID:       "agent-shared",
			OS:       "linux",
			Hostname: hostname,
			IP:       "127.0.0.1",
		})
		if err != nil {
			t.Fatalf("marshal heartbeat: %v", err)
		}
		if err := protocol.HandleAgentHeartbeat(body); err != nil {
			t.Fatalf("persist heartbeat for %s: %v", hostname, err)
		}
	}

	firstAgent := first.GetAllAgents()["agent-shared"].(*Agent)
	secondAgent := second.GetAllAgents()["agent-shared"].(*Agent)
	if firstAgent.Hostname != "first-host" ||
		firstAgent.ListenerID != "listener-one" ||
		secondAgent.Hostname != "second-host" ||
		secondAgent.ListenerID != "listener-two" {
		t.Fatalf(
			"listener-scoped agents crossed: first=%#v second=%#v",
			firstAgent,
			secondAgent,
		)
	}
}

func TestHeartbeatPersistenceFailureReturnsGenericServerError(t *testing.T) {
	database, err := persistence.Open(filepath.Join(t.TempDir(), "microc2.db"))
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	protocol, err := NewHTTPPollingProtocolWithPersistence(
		common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"},
		database,
		"listener-one",
	)
	if err != nil {
		t.Fatalf("create durable protocol: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close persistence database: %v", err)
	}

	body := []byte(
		`{"id":"agent-one","os":"linux","hostname":"host-one","ip":"127.0.0.1"}`,
	)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/agent/agent-one/heartbeat",
		bytes.NewReader(body),
	)
	response := httptest.NewRecorder()
	protocol.GetHTTPHandler().ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf(
			"persistence failure status = %d, want %d: %s",
			response.Code,
			http.StatusInternalServerError,
			response.Body.String(),
		)
	}
	if strings.Contains(strings.ToLower(response.Body.String()), "database") {
		t.Fatalf("response disclosed storage failure details: %q", response.Body.String())
	}
}
