package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"microc2/server/internal/behaviour"
	"microc2/server/internal/listeners"
	"microc2/server/pkg/communication"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestOperatorAPIDoesNotServeAgentPollingRoutes(t *testing.T) {
	handler := NewAPIHandler(nil)
	req := httptest.NewRequest(http.MethodPost, "/api/agent/test/heartbeat", nil)
	rec := httptest.NewRecorder()

	handler.HandleRequest(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected operator API to reject agent polling route with 404, got %d", rec.Code)
	}
}

func TestOperatorAPIQueuesCommandsAndReturnsResults(t *testing.T) {
	handler, proto := newTestAPIHandler(t, "agent-one")

	rec := httptest.NewRecorder()
	req := jsonRequest(t, http.MethodPost, "/api/agents/command", map[string]string{
		"agent_id": "agent-one",
		"command":  "whoami",
	})
	handler.HandleRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected body command route 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertNextAgentCommand(t, proto, "agent-one", "whoami")

	rec = httptest.NewRecorder()
	req = jsonRequest(t, http.MethodPost, "/api/agents/agent-one/command", map[string]string{
		"command": "pwd",
	})
	handler.HandleRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected path command route 200, got %d: %s", rec.Code, rec.Body.String())
	}
	assertNextAgentCommand(t, proto, "agent-one", "pwd")

	postAgentResult(t, proto, "agent-one", "pwd", xorHex("ok\n", "agent-one"))

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/agents/agent-one/results", nil)
	handler.HandleRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected results route 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var results []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode results: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	if results[0]["command"] != "pwd" || results[0]["output"] != "ok\n" {
		t.Fatalf("unexpected result payload: %#v", results[0])
	}
}

func TestOperatorAPIListsAgents(t *testing.T) {
	handler, _ := newTestAPIHandler(t, "agent-one")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agents/list", nil)
	handler.HandleRequest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected agents list 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var agents map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &agents); err != nil {
		t.Fatalf("decode agents list: %v", err)
	}
	if _, ok := agents["agent-one"]; !ok {
		t.Fatalf("expected registered agent in list, got %#v", agents)
	}
}

func TestOperatorAPIRejectsInvalidCommandRequests(t *testing.T) {
	handler, _ := newTestAPIHandler(t, "agent-one")

	tests := []struct {
		name       string
		method     string
		path       string
		body       map[string]string
		wantStatus int
	}{
		{
			name:       "body route requires agent id",
			method:     http.MethodPost,
			path:       "/api/agents/command",
			body:       map[string]string{"command": "whoami"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "body route requires command",
			method:     http.MethodPost,
			path:       "/api/agents/command",
			body:       map[string]string{"agent_id": "agent-one"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "path route requires command",
			method:     http.MethodPost,
			path:       "/api/agents/agent-one/command",
			body:       map[string]string{},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "path route rejects empty agent id",
			method:     http.MethodPost,
			path:       "/api/agents//command",
			body:       map[string]string{"command": "whoami"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "path route rejects malformed agent id",
			method:     http.MethodPost,
			path:       "/api/agents/agent-one/extra/command",
			body:       map[string]string{"command": "whoami"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unknown agent cannot be queued",
			method:     http.MethodPost,
			path:       "/api/agents/missing/command",
			body:       map[string]string{"command": "whoami"},
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := jsonRequest(t, tt.method, tt.path, tt.body)
			handler.HandleRequest(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tt.wantStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

func newTestAPIHandler(t *testing.T, agentID string) (*APIHandler, *behaviour.HTTPPollingProtocol) {
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
			t.Fatalf("restore cwd: %v", err)
		}
	})

	manager, err := communication.NewServerManager(&communication.ServerConfig{
		UploadDir:    filepath.Join(tempDir, "uploads"),
		Port:         "0",
		StaticDir:    filepath.Join(tempDir, "static"),
		ProtocolType: "http",
	})
	if err != nil {
		t.Fatalf("create server manager: %v", err)
	}

	listener, err := listeners.NewListener(listeners.ListenerConfig{
		ID:       "listener-one",
		Name:     "listener-one",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     49001,
	})
	if err != nil {
		t.Fatalf("create listener: %v", err)
	}
	proto, ok := listener.Protocol.(*behaviour.HTTPPollingProtocol)
	if !ok {
		t.Fatalf("expected HTTP polling protocol, got %T", listener.Protocol)
	}
	heartbeat := []byte(`{"id":"` + agentID + `","os":"linux","hostname":"workstation","ip":"127.0.0.1"}`)
	if err := proto.HandleAgentHeartbeat(heartbeat); err != nil {
		t.Fatalf("register agent heartbeat: %v", err)
	}
	if err := manager.GetListenerManager().AddListener(listener); err != nil {
		t.Fatalf("add listener: %v", err)
	}

	return NewAPIHandler(manager), proto
}

func jsonRequest(t *testing.T, method, path string, body interface{}) *http.Request {
	t.Helper()

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func assertNextAgentCommand(t *testing.T, proto *behaviour.HTTPPollingProtocol, agentID, want string) {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/"+agentID+"/command", nil)
	proto.GetHTTPHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected next command 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode command response: %v", err)
	}
	if response["command"] != want {
		t.Fatalf("expected command %q, got %q", want, response["command"])
	}
}

func postAgentResult(t *testing.T, proto *behaviour.HTTPPollingProtocol, agentID, command, output string) {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"command": command,
		"output":  output,
	})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/agent/"+agentID+"/result", bytes.NewReader(body))
	proto.GetHTTPHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("post agent result: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func xorHex(data, key string) string {
	keyBytes := []byte(key)
	out := make([]byte, len(data))
	for i, b := range []byte(data) {
		out[i] = b ^ keyBytes[i%len(keyBytes)]
	}
	return hex.EncodeToString(out)
}
