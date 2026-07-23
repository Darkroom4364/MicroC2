package behaviour

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"microc2/server/internal/common"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPPollingProtocolAgentLifecycle(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{
		UploadDir: t.TempDir(),
		Port:      "0",
	})
	handler := proto.GetHTTPHandler()
	agentID := "agent-one"

	heartbeat := map[string]interface{}{
		"id":       agentID,
		"os":       "linux",
		"hostname": "workstation",
		"ip":       "127.0.0.1",
		"ip_list":  []string{"127.0.0.1"},
	}
	heartbeatBody, err := json.Marshal(heartbeat)
	if err != nil {
		t.Fatalf("marshal heartbeat: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/agent/"+agentID+"/heartbeat", bytes.NewReader(heartbeatBody))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected heartbeat 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if _, ok := proto.GetAllAgents()[agentID]; !ok {
		t.Fatalf("expected heartbeat to register agent %q", agentID)
	}

	proto.QueueCommand(agentID, "whoami")

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/agent/"+agentID+"/command", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected queued command 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var command map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &command); err != nil {
		t.Fatalf("decode command response: %v", err)
	}
	if command["command"] != "whoami" {
		t.Fatalf("expected queued command whoami, got %q", command["command"])
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/agent/"+agentID+"/command", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected drained command queue to return 204, got %d", rec.Code)
	}

	result := CommandResult{
		Command: "whoami",
		Output:  xorHex("operator\n", agentID),
	}
	resultBody, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agent/"+agentID+"/result", bytes.NewReader(resultBody))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected result submission 200, got %d: %s", rec.Code, rec.Body.String())
	}

	results := proto.GetResults(agentID)
	if len(results) != 1 {
		t.Fatalf("expected one stored result, got %d", len(results))
	}
	if results[0]["output"] != "operator\n" {
		t.Fatalf("expected stored result to be deobfuscated, got %#v", results[0]["output"])
	}
}

func TestHTTPPollingProtocolIsolatesMultipleAgentsPerListener(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{
		UploadDir: t.TempDir(),
		Port:      "0",
	})
	handler := proto.GetHTTPHandler()

	for _, agentID := range []string{"agent-one", "agent-two"} {
		heartbeatBody, err := json.Marshal(map[string]interface{}{
			"id":         agentID,
			"payload_id": "payload-shared",
			"os":         "linux",
			"hostname":   agentID + "-host",
			"ip":         "127.0.0.1",
		})
		if err != nil {
			t.Fatalf("marshal heartbeat for %s: %v", agentID, err)
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/agent/"+agentID+"/heartbeat", bytes.NewReader(heartbeatBody))
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected heartbeat 200 for %s, got %d: %s", agentID, rec.Code, rec.Body.String())
		}
	}

	agents := proto.GetAllAgents()
	if len(agents) != 2 {
		t.Fatalf("expected two distinct agents, got %#v", agents)
	}

	proto.QueueCommand("agent-one", "whoami")
	proto.QueueCommand("agent-two", "pwd")
	assertNextListenerCommand(t, handler, "agent-one", "whoami")
	assertNextListenerCommand(t, handler, "agent-two", "pwd")
	assertNoListenerCommand(t, handler, "agent-one")
	assertNoListenerCommand(t, handler, "agent-two")

	postListenerResult(t, handler, "agent-one", "whoami", xorHex("one\n", "agent-one"))
	postListenerResult(t, handler, "agent-two", "pwd", xorHex("two\n", "agent-two"))

	agentOneResults := proto.GetResults("agent-one")
	agentTwoResults := proto.GetResults("agent-two")
	if len(agentOneResults) != 1 || agentOneResults[0]["output"] != "one\n" {
		t.Fatalf("unexpected agent-one results: %#v", agentOneResults)
	}
	if len(agentTwoResults) != 1 || agentTwoResults[0]["output"] != "two\n" {
		t.Fatalf("unexpected agent-two results: %#v", agentTwoResults)
	}
}

func TestHTTPPollingProtocolRejectsHeartbeatIDMismatch(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{
		UploadDir: t.TempDir(),
		Port:      "0",
	})
	handler := proto.GetHTTPHandler()
	heartbeatBody := []byte(`{"id":"body-agent","os":"linux","hostname":"host","ip":"127.0.0.1"}`)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/agent/path-agent/heartbeat", bytes.NewReader(heartbeatBody))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected mismatch heartbeat 400, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(proto.GetAllAgents()) != 0 {
		t.Fatalf("mismatched heartbeat should not register an agent: %#v", proto.GetAllAgents())
	}
}

func TestHTTPPollingProtocolRejectsMalformedAndOperatorRoutes(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{
		UploadDir: t.TempDir(),
		Port:      "0",
	})
	handler := proto.GetHTTPHandler()

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
	}{
		{
			name:       "operator route stays outside listener API",
			method:     http.MethodGet,
			path:       "/api/agents/list",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "malformed agent route",
			method:     http.MethodGet,
			path:       "/api/agent/agent-one",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "heartbeat requires post",
			method:     http.MethodGet,
			path:       "/api/agent/agent-one/heartbeat",
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "heartbeat rejects invalid json",
			method:     http.MethodPost,
			path:       "/api/agent/agent-one/heartbeat",
			body:       "{",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tt.method, tt.path, bytes.NewBufferString(tt.body))
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("expected status %d, got %d: %s", tt.wantStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHTTPPollingProtocolCORSUsesConfiguredOrigins(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{
		UploadDir:      t.TempDir(),
		Port:           "0",
		AllowedOrigins: []string{"https://operator.lab:8443"},
	})
	handler := proto.GetHTTPHandler()

	tests := []struct {
		name       string
		origin     string
		wantHeader string
	}{
		{"allowed origin is reflected", "https://operator.lab:8443", "https://operator.lab:8443"},
		{"unconfigured loopback origin gets no CORS header", "http://localhost:8080", ""},
		{"disallowed origin gets no CORS header", "https://evil.example", ""},
		{"no origin header gets no CORS header", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/agent/agent-one/command", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			handler.ServeHTTP(rec, req)

			got := rec.Header().Get("Access-Control-Allow-Origin")
			if got != tt.wantHeader {
				t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, tt.wantHeader)
			}
		})
	}
}

func TestHTTPPollingProtocolCORSWildcardIsExplicitEscapeHatch(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{
		UploadDir:      t.TempDir(),
		Port:           "0",
		AllowedOrigins: []string{"*"},
	})
	handler := proto.GetHTTPHandler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/agent-one/command", nil)
	req.Header.Set("Origin", "https://evil.example")
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("expected wildcard CORS header when explicitly configured, got %q", got)
	}
}

func TestHTTPPollingProtocolRejectsTraversalUploadFilename(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{
		UploadDir: t.TempDir(),
		Port:      "0",
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/files/upload", bytes.NewBufferString("pwn"))
	req.Header.Set("X-Filename", "../evil.sh")
	proto.handleFileUpload(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected traversal upload filename 400, got %d: %s", rec.Code, rec.Body.String())
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

func assertNextListenerCommand(t *testing.T, handler http.Handler, agentID, want string) {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/"+agentID+"/command", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected command 200 for %s, got %d: %s", agentID, rec.Code, rec.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode command response: %v", err)
	}
	if response["command"] != want {
		t.Fatalf("expected command %q for %s, got %q", want, agentID, response["command"])
	}
}

func assertNoListenerCommand(t *testing.T, handler http.Handler, agentID string) {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/"+agentID+"/command", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected no command 204 for %s, got %d: %s", agentID, rec.Code, rec.Body.String())
	}
}

func postListenerResult(t *testing.T, handler http.Handler, agentID, command, output string) {
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
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected result post 200 for %s, got %d: %s", agentID, rec.Code, rec.Body.String())
	}
}
