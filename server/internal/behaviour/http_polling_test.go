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

func xorHex(data, key string) string {
	keyBytes := []byte(key)
	out := make([]byte, len(data))
	for i, b := range []byte(data) {
		out[i] = b ^ keyBytes[i%len(keyBytes)]
	}
	return hex.EncodeToString(out)
}
