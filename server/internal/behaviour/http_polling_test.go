package behaviour

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"microc2/server/internal/audit"
	"microc2/server/internal/common"
	"microc2/server/internal/tasks"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestHTTPPollingProtocolRejectsOversizedHeartbeat(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{
		UploadDir: t.TempDir(),
		Port:      "0",
	})
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/agent/agent-one/heartbeat",
		strings.NewReader(strings.Repeat("x", maxAgentHeartbeatBodyBytes+1)),
	)
	response := httptest.NewRecorder()

	proto.GetHTTPHandler().ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf(
			"oversized heartbeat status = %d, want %d: %s",
			response.Code,
			http.StatusRequestEntityTooLarge,
			response.Body.String(),
		)
	}
}

func TestHTTPPollingProtocolTypedTaskLifecycle(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"})
	handler := proto.GetHTTPHandler()
	agentID := "agent-one"
	expiresIn := 300

	queued, err := proto.CreateTask(agentID, tasks.CreateRequest{
		SchemaVersion:    tasks.SchemaVersion,
		Type:             tasks.TypeShell,
		Arguments:        tasks.ShellArguments{Command: "whoami"},
		TimeoutSeconds:   30,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("queue typed task: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/"+agentID+"/tasks", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected task dispatch 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var dispatched tasks.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &dispatched); err != nil {
		t.Fatalf("decode dispatched task: %v", err)
	}
	if dispatched.ID != queued.ID || dispatched.Status != tasks.StatusDispatched {
		t.Fatalf("unexpected dispatched task: %#v", dispatched)
	}

	startedAt := dispatched.DispatchedAt.Add(time.Second)
	statusBody, err := json.Marshal(tasks.StatusUpdate{
		SchemaVersion: tasks.SchemaVersion,
		TaskID:        dispatched.ID,
		AgentID:       agentID,
		Status:        tasks.StatusRunning,
		Timestamp:     startedAt,
	})
	if err != nil {
		t.Fatalf("marshal status update: %v", err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodPost,
		"/api/agent/"+agentID+"/tasks/"+dispatched.ID+"/status",
		bytes.NewReader(statusBody),
	)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected running update 200, got %d: %s", rec.Code, rec.Body.String())
	}

	exitCode := 0
	resultBody, err := json.Marshal(tasks.Result{
		SchemaVersion: tasks.SchemaVersion,
		TaskID:        dispatched.ID,
		AgentID:       agentID,
		Outcome:       tasks.OutcomeCompleted,
		StartedAt:     startedAt,
		CompletedAt:   startedAt.Add(time.Second),
		ExitCode:      &exitCode,
		Output:        tasks.Output{Stdout: "operator\n", Stderr: ""},
	})
	if err != nil {
		t.Fatalf("marshal task result: %v", err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agent/"+agentID+"/results", bytes.NewReader(resultBody))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected task result 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var completed tasks.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &completed); err != nil {
		t.Fatalf("decode completed task: %v", err)
	}
	if completed.Status != tasks.StatusCompleted || completed.Result == nil ||
		completed.Result.Output.Stdout != "operator\n" {
		t.Fatalf("unexpected completed task: %#v", completed)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/agent/"+agentID+"/tasks", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected empty typed queue 204, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPPollingProtocolTypedTaskRejectsInvalidUpdates(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"})
	handler := proto.GetHTTPHandler()
	expiresIn := 300
	task, err := proto.CreateTask("agent-one", tasks.CreateRequest{
		SchemaVersion:    tasks.SchemaVersion,
		Type:             tasks.TypeShell,
		Arguments:        tasks.ShellArguments{Command: "whoami"},
		TimeoutSeconds:   30,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("queue typed task: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/agent-one/tasks", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dispatch typed task: %d: %s", rec.Code, rec.Body.String())
	}
	var dispatched tasks.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &dispatched); err != nil {
		t.Fatalf("decode dispatched task: %v", err)
	}

	mismatch := `{"schema_version":1,"task_id":"` + task.ID +
		`","agent_id":"agent-two","status":"running","timestamp":"` +
		dispatched.DispatchedAt.Add(time.Second).Format(time.RFC3339Nano) + `"}`
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodPost,
		"/api/agent/agent-one/tasks/"+task.ID+"/status",
		bytes.NewBufferString(mismatch),
	)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected mismatched agent 400, got %d: %s", rec.Code, rec.Body.String())
	}

	withUnknownField := `{"schema_version":1,"task_id":"` + task.ID +
		`","agent_id":"agent-one","status":"running","timestamp":"` +
		dispatched.DispatchedAt.Add(time.Second).Format(time.RFC3339Nano) + `","extra":true}`
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodPost,
		"/api/agent/agent-one/tasks/"+task.ID+"/status",
		bytes.NewBufferString(withUnknownField),
	)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected unknown field 400, got %d: %s", rec.Code, rec.Body.String())
	}

	resultBeforeRunning := `{"schema_version":1,"task_id":"` + task.ID +
		`","agent_id":"agent-one","outcome":"completed","started_at":"` +
		dispatched.DispatchedAt.Add(time.Second).Format(time.RFC3339Nano) +
		`","completed_at":"` + dispatched.DispatchedAt.Add(2*time.Second).Format(time.RFC3339Nano) +
		`","exit_code":0,"output":{"stdout":"","stderr":""}}`
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/agent/agent-one/results", bytes.NewBufferString(resultBeforeRunning))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected dispatched result transition 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPPollingProtocolLegacyPollSkipsTypedOriginTasks(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"})
	handler := proto.GetHTTPHandler()
	expiresIn := 300
	typed, err := proto.CreateTask("agent-one", tasks.CreateRequest{
		SchemaVersion:    tasks.SchemaVersion,
		Type:             tasks.TypeShell,
		Arguments:        tasks.ShellArguments{Command: "typed-only"},
		TimeoutSeconds:   30,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("create typed task: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/agent-one/command", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("legacy poll consumed typed-origin task: %d: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/agent/agent-one/tasks", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("typed poll did not receive typed task: %d: %s", rec.Code, rec.Body.String())
	}
	var dispatched tasks.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &dispatched); err != nil {
		t.Fatalf("decode typed task: %v", err)
	}
	if dispatched.ID != typed.ID {
		t.Fatalf("typed poll received task %q, want %q", dispatched.ID, typed.ID)
	}
}

func TestHTTPPollingProtocolTypedCompletionProjectsLegacyHistoryOnce(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"})
	handler := proto.GetHTTPHandler()
	legacy, err := proto.QueueLegacyShellTask("agent-one", "whoami")
	if err != nil {
		t.Fatalf("queue legacy task: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/agent-one/tasks", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dispatch legacy-origin task through typed API: %d: %s", rec.Code, rec.Body.String())
	}
	var dispatched tasks.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &dispatched); err != nil {
		t.Fatalf("decode dispatched task: %v", err)
	}
	if dispatched.ID != legacy.ID {
		t.Fatalf("dispatched task %q, want %q", dispatched.ID, legacy.ID)
	}

	agentStartedAt := dispatched.DispatchedAt.Add(time.Second)
	statusBody, err := json.Marshal(tasks.StatusUpdate{
		SchemaVersion: tasks.SchemaVersion,
		TaskID:        legacy.ID,
		AgentID:       "agent-one",
		Status:        tasks.StatusRunning,
		Timestamp:     agentStartedAt,
	})
	if err != nil {
		t.Fatalf("marshal running update: %v", err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodPost,
		"/api/agent/agent-one/tasks/"+legacy.ID+"/status",
		bytes.NewReader(statusBody),
	)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mark legacy-origin task running: %d: %s", rec.Code, rec.Body.String())
	}

	exitCode := 0
	resultBody, err := json.Marshal(tasks.Result{
		SchemaVersion: tasks.SchemaVersion,
		TaskID:        legacy.ID,
		AgentID:       "agent-one",
		Outcome:       tasks.OutcomeCompleted,
		StartedAt:     agentStartedAt,
		CompletedAt:   agentStartedAt.Add(time.Second),
		ExitCode:      &exitCode,
		Output:        tasks.Output{Stdout: "operator\n", Stderr: ""},
	})
	if err != nil {
		t.Fatalf("marshal typed result: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		rec = httptest.NewRecorder()
		req = httptest.NewRequest(
			http.MethodPost,
			"/api/agent/agent-one/results",
			bytes.NewReader(resultBody),
		)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("typed result attempt %d: %d: %s", attempt, rec.Code, rec.Body.String())
		}
	}

	results := proto.GetResults("agent-one")
	if len(results) != 1 {
		t.Fatalf("idempotent typed completion projected %d legacy results, want 1", len(results))
	}
	if results[0]["command"] != "whoami" || results[0]["output"] != "operator\n" {
		t.Fatalf("unexpected projected legacy result: %#v", results[0])
	}
}

func TestHTTPPollingProtocolLegacyErrorIsFailedTypedHistory(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"})
	handler := proto.GetHTTPHandler()
	proto.QueueCommand("agent-one", "whoami")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/agent-one/command", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dispatch legacy command: %d: %s", rec.Code, rec.Body.String())
	}

	postListenerResult(t, handler, "agent-one", "whoami", xorHex("Error: timed out", "agent-one"))
	history, err := proto.ListTasks("agent-one")
	if err != nil {
		t.Fatalf("list typed history: %v", err)
	}
	if len(history) != 1 ||
		history[0].Status != tasks.StatusFailed ||
		history[0].Result == nil ||
		history[0].Result.Outcome != tasks.OutcomeFailed ||
		history[0].Result.ExitCode != nil ||
		history[0].Result.Error != "Error: timed out" {
		t.Fatalf("legacy error was not preserved as a failed typed task: %#v", history)
	}
}

func TestHTTPPollingProtocolRejectsOversizedTaskUpdateBody(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/agent/agent-one/tasks/task-one/status",
		bytes.NewBufferString(
			`{"schema_version":1,"task_id":"task-one","agent_id":"agent-one",`+
				`"status":"running","timestamp":"`+
				strings.Repeat("x", int(tasks.MaxStatusUpdateBodyBytes)+1)+`"}`,
		),
	)
	proto.GetHTTPHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected oversized status update 413, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPPollingProtocolAcceptsWorstCaseValidResultBody(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"})
	handler := proto.GetHTTPHandler()
	expiresIn := 300
	task, err := proto.CreateTask("agent-one", tasks.CreateRequest{
		SchemaVersion:    tasks.SchemaVersion,
		Type:             tasks.TypeShell,
		Arguments:        tasks.ShellArguments{Command: "emit-astral-characters"},
		TimeoutSeconds:   30,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("create typed task: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/agent-one/tasks", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dispatch typed task: %d: %s", rec.Code, rec.Body.String())
	}
	var dispatched tasks.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &dispatched); err != nil {
		t.Fatalf("decode dispatched task: %v", err)
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
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodPost,
		"/api/agent/agent-one/tasks/"+task.ID+"/status",
		bytes.NewReader(statusBody),
	)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mark task running: %d: %s", rec.Code, rec.Body.String())
	}

	exitCode := 0
	const astralSentinel = "😀"
	resultBody, err := json.Marshal(tasks.Result{
		SchemaVersion: tasks.SchemaVersion,
		TaskID:        task.ID,
		AgentID:       task.AgentID,
		Outcome:       tasks.OutcomeCompleted,
		StartedAt:     startedAt,
		CompletedAt:   startedAt.Add(time.Second),
		ExitCode:      &exitCode,
		Output: tasks.Output{
			Stdout: astralSentinel,
			Stderr: astralSentinel,
		},
	})
	if err != nil {
		t.Fatalf("marshal astral result template: %v", err)
	}
	surrogateEscapedStream := strings.Repeat(`\ud83d\ude00`, tasks.MaxResultStreamCharacters)
	resultBody = bytes.ReplaceAll(
		resultBody,
		[]byte(astralSentinel),
		[]byte(surrogateEscapedStream),
	)
	if len(resultBody) <= 16<<20 {
		t.Fatalf(
			"regression body is %d bytes; must exceed the old 16 MiB cap",
			len(resultBody),
		)
	}
	if len(resultBody) > int(tasks.MaxTaskResultBodyBytes) {
		t.Fatalf(
			"schema-valid result is %d bytes; exceeds current %d-byte cap",
			len(resultBody),
			tasks.MaxTaskResultBodyBytes,
		)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodPost,
		"/api/agent/agent-one/results",
		bytes.NewReader(resultBody),
	)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("schema-valid result body rejected: %d: %s", rec.Code, rec.Body.String())
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

func TestHTTPPollingProtocolPagesLegacyResultsAndReportsTotal(t *testing.T) {
	proto := NewHTTPPollingProtocol(common.BaseProtocolConfig{
		UploadDir: t.TempDir(),
		Port:      "0",
	})
	for i := 0; i < 125; i++ {
		proto.recordLegacyResultForAgent("agent-one", CommandResult{
			Command:   fmt.Sprintf("command-%03d", i),
			Output:    fmt.Sprintf("output-%03d", i),
			Timestamp: "2026-07-23T16:30:00Z",
		})
	}

	page, total := proto.GetResultsPage("agent-one", 50, 25)
	if total != 125 {
		t.Fatalf("legacy result total = %d, want 125", total)
	}
	if len(page) != 25 ||
		page[0]["command"] != "command-050" ||
		page[24]["command"] != "command-074" {
		t.Fatalf("unexpected legacy result page: %#v", page)
	}

	page, total = proto.GetResultsPage("agent-one", 200, 25)
	if total != 125 || page == nil || len(page) != 0 {
		t.Fatalf("beyond-end legacy result page = %#v, total %d; want [] and 125", page, total)
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

func TestHTTPPollingProtocolContextTaskAdaptersPreserveOperatorActor(t *testing.T) {
	store := &contextCapturingTaskStore{Store: tasks.NewStore()}
	protocol := newHTTPPollingProtocol(
		common.BaseProtocolConfig{UploadDir: t.TempDir(), Port: "0"},
		store,
		nil,
		"",
	)
	operator := audit.Actor{Kind: audit.ActorOperator, ID: "operator-test"}
	ctx := audit.WithActor(context.Background(), operator)
	expiresIn := tasks.DefaultExpiresIn

	typed, err := protocol.CreateTaskContext(
		ctx,
		"agent-one",
		tasks.CreateRequest{
			SchemaVersion:    tasks.SchemaVersion,
			Type:             tasks.TypeShell,
			Arguments:        tasks.ShellArguments{Command: "whoami"},
			TimeoutSeconds:   tasks.DefaultTimeoutSeconds,
			ExpiresInSeconds: &expiresIn,
		},
	)
	if err != nil {
		t.Fatalf("create context-aware typed task: %v", err)
	}
	if store.createActor != operator {
		t.Fatalf("typed task actor=%#v, want %#v", store.createActor, operator)
	}
	if _, err := protocol.QueueLegacyShellTaskContext(
		ctx,
		"agent-one",
		"hostname",
	); err != nil {
		t.Fatalf("create context-aware legacy task: %v", err)
	}
	if store.legacyActor != operator {
		t.Fatalf("legacy task actor=%#v, want %#v", store.legacyActor, operator)
	}
	if _, err := protocol.CancelTaskContext(
		ctx,
		"agent-one",
		typed.ID,
	); err != nil {
		t.Fatalf("cancel context-aware task: %v", err)
	}
	if store.cancelActor != operator {
		t.Fatalf("cancel actor=%#v, want %#v", store.cancelActor, operator)
	}
}

type contextCapturingTaskStore struct {
	*tasks.Store
	createActor audit.Actor
	legacyActor audit.Actor
	cancelActor audit.Actor
}

func (s *contextCapturingTaskStore) CreateContext(
	ctx context.Context,
	agentID string,
	request tasks.CreateRequest,
) (tasks.Task, error) {
	s.createActor, _ = audit.ActorFromContext(ctx)
	// Store.Create inserts a typed task into this test's in-memory map; it
	// never creates or opens a filesystem path.
	// foxguard: ignore[go/taint-path-traversal]
	return s.Store.Create(agentID, request)
}

func (s *contextCapturingTaskStore) CreateLegacyShellContext(
	ctx context.Context,
	agentID, command string,
) (tasks.Task, error) {
	s.legacyActor, _ = audit.ActorFromContext(ctx)
	return s.Store.CreateLegacyShell(agentID, command)
}

func (s *contextCapturingTaskStore) CancelContext(
	ctx context.Context,
	agentID, taskID string,
) (tasks.Task, error) {
	s.cancelActor, _ = audit.ActorFromContext(ctx)
	return s.Store.Cancel(agentID, taskID)
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
