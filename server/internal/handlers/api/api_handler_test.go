package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"microc2/server/internal/behaviour"
	"microc2/server/internal/common"
	"microc2/server/internal/listeners"
	"microc2/server/internal/tasks"
	"microc2/server/pkg/communication"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
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
	assertLegacyResultPageHeaders(t, rec, 50, 0, 1, 1, "")
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
	taskHistory, err := proto.ListTasks("agent-one")
	if err != nil {
		t.Fatalf("list typed task history for legacy adapter: %v", err)
	}
	if len(taskHistory) != 2 ||
		taskHistory[0].Status != tasks.StatusDispatched ||
		taskHistory[1].Status != tasks.StatusCompleted {
		t.Fatalf("legacy command adapter did not use typed task lifecycle: %#v", taskHistory)
	}
}

func TestOperatorAPITypedTaskCreateListAndCancel(t *testing.T) {
	handler, _ := newTestAPIHandler(t, "agent-one")

	rec := httptest.NewRecorder()
	req := jsonRequest(t, http.MethodPost, "/api/agents/agent-one/tasks", map[string]interface{}{
		"schema_version":     1,
		"type":               "shell",
		"arguments":          map[string]string{"command": "whoami"},
		"timeout_seconds":    30,
		"expires_in_seconds": 120,
	})
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected typed task create 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var created tasks.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created task: %v", err)
	}
	if created.SchemaVersion != 1 || created.AgentID != "agent-one" ||
		created.Status != tasks.StatusQueued || created.ExpiresAt == nil {
		t.Fatalf("unexpected created task: %#v", created)
	}
	if delta := created.ExpiresAt.Sub(created.CreatedAt); delta != 120*time.Second {
		t.Fatalf("expiry delta = %s, want 2m", delta)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/agents/agent-one/tasks", nil)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected typed task list 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var listed taskListEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode task list: %v", err)
	}
	if listed.SchemaVersion != tasks.SchemaVersion ||
		listed.Limit != defaultTaskListLimit ||
		listed.Offset != 0 ||
		listed.Total != 1 ||
		listed.NextOffset != nil ||
		len(listed.Tasks) != 1 ||
		listed.Tasks[0].ID != created.ID {
		t.Fatalf("unexpected task list: %#v", listed)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodPost,
		"/api/agents/agent-one/tasks/"+created.ID+"/cancel",
		nil,
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected cancellation 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var cancelled tasks.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &cancelled); err != nil {
		t.Fatalf("decode cancelled task: %v", err)
	}
	if cancelled.Status != tasks.StatusCancelled || cancelled.CompletedAt == nil {
		t.Fatalf("unexpected cancelled task: %#v", cancelled)
	}
}

func TestOperatorAPITaskListPaginationIsBoundedAndNewestFirst(t *testing.T) {
	handler, proto := newTestAPIHandler(t, "agent-one")
	expiresIn := 300
	created := make([]tasks.Task, 0, 105)
	for i := 0; i < 105; i++ {
		task, err := proto.CreateTask("agent-one", tasks.CreateRequest{
			SchemaVersion:    tasks.SchemaVersion,
			Type:             tasks.TypeShell,
			Arguments:        tasks.ShellArguments{Command: fmt.Sprintf("command-%03d", i)},
			TimeoutSeconds:   30,
			ExpiresInSeconds: &expiresIn,
		})
		if err != nil {
			t.Fatalf("create task %d: %v", i, err)
		}
		created = append(created, task)
	}
	expected := append([]tasks.Task(nil), created...)
	sort.Slice(expected, func(i, j int) bool {
		if expected[i].CreatedAt.Equal(expected[j].CreatedAt) {
			return expected[i].ID > expected[j].ID
		}
		return expected[i].CreatedAt.After(expected[j].CreatedAt)
	})

	defaultPage := getTaskList(t, handler, "/api/agents/agent-one/tasks")
	if defaultPage.SchemaVersion != tasks.SchemaVersion ||
		defaultPage.Limit != defaultTaskListLimit ||
		defaultPage.Offset != 0 ||
		defaultPage.Total != len(created) ||
		defaultPage.NextOffset == nil ||
		*defaultPage.NextOffset != defaultTaskListLimit ||
		len(defaultPage.Tasks) != defaultTaskListLimit {
		t.Fatalf("unexpected default page: %#v", defaultPage)
	}
	assertTaskSummariesNewestFirst(t, defaultPage.Tasks)
	if defaultPage.Tasks[0].ID != expected[0].ID {
		t.Fatalf(
			"default page starts with task %q, want newest %q",
			defaultPage.Tasks[0].ID,
			expected[0].ID,
		)
	}

	maxPage := getTaskList(t, handler, "/api/agents/agent-one/tasks?limit=100")
	if maxPage.Limit != maxTaskListLimit ||
		maxPage.Offset != 0 ||
		maxPage.Total != len(created) ||
		maxPage.NextOffset == nil ||
		*maxPage.NextOffset != maxTaskListLimit ||
		len(maxPage.Tasks) != maxTaskListLimit {
		t.Fatalf("unexpected maximum page: %#v", maxPage)
	}
	assertTaskSummariesNewestFirst(t, maxPage.Tasks)

	finalPage := getTaskList(
		t,
		handler,
		"/api/agents/agent-one/tasks?limit=100&offset=100",
	)
	if finalPage.Limit != maxTaskListLimit ||
		finalPage.Offset != maxTaskListLimit ||
		finalPage.Total != len(created) ||
		finalPage.NextOffset != nil ||
		len(finalPage.Tasks) != 5 {
		t.Fatalf("unexpected final page: %#v", finalPage)
	}
	assertTaskSummariesNewestFirst(t, finalPage.Tasks)
	if finalPage.Tasks[0].ID != expected[100].ID ||
		finalPage.Tasks[len(finalPage.Tasks)-1].ID != expected[104].ID {
		t.Fatalf("pagination omitted or reordered tail tasks: %#v", finalPage.Tasks)
	}

	emptyPage := getTaskList(
		t,
		handler,
		"/api/agents/agent-one/tasks?limit=10&offset=1000",
	)
	if emptyPage.Total != len(created) ||
		emptyPage.Offset != 1000 ||
		emptyPage.NextOffset != nil ||
		len(emptyPage.Tasks) != 0 {
		t.Fatalf("unexpected beyond-end page: %#v", emptyPage)
	}
}

func TestOperatorAPITaskListRejectsInvalidQueries(t *testing.T) {
	handler, _ := newTestAPIHandler(t, "agent-one")
	tests := []string{
		"?limit=0",
		"?limit=101",
		"?limit=-1",
		"?limit=one",
		"?limit=",
		"?offset=-1",
		"?offset=one",
		"?offset=",
		"?offset=999999999999999999999999999999999999",
		"?limit=1&limit=2",
		"?offset=1&offset=2",
		"?unknown=1",
		"?limit=1;offset=2",
	}
	for _, query := range tests {
		t.Run(query, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				http.MethodGet,
				"/api/agents/agent-one/tasks"+query,
				nil,
			)
			handler.HandleRequest(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("query %q: expected 400, got %d: %s", query, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestOperatorAPITaskListOmitsOutputAndDetailReturnsCanonicalTask(t *testing.T) {
	handler, proto := newTestAPIHandler(t, "agent-one")
	expiresIn := 300
	task, err := proto.CreateTask("agent-one", tasks.CreateRequest{
		SchemaVersion:    tasks.SchemaVersion,
		Type:             tasks.TypeShell,
		Arguments:        tasks.ShellArguments{Command: "collect-output"},
		TimeoutSeconds:   30,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	completeTypedTask(t, proto, task, "stdout-sentinel", "stderr-sentinel")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agents/agent-one/tasks", nil)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list task history: %d: %s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(`"output"`)) ||
		bytes.Contains(rec.Body.Bytes(), []byte("stdout-sentinel")) ||
		bytes.Contains(rec.Body.Bytes(), []byte("stderr-sentinel")) {
		t.Fatalf("task list leaked result streams: %s", rec.Body.String())
	}
	var page taskListEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode task list: %v", err)
	}
	if len(page.Tasks) != 1 ||
		page.Tasks[0].Result == nil ||
		page.Tasks[0].Result.TaskID != task.ID ||
		page.Tasks[0].Result.Outcome != tasks.OutcomeCompleted {
		t.Fatalf("task list omitted result summary: %#v", page)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodGet,
		"/api/agents/agent-one/tasks/"+task.ID,
		nil,
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get task detail: %d: %s", rec.Code, rec.Body.String())
	}
	var detail tasks.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode task detail: %v", err)
	}
	if detail.ID != task.ID ||
		detail.Result == nil ||
		detail.Result.Output.Stdout != "stdout-sentinel" ||
		detail.Result.Output.Stderr != "stderr-sentinel" {
		t.Fatalf("detail did not return canonical output: %#v", detail)
	}
}

func TestOperatorAPITypedTaskValidationAndTransitions(t *testing.T) {
	handler, proto := newTestAPIHandler(t, "agent-one")

	invalidBodies := []map[string]interface{}{
		{
			"schema_version":     2,
			"type":               "shell",
			"arguments":          map[string]string{"command": "whoami"},
			"timeout_seconds":    30,
			"expires_in_seconds": 300,
		},
		{
			"schema_version":     1,
			"type":               "file",
			"arguments":          map[string]string{"command": "whoami"},
			"timeout_seconds":    30,
			"expires_in_seconds": 300,
		},
		{
			"schema_version":     1,
			"type":               "shell",
			"arguments":          map[string]string{"command": ""},
			"timeout_seconds":    30,
			"expires_in_seconds": 300,
		},
		{
			"schema_version":     1,
			"type":               "shell",
			"arguments":          map[string]string{"command": "whoami"},
			"timeout_seconds":    3601,
			"expires_in_seconds": 300,
		},
		{
			"schema_version":     1,
			"type":               "shell",
			"arguments":          map[string]string{"command": "whoami"},
			"timeout_seconds":    30,
			"expires_in_seconds": 604801,
		},
		{
			"schema_version":     1,
			"type":               "shell",
			"arguments":          map[string]string{"command": "whoami"},
			"timeout_seconds":    30,
			"expires_in_seconds": 300,
			"unknown":            true,
		},
		{
			"type":               "shell",
			"arguments":          map[string]string{"command": "whoami"},
			"timeout_seconds":    30,
			"expires_in_seconds": 300,
		},
		{
			"schema_version":  1,
			"type":            "shell",
			"arguments":       map[string]string{"command": "whoami"},
			"timeout_seconds": 30,
		},
	}
	for i, body := range invalidBodies {
		rec := httptest.NewRecorder()
		req := jsonRequest(t, http.MethodPost, "/api/agents/agent-one/tasks", body)
		handler.HandleRequest(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid body %d: expected 400, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	rec := httptest.NewRecorder()
	req := jsonRequest(t, http.MethodPost, "/api/agents/agent-one/tasks", map[string]interface{}{
		"schema_version":     1,
		"type":               "shell",
		"arguments":          map[string]string{"command": "whoami"},
		"timeout_seconds":    30,
		"expires_in_seconds": 300,
	})
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create task: expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	var created tasks.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode task: %v", err)
	}
	assertNextTypedTask(t, proto, "agent-one", created.ID)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodPost,
		"/api/agents/agent-one/tasks/"+created.ID+"/cancel",
		nil,
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("dispatched cancellation: expected 409, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = jsonRequest(t, http.MethodPost, "/api/agents/missing/tasks", map[string]interface{}{
		"schema_version":     1,
		"type":               "shell",
		"arguments":          map[string]string{"command": "whoami"},
		"timeout_seconds":    30,
		"expires_in_seconds": 300,
	})
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown agent: expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOperatorAPITaskRoutingRejectsDuplicateActiveAgent(t *testing.T) {
	handler, first := newTestAPIHandler(t, "agent-one")
	second := addTestHTTPListener(
		t,
		handler,
		"listener-two",
		49002,
		listeners.StatusActive,
		"agent-one",
	)

	rec := httptest.NewRecorder()
	req := jsonRequest(
		t,
		http.MethodPost,
		"/api/agents/agent-one/tasks",
		validTaskRequestBody("ambiguous"),
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate active agent: expected 409, got %d: %s", rec.Code, rec.Body.String())
	}

	expiresIn := 300
	firstTask, err := first.CreateTask("agent-one", tasks.CreateRequest{
		SchemaVersion:    tasks.SchemaVersion,
		Type:             tasks.TypeShell,
		Arguments:        tasks.ShellArguments{Command: "first"},
		TimeoutSeconds:   30,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("create first listener task: %v", err)
	}
	secondTask, err := second.CreateTask("agent-one", tasks.CreateRequest{
		SchemaVersion:    tasks.SchemaVersion,
		Type:             tasks.TypeShell,
		Arguments:        tasks.ShellArguments{Command: "second"},
		TimeoutSeconds:   30,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("create second listener task: %v", err)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/agents/agent-one/tasks", nil)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list duplicate-listener history: %d: %s", rec.Code, rec.Body.String())
	}
	var history taskListEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &history); err != nil {
		t.Fatalf("decode duplicate-listener history: %v", err)
	}
	if len(history.Tasks) != 2 || history.Total != 2 {
		t.Fatalf("combined history has %d tasks, want 2: %#v", len(history.Tasks), history)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodPost,
		"/api/agents/agent-one/tasks/"+firstTask.ID+"/cancel",
		nil,
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel uniquely owned task with duplicate active agent: %d: %s", rec.Code, rec.Body.String())
	}
	secondState, err := second.GetTask("agent-one", secondTask.ID)
	if err != nil || secondState.Status != tasks.StatusQueued {
		t.Fatalf("cancelling first task changed second listener task: %#v err=%v", secondState, err)
	}
}

func TestOperatorAPITaskRoutingIgnoresStoppedDuplicateForCreation(t *testing.T) {
	handler, active := newTestAPIHandler(t, "agent-one")
	stopped := addTestHTTPListener(
		t,
		handler,
		"listener-zero",
		49002,
		listeners.StatusStopped,
		"agent-one",
	)

	rec := httptest.NewRecorder()
	req := jsonRequest(
		t,
		http.MethodPost,
		"/api/agents/agent-one/tasks",
		validTaskRequestBody("active-only"),
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("active plus stopped duplicate: expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	activeHistory, err := active.ListTasks("agent-one")
	if err != nil {
		t.Fatalf("list active listener tasks: %v", err)
	}
	stoppedHistory, err := stopped.ListTasks("agent-one")
	if err != nil {
		t.Fatalf("list stopped listener tasks: %v", err)
	}
	if len(activeHistory) != 1 || len(stoppedHistory) != 0 {
		t.Fatalf(
			"task routed to wrong listener: active=%#v stopped=%#v",
			activeHistory,
			stoppedHistory,
		)
	}
}

func TestOperatorAPITaskHistoryIncludesStoppedListenerDetail(t *testing.T) {
	handler, _ := newTestAPIHandler(t, "agent-one")
	stopped := addTestHTTPListener(
		t,
		handler,
		"listener-zero",
		49002,
		listeners.StatusStopped,
		"agent-one",
	)
	expiresIn := 300
	task, err := stopped.CreateTask("agent-one", tasks.CreateRequest{
		SchemaVersion:    tasks.SchemaVersion,
		Type:             tasks.TypeShell,
		Arguments:        tasks.ShellArguments{Command: "stopped-history"},
		TimeoutSeconds:   30,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("create stopped-listener task: %v", err)
	}
	completeTypedTask(t, stopped, task, "stopped-stdout", "")

	page := getTaskList(t, handler, "/api/agents/agent-one/tasks")
	if page.Total != 1 ||
		len(page.Tasks) != 1 ||
		page.Tasks[0].ID != task.ID {
		t.Fatalf("stopped-listener history missing from list: %#v", page)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/agents/agent-one/tasks/"+task.ID,
		nil,
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get stopped-listener detail: %d: %s", rec.Code, rec.Body.String())
	}
	var detail tasks.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode stopped-listener detail: %v", err)
	}
	if detail.Result == nil || detail.Result.Output.Stdout != "stopped-stdout" {
		t.Fatalf("stopped-listener detail lost canonical output: %#v", detail)
	}
}

func TestOperatorAPITaskDetailRejectsAmbiguousOwnership(t *testing.T) {
	handler, _ := newTestAPIHandler(t, "agent-one")
	now := time.Now().UTC()
	expiresAt := now.Add(time.Minute)
	duplicate := tasks.Task{
		SchemaVersion:  tasks.SchemaVersion,
		ID:             "duplicate-task",
		AgentID:        "agent-one",
		Type:           tasks.TypeShell,
		Arguments:      tasks.ShellArguments{Command: "ambiguous"},
		TimeoutSeconds: 30,
		Status:         tasks.StatusQueued,
		CreatedAt:      now,
		QueuedAt:       now,
		ExpiresAt:      &expiresAt,
	}
	first := &staticTaskProtocol{
		agentID:  "agent-one",
		lastSeen: now,
		tasks:    map[string]tasks.Task{duplicate.ID: duplicate},
	}
	listenersInManager := handler.serverManager.GetListenerManager().ListListeners()
	if len(listenersInManager) != 1 {
		t.Fatalf("initial listener count = %d, want 1", len(listenersInManager))
	}
	listenersInManager[0].Protocol = first

	secondListener, err := listeners.NewListener(listeners.ListenerConfig{
		ID:       "listener-two",
		Name:     "listener-two",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     49002,
	})
	if err != nil {
		t.Fatalf("create second listener: %v", err)
	}
	secondListener.Protocol = &staticTaskProtocol{
		agentID:  "agent-one",
		lastSeen: now,
		tasks:    map[string]tasks.Task{duplicate.ID: duplicate},
	}
	secondListener.Status = listeners.StatusStopped
	if err := handler.serverManager.GetListenerManager().AddListener(secondListener); err != nil {
		t.Fatalf("add second listener: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/agents/agent-one/tasks/"+duplicate.ID,
		nil,
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("ambiguous detail: expected 409, got %d: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodGet,
		"/api/agents/agent-one/tasks/missing-task",
		nil,
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing detail: expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestOperatorAPILegacyResultsAggregateDeterministicallyAcrossListeners(t *testing.T) {
	handler, primary := newTestAPIHandler(t, "agent-one")
	stopped := addTestHTTPListener(
		t,
		handler,
		"listener-zero",
		49002,
		listeners.StatusStopped,
		"agent-one",
	)

	for i := 0; i < 3; i++ {
		command := fmt.Sprintf("one-%d", i)
		primary.QueueCommand("agent-one", command)
		assertNextAgentCommand(t, primary, "agent-one", command)
		postAgentResult(t, primary, "agent-one", command, xorHex(command+"\n", "agent-one"))
	}
	for i := 0; i < 3; i++ {
		command := fmt.Sprintf("zero-%d", i)
		stopped.QueueCommand("agent-one", command)
		assertNextAgentCommand(t, stopped, "agent-one", command)
		postAgentResult(t, stopped, "agent-one", command, xorHex(command+"\n", "agent-one"))
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/agents/agent-one/results?limit=3&offset=2",
		nil,
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("aggregate results: %d: %s", rec.Code, rec.Body.String())
	}
	assertLegacyResultPageHeaders(t, rec, 3, 2, 6, 3, "5")
	var results []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode aggregate results: %v", err)
	}
	if len(results) != 3 ||
		results[0]["command"] != "one-2" ||
		results[1]["command"] != "zero-0" ||
		results[2]["command"] != "zero-1" {
		t.Fatalf("results are not ordered by listener ID: %#v", results)
	}
}

func TestOperatorAPILegacyResultsPagingDefaultsAndStrictQueries(t *testing.T) {
	handler, proto := newTestAPIHandler(t, "agent-one")
	for i := 0; i < 105; i++ {
		command := fmt.Sprintf("command-%03d", i)
		proto.QueueCommand("agent-one", command)
		assertNextAgentCommand(t, proto, "agent-one", command)
		postAgentResult(t, proto, "agent-one", command, xorHex(command+"\n", "agent-one"))
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agents/agent-one/results", nil)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("default legacy result page: %d: %s", rec.Code, rec.Body.String())
	}
	assertLegacyResultPageHeaders(t, rec, 50, 0, 105, 50, "50")
	var firstPage []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &firstPage); err != nil {
		t.Fatalf("decode default legacy result page: %v", err)
	}
	if len(firstPage) != 50 ||
		firstPage[0]["command"] != "command-000" ||
		firstPage[49]["command"] != "command-049" {
		t.Fatalf("unexpected default legacy result page: %#v", firstPage)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodGet,
		"/api/agents/agent-one/results?limit=100&offset=100",
		nil,
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("final legacy result page: %d: %s", rec.Code, rec.Body.String())
	}
	assertLegacyResultPageHeaders(t, rec, 100, 100, 105, 5, "")
	var finalPage []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &finalPage); err != nil {
		t.Fatalf("decode final legacy result page: %v", err)
	}
	if len(finalPage) != 5 ||
		finalPage[0]["command"] != "command-100" ||
		finalPage[4]["command"] != "command-104" {
		t.Fatalf("unexpected final legacy result page: %#v", finalPage)
	}

	invalidQueries := []string{
		"?limit=0",
		"?limit=101",
		"?limit=-1",
		"?limit=one",
		"?limit=",
		"?offset=-1",
		"?offset=one",
		"?offset=",
		"?offset=999999999999999999999999999999999999",
		"?limit=1&limit=2",
		"?offset=1&offset=2",
		"?unknown=1",
		"?limit=1;offset=2",
	}
	for _, query := range invalidQueries {
		t.Run(query, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(
				http.MethodGet,
				"/api/agents/agent-one/results"+query,
				nil,
			)
			handler.HandleRequest(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("query %q: expected 400, got %d: %s", query, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestOperatorAPILegacyResultsEmptyPageIsJSONArray(t *testing.T) {
	handler, _ := newTestAPIHandler(t, "agent-one")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agents/agent-one/results", nil)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty legacy result page: %d: %s", rec.Code, rec.Body.String())
	}
	assertLegacyResultPageHeaders(t, rec, 50, 0, 0, 0, "")
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty legacy result page must be a JSON array, got %q", rec.Body.String())
	}
}

func TestOperatorAPILegacyResultsBodyBudgetKeepsLosslessCursor(t *testing.T) {
	handler, _ := newTestAPIHandler(t, "agent-one")
	listenersInManager := handler.serverManager.GetListenerManager().ListListeners()
	if len(listenersInManager) != 1 {
		t.Fatalf("initial listener count = %d, want 1", len(listenersInManager))
	}

	const totalResults = 20
	largeOutput := strings.Repeat("x", 1<<20)
	history := make([]map[string]interface{}, 0, totalResults)
	for i := 0; i < totalResults; i++ {
		history = append(history, map[string]interface{}{
			"command":   fmt.Sprintf("large-%02d", i),
			"output":    largeOutput,
			"timestamp": "2026-07-23T16:30:00Z",
		})
	}
	listenersInManager[0].Protocol = &staticTaskProtocol{
		agentID:  "agent-one",
		lastSeen: time.Now().UTC(),
		tasks:    map[string]tasks.Task{},
		results:  history,
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"/api/agents/agent-one/results?limit=20",
		nil,
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("budgeted legacy result page: %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() > 16<<20 {
		t.Fatalf("legacy result page is %d bytes, exceeds 16 MiB budget", rec.Body.Len())
	}
	var firstPage []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &firstPage); err != nil {
		t.Fatalf("decode budgeted legacy result page: %v", err)
	}
	if len(firstPage) == 0 || len(firstPage) >= totalResults {
		t.Fatalf("body budget returned %d records, want between 1 and %d", len(firstPage), totalResults-1)
	}
	nextOffset := strconv.Itoa(len(firstPage))
	assertLegacyResultPageHeaders(t, rec, 20, 0, totalResults, len(firstPage), nextOffset)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodGet,
		"/api/agents/agent-one/results?limit=20&offset="+nextOffset,
		nil,
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("budgeted legacy result continuation: %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() > 16<<20 {
		t.Fatalf("legacy result continuation is %d bytes, exceeds 16 MiB budget", rec.Body.Len())
	}
	var secondPage []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &secondPage); err != nil {
		t.Fatalf("decode budgeted legacy result continuation: %v", err)
	}
	assertLegacyResultPageHeaders(
		t,
		rec,
		20,
		len(firstPage),
		totalResults,
		len(secondPage),
		"",
	)

	combined := append(append([]map[string]interface{}{}, firstPage...), secondPage...)
	if len(combined) != totalResults {
		t.Fatalf("budgeted pages returned %d records, want %d", len(combined), totalResults)
	}
	for i, result := range combined {
		want := fmt.Sprintf("large-%02d", i)
		if result["command"] != want {
			t.Fatalf("budgeted pages lost or duplicated cursor at %d: got %#v, want %q", i, result, want)
		}
	}
}

func TestOperatorAPIRejectsOversizedTaskCreateBody(t *testing.T) {
	handler, _ := newTestAPIHandler(t, "agent-one")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/agents/agent-one/tasks",
		bytes.NewBufferString(
			`{"schema_version":1,"type":"shell","arguments":{"command":"`+
				strings.Repeat("x", int(tasks.MaxTaskCreateBodyBytes)+1)+
				`"},"timeout_seconds":30,"expires_in_seconds":300}`,
		),
	)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected oversized task request 413, got %d: %s", rec.Code, rec.Body.String())
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
			wantStatus: http.StatusNotFound,
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
	listener.Status = listeners.StatusActive
	if err := manager.GetListenerManager().AddListener(listener); err != nil {
		t.Fatalf("add listener: %v", err)
	}

	return NewAPIHandler(manager), proto
}

func addTestHTTPListener(
	t *testing.T,
	handler *APIHandler,
	listenerID string,
	port int,
	status listeners.ListenerStatus,
	agentID string,
) *behaviour.HTTPPollingProtocol {
	t.Helper()
	listener, err := listeners.NewListener(listeners.ListenerConfig{
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
	heartbeat := []byte(
		`{"id":"` + agentID +
			`","os":"linux","hostname":"` + listenerID +
			`","ip":"127.0.0.1"}`,
	)
	if err := proto.HandleAgentHeartbeat(heartbeat); err != nil {
		t.Fatalf("register %s heartbeat on %s: %v", agentID, listenerID, err)
	}
	listener.Status = status
	if err := handler.serverManager.GetListenerManager().AddListener(listener); err != nil {
		t.Fatalf("add listener %s: %v", listenerID, err)
	}
	return proto
}

func validTaskRequestBody(command string) map[string]interface{} {
	return map[string]interface{}{
		"schema_version":     tasks.SchemaVersion,
		"type":               tasks.TypeShell,
		"arguments":          map[string]string{"command": command},
		"timeout_seconds":    30,
		"expires_in_seconds": 300,
	}
}

func assertLegacyResultPageHeaders(
	t *testing.T,
	rec *httptest.ResponseRecorder,
	limit int,
	offset int,
	total int,
	count int,
	nextOffset string,
) {
	t.Helper()
	want := map[string]string{
		"Deprecation":     "true",
		"X-Result-Limit":  strconv.Itoa(limit),
		"X-Result-Offset": strconv.Itoa(offset),
		"X-Result-Total":  strconv.Itoa(total),
		"X-Result-Count":  strconv.Itoa(count),
		"X-Next-Offset":   nextOffset,
		"Link":            `</api/agents/agent-one/tasks>; rel="successor-version"`,
	}
	for name, expected := range want {
		if actual := rec.Header().Get(name); actual != expected {
			t.Fatalf("%s header = %q, want %q", name, actual, expected)
		}
	}
}

func getTaskList(t *testing.T, handler *APIHandler, path string) taskListEnvelope {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	handler.HandleRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get task list %q: %d: %s", path, rec.Code, rec.Body.String())
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &fields); err != nil {
		t.Fatalf("decode task list envelope fields: %v", err)
	}
	if _, ok := fields["next_offset"]; !ok {
		t.Fatalf("task list omitted next_offset: %s", rec.Body.String())
	}
	var page taskListEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode task list envelope: %v", err)
	}
	return page
}

func assertTaskSummariesNewestFirst(t *testing.T, summaries []tasks.TaskSummary) {
	t.Helper()
	for i := 1; i < len(summaries); i++ {
		previous := summaries[i-1]
		current := summaries[i]
		if current.CreatedAt.After(previous.CreatedAt) ||
			(current.CreatedAt.Equal(previous.CreatedAt) && current.ID > previous.ID) {
			t.Fatalf(
				"task summaries are not newest-first at %d: previous=%#v current=%#v",
				i,
				previous,
				current,
			)
		}
	}
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

func assertNextTypedTask(t *testing.T, proto *behaviour.HTTPPollingProtocol, agentID, taskID string) {
	t.Helper()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/"+agentID+"/tasks", nil)
	proto.GetHTTPHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected next task 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var task tasks.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &task); err != nil {
		t.Fatalf("decode task response: %v", err)
	}
	if task.ID != taskID || task.Status != tasks.StatusDispatched {
		t.Fatalf("unexpected dispatched task: %#v", task)
	}
}

func completeTypedTask(
	t *testing.T,
	proto *behaviour.HTTPPollingProtocol,
	task tasks.Task,
	stdout string,
	stderr string,
) {
	t.Helper()
	handler := proto.GetHTTPHandler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agent/"+task.AgentID+"/tasks", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dispatch typed task: %d: %s", rec.Code, rec.Body.String())
	}
	var dispatched tasks.Task
	if err := json.Unmarshal(rec.Body.Bytes(), &dispatched); err != nil {
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
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodPost,
		"/api/agent/"+task.AgentID+"/tasks/"+task.ID+"/status",
		bytes.NewReader(statusBody),
	)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mark typed task running: %d: %s", rec.Code, rec.Body.String())
	}

	exitCode := 0
	resultBody, err := json.Marshal(tasks.Result{
		SchemaVersion: tasks.SchemaVersion,
		TaskID:        task.ID,
		AgentID:       task.AgentID,
		Outcome:       tasks.OutcomeCompleted,
		StartedAt:     startedAt,
		CompletedAt:   startedAt.Add(time.Second),
		ExitCode:      &exitCode,
		Output: tasks.Output{
			Stdout: stdout,
			Stderr: stderr,
		},
	})
	if err != nil {
		t.Fatalf("marshal typed result: %v", err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(
		http.MethodPost,
		"/api/agent/"+task.AgentID+"/results",
		bytes.NewReader(resultBody),
	)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("complete typed task: %d: %s", rec.Code, rec.Body.String())
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

type staticTaskProtocol struct {
	agentID  string
	lastSeen time.Time
	tasks    map[string]tasks.Task
	results  []map[string]interface{}
}

var _ common.Protocol = (*staticTaskProtocol)(nil)
var _ taskProtocol = (*staticTaskProtocol)(nil)

func (p *staticTaskProtocol) Initialize() error {
	return nil
}

func (p *staticTaskProtocol) HandleCommand(string) error {
	return nil
}

func (p *staticTaskProtocol) HandleFileUpload(string, io.Reader) error {
	return nil
}

func (p *staticTaskProtocol) HandleFileDownload(string) (io.Reader, error) {
	return nil, errors.New("not implemented")
}

func (p *staticTaskProtocol) HandleAgentHeartbeat([]byte) error {
	return nil
}

func (p *staticTaskProtocol) GetRoutes() map[string]http.HandlerFunc {
	return nil
}

func (p *staticTaskProtocol) GetHTTPHandler() http.Handler {
	return nil
}

func (p *staticTaskProtocol) CreateTask(string, tasks.CreateRequest) (tasks.Task, error) {
	return tasks.Task{}, errors.New("not implemented")
}

func (p *staticTaskProtocol) ListTasks(agentID string) ([]tasks.Task, error) {
	history := make([]tasks.Task, 0, len(p.tasks))
	for _, task := range p.tasks {
		if task.AgentID == agentID {
			history = append(history, task)
		}
	}
	return history, nil
}

func (p *staticTaskProtocol) CancelTask(agentID, taskID string) (tasks.Task, error) {
	return p.GetTask(agentID, taskID)
}

func (p *staticTaskProtocol) GetTask(agentID, taskID string) (tasks.Task, error) {
	task, ok := p.tasks[taskID]
	if !ok || task.AgentID != agentID {
		return tasks.Task{}, tasks.ErrNotFound
	}
	return task, nil
}

func (p *staticTaskProtocol) GetResults(agentID string) []map[string]interface{} {
	page, _ := p.GetResultsPage(agentID, 0, len(p.results))
	return page
}

func (p *staticTaskProtocol) GetResultsPage(
	agentID string,
	offset int,
	limit int,
) ([]map[string]interface{}, int) {
	if agentID != p.agentID {
		return []map[string]interface{}{}, 0
	}
	total := len(p.results)
	start := offset
	if start < 0 {
		start = 0
	}
	if start > total {
		start = total
	}
	if limit < 0 {
		limit = 0
	}
	if limit > total-start {
		limit = total - start
	}
	end := start + limit
	return append([]map[string]interface{}{}, p.results[start:end]...), total
}

func (p *staticTaskProtocol) QueueLegacyShellTask(string, string) (tasks.Task, error) {
	return tasks.Task{}, errors.New("not implemented")
}

func (p *staticTaskProtocol) AgentLastSeen(agentID string) (time.Time, bool) {
	return p.lastSeen, agentID == p.agentID
}

func xorHex(data, key string) string {
	keyBytes := []byte(key)
	out := make([]byte, len(data))
	for i, b := range []byte(data) {
		out[i] = b ^ keyBytes[i%len(keyBytes)]
	}
	return hex.EncodeToString(out)
}
