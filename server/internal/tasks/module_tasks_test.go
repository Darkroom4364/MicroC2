package tasks

import (
	"encoding/json"
	"testing"
	"time"
)

func TestModuleTaskLifecycleValidatesClosedResultData(t *testing.T) {
	now := time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC)
	store := NewStoreWithClock(func() time.Time { return now })
	expiresIn := 300
	task, err := store.Create("agent-one", CreateRequest{
		SchemaVersion: SchemaVersion,
		Type:          TypeModule,
		Arguments: TaskArguments{
			ModuleID: "agent.capability_inventory.v1",
			Input:    json.RawMessage(`{}`),
		},
		TimeoutSeconds:   DefaultTimeoutSeconds,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("create module task: %v", err)
	}
	if task.Arguments.ModuleID != "agent.capability_inventory.v1" || task.Arguments.Command != "" {
		t.Fatalf("module task arguments did not round-trip: %#v", task.Arguments)
	}

	dispatched, found, err := store.DispatchNext("agent-one")
	if err != nil || !found {
		t.Fatalf("dispatch module task: found=%v err=%v", found, err)
	}
	if _, err := store.MarkRunning("agent-one", dispatched.ID, StatusUpdate{
		SchemaVersion: SchemaVersion,
		TaskID:        dispatched.ID,
		AgentID:       "agent-one",
		Status:        StatusRunning,
		Timestamp:     now,
	}); err != nil {
		t.Fatalf("mark module task running: %v", err)
	}

	exitCode := 0
	result := Result{
		SchemaVersion: SchemaVersion,
		TaskID:        dispatched.ID,
		AgentID:       "agent-one",
		Outcome:       OutcomeCompleted,
		StartedAt:     now,
		CompletedAt:   now.Add(time.Second),
		ExitCode:      &exitCode,
		Output: Output{
			Stdout: "",
			Stderr: "",
			Data: json.RawMessage(`{
				"operating_system":"linux",
				"architecture":"x86_64",
				"logical_cpu_count":8,
				"total_memory_bytes":17179869184
			}`),
		},
	}

	invalid := result
	invalid.Output.Data = json.RawMessage(`{"operating_system":"linux"}`)
	if _, err := store.Complete("agent-one", invalid); err == nil {
		t.Fatal("accepted incomplete module output")
	}

	completed, err := store.Complete("agent-one", result)
	if err != nil {
		t.Fatalf("complete module task: %v", err)
	}
	if completed.Status != StatusCompleted || completed.Result == nil {
		t.Fatalf("module task did not complete: %#v", completed)
	}
	if string(completed.Result.Output.Data) != string(result.Output.Data) {
		t.Fatalf("module result data did not round-trip: got %s", completed.Result.Output.Data)
	}
}

func TestModuleTaskRejectsUnknownModuleAndUnexpectedInput(t *testing.T) {
	expiresIn := 300
	base := CreateRequest{
		SchemaVersion:    SchemaVersion,
		Type:             TypeModule,
		TimeoutSeconds:   DefaultTimeoutSeconds,
		ExpiresInSeconds: &expiresIn,
		Arguments: TaskArguments{
			ModuleID: "agent.capability_inventory.v1",
			Input:    json.RawMessage(`{}`),
		},
	}
	if err := ValidateCreateRequest(base); err != nil {
		t.Fatalf("validate known module request: %v", err)
	}

	unknown := base
	unknown.Arguments.ModuleID = "agent.unknown.v1"
	if err := ValidateCreateRequest(unknown); err == nil {
		t.Fatal("accepted unknown module")
	}

	unexpectedInput := base
	unexpectedInput.Arguments.Input = json.RawMessage(`{"unexpected":true}`)
	if err := ValidateCreateRequest(unexpectedInput); err == nil {
		t.Fatal("accepted unexpected module input")
	}
}
