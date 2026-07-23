package tasks

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestStoreLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := NewStoreWithClock(func() time.Time { return now })
	expiresIn := 120

	task, err := store.Create("agent-one", CreateRequest{
		SchemaVersion:    SchemaVersion,
		Type:             TypeShell,
		Arguments:        ShellArguments{Command: "whoami"},
		TimeoutSeconds:   30,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if task.SchemaVersion != SchemaVersion || task.Status != StatusQueued {
		t.Fatalf("unexpected created task: %#v", task)
	}
	if task.ExpiresAt == nil || !task.ExpiresAt.Equal(now.Add(120*time.Second)) {
		t.Fatalf("unexpected expiry: %v", task.ExpiresAt)
	}

	now = now.Add(time.Second)
	dispatched, ok, err := store.DispatchNext("agent-one")
	if err != nil {
		t.Fatalf("dispatch task: %v", err)
	}
	if !ok || dispatched.ID != task.ID || dispatched.Status != StatusDispatched {
		t.Fatalf("unexpected dispatched task: %#v, ok=%t", dispatched, ok)
	}

	now = now.Add(time.Second)
	running, err := store.MarkRunning("agent-one", task.ID, StatusUpdate{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Status:        StatusRunning,
		Timestamp:     now,
	})
	if err != nil {
		t.Fatalf("mark running: %v", err)
	}
	if running.Status != StatusRunning || running.StartedAt == nil {
		t.Fatalf("unexpected running task: %#v", running)
	}

	now = now.Add(time.Second)
	exitCode := 0
	completed, err := store.Complete("agent-one", Result{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Outcome:       OutcomeCompleted,
		StartedAt:     *running.StartedAt,
		CompletedAt:   now,
		ExitCode:      &exitCode,
		Output:        Output{Stdout: "operator\n", Stderr: ""},
	})
	if err != nil {
		t.Fatalf("complete task: %v", err)
	}
	if completed.Status != StatusCompleted || completed.Result == nil ||
		completed.Result.Output.Stdout != "operator\n" {
		t.Fatalf("unexpected completed task: %#v", completed)
	}
}

func TestStoreRejectsInvalidTransitionsAndMismatchedIDs(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := NewStoreWithClock(func() time.Time { return now })
	task, err := store.CreateLegacyShell("agent-one", "whoami")
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	_, err = store.MarkRunning("agent-one", task.ID, StatusUpdate{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Status:        StatusRunning,
		Timestamp:     now,
	})
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected queued -> running transition error, got %v", err)
	}

	_, _, err = store.DispatchNext("agent-one")
	if err != nil {
		t.Fatalf("dispatch task: %v", err)
	}
	_, err = store.MarkRunning("agent-one", task.ID, StatusUpdate{
		SchemaVersion: SchemaVersion,
		TaskID:        "different-task",
		AgentID:       "agent-one",
		Status:        StatusRunning,
		Timestamp:     now,
	})
	if !IsValidationError(err) {
		t.Fatalf("expected task ID validation error, got %v", err)
	}
}

func TestStoreExpiresQueuedTasksBeforeDispatch(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := NewStoreWithClock(func() time.Time { return now })
	expiresIn := 1
	task, err := store.Create("agent-one", CreateRequest{
		SchemaVersion:    SchemaVersion,
		Type:             TypeShell,
		Arguments:        ShellArguments{Command: "whoami"},
		TimeoutSeconds:   30,
		ExpiresInSeconds: &expiresIn,
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	now = now.Add(2 * time.Second)
	if _, ok, err := store.DispatchNext("agent-one"); err != nil || ok {
		t.Fatalf("expired task should not dispatch: ok=%t err=%v", ok, err)
	}
	expired, err := store.Get("agent-one", task.ID)
	if err != nil {
		t.Fatalf("get expired task: %v", err)
	}
	if expired.Status != StatusExpired || expired.CompletedAt == nil {
		t.Fatalf("unexpected expired task: %#v", expired)
	}
}

func TestStoreCancellationAndTerminalImmutability(t *testing.T) {
	store := NewStore()
	task, err := store.CreateLegacyShell("agent-one", "whoami")
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	cancelled, err := store.Cancel("agent-one", task.ID)
	if err != nil {
		t.Fatalf("cancel task: %v", err)
	}
	if cancelled.Status != StatusCancelled || cancelled.CompletedAt == nil {
		t.Fatalf("unexpected cancelled task: %#v", cancelled)
	}
	if _, err := store.Cancel("agent-one", task.ID); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected terminal transition rejection, got %v", err)
	}
}

func TestCreateRejectsUnsupportedContractValues(t *testing.T) {
	store := NewStore()
	validExpiry := DefaultExpiresIn
	zeroExpiry := 0
	tooLongExpiry := MaxExpiresIn + 1
	valid := CreateRequest{
		SchemaVersion:    SchemaVersion,
		Type:             TypeShell,
		Arguments:        ShellArguments{Command: "whoami"},
		TimeoutSeconds:   DefaultTimeoutSeconds,
		ExpiresInSeconds: &validExpiry,
	}
	tests := []struct {
		name    string
		request CreateRequest
	}{
		{name: "missing schema version", request: func() CreateRequest {
			request := valid
			request.SchemaVersion = 0
			return request
		}()},
		{name: "unsupported schema version", request: func() CreateRequest {
			request := valid
			request.SchemaVersion = SchemaVersion + 1
			return request
		}()},
		{name: "unsupported type", request: func() CreateRequest {
			request := valid
			request.Type = "file"
			return request
		}()},
		{name: "missing command", request: func() CreateRequest {
			request := valid
			request.Arguments.Command = ""
			return request
		}()},
		{name: "timeout below minimum", request: func() CreateRequest {
			request := valid
			request.TimeoutSeconds = 0
			return request
		}()},
		{name: "timeout above maximum", request: func() CreateRequest {
			request := valid
			request.TimeoutSeconds = MaxTimeoutSeconds + 1
			return request
		}()},
		{name: "missing expiry", request: func() CreateRequest {
			request := valid
			request.ExpiresInSeconds = nil
			return request
		}()},
		{name: "expiry below minimum", request: func() CreateRequest {
			request := valid
			request.ExpiresInSeconds = &zeroExpiry
			return request
		}()},
		{name: "expiry above maximum", request: func() CreateRequest {
			request := valid
			request.ExpiresInSeconds = &tooLongExpiry
			return request
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := store.Create("agent-one", tt.request); !IsValidationError(err) {
				t.Fatalf("request %#v: expected validation error, got %v", tt.request, err)
			}
		})
	}
}

func TestDispatchLeaseRedeliversSameTaskAndPrioritizesIt(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := newStoreWithOptions(func() time.Time { return now }, 10*time.Second, 10)

	first, err := store.Create("agent-one", validCreateRequest("first", 300))
	if err != nil {
		t.Fatalf("create first task: %v", err)
	}
	dispatched, ok, err := store.DispatchNext("agent-one")
	if err != nil || !ok {
		t.Fatalf("dispatch first task: ok=%t err=%v", ok, err)
	}
	if dispatched.ID != first.ID || dispatched.DispatchedAt == nil {
		t.Fatalf("unexpected first dispatch: %#v", dispatched)
	}
	originalDispatchedAt := *dispatched.DispatchedAt

	now = now.Add(9 * time.Second)
	if _, ok, err := store.DispatchNext("agent-one"); err != nil || ok {
		t.Fatalf("task must not redeliver before lease: ok=%t err=%v", ok, err)
	}
	second, err := store.Create("agent-one", validCreateRequest("second", 300))
	if err != nil {
		t.Fatalf("create second task: %v", err)
	}

	now = now.Add(time.Second)
	redelivered, ok, err := store.DispatchNext("agent-one")
	if err != nil || !ok {
		t.Fatalf("redeliver first task: ok=%t err=%v", ok, err)
	}
	if redelivered.ID != first.ID {
		t.Fatalf("lease-expired task was not prioritized: got %s want %s", redelivered.ID, first.ID)
	}
	if redelivered.DispatchedAt == nil || !redelivered.DispatchedAt.Equal(originalDispatchedAt) {
		t.Fatalf("redelivery changed original dispatched_at: %#v", redelivered.DispatchedAt)
	}

	runningUpdate := StatusUpdate{
		SchemaVersion: SchemaVersion,
		TaskID:        first.ID,
		AgentID:       "agent-one",
		Status:        StatusRunning,
		Timestamp:     now.Add(-time.Hour),
	}
	if _, err := store.MarkRunning("agent-one", first.ID, runningUpdate); err != nil {
		t.Fatalf("mark first task running: %v", err)
	}
	next, ok, err := store.DispatchNext("agent-one")
	if err != nil || !ok || next.ID != second.ID {
		t.Fatalf("dispatch queued second task: got=%#v ok=%t err=%v", next, ok, err)
	}
}

func TestDispatchableTasksExpireAtBoundaryAcrossOperations(t *testing.T) {
	t.Run("dispatch and list", func(t *testing.T) {
		now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
		store := newStoreWithOptions(func() time.Time { return now }, time.Second, 10)
		dispatchedTask, err := store.Create("agent-one", validCreateRequest("dispatched", 5))
		if err != nil {
			t.Fatalf("create dispatched task: %v", err)
		}
		queuedTask, err := store.Create("agent-one", validCreateRequest("queued", 5))
		if err != nil {
			t.Fatalf("create queued task: %v", err)
		}
		if _, ok, err := store.DispatchNext("agent-one"); err != nil || !ok {
			t.Fatalf("dispatch task: ok=%t err=%v", ok, err)
		}

		now = now.Add(5 * time.Second)
		if _, ok, err := store.DispatchNext("agent-one"); err != nil || ok {
			t.Fatalf("expired tasks must not dispatch: ok=%t err=%v", ok, err)
		}
		history, err := store.List("agent-one")
		if err != nil {
			t.Fatalf("list expired tasks: %v", err)
		}
		if len(history) != 2 ||
			history[0].ID != dispatchedTask.ID ||
			history[1].ID != queuedTask.ID ||
			history[0].Status != StatusExpired ||
			history[1].Status != StatusExpired {
			t.Fatalf("unexpected expired history: %#v", history)
		}
	})

	t.Run("mark running", func(t *testing.T) {
		now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
		store := newStoreWithOptions(func() time.Time { return now }, time.Second, 10)
		task, err := store.Create("agent-one", validCreateRequest("expires", 1))
		if err != nil {
			t.Fatalf("create task: %v", err)
		}
		if _, ok, err := store.DispatchNext("agent-one"); err != nil || !ok {
			t.Fatalf("dispatch task: ok=%t err=%v", ok, err)
		}
		now = now.Add(time.Second)
		_, err = store.MarkRunning("agent-one", task.ID, StatusUpdate{
			SchemaVersion: SchemaVersion,
			TaskID:        task.ID,
			AgentID:       "agent-one",
			Status:        StatusRunning,
			Timestamp:     now.Add(-time.Hour),
		})
		if !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("expected expired transition conflict, got %v", err)
		}
		expired, err := store.Get("agent-one", task.ID)
		if err != nil || expired.Status != StatusExpired {
			t.Fatalf("task was not expired before running update: %#v err=%v", expired, err)
		}
	})
}

func TestRunningUpdateIsIdempotentAndUsesServerReceiptTime(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := newStoreWithOptions(func() time.Time { return now }, time.Second, 10)
	task, err := store.Create("agent-one", validCreateRequest("whoami", 300))
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if _, ok, err := store.DispatchNext("agent-one"); err != nil || !ok {
		t.Fatalf("dispatch task: ok=%t err=%v", ok, err)
	}

	now = now.Add(2 * time.Second)
	agentTimestamp := now.Add(-time.Hour).In(time.FixedZone("agent", 3600))
	update := StatusUpdate{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Status:        StatusRunning,
		Timestamp:     agentTimestamp,
	}
	running, err := store.MarkRunning("agent-one", task.ID, update)
	if err != nil {
		t.Fatalf("clock-skewed running update: %v", err)
	}
	if running.StartedAt == nil || !running.StartedAt.Equal(now) {
		t.Fatalf("task started_at must use server receipt time: got %v want %v", running.StartedAt, now)
	}

	sameInstant := update
	sameInstant.Timestamp = update.Timestamp.UTC()
	repeated, err := store.MarkRunning("agent-one", task.ID, sameInstant)
	if err != nil || repeated.Status != StatusRunning {
		t.Fatalf("idempotent running update failed: task=%#v err=%v", repeated, err)
	}

	conflict := update
	conflict.Timestamp = conflict.Timestamp.Add(time.Second)
	if _, err := store.MarkRunning("agent-one", task.ID, conflict); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected conflicting repeated update, got %v", err)
	}
}

func TestCompletionIsIdempotentAndUsesServerReceiptTime(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := newStoreWithOptions(func() time.Time { return now }, time.Second, 10)
	task, err := store.Create("agent-one", validCreateRequest("whoami", 300))
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	if _, ok, err := store.DispatchNext("agent-one"); err != nil || !ok {
		t.Fatalf("dispatch task: ok=%t err=%v", ok, err)
	}
	agentStartedAt := now.Add(-time.Hour)
	now = now.Add(time.Second)
	runningUpdate := StatusUpdate{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Status:        StatusRunning,
		Timestamp:     agentStartedAt,
	}
	if _, err := store.MarkRunning("agent-one", task.ID, runningUpdate); err != nil {
		t.Fatalf("mark running: %v", err)
	}
	serverStartedAt := now

	now = now.Add(2 * time.Second)
	exitCode := 0
	result := Result{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Outcome:       OutcomeCompleted,
		StartedAt:     agentStartedAt,
		CompletedAt:   agentStartedAt.Add(500 * time.Millisecond),
		ExitCode:      &exitCode,
		Output:        Output{Stdout: "ok\n", Stderr: ""},
	}
	completed, info, err := store.CompleteWithInfo("agent-one", result)
	if err != nil || !info.Applied {
		t.Fatalf("complete task: task=%#v info=%#v err=%v", completed, info, err)
	}
	if completed.StartedAt == nil || !completed.StartedAt.Equal(serverStartedAt) {
		t.Fatalf("task started_at changed from server receipt time: %v", completed.StartedAt)
	}
	if completed.CompletedAt == nil || !completed.CompletedAt.Equal(now) {
		t.Fatalf("task completed_at must use server receipt time: got %v want %v", completed.CompletedAt, now)
	}
	if completed.Result == nil ||
		!completed.Result.StartedAt.Equal(agentStartedAt) ||
		!completed.Result.CompletedAt.Equal(result.CompletedAt) {
		t.Fatalf("agent result timestamps were not preserved: %#v", completed.Result)
	}

	repeatedResult := result
	repeatedResult.StartedAt = result.StartedAt.In(time.FixedZone("repeat", -5*3600))
	repeatedResult.CompletedAt = result.CompletedAt.In(time.FixedZone("repeat", -5*3600))
	repeated, repeatInfo, err := store.CompleteWithInfo("agent-one", repeatedResult)
	if err != nil || repeatInfo.Applied || repeated.Status != StatusCompleted {
		t.Fatalf("idempotent result failed: task=%#v info=%#v err=%v", repeated, repeatInfo, err)
	}
	replayedRunning, err := store.MarkRunning("agent-one", task.ID, runningUpdate)
	if err != nil || replayedRunning.Status != StatusCompleted {
		t.Fatalf("accepted running update did not remain idempotent after completion: task=%#v err=%v", replayedRunning, err)
	}

	conflict := result
	conflict.Output.Stdout = "different"
	if _, _, err := store.CompleteWithInfo("agent-one", conflict); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected conflicting terminal result, got %v", err)
	}
}

func TestTaskHistoryCapacityPrunesOnlyTerminalTasks(t *testing.T) {
	store := newStoreWithOptions(time.Now, time.Second, 2)
	first, err := store.Create("agent-one", validCreateRequest("first", 300))
	if err != nil {
		t.Fatalf("create first: %v", err)
	}
	second, err := store.Create("agent-one", validCreateRequest("second", 300))
	if err != nil {
		t.Fatalf("create second: %v", err)
	}
	if _, err := store.Create("agent-one", validCreateRequest("blocked", 300)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("expected capacity error with only active tasks, got %v", err)
	}
	if _, err := store.Cancel("agent-one", first.ID); err != nil {
		t.Fatalf("cancel first: %v", err)
	}
	third, err := store.Create("agent-one", validCreateRequest("third", 300))
	if err != nil {
		t.Fatalf("create after terminal prune: %v", err)
	}
	history, err := store.List("agent-one")
	if err != nil {
		t.Fatalf("list history: %v", err)
	}
	if len(history) != 2 || history[0].ID != second.ID || history[1].ID != third.ID {
		t.Fatalf("terminal pruning retained wrong tasks: %#v", history)
	}
	if _, err := store.Get("agent-one", first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pruned task should be removed by id, got %v", err)
	}
}

func TestLegacyDispatchSkipsTypedTasksAndRecordsErrorsHonestly(t *testing.T) {
	store := newStoreWithOptions(time.Now, time.Second, 10)
	typed, err := store.Create("agent-one", validCreateRequest("typed", 300))
	if err != nil {
		t.Fatalf("create typed task: %v", err)
	}
	legacy, err := store.CreateLegacyShell("agent-one", "legacy")
	if err != nil {
		t.Fatalf("create legacy task: %v", err)
	}
	got, ok, err := store.DispatchNextLegacy("agent-one")
	if err != nil || !ok || got.ID != legacy.ID {
		t.Fatalf("legacy poll consumed wrong task: got=%#v ok=%t err=%v", got, ok, err)
	}
	if typedState, err := store.Get("agent-one", typed.ID); err != nil || typedState.Status != StatusQueued {
		t.Fatalf("typed-origin task was consumed by legacy poll: %#v err=%v", typedState, err)
	}
	failed, matched, err := store.CompleteLegacy("agent-one", "legacy", "Error: timed out")
	if err != nil || !matched {
		t.Fatalf("complete legacy failure: matched=%t err=%v", matched, err)
	}
	if failed.Status != StatusFailed ||
		failed.Result == nil ||
		failed.Result.Outcome != OutcomeFailed ||
		failed.Result.ExitCode != nil ||
		failed.Result.Error != "Error: timed out" {
		t.Fatalf("legacy failure was recorded dishonestly: %#v", failed)
	}
}

func TestContractCharacterLimits(t *testing.T) {
	store := newStoreWithOptions(time.Now, time.Second, 10)
	if _, err := store.Create(
		"agent-one",
		validCreateRequest(strings.Repeat("界", MaxCommandCharacters), 300),
	); err != nil {
		t.Fatalf("maximum Unicode command should be accepted: %v", err)
	}
	if _, err := store.Create(
		"agent-two",
		validCreateRequest(strings.Repeat("界", MaxCommandCharacters+1), 300),
	); !IsValidationError(err) {
		t.Fatalf("oversized Unicode command should be rejected, got %v", err)
	}
}

func validCreateRequest(command string, expiresIn int) CreateRequest {
	return CreateRequest{
		SchemaVersion:    SchemaVersion,
		Type:             TypeShell,
		Arguments:        ShellArguments{Command: command},
		TimeoutSeconds:   DefaultTimeoutSeconds,
		ExpiresInSeconds: &expiresIn,
	}
}
