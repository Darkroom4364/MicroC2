package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"microc2/server/internal/audit"
	"microc2/server/internal/persistence"
)

func TestDurableStoreRestartPreservesDispatchLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	db, store := openDurableTestStore(t, path, "listener-one", &now, 10*time.Second, 10)
	queued, err := store.Create("agent-one", validCreateRequest("whoami", 300))
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	dispatched, ok, err := store.DispatchNext("agent-one")
	if err != nil || !ok {
		t.Fatalf("dispatch task: task=%#v ok=%t err=%v", dispatched, ok, err)
	}
	if dispatched.ID != queued.ID || dispatched.DispatchedAt == nil {
		t.Fatalf("unexpected initial dispatch: %#v", dispatched)
	}
	originalDispatchedAt := *dispatched.DispatchedAt
	closeDurableTestDatabase(t, db)

	now = now.Add(9 * time.Second)
	db, store = openDurableTestStore(t, path, "listener-one", &now, 10*time.Second, 10)
	if task, ok, err := store.DispatchNext("agent-one"); err != nil || ok {
		t.Fatalf("redelivery before persisted lease expired: task=%#v ok=%t err=%v", task, ok, err)
	}
	closeDurableTestDatabase(t, db)

	now = now.Add(time.Second)
	db, store = openDurableTestStore(t, path, "listener-one", &now, 10*time.Second, 10)
	defer closeDurableTestDatabase(t, db)
	redelivered, ok, err := store.DispatchNext("agent-one")
	if err != nil || !ok {
		t.Fatalf("redeliver persisted task: task=%#v ok=%t err=%v", redelivered, ok, err)
	}
	if redelivered.ID != queued.ID {
		t.Fatalf("redelivered task %q, want %q", redelivered.ID, queued.ID)
	}
	if redelivered.DispatchedAt == nil ||
		!redelivered.DispatchedAt.Equal(originalDispatchedAt) {
		t.Fatalf(
			"redelivery changed original dispatched_at: got %v want %v",
			redelivered.DispatchedAt,
			originalDispatchedAt,
		)
	}
}

func TestDurableStoreAuditLifecycleIsCausalAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, 7, 24, 9, 0, 0, 0, time.UTC)
	db, store := openDurableTestStore(
		t,
		path,
		"listener-one",
		&now,
		10*time.Second,
		10,
	)
	defer closeDurableTestDatabase(t, db)

	operator := audit.Actor{Kind: audit.ActorOperator, ID: "operator-test"}
	operatorContext := audit.WithActor(context.Background(), operator)
	secretCommand := "printf super-secret-command"
	task, err := store.CreateContext(
		operatorContext,
		"agent-one",
		validCreateRequest(secretCommand, 300),
	)
	if err != nil {
		t.Fatalf("create audited task: %v", err)
	}
	var taskRootSequence int64
	if err := db.SQL().QueryRow(
		`SELECT created_audit_event_seq
		 FROM tasks
		 WHERE listener_id = ? AND task_id = ?`,
		"listener-one",
		task.ID,
	).Scan(&taskRootSequence); err != nil {
		t.Fatalf("read task causal audit sequence: %v", err)
	}
	if taskRootSequence <= 0 {
		t.Fatalf("task has invalid causal audit sequence %d", taskRootSequence)
	}
	encodedTask, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("encode public task: %v", err)
	}
	if strings.Contains(string(encodedTask), "audit") {
		t.Fatalf("public Task JSON exposed audit internals: %s", encodedTask)
	}

	if _, ok, err := store.DispatchNext("agent-one"); err != nil || !ok {
		t.Fatalf("dispatch audited task: ok=%t err=%v", ok, err)
	}
	if _, ok, err := store.DispatchNext("agent-one"); err != nil || ok {
		t.Fatalf("dispatch inside lease: ok=%t err=%v", ok, err)
	}
	now = now.Add(10 * time.Second)
	if _, ok, err := store.DispatchNext("agent-one"); err != nil || !ok {
		t.Fatalf("redeliver audited task: ok=%t err=%v", ok, err)
	}

	startedAt := now.Add(-time.Second)
	runningUpdate := StatusUpdate{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Status:        StatusRunning,
		Timestamp:     startedAt,
	}
	if _, err := store.MarkRunning("agent-one", task.ID, runningUpdate); err != nil {
		t.Fatalf("mark audited task running: %v", err)
	}
	if _, err := store.MarkRunning("agent-one", task.ID, runningUpdate); err != nil {
		t.Fatalf("replay audited running update: %v", err)
	}

	exitCode := 0
	secretOutput := "super-secret-result"
	result := Result{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Outcome:       OutcomeCompleted,
		StartedAt:     startedAt,
		CompletedAt:   now,
		ExitCode:      &exitCode,
		Output:        Output{Stdout: secretOutput},
	}
	if _, info, err := store.CompleteWithInfo("agent-one", result); err != nil || !info.Applied {
		t.Fatalf("complete audited task: info=%#v err=%v", info, err)
	}
	if _, info, err := store.CompleteWithInfo("agent-one", result); err != nil || info.Applied {
		t.Fatalf("replay audited completion: info=%#v err=%v", info, err)
	}

	cancelled, err := store.CreateContext(
		operatorContext,
		"agent-one",
		validCreateRequest("another-secret-command", 300),
	)
	if err != nil {
		t.Fatalf("create task for audited cancellation: %v", err)
	}
	var cancelledRootSequence int64
	if err := db.SQL().QueryRow(
		`SELECT created_audit_event_seq
		 FROM tasks
		 WHERE listener_id = ? AND task_id = ?`,
		"listener-one",
		cancelled.ID,
	).Scan(&cancelledRootSequence); err != nil {
		t.Fatalf("read cancelled task causal sequence: %v", err)
	}
	if _, err := store.CancelContext(
		operatorContext,
		"agent-one",
		cancelled.ID,
	); err != nil {
		t.Fatalf("cancel audited task: %v", err)
	}
	if _, err := store.CancelContext(
		operatorContext,
		"agent-one",
		cancelled.ID,
	); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("repeated cancellation returned %v", err)
	}

	auditStore, err := audit.NewStore(db)
	if err != nil {
		t.Fatalf("open audit store: %v", err)
	}
	page, err := auditStore.Page(context.Background(), audit.PageOptions{
		Limit:  50,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("page task audit events: %v", err)
	}
	if page.Total != 7 || len(page.Events) != 7 {
		t.Fatalf("unexpected task audit event count: total=%d events=%#v", page.Total, page.Events)
	}
	events := make([]audit.Event, len(page.Events))
	for index := range page.Events {
		events[index] = page.Events[len(page.Events)-1-index]
	}
	expectedActions := []string{
		"task.queued",
		"task.dispatched",
		"task.redelivered",
		"task.running",
		"task.result_received",
		"task.queued",
		"task.cancelled",
	}
	for index, expectedAction := range expectedActions {
		event := events[index]
		if event.Action != expectedAction ||
			event.Target.Kind != "task" ||
			event.ListenerID != "listener-one" ||
			event.AgentID != "agent-one" {
			t.Fatalf("unexpected audit event %d: %#v", index, event)
		}
		expectedTaskID := task.ID
		expectedRoot := taskRootSequence
		if index >= 5 {
			expectedTaskID = cancelled.ID
			expectedRoot = cancelledRootSequence
		}
		if event.TaskID != expectedTaskID || event.Target.ID != expectedTaskID {
			t.Fatalf("audit event %d targeted the wrong task: %#v", index, event)
		}
		if expectedAction == "task.queued" {
			if event.CausationSequence != nil || event.Actor != operator {
				t.Fatalf("unexpected task root event %d: %#v", index, event)
			}
			if event.Sequence != expectedRoot {
				t.Fatalf(
					"task root event %d sequence=%d, linked row=%d",
					index,
					event.Sequence,
					expectedRoot,
				)
			}
			continue
		}
		if event.CausationSequence == nil ||
			*event.CausationSequence != expectedRoot {
			t.Fatalf("audit event %d lost causation: %#v", index, event)
		}
		expectedActor := audit.Actor{Kind: audit.ActorAgent, ID: "agent-one"}
		if expectedAction == "task.cancelled" {
			expectedActor = operator
		}
		if event.Actor != expectedActor {
			t.Fatalf("audit event %d has actor %#v, want %#v", index, event.Actor, expectedActor)
		}
	}
	encodedAudit, err := json.Marshal(page)
	if err != nil {
		t.Fatalf("encode task audit page: %v", err)
	}
	for _, secret := range []string{
		secretCommand,
		"another-secret-command",
		secretOutput,
	} {
		if strings.Contains(string(encodedAudit), secret) {
			t.Fatalf("task audit page retained secret %q: %s", secret, encodedAudit)
		}
	}
}

func TestDurableStoreAuditFailureRollsBackTaskMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	db, store := openDurableTestStore(
		t,
		path,
		"listener-one",
		&now,
		time.Second,
		10,
	)
	defer closeDurableTestDatabase(t, db)

	if _, err := db.SQL().Exec(`
		CREATE TRIGGER reject_task_queue_audit
		BEFORE INSERT ON audit_events
		WHEN NEW.action = 'task.queued'
		BEGIN
			SELECT RAISE(ABORT, 'injected task queue audit failure');
		END
	`); err != nil {
		t.Fatalf("create task queue audit failure trigger: %v", err)
	}
	if _, err := store.Create(
		"agent-one",
		validCreateRequest("must-not-persist", 300),
	); err == nil {
		t.Fatal("task creation unexpectedly survived audit failure")
	}
	var taskCount int
	if err := db.SQL().QueryRow(
		`SELECT COUNT(*) FROM tasks WHERE listener_id = ?`,
		"listener-one",
	).Scan(&taskCount); err != nil {
		t.Fatalf("count tasks after audit failure: %v", err)
	}
	if taskCount != 0 {
		t.Fatalf("audit failure left %d queued tasks", taskCount)
	}
	if _, err := db.SQL().Exec(`DROP TRIGGER reject_task_queue_audit`); err != nil {
		t.Fatalf("drop task queue audit failure trigger: %v", err)
	}

	task, err := store.Create(
		"agent-one",
		validCreateRequest("dispatch-must-roll-back", 300),
	)
	if err != nil {
		t.Fatalf("create dispatch rollback fixture: %v", err)
	}
	if _, err := db.SQL().Exec(`
		CREATE TRIGGER reject_task_dispatch_audit
		BEFORE INSERT ON audit_events
		WHEN NEW.action = 'task.dispatched'
		BEGIN
			SELECT RAISE(ABORT, 'injected task dispatch audit failure');
		END
	`); err != nil {
		t.Fatalf("create task dispatch audit failure trigger: %v", err)
	}
	if _, ok, err := store.DispatchNext("agent-one"); err == nil || ok {
		t.Fatalf("task dispatch survived audit failure: ok=%t err=%v", ok, err)
	}
	persisted, err := store.Get("agent-one", task.ID)
	if err != nil {
		t.Fatalf("get task after rolled-back dispatch: %v", err)
	}
	if persisted.Status != StatusQueued || persisted.DispatchedAt != nil {
		t.Fatalf("audit failure left partial dispatch state: %#v", persisted)
	}
}

func TestDurableStoreRunningAndTerminalReplaysSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, 7, 23, 12, 0, 0, 123456789, time.UTC)

	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	task, err := store.CreateLegacyShell("agent-one", "whoami")
	if err != nil {
		t.Fatalf("create legacy-origin task: %v", err)
	}
	if _, ok, err := store.DispatchNext("agent-one"); err != nil || !ok {
		t.Fatalf("dispatch task: ok=%t err=%v", ok, err)
	}
	agentStartedAt := now.Add(-time.Hour).In(time.FixedZone("agent", 3600))
	update := StatusUpdate{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Status:        StatusRunning,
		Timestamp:     agentStartedAt,
	}
	now = now.Add(time.Second)
	running, err := store.MarkRunning("agent-one", task.ID, update)
	if err != nil {
		t.Fatalf("mark running: %v", err)
	}
	serverStartedAt := *running.StartedAt
	closeDurableTestDatabase(t, db)

	now = now.Add(time.Second)
	db, store = openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	replayedRunning, err := store.MarkRunning("agent-one", task.ID, update)
	if err != nil {
		t.Fatalf("replay running update after restart: %v", err)
	}
	if replayedRunning.StartedAt == nil ||
		!replayedRunning.StartedAt.Equal(serverStartedAt) {
		t.Fatalf(
			"running replay changed server started_at: got %v want %v",
			replayedRunning.StartedAt,
			serverStartedAt,
		)
	}

	exitCode := 0
	result := Result{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Outcome:       OutcomeCompleted,
		StartedAt:     agentStartedAt.UTC(),
		CompletedAt:   agentStartedAt.Add(500 * time.Millisecond),
		ExitCode:      &exitCode,
		Output:        Output{Stdout: "operator\n", Stderr: ""},
	}
	now = now.Add(time.Second)
	completed, info, err := store.CompleteWithInfo("agent-one", result)
	if err != nil || !info.Applied || !info.LegacyOrigin {
		t.Fatalf("complete task: task=%#v info=%#v err=%v", completed, info, err)
	}
	if completed.StartedAt == nil || !completed.StartedAt.Equal(serverStartedAt) {
		t.Fatalf("completion changed server started_at: %#v", completed)
	}
	page, total, _, err := store.GetLegacyResultsPage(
		"agent-one",
		0,
		10,
		MaxLegacyResultPageBytes,
	)
	if err != nil {
		t.Fatalf("page projected legacy result: %v", err)
	}
	if total != 1 || len(page) != 1 ||
		page[0].Command != "whoami" ||
		page[0].Output != "operator\n" {
		t.Fatalf("unexpected projected legacy history: total=%d page=%#v", total, page)
	}
	closeDurableTestDatabase(t, db)

	db, store = openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	defer closeDurableTestDatabase(t, db)
	repeated, repeatInfo, err := store.CompleteWithInfo("agent-one", result)
	if err != nil || repeatInfo.Applied || repeated.Status != StatusCompleted {
		t.Fatalf(
			"replay terminal result after restart: task=%#v info=%#v err=%v",
			repeated,
			repeatInfo,
			err,
		)
	}
	page, total, _, err = store.GetLegacyResultsPage(
		"agent-one",
		0,
		10,
		MaxLegacyResultPageBytes,
	)
	if err != nil || total != 1 || len(page) != 1 {
		t.Fatalf("terminal replay duplicated history: total=%d page=%#v err=%v", total, page, err)
	}

	conflict := result
	conflict.Output.Stdout = "different"
	if _, _, err := store.CompleteWithInfo("agent-one", conflict); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("conflicting terminal replay returned %v", err)
	}
}

func TestDurableStoreCompletionAndLegacyProjectionAreAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	defer closeDurableTestDatabase(t, db)

	task, err := store.CreateLegacyShell("agent-one", "whoami")
	if err != nil {
		t.Fatalf("create legacy-origin task: %v", err)
	}
	if _, ok, err := store.DispatchNext("agent-one"); err != nil || !ok {
		t.Fatalf("dispatch legacy-origin task: ok=%t err=%v", ok, err)
	}
	agentStartedAt := now.Add(-time.Minute)
	update := StatusUpdate{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Status:        StatusRunning,
		Timestamp:     agentStartedAt,
	}
	if _, err := store.MarkRunning("agent-one", task.ID, update); err != nil {
		t.Fatalf("mark task running: %v", err)
	}

	// Force the compatibility projection to conflict after the task/result SQL
	// has run. The surrounding completion transaction must roll all of it back.
	if _, err := db.SQL().Exec(
		`INSERT INTO legacy_results (
			listener_id, agent_id, source_task_id, command, output, recorded_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		"listener-one",
		"agent-one",
		task.ID,
		"conflicting-command",
		"conflicting-output",
		formatDurableTime(now),
	); err != nil {
		t.Fatalf("insert conflicting legacy projection: %v", err)
	}
	exitCode := 0
	result := Result{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Outcome:       OutcomeCompleted,
		StartedAt:     agentStartedAt,
		CompletedAt:   agentStartedAt.Add(time.Second),
		ExitCode:      &exitCode,
		Output:        Output{Stdout: "operator\n", Stderr: ""},
	}
	if _, _, err := store.CompleteWithInfo("agent-one", result); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("completion with conflicting projection returned %v", err)
	}
	stillRunning, err := store.Get("agent-one", task.ID)
	if err != nil {
		t.Fatalf("get rolled-back task: %v", err)
	}
	if stillRunning.Status != StatusRunning ||
		stillRunning.CompletedAt != nil ||
		stillRunning.Result != nil {
		t.Fatalf("failed projection left partial terminal state: %#v", stillRunning)
	}

	if _, err := db.SQL().Exec(
		`DELETE FROM legacy_results WHERE listener_id = ? AND source_task_id = ?`,
		"listener-one",
		task.ID,
	); err != nil {
		t.Fatalf("remove conflicting legacy projection: %v", err)
	}
	completed, info, err := store.CompleteWithInfo("agent-one", result)
	if err != nil || !info.Applied || completed.Status != StatusCompleted {
		t.Fatalf("retry atomic completion: task=%#v info=%#v err=%v", completed, info, err)
	}
	page, total, _, err := store.GetLegacyResultsPage(
		"agent-one",
		0,
		10,
		MaxLegacyResultPageBytes,
	)
	if err != nil || total != 1 || len(page) != 1 || page[0].Command != "whoami" {
		t.Fatalf("atomic completion history: total=%d page=%#v err=%v", total, page, err)
	}
}

func TestDurableStoreScopesTasksByListener(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	db, err := persistence.Open(path)
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	defer closeDurableTestDatabase(t, db)

	first, err := newDurableStoreWithOptions(
		db,
		"listener-one",
		func() time.Time { return now },
		time.Second,
		10,
	)
	if err != nil {
		t.Fatalf("create first listener store: %v", err)
	}
	second, err := newDurableStoreWithOptions(
		db,
		"listener-two",
		func() time.Time { return now },
		time.Second,
		10,
	)
	if err != nil {
		t.Fatalf("create second listener store: %v", err)
	}

	firstTask, err := first.Create("agent-shared", validCreateRequest("first", 300))
	if err != nil {
		t.Fatalf("create first-listener task: %v", err)
	}
	secondTask, err := second.Create("agent-shared", validCreateRequest("second", 300))
	if err != nil {
		t.Fatalf("create second-listener task: %v", err)
	}

	firstHistory, err := first.List("agent-shared")
	if err != nil {
		t.Fatalf("list first-listener history: %v", err)
	}
	secondHistory, err := second.List("agent-shared")
	if err != nil {
		t.Fatalf("list second-listener history: %v", err)
	}
	if len(firstHistory) != 1 || firstHistory[0].ID != firstTask.ID {
		t.Fatalf("first listener leaked history: %#v", firstHistory)
	}
	if len(secondHistory) != 1 || secondHistory[0].ID != secondTask.ID {
		t.Fatalf("second listener leaked history: %#v", secondHistory)
	}
	if _, err := first.Get("agent-shared", secondTask.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-listener task lookup returned %v", err)
	}
	if _, err := second.Get("agent-shared", firstTask.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-listener task lookup returned %v", err)
	}

	// A UUID collision must remain harmless because legacy-result idempotency is
	// scoped by the server-owned listener ID as well as the source task ID.
	for _, fixture := range []struct {
		store   *DurableStore
		command string
		output  string
	}{
		{store: first, command: "first", output: "one\n"},
		{store: second, command: "second", output: "two\n"},
	} {
		tx, err := db.SQL().BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatalf("begin scoped legacy-result fixture: %v", err)
		}
		if err := fixture.store.insertLegacyResultTx(
			context.Background(),
			tx,
			"agent-shared",
			"colliding-task-id",
			LegacyResult{
				Command:   fixture.command,
				Output:    fixture.output,
				Timestamp: now.Format(time.RFC3339),
			},
		); err != nil {
			_ = tx.Rollback()
			t.Fatalf("insert scoped legacy-result fixture: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit scoped legacy-result fixture: %v", err)
		}
	}
	firstPage, firstTotal, _, err := first.GetLegacyResultsPage(
		"agent-shared",
		0,
		10,
		MaxLegacyResultPageBytes,
	)
	if err != nil {
		t.Fatalf("page first-listener legacy history: %v", err)
	}
	secondPage, secondTotal, _, err := second.GetLegacyResultsPage(
		"agent-shared",
		0,
		10,
		MaxLegacyResultPageBytes,
	)
	if err != nil {
		t.Fatalf("page second-listener legacy history: %v", err)
	}
	if firstTotal != 1 || len(firstPage) != 1 ||
		firstPage[0].Command != "first" ||
		secondTotal != 1 || len(secondPage) != 1 ||
		secondPage[0].Command != "second" {
		t.Fatalf(
			"colliding source task IDs crossed listener scopes: first=%#v second=%#v",
			firstPage,
			secondPage,
		)
	}
}

func TestDurableStoreExpiresDispatchableTasksAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	dispatched, err := store.Create("agent-one", validCreateRequest("dispatched", 5))
	if err != nil {
		t.Fatalf("create dispatched task: %v", err)
	}
	queued, err := store.Create("agent-one", validCreateRequest("queued", 5))
	if err != nil {
		t.Fatalf("create queued task: %v", err)
	}
	if _, ok, err := store.DispatchNext("agent-one"); err != nil || !ok {
		t.Fatalf("dispatch first task: ok=%t err=%v", ok, err)
	}
	closeDurableTestDatabase(t, db)

	now = now.Add(5 * time.Second)
	db, store = openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	defer closeDurableTestDatabase(t, db)
	history, err := store.List("agent-one")
	if err != nil {
		t.Fatalf("list expired durable history: %v", err)
	}
	if len(history) != 2 ||
		history[0].ID != dispatched.ID ||
		history[1].ID != queued.ID ||
		history[0].Status != StatusExpired ||
		history[1].Status != StatusExpired ||
		history[0].CompletedAt == nil ||
		history[1].CompletedAt == nil {
		t.Fatalf("unexpected expired durable history: %#v", history)
	}
	if _, ok, err := store.DispatchNext("agent-one"); err != nil || ok {
		t.Fatalf("expired durable task dispatched: ok=%t err=%v", ok, err)
	}
}

func TestDurableStoreRetentionSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 2)

	first, err := store.Create("agent-one", validCreateRequest("first", 300))
	if err != nil {
		t.Fatalf("create first task: %v", err)
	}
	second, err := store.Create("agent-one", validCreateRequest("second", 300))
	if err != nil {
		t.Fatalf("create second task: %v", err)
	}
	if _, err := store.Create("agent-one", validCreateRequest("blocked", 300)); !errors.Is(err, ErrCapacity) {
		t.Fatalf("create above active capacity returned %v", err)
	}
	if _, err := store.Cancel("agent-one", first.ID); err != nil {
		t.Fatalf("cancel first task: %v", err)
	}
	third, err := store.Create("agent-one", validCreateRequest("third", 300))
	if err != nil {
		t.Fatalf("create after terminal prune: %v", err)
	}
	closeDurableTestDatabase(t, db)

	db, store = openDurableTestStore(t, path, "listener-one", &now, time.Second, 2)
	defer closeDurableTestDatabase(t, db)
	history, err := store.List("agent-one")
	if err != nil {
		t.Fatalf("list retained durable history: %v", err)
	}
	if len(history) != 2 ||
		history[0].ID != second.ID ||
		history[1].ID != third.ID {
		t.Fatalf("unexpected retained durable history: %#v", history)
	}
	if _, err := store.Get("agent-one", first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pruned durable task lookup returned %v", err)
	}
}

func TestDurableStoreLegacyCompletionAndPagingSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)

	task, err := store.CreateLegacyShell("agent-one", "whoami")
	if err != nil {
		t.Fatalf("create legacy task: %v", err)
	}
	dispatched, ok, err := store.DispatchNextLegacy("agent-one")
	if err != nil || !ok || dispatched.ID != task.ID {
		t.Fatalf("dispatch legacy task: task=%#v ok=%t err=%v", dispatched, ok, err)
	}
	completed, matched, err := store.CompleteLegacy("agent-one", "whoami", "operator\n")
	if err != nil || !matched || completed.Status != StatusCompleted {
		t.Fatalf("complete legacy task: task=%#v matched=%t err=%v", completed, matched, err)
	}
	closeDurableTestDatabase(t, db)

	db, store = openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	defer closeDurableTestDatabase(t, db)
	page, total, _, err := store.GetLegacyResultsPage(
		"agent-one",
		0,
		10,
		MaxLegacyResultPageBytes,
	)
	if err != nil {
		t.Fatalf("page durable legacy history: %v", err)
	}
	if total != 1 || len(page) != 1 ||
		page[0].Command != "whoami" ||
		page[0].Output != "operator\n" {
		t.Fatalf("unexpected durable legacy history: total=%d page=%#v", total, page)
	}
	if _, matched, err := store.CompleteLegacy("agent-one", "whoami", "operator\n"); err != nil || matched {
		t.Fatalf("repeated legacy completion: matched=%t err=%v", matched, err)
	}
	auditStore, err := audit.NewStore(db)
	if err != nil {
		t.Fatalf("open legacy task audit store: %v", err)
	}
	auditPage, err := auditStore.Page(context.Background(), audit.PageOptions{
		Limit:  10,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("page legacy task audit events: %v", err)
	}
	actionCounts := make(map[string]int)
	for _, event := range auditPage.Events {
		actionCounts[event.Action]++
		if event.TaskID != task.ID ||
			event.ListenerID != "listener-one" ||
			event.AgentID != "agent-one" {
			t.Fatalf("legacy task audit event lost scope: %#v", event)
		}
	}
	for _, action := range []string{
		"task.queued",
		"task.dispatched",
		"task.result_received",
	} {
		if actionCounts[action] != 1 {
			t.Fatalf(
				"legacy task audit action %q count=%d, events=%#v",
				action,
				actionCounts[action],
				auditPage.Events,
			)
		}
	}
	if auditPage.Total != 3 {
		t.Fatalf("legacy result retry duplicated audit history: %#v", auditPage)
	}
	page, total, _, err = store.GetLegacyResultsPage(
		"agent-one",
		1,
		10,
		MaxLegacyResultPageBytes,
	)
	if err != nil || total != 1 || page == nil || len(page) != 0 {
		t.Fatalf("beyond-end durable legacy page: total=%d page=%#v err=%v", total, page, err)
	}
}

func TestDurableStoreSummaryPageOmitsResultStreams(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	defer closeDurableTestDatabase(t, db)

	completedTask, err := store.Create("agent-one", validCreateRequest("first", 300))
	if err != nil {
		t.Fatalf("create completed task: %v", err)
	}
	if _, ok, err := store.DispatchNext("agent-one"); err != nil || !ok {
		t.Fatalf("dispatch completed task: ok=%t err=%v", ok, err)
	}
	agentStartedAt := now.Add(-time.Second)
	if _, err := store.MarkRunning("agent-one", completedTask.ID, StatusUpdate{
		SchemaVersion: SchemaVersion,
		TaskID:        completedTask.ID,
		AgentID:       "agent-one",
		Status:        StatusRunning,
		Timestamp:     agentStartedAt,
	}); err != nil {
		t.Fatalf("mark completed task running: %v", err)
	}
	exitCode := 0
	if _, _, err := store.CompleteWithInfo("agent-one", Result{
		SchemaVersion: SchemaVersion,
		TaskID:        completedTask.ID,
		AgentID:       "agent-one",
		Outcome:       OutcomeCompleted,
		StartedAt:     agentStartedAt,
		CompletedAt:   agentStartedAt.Add(time.Second),
		ExitCode:      &exitCode,
		Output: Output{
			Stdout: strings.Repeat("x", 64<<10),
			Stderr: strings.Repeat("y", 64<<10),
		},
	}); err != nil {
		t.Fatalf("complete task with streams: %v", err)
	}

	now = now.Add(time.Second)
	newest, err := store.Create("agent-one", validCreateRequest("second", 300))
	if err != nil {
		t.Fatalf("create newest task: %v", err)
	}

	page, total, err := store.ListTaskSummariesPage("agent-one", 0, 1)
	if err != nil {
		t.Fatalf("page newest task summary: %v", err)
	}
	if total != 2 || len(page) != 1 || page[0].ID != newest.ID {
		t.Fatalf("unexpected newest summary page: total=%d page=%#v", total, page)
	}
	page, total, err = store.ListTaskSummariesPage("agent-one", 1, 1)
	if err != nil {
		t.Fatalf("page completed task summary: %v", err)
	}
	if total != 2 || len(page) != 1 || page[0].ID != completedTask.ID ||
		page[0].Result == nil || page[0].Result.Outcome != OutcomeCompleted {
		t.Fatalf("unexpected completed summary page: total=%d page=%#v", total, page)
	}
	encoded, err := json.Marshal(page[0])
	if err != nil {
		t.Fatalf("encode task summary: %v", err)
	}
	if strings.Contains(string(encoded), `"stdout"`) ||
		strings.Contains(string(encoded), `"stderr"`) ||
		strings.Contains(durableTaskSummarySelect, "r.stdout") ||
		strings.Contains(durableTaskSummarySelect, "r.stderr") {
		t.Fatalf("summary query or payload included result streams: %s", encoded)
	}
}

func TestDurableStoreLegacyPageStopsAtEncodedByteBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	defer closeDurableTestDatabase(t, db)

	for index := 0; index < 3; index++ {
		command := "command-" + string(rune('a'+index))
		if _, err := store.CreateLegacyShell("agent-one", command); err != nil {
			t.Fatalf("create legacy task %d: %v", index, err)
		}
		if _, ok, err := store.DispatchNextLegacy("agent-one"); err != nil || !ok {
			t.Fatalf("dispatch legacy task %d: ok=%t err=%v", index, ok, err)
		}
		if _, matched, err := store.CompleteLegacy(
			"agent-one",
			command,
			strings.Repeat(string(rune('a'+index)), 128),
		); err != nil || !matched {
			t.Fatalf("complete legacy task %d: matched=%t err=%v", index, matched, err)
		}
		now = now.Add(time.Second)
	}

	firstOnly, _, _, err := store.GetLegacyResultsPage(
		"agent-one",
		0,
		1,
		MaxLegacyResultPageBytes,
	)
	if err != nil || len(firstOnly) != 1 {
		t.Fatalf("read first legacy fixture: page=%#v err=%v", firstOnly, err)
	}
	encodedFirst, err := json.Marshal(firstOnly[0])
	if err != nil {
		t.Fatalf("encode first legacy fixture: %v", err)
	}
	oneResultBudget := len("[]\n") + len(encodedFirst)
	page, total, truncated, err := store.GetLegacyResultsPage(
		"agent-one",
		0,
		100,
		oneResultBudget,
	)
	if err != nil {
		t.Fatalf("read byte-bounded legacy page: %v", err)
	}
	if total != 3 || len(page) != 1 || !truncated {
		t.Fatalf(
			"legacy byte budget was not enforced: total=%d truncated=%t page=%#v",
			total,
			truncated,
			page,
		)
	}
	next, total, truncated, err := store.GetLegacyResultsPage(
		"agent-one",
		1,
		100,
		oneResultBudget,
	)
	if err != nil || total != 3 || len(next) != 1 || !truncated {
		t.Fatalf(
			"legacy continuation was not bounded: total=%d truncated=%t page=%#v err=%v",
			total,
			truncated,
			next,
			err,
		)
	}
}

func openDurableTestStore(
	t *testing.T,
	path, listenerID string,
	now *time.Time,
	dispatchLease time.Duration,
	maxTasks int,
) (*persistence.Database, *DurableStore) {
	t.Helper()
	db, err := persistence.Open(path)
	if err != nil {
		t.Fatalf("open persistence database: %v", err)
	}
	store, err := newDurableStoreWithOptions(
		db,
		listenerID,
		func() time.Time { return *now },
		dispatchLease,
		maxTasks,
	)
	if err != nil {
		_ = db.Close()
		t.Fatalf("create durable store: %v", err)
	}
	return db, store
}

func closeDurableTestDatabase(t *testing.T, db *persistence.Database) {
	t.Helper()
	if err := db.Close(); err != nil {
		t.Fatalf("close persistence database: %v", err)
	}
}
