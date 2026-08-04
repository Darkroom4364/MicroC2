package tasks

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"microc2/server/internal/audit"
)

func validModuleCreateRequest(expiresIn *int) ModuleCreateRequest {
	return ModuleCreateRequest{
		SchemaVersion:    SchemaVersion,
		ModuleID:         capabilityInventoryModuleID,
		Input:            json.RawMessage(`{}`),
		TimeoutSeconds:   moduleTaskMaxTimeoutSeconds,
		ExpiresInSeconds: expiresIn,
	}
}

func TestDurableModuleTaskPersistsServerOnlyPolicyAndCausalAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)
	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	defer closeDurableTestDatabase(t, db)

	expiresIn := 120
	task, err := store.CreateModuleContext(
		audit.WithActor(context.Background(), audit.Actor{Kind: audit.ActorOperator, ID: "operator-test"}),
		"agent-one",
		validModuleCreateRequest(&expiresIn),
	)
	if err != nil {
		t.Fatalf("create module task: %v", err)
	}

	var moduleID, riskLevel, targetScope string
	var moduleVersion, inputMax, outputMax, timeoutMax, evidenceRequired, approvalRequired int
	if err := db.SQL().QueryRow(
		`SELECT module_id, module_version, input_max_bytes, output_max_bytes,
		        max_timeout_seconds, risk_level, target_scope, evidence_required,
		        approval_required
		 FROM module_task_policies WHERE listener_id = ? AND task_id = ?`,
		"listener-one",
		task.ID,
	).Scan(
		&moduleID,
		&moduleVersion,
		&inputMax,
		&outputMax,
		&timeoutMax,
		&riskLevel,
		&targetScope,
		&evidenceRequired,
		&approvalRequired,
	); err != nil {
		t.Fatalf("load persisted module policy: %v", err)
	}
	if moduleID != capabilityInventoryModuleID ||
		moduleVersion != capabilityInventoryModuleVersion ||
		inputMax != 1024 || outputMax != 1024 || timeoutMax != 5 ||
		riskLevel != "read_only" || targetScope != "self" ||
		evidenceRequired != 1 || approvalRequired != 0 {
		t.Fatalf("unexpected persisted policy values")
	}
	if _, err := db.SQL().Exec(
		`UPDATE module_task_policies SET module_version = 2
		 WHERE listener_id = ? AND task_id = ?`,
		"listener-one",
		task.ID,
	); err == nil {
		t.Fatal("policy table accepted an unsupported module version")
	}
	encoded, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("marshal Task v1: %v", err)
	}
	if string(encoded) == "" || containsPolicyWireField(encoded) {
		t.Fatalf("Task v1 exposed server-only policy: %s", encoded)
	}

	rows, err := db.SQL().Query(
		`SELECT action, causation_sequence FROM audit_events
		 WHERE task_id = ? ORDER BY seq ASC`,
		task.ID,
	)
	if err != nil {
		t.Fatalf("query module task audit chain: %v", err)
	}
	defer rows.Close()
	var actions []string
	var queueCausation int64
	for rows.Next() {
		var action string
		var causation *int64
		if err := rows.Scan(&action, &causation); err != nil {
			t.Fatalf("scan module task audit event: %v", err)
		}
		actions = append(actions, action)
		if action == "task.queued" && causation != nil {
			queueCausation = *causation
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate module task audit chain: %v", err)
	}
	if len(actions) != 2 || actions[0] != "module_task.policy_applied" ||
		actions[1] != "task.queued" || queueCausation <= 0 {
		t.Fatalf("unexpected causal module audit chain: actions=%v queue=%d", actions, queueCausation)
	}
}

func TestDurableModulePolicyInsertFailureRollsBackTaskAndAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, time.August, 4, 12, 30, 0, 0, time.UTC)
	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	defer closeDurableTestDatabase(t, db)

	if _, err := db.SQL().Exec(
		`CREATE TRIGGER reject_module_policy_insert
		 BEFORE INSERT ON module_task_policies
		 BEGIN SELECT RAISE(ABORT, 'reject module policy insert'); END`,
	); err != nil {
		t.Fatalf("create policy insertion rejection trigger: %v", err)
	}
	expiresIn := 120
	if _, err := store.CreateModule("agent-one", validModuleCreateRequest(&expiresIn)); err == nil {
		t.Fatal("created module task despite policy insert failure")
	}
	var taskCount, policyCount, auditCount int
	if err := db.SQL().QueryRow(
		`SELECT COUNT(*) FROM tasks WHERE listener_id = ?`,
		"listener-one",
	).Scan(&taskCount); err != nil || taskCount != 0 {
		t.Fatalf("policy rollback task count=%d err=%v", taskCount, err)
	}
	if err := db.SQL().QueryRow(
		`SELECT COUNT(*) FROM module_task_policies WHERE listener_id = ?`,
		"listener-one",
	).Scan(&policyCount); err != nil || policyCount != 0 {
		t.Fatalf("policy rollback policy count=%d err=%v", policyCount, err)
	}
	if err := db.SQL().QueryRow(
		`SELECT COUNT(*) FROM audit_events WHERE listener_id = ?`,
		"listener-one",
	).Scan(&auditCount); err != nil || auditCount != 0 {
		t.Fatalf("policy rollback audit count=%d err=%v", auditCount, err)
	}
}

func TestDurableModuleTaskEligibilityWithdrawalDoesNotBlockShell(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, time.August, 4, 13, 0, 0, 0, time.UTC)
	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	defer closeDurableTestDatabase(t, db)

	expiresIn := 120
	moduleTask, err := store.CreateModule("agent-one", validModuleCreateRequest(&expiresIn))
	if err != nil {
		t.Fatalf("create module task: %v", err)
	}
	shellTask, err := store.Create("agent-one", validCreateRequest("whoami", 120))
	if err != nil {
		t.Fatalf("create shell task: %v", err)
	}
	dispatched, ok, err := store.DispatchNextEligible("agent-one", map[string]struct{}{})
	if err != nil || !ok || dispatched.ID != shellTask.ID {
		t.Fatalf("withdrawn module should yield shell task: task=%#v ok=%t err=%v", dispatched, ok, err)
	}
	cancelled, err := store.Get("agent-one", moduleTask.ID)
	if err != nil || cancelled.Status != StatusCancelled {
		t.Fatalf("withdrawn module status=%q err=%v", cancelled.Status, err)
	}
	var reason string
	if err := db.SQL().QueryRow(
		`SELECT reason_code FROM audit_events
		 WHERE task_id = ? AND action = ? ORDER BY seq DESC LIMIT 1`,
		moduleTask.ID,
		"task.cancelled",
	).Scan(&reason); err != nil || reason != "module_capability_unavailable" {
		t.Fatalf("withdrawal cancellation audit reason=%q err=%v", reason, err)
	}
}

func TestDurableExpiredModuleLeaseWithdrawalCancelsBeforeShellDispatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, time.August, 4, 13, 15, 0, 0, time.UTC)
	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	defer closeDurableTestDatabase(t, db)

	expiresIn := 120
	moduleTask, err := store.CreateModule("agent-one", validModuleCreateRequest(&expiresIn))
	if err != nil {
		t.Fatalf("create module task: %v", err)
	}
	shellTask, err := store.Create("agent-one", validCreateRequest("whoami", 120))
	if err != nil {
		t.Fatalf("create shell task: %v", err)
	}
	dispatched, ok, err := store.DispatchNextEligible(
		"agent-one",
		map[string]struct{}{capabilityInventoryModuleID: {}},
	)
	if err != nil || !ok || dispatched.ID != moduleTask.ID {
		t.Fatalf("initial module dispatch: task=%#v ok=%t err=%v", dispatched, ok, err)
	}
	now = now.Add(2 * time.Second)
	dispatched, ok, err = store.DispatchNextEligible("agent-one", map[string]struct{}{})
	if err != nil || !ok || dispatched.ID != shellTask.ID {
		t.Fatalf("withdrawn expired module should yield shell: task=%#v ok=%t err=%v", dispatched, ok, err)
	}
	cancelled, err := store.Get("agent-one", moduleTask.ID)
	if err != nil || cancelled.Status != StatusCancelled {
		t.Fatalf("withdrawn leased module status=%q err=%v", cancelled.Status, err)
	}
	var redeliveryCount, cancellationCount int
	if err := db.SQL().QueryRow(
		`SELECT
			SUM(CASE WHEN action = 'task.redelivered' THEN 1 ELSE 0 END),
			SUM(CASE WHEN action = 'task.cancelled'
			          AND reason_code = 'module_capability_unavailable' THEN 1 ELSE 0 END)
		 FROM audit_events WHERE task_id = ?`,
		moduleTask.ID,
	).Scan(&redeliveryCount, &cancellationCount); err != nil ||
		redeliveryCount != 0 || cancellationCount != 1 {
		t.Fatalf(
			"leased module withdrawal audits redelivery=%d cancellation=%d err=%v",
			redeliveryCount,
			cancellationCount,
			err,
		)
	}
}

func TestDurableModuleResultRequiresPersistedPolicyBoundedEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, time.August, 4, 13, 30, 0, 0, time.UTC)
	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	defer closeDurableTestDatabase(t, db)

	expiresIn := 120
	task, err := store.CreateModule("agent-one", validModuleCreateRequest(&expiresIn))
	if err != nil {
		t.Fatalf("create module task: %v", err)
	}
	dispatched, ok, err := store.DispatchNextEligible(
		"agent-one",
		map[string]struct{}{capabilityInventoryModuleID: {}},
	)
	if err != nil || !ok || dispatched.ID != task.ID {
		t.Fatalf("dispatch module task: task=%#v ok=%t err=%v", dispatched, ok, err)
	}
	if _, err := store.MarkRunning("agent-one", task.ID, StatusUpdate{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Status:        StatusRunning,
		Timestamp:     now,
	}); err != nil {
		t.Fatalf("mark module task running: %v", err)
	}
	exitCode := 0
	oversized := Result{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       "agent-one",
		Outcome:       OutcomeCompleted,
		StartedAt:     now,
		CompletedAt:   now.Add(time.Second),
		ExitCode:      &exitCode,
		Output: Output{Data: json.RawMessage(
			`{"operating_system":"` + strings.Repeat("x", 1025) +
				`","architecture":"x","logical_cpu_count":1,"total_memory_bytes":0}`,
		)},
	}
	if _, err := store.Complete("agent-one", oversized); err == nil {
		t.Fatal("accepted oversized module evidence")
	}
	duplicate := oversized
	duplicate.Output.Data = json.RawMessage(
		`{"operating_system":"linux","operating_system":"darwin","architecture":"arm64","logical_cpu_count":8,"total_memory_bytes":1}`,
	)
	if _, err := store.Complete("agent-one", duplicate); err == nil {
		t.Fatal("accepted duplicate-key module evidence")
	}
	nonterminal, err := store.Get("agent-one", task.ID)
	if err != nil || nonterminal.Status != StatusRunning || nonterminal.Result != nil {
		t.Fatalf("duplicate evidence changed task=%#v err=%v", nonterminal, err)
	}
	var duplicateTerminalAuditCount int
	if err := db.SQL().QueryRow(
		`SELECT COUNT(*) FROM audit_events
		 WHERE task_id = ? AND action IN ('module_task.evidence_accepted', 'task.result_received')`,
		task.ID,
	).Scan(&duplicateTerminalAuditCount); err != nil || duplicateTerminalAuditCount != 0 {
		t.Fatalf("duplicate evidence audit count=%d err=%v", duplicateTerminalAuditCount, err)
	}

	failed := oversized
	failed.Outcome = OutcomeFailed
	failed.ExitCode = nil
	failed.Output.Data = nil
	failed.Error = "collection failed"
	if _, err := store.Complete("agent-one", failed); err != nil {
		t.Fatalf("complete failed module task without evidence: %v", err)
	}
}

func TestDurableModuleEvidenceAuditIsOrderedAndAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, time.August, 4, 13, 45, 0, 0, time.UTC)
	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	defer closeDurableTestDatabase(t, db)

	startModuleTask := func() (Task, time.Time) {
		expiresIn := 120
		task, err := store.CreateModule("agent-one", validModuleCreateRequest(&expiresIn))
		if err != nil {
			t.Fatalf("create module task: %v", err)
		}
		if _, ok, err := store.DispatchNextEligible(
			"agent-one",
			map[string]struct{}{capabilityInventoryModuleID: {}},
		); err != nil || !ok {
			t.Fatalf("dispatch module task: ok=%t err=%v", ok, err)
		}
		if _, err := store.MarkRunning("agent-one", task.ID, StatusUpdate{
			SchemaVersion: SchemaVersion,
			TaskID:        task.ID,
			AgentID:       "agent-one",
			Status:        StatusRunning,
			Timestamp:     now,
		}); err != nil {
			t.Fatalf("mark module task running: %v", err)
		}
		return task, now
	}
	completedResult := func(task Task, startedAt time.Time) Result {
		exitCode := 0
		return Result{
			SchemaVersion: SchemaVersion,
			TaskID:        task.ID,
			AgentID:       "agent-one",
			Outcome:       OutcomeCompleted,
			StartedAt:     startedAt,
			CompletedAt:   startedAt.Add(time.Second),
			ExitCode:      &exitCode,
			Output: Output{Data: json.RawMessage(
				`{"operating_system":"linux","architecture":"arm64","logical_cpu_count":8,"total_memory_bytes":17179869184}`,
			)},
		}
	}

	completedTask, startedAt := startModuleTask()
	if _, err := store.Complete("agent-one", completedResult(completedTask, startedAt)); err != nil {
		t.Fatalf("complete module task: %v", err)
	}
	rows, err := db.SQL().Query(
		`SELECT action, causation_sequence FROM audit_events
		 WHERE task_id = ? ORDER BY seq ASC`,
		completedTask.ID,
	)
	if err != nil {
		t.Fatalf("query completed module audits: %v", err)
	}
	evidenceIndex, resultIndex := -1, -1
	var evidenceCause, resultCause *int64
	for index := 0; rows.Next(); index++ {
		var action string
		var causation *int64
		if err := rows.Scan(&action, &causation); err != nil {
			t.Fatalf("scan completed module audit: %v", err)
		}
		switch action {
		case "module_task.evidence_accepted":
			evidenceIndex, evidenceCause = index, causation
		case "task.result_received":
			resultIndex, resultCause = index, causation
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate completed module audits: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close completed module audits: %v", err)
	}
	if evidenceIndex < 0 || resultIndex < 0 || evidenceIndex >= resultIndex ||
		evidenceCause == nil || resultCause == nil || *evidenceCause != *resultCause {
		t.Fatalf(
			"unexpected evidence audit order/causation: evidence=%d/%v result=%d/%v",
			evidenceIndex,
			evidenceCause,
			resultIndex,
			resultCause,
		)
	}

	failedTask, failedStartedAt := startModuleTask()
	failed := completedResult(failedTask, failedStartedAt)
	failed.Outcome = OutcomeFailed
	failed.ExitCode = nil
	failed.Output.Data = nil
	failed.Error = "collection failed"
	if _, err := store.Complete("agent-one", failed); err != nil {
		t.Fatalf("complete failed module task: %v", err)
	}
	var failedEvidenceCount int
	if err := db.SQL().QueryRow(
		`SELECT COUNT(*) FROM audit_events
		 WHERE task_id = ? AND action = 'module_task.evidence_accepted'`,
		failedTask.ID,
	).Scan(&failedEvidenceCount); err != nil || failedEvidenceCount != 0 {
		t.Fatalf("failed module evidence audit count=%d err=%v", failedEvidenceCount, err)
	}

	if _, err := db.SQL().Exec(
		`CREATE TRIGGER reject_module_evidence_audit
		 BEFORE INSERT ON audit_events
		 WHEN NEW.action = 'module_task.evidence_accepted'
		 BEGIN SELECT RAISE(ABORT, 'reject module evidence audit'); END`,
	); err != nil {
		t.Fatalf("create evidence audit rejection trigger: %v", err)
	}
	rejectedTask, rejectedStartedAt := startModuleTask()
	if _, err := store.Complete(
		"agent-one",
		completedResult(rejectedTask, rejectedStartedAt),
	); err == nil {
		t.Fatal("completed module task despite rejected evidence audit")
	}
	rejected, err := store.Get("agent-one", rejectedTask.ID)
	if err != nil || rejected.Status != StatusRunning || rejected.Result != nil {
		t.Fatalf("evidence audit rollback task=%#v err=%v", rejected, err)
	}
	var terminalAuditCount, resultCount int
	if err := db.SQL().QueryRow(
		`SELECT COUNT(*) FROM audit_events
		 WHERE task_id = ? AND action IN ('module_task.evidence_accepted', 'task.result_received')`,
		rejectedTask.ID,
	).Scan(&terminalAuditCount); err != nil || terminalAuditCount != 0 {
		t.Fatalf("evidence audit rollback count=%d err=%v", terminalAuditCount, err)
	}
	if err := db.SQL().QueryRow(
		`SELECT COUNT(*) FROM task_results
		 WHERE listener_id = ? AND task_id = ?`,
		"listener-one",
		rejectedTask.ID,
	).Scan(&resultCount); err != nil || resultCount != 0 {
		t.Fatalf("evidence result rollback count=%d err=%v", resultCount, err)
	}
}

func TestDurableStoreQuarantinesOnlyNonterminalUnboundModuleTasks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "microc2.db")
	now := time.Date(2026, time.August, 4, 14, 0, 0, 0, time.UTC)
	db, store := openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)

	queued, err := store.Create("agent-one", validCreateRequest("queued", 120))
	if err != nil {
		t.Fatalf("create queued historic task: %v", err)
	}
	terminal, err := store.Create("agent-one", validCreateRequest("terminal", 120))
	if err != nil {
		t.Fatalf("create terminal historic task: %v", err)
	}
	moduleArguments := `{"module_id":"agent.capability_inventory.v1","input":{}}`
	if _, err := db.SQL().Exec(
		`UPDATE tasks SET task_type = ?, command = '', arguments_json = ?
		 WHERE listener_id = ? AND task_id IN (?, ?)`,
		string(TypeModule),
		moduleArguments,
		"listener-one",
		queued.ID,
		terminal.ID,
	); err != nil {
		t.Fatalf("shape historic module tasks: %v", err)
	}
	if _, err := db.SQL().Exec(
		`UPDATE tasks SET status = ?, server_completed_at = ?
		 WHERE listener_id = ? AND task_id = ?`,
		string(StatusCompleted),
		formatDurableTime(now),
		"listener-one",
		terminal.ID,
	); err != nil {
		t.Fatalf("make terminal historic task: %v", err)
	}
	closeDurableTestDatabase(t, db)

	db, store = openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	quarantined, err := store.Get("agent-one", queued.ID)
	if err != nil || quarantined.Status != StatusCancelled {
		t.Fatalf("queued historic module was not quarantined: status=%q err=%v", quarantined.Status, err)
	}
	readableTerminal, err := store.Get("agent-one", terminal.ID)
	if err != nil || readableTerminal.Status != StatusCompleted {
		t.Fatalf("terminal historic module changed: status=%q err=%v", readableTerminal.Status, err)
	}
	var count int
	if err := db.SQL().QueryRow(
		`SELECT COUNT(*) FROM audit_events
		 WHERE task_id = ? AND reason_code = ?`,
		queued.ID,
		"module_policy_missing",
	).Scan(&count); err != nil || count != 1 {
		t.Fatalf("quarantine audit count=%d err=%v", count, err)
	}
	closeDurableTestDatabase(t, db)
	db, _ = openDurableTestStore(t, path, "listener-one", &now, time.Second, 10)
	defer closeDurableTestDatabase(t, db)
	if err := db.SQL().QueryRow(
		`SELECT COUNT(*) FROM audit_events
		 WHERE task_id = ? AND reason_code = ?`,
		queued.ID,
		"module_policy_missing",
	).Scan(&count); err != nil || count != 1 {
		t.Fatalf("second reopen duplicated quarantine audit count=%d err=%v", count, err)
	}
}

func containsPolicyWireField(encoded []byte) bool {
	return bytes.Contains(encoded, []byte(`"policy"`)) ||
		bytes.Contains(encoded, []byte(`"approval"`))
}
