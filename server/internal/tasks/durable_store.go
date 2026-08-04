package tasks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"microc2/server/internal/audit"
	"microc2/server/internal/persistence"

	"github.com/google/uuid"
)

const durableTimeLayout = "2006-01-02T15:04:05.000000000Z"

// LegacyResult is the durable representation returned by the deprecated
// command-results adapter.
type LegacyResult struct {
	Command   string `json:"command"`
	Output    string `json:"output"`
	Timestamp string `json:"timestamp"`
}

// DurableStore implements the task lifecycle over a listener-scoped SQLite
// database. The mutex keeps one store's read/modify/write transactions ordered;
// SQL constraints and conditional updates remain the source of truth.
type DurableStore struct {
	mu               sync.Mutex
	db               *persistence.Database
	audit            *audit.Store
	listenerID       string
	now              func() time.Time
	dispatchLease    time.Duration
	maxTasksPerAgent int
}

// NewDurableStore constructs a listener-scoped durable task store.
func NewDurableStore(
	db *persistence.Database,
	listenerID string,
	now func() time.Time,
) (*DurableStore, error) {
	return newDurableStoreWithOptions(
		db,
		listenerID,
		now,
		DefaultDispatchLease,
		MaxTaskHistoryPerAgent,
	)
}

func newDurableStoreWithOptions(
	db *persistence.Database,
	listenerID string,
	now func() time.Time,
	dispatchLease time.Duration,
	maxTasksPerAgent int,
) (*DurableStore, error) {
	if db == nil || db.SQL() == nil {
		return nil, errors.New("durable task store requires an open database")
	}
	if err := ValidateIdentifier("listener_id", listenerID); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	if dispatchLease <= 0 {
		dispatchLease = DefaultDispatchLease
	}
	if maxTasksPerAgent <= 0 {
		maxTasksPerAgent = MaxTaskHistoryPerAgent
	}
	auditStore, err := audit.NewStore(db)
	if err != nil {
		return nil, fmt.Errorf("initialize durable task audit store: %w", err)
	}
	store := &DurableStore{
		db:               db,
		audit:            auditStore,
		listenerID:       listenerID,
		now:              now,
		dispatchLease:    dispatchLease,
		maxTasksPerAgent: maxTasksPerAgent,
	}
	if err := store.quarantineUnboundModuleTasks(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *DurableStore) Create(agentID string, request CreateRequest) (Task, error) {
	return s.CreateContext(context.Background(), agentID, request)
}

// CreateContext creates a shell task with the trusted operator actor attached
// by the authentication boundary.
func (s *DurableStore) CreateContext(
	ctx context.Context,
	agentID string,
	request CreateRequest,
) (Task, error) {
	return s.create(ctx, agentID, request, false, nil)
}

func (s *DurableStore) CreateModule(
	agentID string,
	request ModuleCreateRequest,
) (Task, error) {
	return s.CreateModuleContext(context.Background(), agentID, request)
}

// CreateModuleContext is the sole durable module-creation authority. It derives
// and persists the server policy in the same transaction as its task and audit
// chain.
func (s *DurableStore) CreateModuleContext(
	ctx context.Context,
	agentID string,
	request ModuleCreateRequest,
) (Task, error) {
	taskRequest, policy, err := deriveModuleTaskPolicy(request)
	if err != nil {
		return Task{}, err
	}
	return s.create(ctx, agentID, taskRequest, false, &policy)
}

func (s *DurableStore) CreateLegacyShell(agentID, command string) (Task, error) {
	return s.CreateLegacyShellContext(context.Background(), agentID, command)
}

// CreateLegacyShellContext is the actor-aware form of the deprecated shell
// task adapter.
func (s *DurableStore) CreateLegacyShellContext(
	ctx context.Context,
	agentID, command string,
) (Task, error) {
	expiresIn := DefaultExpiresIn
	return s.create(ctx, agentID, CreateRequest{
		SchemaVersion:    SchemaVersion,
		Type:             TypeShell,
		Arguments:        ShellArguments{Command: command},
		TimeoutSeconds:   DefaultTimeoutSeconds,
		ExpiresInSeconds: &expiresIn,
	}, true, nil)
}

func (s *DurableStore) create(
	ctx context.Context,
	agentID string,
	request CreateRequest,
	legacyOrigin bool,
	policy *moduleTaskPolicy,
) (Task, error) {
	if err := ValidateIdentifier("agent_id", agentID); err != nil {
		return Task{}, err
	}
	if policy == nil {
		if err := request.validate(); err != nil {
			return Task{}, err
		}
	} else if err := policy.validateTask(&Task{
		Type:           request.Type,
		Arguments:      request.Arguments,
		TimeoutSeconds: request.TimeoutSeconds,
	}); err != nil {
		return Task{}, err
	}
	argumentsJSON, err := json.Marshal(request.Arguments)
	if err != nil {
		return Task{}, fmt.Errorf("encode task arguments: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return Task{}, fmt.Errorf("begin durable task create: %w", err)
	}
	defer rollbackDurableTx(tx)

	now := normalizeTime(s.now())
	if err := s.expireDispatchableTx(ctx, tx, agentID, now); err != nil {
		return Task{}, err
	}
	if err := s.makeTaskRoomTx(ctx, tx, agentID); err != nil {
		return Task{}, err
	}

	expiresIn := DefaultExpiresIn
	if request.ExpiresInSeconds != nil {
		expiresIn = *request.ExpiresInSeconds
	}
	expiresAt := now.Add(time.Duration(expiresIn) * time.Second)
	taskID := uuid.NewString()
	var causationSequence *int64
	if policy != nil {
		policyEvent, err := s.audit.AppendTx(ctx, tx, audit.Input{
			Actor:      audit.ActorOr(ctx, audit.DefaultOperatorActor()),
			Action:     "module_task.policy_applied",
			Route:      "/api/agents/{agent_id}/module-tasks",
			Target:     audit.Target{Kind: "task", ID: taskID},
			Outcome:    audit.OutcomeSucceeded,
			ListenerID: s.listenerID,
			AgentID:    agentID,
			TaskID:     taskID,
		})
		if err != nil {
			return Task{}, fmt.Errorf("record durable module policy audit event: %w", err)
		}
		causationSequence = &policyEvent.Sequence
	}
	queuedEvent, err := s.audit.AppendTx(ctx, tx, audit.Input{
		Actor:             audit.ActorOr(ctx, audit.DefaultOperatorActor()),
		Action:            "task.queued",
		Route:             taskQueueAuditRoute(legacyOrigin, policy != nil),
		Target:            audit.Target{Kind: "task", ID: taskID},
		Outcome:           audit.OutcomeSucceeded,
		CausationSequence: causationSequence,
		ListenerID:        s.listenerID,
		AgentID:           agentID,
		TaskID:            taskID,
	})
	if err != nil {
		return Task{}, fmt.Errorf("record durable task queue audit event: %w", err)
	}
	// The statement is static and every request-derived value is bound through
	// SQLite parameters.
	// foxguard: ignore[go/taint-sql-injection]
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO tasks (
			listener_id, task_id, agent_id, schema_version, task_type, command,
			arguments_json, timeout_seconds, status, created_at, queued_at, expires_at,
			legacy_origin, created_audit_event_seq
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.listenerID,
		taskID,
		agentID,
		SchemaVersion,
		string(request.Type),
		request.Arguments.Command,
		string(argumentsJSON),
		request.TimeoutSeconds,
		string(StatusQueued),
		formatDurableTime(now),
		formatDurableTime(now),
		formatDurableTime(expiresAt),
		boolToSQLite(legacyOrigin),
		queuedEvent.Sequence,
	); err != nil {
		return Task{}, fmt.Errorf("insert durable task: %w", err)
	}
	if policy != nil {
		if err := s.insertModulePolicyTx(ctx, tx, taskID, *policy); err != nil {
			return Task{}, err
		}
	}

	record, err := s.getTaskTx(ctx, tx, agentID, taskID)
	if err != nil {
		return Task{}, err
	}
	if err := tx.Commit(); err != nil {
		return Task{}, fmt.Errorf("commit durable task create: %w", err)
	}
	return record.task, nil
}

func taskQueueAuditRoute(legacyOrigin, module bool) string {
	if legacyOrigin {
		return "/api/agents/{agent_id}/command"
	}
	if module {
		return "/api/agents/{agent_id}/module-tasks"
	}
	return "/api/agents/{agent_id}/tasks"
}

func taskAgentAuditRoute(action string, legacyOrigin bool) string {
	switch action {
	case "task.dispatched", "task.redelivered":
		if legacyOrigin {
			return "/api/agent/{agent_id}/command"
		}
		return "/api/agent/{agent_id}/tasks"
	case "task.running":
		return "/api/agent/{agent_id}/tasks/{task_id}/status"
	case "task.result_received":
		if legacyOrigin {
			return "/api/agent/{agent_id}/result"
		}
		return "/api/agent/{agent_id}/results"
	default:
		return "internal:task_store"
	}
}

func (s *DurableStore) appendTaskAuditTx(
	ctx context.Context,
	tx *sql.Tx,
	actor audit.Actor,
	action string,
	route string,
	record durableTaskRecord,
) error {
	causationSequence := record.createdAuditEventSeq
	_, err := s.audit.AppendTx(ctx, tx, audit.Input{
		Actor:             actor,
		Action:            action,
		Route:             route,
		Target:            audit.Target{Kind: "task", ID: record.task.ID},
		Outcome:           audit.OutcomeSucceeded,
		CausationSequence: &causationSequence,
		ListenerID:        s.listenerID,
		AgentID:           record.task.AgentID,
		TaskID:            record.task.ID,
	})
	if err != nil {
		return fmt.Errorf("record %s audit event: %w", action, err)
	}
	return nil
}
func (s *DurableStore) insertModulePolicyTx(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
	policy moduleTaskPolicy,
) error {
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO module_task_policies (
			listener_id, task_id, module_id, module_version, input_max_bytes,
			output_max_bytes, max_timeout_seconds, risk_level, target_scope,
			evidence_required, approval_required
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.listenerID,
		taskID,
		policy.moduleID,
		policy.moduleVersion,
		policy.inputMaxBytes,
		policy.outputMaxBytes,
		policy.maxTimeoutSeconds,
		policy.riskLevel,
		policy.targetScope,
		boolToSQLite(policy.evidenceRequired),
		boolToSQLite(policy.approvalRequired),
	); err != nil {
		return fmt.Errorf("insert durable module task policy: %w", err)
	}
	return nil
}

func (s *DurableStore) getModulePolicyTx(
	ctx context.Context,
	tx *sql.Tx,
	taskID string,
) (*moduleTaskPolicy, error) {
	var policy moduleTaskPolicy
	var evidenceRequired, approvalRequired int
	err := tx.QueryRowContext(
		ctx,
		`SELECT
			module_id, module_version, input_max_bytes, output_max_bytes,
			max_timeout_seconds, risk_level, target_scope, evidence_required,
			approval_required
		 FROM module_task_policies
		 WHERE listener_id = ? AND task_id = ?`,
		s.listenerID,
		taskID,
	).Scan(
		&policy.moduleID,
		&policy.moduleVersion,
		&policy.inputMaxBytes,
		&policy.outputMaxBytes,
		&policy.maxTimeoutSeconds,
		&policy.riskLevel,
		&policy.targetScope,
		&evidenceRequired,
		&approvalRequired,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load durable module task policy: %w", err)
	}
	if evidenceRequired != 0 && evidenceRequired != 1 ||
		approvalRequired != 0 && approvalRequired != 1 {
		return nil, errors.New("durable module task policy has invalid flags")
	}
	policy.evidenceRequired = evidenceRequired != 0
	policy.approvalRequired = approvalRequired != 0
	return &policy, nil
}

func (s *DurableStore) quarantineUnboundModuleTasks() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin module policy recovery: %w", err)
	}
	defer rollbackDurableTx(tx)

	rows, err := tx.QueryContext(
		ctx,
		`SELECT t.agent_id, t.task_id
		 FROM tasks t
		 LEFT JOIN module_task_policies p
		   ON p.listener_id = t.listener_id AND p.task_id = t.task_id
		 WHERE t.listener_id = ? AND t.task_type = ?
		   AND t.status IN (?, ?, ?) AND p.task_id IS NULL
		 ORDER BY t.seq ASC`,
		s.listenerID,
		string(TypeModule),
		string(StatusQueued),
		string(StatusDispatched),
		string(StatusRunning),
	)
	if err != nil {
		return fmt.Errorf("find unbound historic module tasks: %w", err)
	}
	type taskRef struct{ agentID, taskID string }
	var unbound []taskRef
	for rows.Next() {
		var ref taskRef
		if err := rows.Scan(&ref.agentID, &ref.taskID); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan unbound historic module task: %w", err)
		}
		unbound = append(unbound, ref)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate unbound historic module tasks: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close unbound historic module task query: %w", err)
	}
	now := normalizeTime(s.now())
	for _, ref := range unbound {
		record, err := s.getTaskTx(ctx, tx, ref.agentID, ref.taskID)
		if err != nil {
			return err
		}
		result, err := tx.ExecContext(
			ctx,
			`UPDATE tasks
			 SET status = ?, server_completed_at = ?, last_delivery_at = NULL
			 WHERE listener_id = ? AND agent_id = ? AND task_id = ?
			   AND status IN (?, ?, ?)`,
			string(StatusCancelled),
			formatDurableTime(now),
			s.listenerID,
			ref.agentID,
			ref.taskID,
			string(StatusQueued),
			string(StatusDispatched),
			string(StatusRunning),
		)
		if err != nil {
			return fmt.Errorf("cancel unbound historic module task: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("count unbound historic module cancellation: %w", err)
		}
		if affected == 0 {
			continue
		}
		causationSequence := record.createdAuditEventSeq
		if _, err := s.audit.AppendTx(ctx, tx, audit.Input{
			Actor:             audit.Actor{Kind: audit.ActorSystem, ID: "module_task_recovery"},
			Action:            "task.cancelled",
			Route:             "internal:module_task_policy_recovery",
			Target:            audit.Target{Kind: "task", ID: record.task.ID},
			Outcome:           audit.OutcomeSucceeded,
			ReasonCode:        "module_policy_missing",
			CausationSequence: &causationSequence,
			ListenerID:        s.listenerID,
			AgentID:           record.task.AgentID,
			TaskID:            record.task.ID,
		}); err != nil {
			return fmt.Errorf("audit unbound historic module cancellation: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit module policy recovery: %w", err)
	}
	return nil
}

func (s *DurableStore) List(agentID string) ([]Task, error) {
	if err := ValidateIdentifier("agent_id", agentID); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin durable task list: %w", err)
	}
	defer rollbackDurableTx(tx)

	if err := s.expireDispatchableTx(ctx, tx, agentID, normalizeTime(s.now())); err != nil {
		return nil, err
	}
	records, err := s.listTasksTx(ctx, tx, agentID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit durable task list: %w", err)
	}

	tasks := make([]Task, 0, len(records))
	for _, record := range records {
		tasks = append(tasks, record.task)
	}
	return tasks, nil
}

// QueueStats aggregates pending and recently failed tasks for this listener
// scope with two constant-time COUNT aggregates over the durable tasks table.
// It never scans task payloads, so it stays cheap enough to serve on every
// telemetry request. failedSince bounds the recent-failure window; pending
// counts are not windowed.
func (s *DurableStore) QueueStats(failedSince time.Time) (QueueStats, error) {
	row := s.db.SQL().QueryRow(
		`SELECT
			COALESCE(SUM(CASE WHEN status IN (?, ?) THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(
				CASE WHEN status = ? AND server_completed_at >= ? THEN 1 ELSE 0 END
			), 0)
		 FROM tasks
		 WHERE listener_id = ?`,
		string(StatusQueued),
		string(StatusDispatched),
		string(StatusFailed),
		formatDurableTime(failedSince),
		s.listenerID,
	)
	var stats QueueStats
	if err := row.Scan(&stats.Pending, &stats.RecentFailed); err != nil {
		return QueueStats{}, fmt.Errorf("summarize durable task queue: %w", err)
	}
	return stats, nil
}

// ListTaskSummariesPage returns newest-first task metadata without selecting
// stdout or stderr. Keeping the collection query separate from Get prevents a
// bounded operator page from materializing the full retained result corpus.
func (s *DurableStore) ListTaskSummariesPage(
	agentID string,
	offset, limit int,
) ([]TaskSummary, int, error) {
	if err := ValidateIdentifier("agent_id", agentID); err != nil {
		return nil, 0, err
	}
	if offset < 0 {
		offset = 0
	}
	if limit < 0 {
		limit = 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("begin durable task summary page: %w", err)
	}
	defer rollbackDurableTx(tx)

	if err := s.expireDispatchableTx(ctx, tx, agentID, normalizeTime(s.now())); err != nil {
		return nil, 0, err
	}
	var total int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM tasks
		 WHERE listener_id = ? AND agent_id = ?`,
		s.listenerID,
		agentID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count durable task summaries: %w", err)
	}
	if offset > total {
		offset = total
	}
	if limit > total-offset {
		limit = total - offset
	}

	summaries := make([]TaskSummary, 0, limit)
	if limit > 0 {
		rows, err := tx.QueryContext(
			ctx,
			durableTaskSummarySelect+`
			 WHERE t.listener_id = ? AND t.agent_id = ?
			 ORDER BY t.created_at DESC, t.task_id DESC
			 LIMIT ? OFFSET ?`,
			s.listenerID,
			agentID,
			limit,
			offset,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("query durable task summaries: %w", err)
		}
		for rows.Next() {
			summary, err := scanDurableTaskSummary(rows)
			if err != nil {
				_ = rows.Close()
				return nil, 0, fmt.Errorf("scan durable task summary: %w", err)
			}
			summaries = append(summaries, summary)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, 0, fmt.Errorf("iterate durable task summaries: %w", err)
		}
		if err := rows.Close(); err != nil {
			return nil, 0, fmt.Errorf("close durable task summaries: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, fmt.Errorf("commit durable task summary page: %w", err)
	}
	return summaries, total, nil
}

func (s *DurableStore) Get(agentID, taskID string) (Task, error) {
	if err := validateIDs(agentID, taskID); err != nil {
		return Task{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return Task{}, fmt.Errorf("begin durable task get: %w", err)
	}
	defer rollbackDurableTx(tx)

	if err := s.expireDispatchableTx(ctx, tx, agentID, normalizeTime(s.now())); err != nil {
		return Task{}, err
	}
	record, err := s.getTaskTx(ctx, tx, agentID, taskID)
	if err != nil {
		return Task{}, err
	}
	if err := tx.Commit(); err != nil {
		return Task{}, fmt.Errorf("commit durable task get: %w", err)
	}
	return record.task, nil
}

func (s *DurableStore) DispatchNext(agentID string) (Task, bool, error) {
	return s.dispatchNext(agentID, false, nil)
}

// DispatchNextEligible rechecks the caller's immutable, current-heartbeat
// eligibility snapshot while selecting durable module work.
func (s *DurableStore) DispatchNextEligible(
	agentID string,
	eligible map[string]struct{},
) (Task, bool, error) {
	return s.dispatchNext(agentID, false, eligible)
}

func (s *DurableStore) DispatchNextLegacy(agentID string) (Task, bool, error) {
	return s.dispatchNext(agentID, true, nil)
}

func (s *DurableStore) dispatchNext(
	agentID string,
	legacyOnly bool,
	eligible map[string]struct{},
) (Task, bool, error) {
	if err := ValidateIdentifier("agent_id", agentID); err != nil {
		return Task{}, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return Task{}, false, fmt.Errorf("begin durable task dispatch: %w", err)
	}
	defer rollbackDurableTx(tx)

	now := normalizeTime(s.now())
	if err := s.expireDispatchableTx(ctx, tx, agentID, now); err != nil {
		return Task{}, false, err
	}

	for {
		record, found, err := s.nextDispatchedTx(
			ctx,
			tx,
			agentID,
			legacyOnly,
			now.Add(-s.dispatchLease),
		)
		if err != nil {
			return Task{}, false, err
		}
		if !found {
			break
		}
		allowed, reason, err := s.moduleDispatchAllowedTx(ctx, tx, record, eligible)
		if err != nil {
			return Task{}, false, err
		}
		if !allowed {
			if err := s.cancelModuleDispatchTx(ctx, tx, record, now, reason); err != nil {
				return Task{}, false, err
			}
			continue
		}
		result, err := tx.ExecContext(
			ctx,
			`UPDATE tasks
			 SET last_delivery_at = ?
			 WHERE listener_id = ? AND agent_id = ? AND task_id = ? AND status = ?`,
			formatDurableTime(now),
			s.listenerID,
			agentID,
			record.task.ID,
			string(StatusDispatched),
		)
		if err != nil {
			return Task{}, false, fmt.Errorf("renew durable dispatch lease: %w", err)
		}
		if err := requireOneDurableRow(result, "renew durable dispatch lease"); err != nil {
			return Task{}, false, err
		}
		record, err = s.getTaskTx(ctx, tx, agentID, record.task.ID)
		if err != nil {
			return Task{}, false, err
		}
		if err := s.appendTaskAuditTx(
			ctx,
			tx,
			audit.Actor{Kind: audit.ActorAgent, ID: agentID},
			"task.redelivered",
			taskAgentAuditRoute("task.redelivered", record.legacyOrigin),
			record,
		); err != nil {
			return Task{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return Task{}, false, fmt.Errorf("commit durable task redelivery: %w", err)
		}
		return record.task, true, nil
	}

	for {
		record, found, err := s.nextQueuedTx(ctx, tx, agentID, legacyOnly)
		if err != nil {
			return Task{}, false, err
		}
		if !found {
			if err := tx.Commit(); err != nil {
				return Task{}, false, fmt.Errorf("commit empty durable task dispatch: %w", err)
			}
			return Task{}, false, nil
		}
		allowed, reason, err := s.moduleDispatchAllowedTx(ctx, tx, record, eligible)
		if err != nil {
			return Task{}, false, err
		}
		if !allowed {
			if err := s.cancelModuleDispatchTx(ctx, tx, record, now, reason); err != nil {
				return Task{}, false, err
			}
			continue
		}

		result, err := tx.ExecContext(
			ctx,
			`UPDATE tasks
			 SET status = ?, dispatched_at = ?, last_delivery_at = ?
			 WHERE listener_id = ? AND agent_id = ? AND task_id = ? AND status = ?`,
			string(StatusDispatched),
			formatDurableTime(now),
			formatDurableTime(now),
			s.listenerID,
			agentID,
			record.task.ID,
			string(StatusQueued),
		)
		if err != nil {
			return Task{}, false, fmt.Errorf("dispatch durable task: %w", err)
		}
		if err := requireOneDurableRow(result, "dispatch durable task"); err != nil {
			return Task{}, false, err
		}
		record, err = s.getTaskTx(ctx, tx, agentID, record.task.ID)
		if err != nil {
			return Task{}, false, err
		}
		if err := s.appendTaskAuditTx(
			ctx,
			tx,
			audit.Actor{Kind: audit.ActorAgent, ID: agentID},
			"task.dispatched",
			taskAgentAuditRoute("task.dispatched", record.legacyOrigin),
			record,
		); err != nil {
			return Task{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return Task{}, false, fmt.Errorf("commit durable task dispatch: %w", err)
		}
		return record.task, true, nil
	}
}

func (s *DurableStore) moduleDispatchAllowedTx(
	ctx context.Context,
	tx *sql.Tx,
	record durableTaskRecord,
	eligible map[string]struct{},
) (bool, string, error) {
	if record.task.Type != TypeModule {
		return true, "", nil
	}
	policy, err := s.getModulePolicyTx(ctx, tx, record.task.ID)
	if err != nil {
		return false, "", err
	}
	if policy == nil || policy.validateTask(&record.task) != nil {
		return false, "module_policy_missing", nil
	}
	if _, ok := eligible[policy.moduleID]; !ok {
		return false, "module_capability_unavailable", nil
	}
	return true, "", nil
}

func (s *DurableStore) cancelModuleDispatchTx(
	ctx context.Context,
	tx *sql.Tx,
	record durableTaskRecord,
	now time.Time,
	reason string,
) error {
	result, err := tx.ExecContext(
		ctx,
		`UPDATE tasks
		 SET status = ?, server_completed_at = ?, last_delivery_at = NULL
		 WHERE listener_id = ? AND agent_id = ? AND task_id = ?
		   AND status IN (?, ?)`,
		string(StatusCancelled),
		formatDurableTime(now),
		s.listenerID,
		record.task.AgentID,
		record.task.ID,
		string(StatusQueued),
		string(StatusDispatched),
	)
	if err != nil {
		return fmt.Errorf("cancel ineligible module task: %w", err)
	}
	if err := requireOneDurableRow(result, "cancel ineligible module task"); err != nil {
		return err
	}
	causationSequence := record.createdAuditEventSeq
	if _, err := s.audit.AppendTx(ctx, tx, audit.Input{
		Actor:             audit.Actor{Kind: audit.ActorSystem, ID: "module_task_dispatch"},
		Action:            "task.cancelled",
		Route:             "internal:module_task_dispatch",
		Target:            audit.Target{Kind: "task", ID: record.task.ID},
		Outcome:           audit.OutcomeSucceeded,
		ReasonCode:        reason,
		CausationSequence: &causationSequence,
		ListenerID:        s.listenerID,
		AgentID:           record.task.AgentID,
		TaskID:            record.task.ID,
	}); err != nil {
		return fmt.Errorf("audit ineligible module task cancellation: %w", err)
	}
	return nil
}

func (s *DurableStore) MarkRunning(
	agentID, taskID string,
	update StatusUpdate,
) (Task, error) {
	if err := validateIDs(agentID, taskID); err != nil {
		return Task{}, err
	}
	if err := update.validate(agentID, taskID); err != nil {
		return Task{}, err
	}
	update = normalizeStatusUpdate(update)

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return Task{}, fmt.Errorf("begin durable running update: %w", err)
	}
	defer rollbackDurableTx(tx)

	now := normalizeTime(s.now())
	if err := s.expireDispatchableTx(ctx, tx, agentID, now); err != nil {
		return Task{}, err
	}
	record, err := s.getTaskTx(ctx, tx, agentID, taskID)
	if err != nil {
		return Task{}, err
	}
	if record.acceptedRunningAt != nil {
		accepted := StatusUpdate{
			SchemaVersion: SchemaVersion,
			TaskID:        record.task.ID,
			AgentID:       record.task.AgentID,
			Status:        StatusRunning,
			Timestamp:     *record.acceptedRunningAt,
		}
		if !statusUpdatesEqual(accepted, update) {
			return Task{}, fmt.Errorf(
				"%w: conflicting repeated running update",
				ErrInvalidTransition,
			)
		}
		if err := tx.Commit(); err != nil {
			return Task{}, fmt.Errorf("commit idempotent durable running update: %w", err)
		}
		return record.task, nil
	}
	if err := transition(&record.task, StatusRunning); err != nil {
		return Task{}, err
	}

	result, err := tx.ExecContext(
		ctx,
		`UPDATE tasks
		 SET status = ?, server_started_at = ?, accepted_running_at = ?,
		     last_delivery_at = NULL
		 WHERE listener_id = ? AND agent_id = ? AND task_id = ? AND status = ?`,
		string(StatusRunning),
		formatDurableTime(now),
		formatDurableTime(update.Timestamp),
		s.listenerID,
		agentID,
		taskID,
		string(StatusDispatched),
	)
	if err != nil {
		return Task{}, fmt.Errorf("persist durable running update: %w", err)
	}
	if err := requireOneDurableRow(result, "persist durable running update"); err != nil {
		return Task{}, err
	}
	record, err = s.getTaskTx(ctx, tx, agentID, taskID)
	if err != nil {
		return Task{}, err
	}
	if err := s.appendTaskAuditTx(
		ctx,
		tx,
		audit.Actor{Kind: audit.ActorAgent, ID: agentID},
		"task.running",
		taskAgentAuditRoute("task.running", record.legacyOrigin),
		record,
	); err != nil {
		return Task{}, err
	}
	if err := tx.Commit(); err != nil {
		return Task{}, fmt.Errorf("commit durable running update: %w", err)
	}
	return record.task, nil
}

func (s *DurableStore) Complete(agentID string, result Result) (Task, error) {
	task, _, err := s.CompleteWithInfo(agentID, result)
	return task, err
}

func (s *DurableStore) CompleteWithInfo(
	agentID string,
	result Result,
) (Task, CompletionInfo, error) {
	if err := ValidateIdentifier("agent_id", agentID); err != nil {
		return Task{}, CompletionInfo{}, err
	}
	result = normalizeResult(result)
	if err := result.validate(agentID); err != nil {
		return Task{}, CompletionInfo{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return Task{}, CompletionInfo{}, fmt.Errorf(
			"begin durable task completion: %w",
			err,
		)
	}
	defer rollbackDurableTx(tx)

	record, err := s.getTaskTx(ctx, tx, agentID, result.TaskID)
	if err != nil {
		return Task{}, CompletionInfo{}, err
	}
	info := CompletionInfo{LegacyOrigin: record.legacyOrigin}
	var policy *moduleTaskPolicy
	if record.task.Type == TypeModule {
		policy, err = s.getModulePolicyTx(ctx, tx, record.task.ID)
		if err != nil {
			return Task{}, CompletionInfo{}, err
		}
	}
	if record.task.Status == StatusCompleted || record.task.Status == StatusFailed {
		if record.task.Result == nil || !resultsEqual(*record.task.Result, result) {
			return Task{}, CompletionInfo{}, fmt.Errorf(
				"%w: conflicting repeated terminal result",
				ErrInvalidTransition,
			)
		}
		if err := tx.Commit(); err != nil {
			return Task{}, CompletionInfo{}, fmt.Errorf(
				"commit idempotent durable task completion: %w",
				err,
			)
		}
		return record.task, info, nil
	}
	if err := validateResultForTask(&record.task, result, policy); err != nil {
		return Task{}, CompletionInfo{}, err
	}
	if record.acceptedRunningAt == nil {
		return Task{}, CompletionInfo{}, fmt.Errorf(
			"%w: task has no accepted running update",
			ErrInvalidTransition,
		)
	}
	if !result.StartedAt.Equal(*record.acceptedRunningAt) {
		return Task{}, CompletionInfo{}, &ValidationError{
			Field:   "started_at",
			Message: "must match the running status timestamp",
		}
	}

	targetStatus := StatusCompleted
	if result.Outcome == OutcomeFailed {
		targetStatus = StatusFailed
	}
	if err := transition(&record.task, targetStatus); err != nil {
		return Task{}, CompletionInfo{}, err
	}
	completedAt := normalizeTime(s.now())
	if record.task.StartedAt != nil && completedAt.Before(*record.task.StartedAt) {
		completedAt = *record.task.StartedAt
	}

	updateResult, err := tx.ExecContext(
		ctx,
		`UPDATE tasks
		 SET status = ?, server_completed_at = ?
		 WHERE listener_id = ? AND agent_id = ? AND task_id = ? AND status = ?`,
		string(targetStatus),
		formatDurableTime(completedAt),
		s.listenerID,
		agentID,
		result.TaskID,
		string(StatusRunning),
	)
	if err != nil {
		return Task{}, CompletionInfo{}, fmt.Errorf("persist durable terminal status: %w", err)
	}
	if err := requireOneDurableRow(updateResult, "persist durable terminal status"); err != nil {
		return Task{}, CompletionInfo{}, err
	}
	if err := s.insertTaskResultTx(ctx, tx, result); err != nil {
		return Task{}, CompletionInfo{}, err
	}

	record, err = s.getTaskTx(ctx, tx, agentID, result.TaskID)
	if err != nil {
		return Task{}, CompletionInfo{}, err
	}
	if record.legacyOrigin {
		if err := s.insertLegacyResultTx(
			ctx,
			tx,
			agentID,
			record.task.ID,
			projectDurableLegacyResult(record.task),
		); err != nil {
			return Task{}, CompletionInfo{}, err
		}
	}
	if record.task.Type == TypeModule && result.Outcome == OutcomeCompleted {
		if err := s.appendTaskAuditTx(
			ctx,
			tx,
			audit.Actor{Kind: audit.ActorAgent, ID: agentID},
			"module_task.evidence_accepted",
			taskAgentAuditRoute("task.result_received", false),
			record,
		); err != nil {
			return Task{}, CompletionInfo{}, err
		}
	}
	if err := s.appendTaskAuditTx(
		ctx,
		tx,
		audit.Actor{Kind: audit.ActorAgent, ID: agentID},
		"task.result_received",
		taskAgentAuditRoute("task.result_received", record.legacyOrigin),
		record,
	); err != nil {
		return Task{}, CompletionInfo{}, err
	}
	if err := tx.Commit(); err != nil {
		return Task{}, CompletionInfo{}, fmt.Errorf("commit durable task completion: %w", err)
	}
	info.Applied = true
	return record.task, info, nil
}

func (s *DurableStore) Cancel(agentID, taskID string) (Task, error) {
	return s.CancelContext(context.Background(), agentID, taskID)
}

// CancelContext cancels a task with the trusted operator actor attached by the
// operator authentication boundary.
func (s *DurableStore) CancelContext(
	ctx context.Context,
	agentID, taskID string,
) (Task, error) {
	if err := validateIDs(agentID, taskID); err != nil {
		return Task{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return Task{}, fmt.Errorf("begin durable task cancellation: %w", err)
	}
	defer rollbackDurableTx(tx)

	now := normalizeTime(s.now())
	if err := s.expireDispatchableTx(ctx, tx, agentID, now); err != nil {
		return Task{}, err
	}
	record, err := s.getTaskTx(ctx, tx, agentID, taskID)
	if err != nil {
		return Task{}, err
	}
	previousStatus := record.task.Status
	if err := transition(&record.task, StatusCancelled); err != nil {
		return Task{}, err
	}
	result, err := tx.ExecContext(
		ctx,
		`UPDATE tasks
		 SET status = ?, server_completed_at = ?, last_delivery_at = NULL
		 WHERE listener_id = ? AND agent_id = ? AND task_id = ? AND status = ?`,
		string(StatusCancelled),
		formatDurableTime(now),
		s.listenerID,
		agentID,
		taskID,
		string(previousStatus),
	)
	if err != nil {
		return Task{}, fmt.Errorf("persist durable task cancellation: %w", err)
	}
	if err := requireOneDurableRow(result, "persist durable task cancellation"); err != nil {
		return Task{}, err
	}
	record, err = s.getTaskTx(ctx, tx, agentID, taskID)
	if err != nil {
		return Task{}, err
	}
	if err := s.appendTaskAuditTx(
		ctx,
		tx,
		audit.ActorOr(ctx, audit.DefaultOperatorActor()),
		"task.cancelled",
		"/api/agents/{agent_id}/tasks/{task_id}/cancel",
		record,
	); err != nil {
		return Task{}, err
	}
	if err := tx.Commit(); err != nil {
		return Task{}, fmt.Errorf("commit durable task cancellation: %w", err)
	}
	return record.task, nil
}

func (s *DurableStore) CompleteLegacy(
	agentID, command, output string,
) (Task, bool, error) {
	if err := ValidateIdentifier("agent_id", agentID); err != nil {
		return Task{}, false, err
	}
	if strings.TrimSpace(command) == "" {
		return Task{}, false, &ValidationError{Field: "command", Message: "is required"}
	}
	if utf8.RuneCountInString(command) > MaxCommandCharacters {
		return Task{}, false, &ValidationError{
			Field:   "command",
			Message: fmt.Sprintf("must be at most %d characters", MaxCommandCharacters),
		}
	}
	if utf8.RuneCountInString(output) > MaxResultStreamCharacters {
		return Task{}, false, &ValidationError{
			Field:   "output",
			Message: fmt.Sprintf("must be at most %d characters", MaxResultStreamCharacters),
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return Task{}, false, fmt.Errorf("begin durable legacy completion: %w", err)
	}
	defer rollbackDurableTx(tx)

	now := normalizeTime(s.now())
	if err := s.expireDispatchableTx(ctx, tx, agentID, now); err != nil {
		return Task{}, false, err
	}
	record, found, err := s.nextLegacyCommandTx(ctx, tx, agentID, command)
	if err != nil {
		return Task{}, false, err
	}
	if !found {
		if err := tx.Commit(); err != nil {
			return Task{}, false, fmt.Errorf("commit unmatched durable legacy completion: %w", err)
		}
		return Task{}, false, nil
	}

	outcome := OutcomeCompleted
	targetStatus := StatusCompleted
	var resultError string
	var exitCode *int
	if strings.HasPrefix(strings.TrimSpace(output), "Error:") {
		outcome = OutcomeFailed
		targetStatus = StatusFailed
		resultError = strings.TrimSpace(output)
	} else {
		code := 0
		exitCode = &code
	}
	taskResult := Result{
		SchemaVersion: SchemaVersion,
		TaskID:        record.task.ID,
		AgentID:       agentID,
		Outcome:       outcome,
		StartedAt:     now,
		CompletedAt:   now,
		ExitCode:      exitCode,
		Output:        Output{Stdout: output, Stderr: ""},
		Error:         resultError,
	}
	if err := taskResult.validate(agentID); err != nil {
		return Task{}, false, err
	}
	if err := transition(&record.task, StatusRunning); err != nil {
		return Task{}, false, err
	}
	if err := transition(&record.task, targetStatus); err != nil {
		return Task{}, false, err
	}

	updateResult, err := tx.ExecContext(
		ctx,
		`UPDATE tasks
		 SET status = ?, server_started_at = ?, server_completed_at = ?,
		     last_delivery_at = NULL
		 WHERE listener_id = ? AND agent_id = ? AND task_id = ? AND status = ?`,
		string(targetStatus),
		formatDurableTime(now),
		formatDurableTime(now),
		s.listenerID,
		agentID,
		record.task.ID,
		string(StatusDispatched),
	)
	if err != nil {
		return Task{}, false, fmt.Errorf("persist durable legacy terminal status: %w", err)
	}
	if err := requireOneDurableRow(
		updateResult,
		"persist durable legacy terminal status",
	); err != nil {
		return Task{}, false, err
	}
	if err := s.insertTaskResultTx(ctx, tx, taskResult); err != nil {
		return Task{}, false, err
	}
	if err := s.insertLegacyResultTx(ctx, tx, agentID, record.task.ID, LegacyResult{
		Command:   command,
		Output:    output,
		Timestamp: now.Format(time.RFC3339),
	}); err != nil {
		return Task{}, false, err
	}

	record, err = s.getTaskTx(ctx, tx, agentID, record.task.ID)
	if err != nil {
		return Task{}, false, err
	}
	if err := s.appendTaskAuditTx(
		ctx,
		tx,
		audit.Actor{Kind: audit.ActorAgent, ID: agentID},
		"task.result_received",
		taskAgentAuditRoute("task.result_received", true),
		record,
	); err != nil {
		return Task{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Task{}, false, fmt.Errorf("commit durable legacy completion: %w", err)
	}
	return record.task, true, nil
}

// GetLegacyResultsPage returns a stable, listener-scoped compatibility page.
func (s *DurableStore) GetLegacyResultsPage(
	agentID string,
	offset, limit int,
	maxEncodedBytes int,
) ([]LegacyResult, int, bool, error) {
	if err := ValidateIdentifier("agent_id", agentID); err != nil {
		return nil, 0, false, err
	}
	if offset < 0 {
		offset = 0
	}
	if limit < 0 {
		limit = 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.SQL().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, false, fmt.Errorf("begin durable legacy result page: %w", err)
	}
	defer rollbackDurableTx(tx)

	var total int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM legacy_results
		 WHERE listener_id = ? AND agent_id = ?`,
		s.listenerID,
		agentID,
	).Scan(&total); err != nil {
		return nil, 0, false, fmt.Errorf("count durable legacy results: %w", err)
	}
	if offset > total {
		offset = total
	}
	if limit > total-offset {
		limit = total - offset
	}
	results := make([]LegacyResult, 0, limit)
	truncated := false
	if limit > 0 {
		if maxEncodedBytes < len("[]\n") {
			truncated = true
			limit = 0
		}
	}
	if limit > 0 {
		rows, err := tx.QueryContext(
			ctx,
			`SELECT command, output, recorded_at
			 FROM legacy_results
			 WHERE listener_id = ? AND agent_id = ?
			 ORDER BY seq ASC
			 LIMIT ? OFFSET ?`,
			s.listenerID,
			agentID,
			limit,
			offset,
		)
		if err != nil {
			return nil, 0, false, fmt.Errorf("query durable legacy results: %w", err)
		}
		encodedSize := len("[]\n")
		for rows.Next() {
			var result LegacyResult
			var recordedAt string
			if err := rows.Scan(&result.Command, &result.Output, &recordedAt); err != nil {
				_ = rows.Close()
				return nil, 0, false, fmt.Errorf("scan durable legacy result: %w", err)
			}
			parsed, err := parseDurableTime(recordedAt)
			if err != nil {
				_ = rows.Close()
				return nil, 0, false, fmt.Errorf(
					"parse durable legacy result timestamp: %w",
					err,
				)
			}
			result.Timestamp = parsed.Format(time.RFC3339)
			encoded, err := json.Marshal(result)
			if err != nil {
				_ = rows.Close()
				return nil, 0, false, fmt.Errorf(
					"measure durable legacy result: %w",
					err,
				)
			}
			separatorSize := 0
			if len(results) > 0 {
				separatorSize = 1
			}
			used := encodedSize + separatorSize
			if used > maxEncodedBytes || len(encoded) > maxEncodedBytes-used {
				truncated = true
				break
			}
			results = append(results, result)
			encodedSize = used + len(encoded)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, 0, false, fmt.Errorf("iterate durable legacy results: %w", err)
		}
		if err := rows.Close(); err != nil {
			return nil, 0, false, fmt.Errorf("close durable legacy results: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, 0, false, fmt.Errorf("commit durable legacy result page: %w", err)
	}
	return results, total, truncated, nil
}

type durableTaskRecord struct {
	seq                  int64
	task                 Task
	lastDeliveryAt       *time.Time
	acceptedRunningAt    *time.Time
	legacyOrigin         bool
	createdAuditEventSeq int64
}

// durableTaskSummarySelect intentionally excludes r.stdout and r.stderr. Those
// streams are available from Get, but collection responses only need bounded
// result metadata.
const durableTaskSummarySelect = `SELECT
	t.schema_version,
	t.task_id,
	t.agent_id,
	t.task_type,
	t.arguments_json,
	t.timeout_seconds,
	t.status,
	t.created_at,
	t.queued_at,
	t.dispatched_at,
	t.server_started_at,
	t.server_completed_at,
	t.expires_at,
	r.schema_version,
	r.agent_id,
	r.outcome,
	r.agent_started_at,
	r.agent_completed_at,
	r.exit_code,
	r.error
 FROM tasks t
 LEFT JOIN task_results r
   ON r.listener_id = t.listener_id AND r.task_id = t.task_id`

const durableTaskSelect = `SELECT
	t.seq,
	t.schema_version,
	t.task_id,
	t.agent_id,
	t.task_type,
	t.arguments_json,
	t.timeout_seconds,
	t.status,
	t.created_at,
	t.queued_at,
	t.dispatched_at,
	t.last_delivery_at,
	t.server_started_at,
	t.accepted_running_at,
	t.server_completed_at,
	t.expires_at,
	t.legacy_origin,
	t.created_audit_event_seq,
	r.schema_version,
	r.agent_id,
	r.outcome,
	r.agent_started_at,
	r.agent_completed_at,
	r.exit_code,
	r.stdout,
	r.stderr,
	r.error,
	r.data_json
 FROM tasks t
 LEFT JOIN task_results r
   ON r.listener_id = t.listener_id AND r.task_id = t.task_id`

type durableRowScanner interface {
	Scan(dest ...interface{}) error
}

func scanDurableTaskSummary(scanner durableRowScanner) (TaskSummary, error) {
	var summary TaskSummary
	var taskType, status string
	var createdAt, queuedAt string
	var dispatchedAt, serverStartedAt, serverCompletedAt, expiresAt sql.NullString
	var resultSchema sql.NullInt64
	var resultAgentID, resultOutcome sql.NullString
	var resultStartedAt, resultCompletedAt sql.NullString
	var resultExitCode sql.NullInt64
	var resultError sql.NullString
	var argumentsJSON string

	err := scanner.Scan(
		&summary.SchemaVersion,
		&summary.ID,
		&summary.AgentID,
		&taskType,
		&argumentsJSON,
		&summary.TimeoutSeconds,
		&status,
		&createdAt,
		&queuedAt,
		&dispatchedAt,
		&serverStartedAt,
		&serverCompletedAt,
		&expiresAt,
		&resultSchema,
		&resultAgentID,
		&resultOutcome,
		&resultStartedAt,
		&resultCompletedAt,
		&resultExitCode,
		&resultError,
	)
	if err != nil {
		return TaskSummary{}, err
	}

	summary.Type = Type(taskType)
	if err := decodeStoredTaskArguments(argumentsJSON, &summary.Arguments); err != nil {
		return TaskSummary{}, err
	}
	summary.Status = Status(status)
	if summary.CreatedAt, err = parseDurableTime(createdAt); err != nil {
		return TaskSummary{}, fmt.Errorf("parse task created_at: %w", err)
	}
	if summary.QueuedAt, err = parseDurableTime(queuedAt); err != nil {
		return TaskSummary{}, fmt.Errorf("parse task queued_at: %w", err)
	}
	if summary.DispatchedAt, err = parseNullableDurableTime(dispatchedAt); err != nil {
		return TaskSummary{}, fmt.Errorf("parse task dispatched_at: %w", err)
	}
	if summary.StartedAt, err = parseNullableDurableTime(serverStartedAt); err != nil {
		return TaskSummary{}, fmt.Errorf("parse task server_started_at: %w", err)
	}
	if summary.CompletedAt, err = parseNullableDurableTime(serverCompletedAt); err != nil {
		return TaskSummary{}, fmt.Errorf("parse task server_completed_at: %w", err)
	}
	if summary.ExpiresAt, err = parseNullableDurableTime(expiresAt); err != nil {
		return TaskSummary{}, fmt.Errorf("parse task expires_at: %w", err)
	}

	if resultSchema.Valid {
		if !resultAgentID.Valid ||
			!resultOutcome.Valid ||
			!resultStartedAt.Valid ||
			!resultCompletedAt.Valid ||
			!resultError.Valid {
			return TaskSummary{}, errors.New("durable task result row is incomplete")
		}
		startedAt, err := parseDurableTime(resultStartedAt.String)
		if err != nil {
			return TaskSummary{}, fmt.Errorf("parse result agent_started_at: %w", err)
		}
		completedAt, err := parseDurableTime(resultCompletedAt.String)
		if err != nil {
			return TaskSummary{}, fmt.Errorf("parse result agent_completed_at: %w", err)
		}
		var exitCode *int
		if resultExitCode.Valid {
			value := int(resultExitCode.Int64)
			exitCode = &value
		}
		summary.Result = &ResultSummary{
			SchemaVersion: int(resultSchema.Int64),
			TaskID:        summary.ID,
			AgentID:       resultAgentID.String,
			Outcome:       Outcome(resultOutcome.String),
			StartedAt:     startedAt,
			CompletedAt:   completedAt,
			ExitCode:      exitCode,
			Error:         resultError.String,
		}
	}
	return summary, nil
}

func scanDurableTask(scanner durableRowScanner) (durableTaskRecord, error) {
	var record durableTaskRecord
	var taskType, status string
	var createdAt, queuedAt string
	var dispatchedAt, lastDeliveryAt sql.NullString
	var serverStartedAt, acceptedRunningAt sql.NullString
	var serverCompletedAt, expiresAt sql.NullString
	var legacyOrigin int
	var createdAuditEventSeq sql.NullInt64
	var resultSchema sql.NullInt64
	var resultAgentID, resultOutcome sql.NullString
	var resultStartedAt, resultCompletedAt sql.NullString
	var resultExitCode sql.NullInt64
	var resultStdout, resultStderr, resultError sql.NullString
	var argumentsJSON string
	var resultData sql.NullString

	err := scanner.Scan(
		&record.seq,
		&record.task.SchemaVersion,
		&record.task.ID,
		&record.task.AgentID,
		&taskType,
		&argumentsJSON,
		&record.task.TimeoutSeconds,
		&status,
		&createdAt,
		&queuedAt,
		&dispatchedAt,
		&lastDeliveryAt,
		&serverStartedAt,
		&acceptedRunningAt,
		&serverCompletedAt,
		&expiresAt,
		&legacyOrigin,
		&createdAuditEventSeq,
		&resultSchema,
		&resultAgentID,
		&resultOutcome,
		&resultStartedAt,
		&resultCompletedAt,
		&resultExitCode,
		&resultStdout,
		&resultStderr,
		&resultError,
		&resultData,
	)
	if err != nil {
		return durableTaskRecord{}, err
	}

	record.task.Type = Type(taskType)
	record.task.Status = Status(status)
	record.legacyOrigin = legacyOrigin != 0
	if err := decodeStoredTaskArguments(argumentsJSON, &record.task.Arguments); err != nil {
		return durableTaskRecord{}, err
	}
	if !createdAuditEventSeq.Valid || createdAuditEventSeq.Int64 <= 0 {
		return durableTaskRecord{}, errors.New(
			"durable task is missing its causal audit event",
		)
	}
	record.createdAuditEventSeq = createdAuditEventSeq.Int64
	if record.task.CreatedAt, err = parseDurableTime(createdAt); err != nil {
		return durableTaskRecord{}, fmt.Errorf("parse task created_at: %w", err)
	}
	if record.task.QueuedAt, err = parseDurableTime(queuedAt); err != nil {
		return durableTaskRecord{}, fmt.Errorf("parse task queued_at: %w", err)
	}
	if record.task.DispatchedAt, err = parseNullableDurableTime(dispatchedAt); err != nil {
		return durableTaskRecord{}, fmt.Errorf("parse task dispatched_at: %w", err)
	}
	if record.lastDeliveryAt, err = parseNullableDurableTime(lastDeliveryAt); err != nil {
		return durableTaskRecord{}, fmt.Errorf("parse task last_delivery_at: %w", err)
	}
	if record.task.StartedAt, err = parseNullableDurableTime(serverStartedAt); err != nil {
		return durableTaskRecord{}, fmt.Errorf("parse task server_started_at: %w", err)
	}
	if record.acceptedRunningAt, err = parseNullableDurableTime(acceptedRunningAt); err != nil {
		return durableTaskRecord{}, fmt.Errorf("parse task accepted_running_at: %w", err)
	}
	if record.task.CompletedAt, err = parseNullableDurableTime(serverCompletedAt); err != nil {
		return durableTaskRecord{}, fmt.Errorf("parse task server_completed_at: %w", err)
	}
	if record.task.ExpiresAt, err = parseNullableDurableTime(expiresAt); err != nil {
		return durableTaskRecord{}, fmt.Errorf("parse task expires_at: %w", err)
	}

	if resultSchema.Valid {
		if !resultAgentID.Valid ||
			!resultOutcome.Valid ||
			!resultStartedAt.Valid ||
			!resultCompletedAt.Valid ||
			!resultStdout.Valid ||
			!resultStderr.Valid ||
			!resultError.Valid {
			return durableTaskRecord{}, errors.New("durable task result row is incomplete")
		}
		startedAt, err := parseDurableTime(resultStartedAt.String)
		if err != nil {
			return durableTaskRecord{}, fmt.Errorf("parse result agent_started_at: %w", err)
		}
		completedAt, err := parseDurableTime(resultCompletedAt.String)
		if err != nil {
			return durableTaskRecord{}, fmt.Errorf("parse result agent_completed_at: %w", err)
		}
		var exitCode *int
		if resultExitCode.Valid {
			value := int(resultExitCode.Int64)
			exitCode = &value
		}
		record.task.Result = &Result{
			SchemaVersion: int(resultSchema.Int64),
			TaskID:        record.task.ID,
			AgentID:       resultAgentID.String,
			Outcome:       Outcome(resultOutcome.String),
			StartedAt:     startedAt,
			CompletedAt:   completedAt,
			ExitCode:      exitCode,
			Output: Output{
				Stdout: resultStdout.String,
				Stderr: resultStderr.String,
			},
			Error: resultError.String,
		}
		if resultData.Valid {
			if !json.Valid([]byte(resultData.String)) {
				return durableTaskRecord{}, errors.New("durable task result data is invalid JSON")
			}
			record.task.Result.Output.Data = json.RawMessage(resultData.String)
		}
	}
	return record, nil
}

func decodeStoredTaskArguments(raw string, destination *TaskArguments) error {
	if !json.Valid([]byte(raw)) {
		return errors.New("durable task arguments are invalid JSON")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &object); err != nil || object == nil {
		return errors.New("durable task arguments must be an object")
	}
	if err := decodeStrictBytes([]byte(raw), destination); err != nil {
		return fmt.Errorf("decode durable task arguments: %w", err)
	}
	return nil
}

func (s *DurableStore) getTaskTx(
	ctx context.Context,
	tx *sql.Tx,
	agentID, taskID string,
) (durableTaskRecord, error) {
	record, err := scanDurableTask(tx.QueryRowContext(
		ctx,
		durableTaskSelect+`
		 WHERE t.listener_id = ? AND t.agent_id = ? AND t.task_id = ?`,
		s.listenerID,
		agentID,
		taskID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return durableTaskRecord{}, ErrNotFound
	}
	if err != nil {
		return durableTaskRecord{}, fmt.Errorf("query durable task: %w", err)
	}
	return record, nil
}

func (s *DurableStore) listTasksTx(
	ctx context.Context,
	tx *sql.Tx,
	agentID string,
) ([]durableTaskRecord, error) {
	rows, err := tx.QueryContext(
		ctx,
		durableTaskSelect+`
		 WHERE t.listener_id = ? AND t.agent_id = ?
		 ORDER BY t.seq ASC`,
		s.listenerID,
		agentID,
	)
	if err != nil {
		return nil, fmt.Errorf("list durable tasks: %w", err)
	}
	defer rows.Close()

	records := make([]durableTaskRecord, 0)
	for rows.Next() {
		record, err := scanDurableTask(rows)
		if err != nil {
			return nil, fmt.Errorf("scan durable task: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate durable tasks: %w", err)
	}
	return records, nil
}

func (s *DurableStore) nextDispatchedTx(
	ctx context.Context,
	tx *sql.Tx,
	agentID string,
	legacyOnly bool,
	leaseCutoff time.Time,
) (durableTaskRecord, bool, error) {
	query := durableTaskSelect + `
	 WHERE t.listener_id = ? AND t.agent_id = ? AND t.status = ?
	   AND COALESCE(t.last_delivery_at, t.dispatched_at) <= ?`
	args := []interface{}{
		s.listenerID,
		agentID,
		string(StatusDispatched),
		formatDurableTime(leaseCutoff),
	}
	if legacyOnly {
		query += ` AND t.legacy_origin = 1`
	}
	query += ` ORDER BY t.seq ASC LIMIT 1`
	record, err := scanDurableTask(tx.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return durableTaskRecord{}, false, nil
	}
	if err != nil {
		return durableTaskRecord{}, false, fmt.Errorf(
			"query durable task redelivery: %w",
			err,
		)
	}
	return record, true, nil
}

func (s *DurableStore) nextQueuedTx(
	ctx context.Context,
	tx *sql.Tx,
	agentID string,
	legacyOnly bool,
) (durableTaskRecord, bool, error) {
	query := durableTaskSelect + `
	 WHERE t.listener_id = ? AND t.agent_id = ? AND t.status = ?`
	args := []interface{}{s.listenerID, agentID, string(StatusQueued)}
	if legacyOnly {
		query += ` AND t.legacy_origin = 1`
	}
	query += ` ORDER BY t.seq ASC LIMIT 1`
	record, err := scanDurableTask(tx.QueryRowContext(ctx, query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return durableTaskRecord{}, false, nil
	}
	if err != nil {
		return durableTaskRecord{}, false, fmt.Errorf("query next durable task: %w", err)
	}
	return record, true, nil
}

func (s *DurableStore) nextLegacyCommandTx(
	ctx context.Context,
	tx *sql.Tx,
	agentID, command string,
) (durableTaskRecord, bool, error) {
	record, err := scanDurableTask(tx.QueryRowContext(
		ctx,
		durableTaskSelect+`
		 WHERE t.listener_id = ? AND t.agent_id = ? AND t.status = ?
		   AND t.legacy_origin = 1 AND t.task_type = ? AND t.command = ?
		 ORDER BY t.seq ASC LIMIT 1`,
		s.listenerID,
		agentID,
		string(StatusDispatched),
		string(TypeShell),
		command,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return durableTaskRecord{}, false, nil
	}
	if err != nil {
		return durableTaskRecord{}, false, fmt.Errorf(
			"query durable legacy task: %w",
			err,
		)
	}
	return record, true, nil
}

func (s *DurableStore) expireDispatchableTx(
	ctx context.Context,
	tx *sql.Tx,
	agentID string,
	now time.Time,
) error {
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE tasks
		 SET status = ?, server_completed_at = ?, last_delivery_at = NULL
		 WHERE listener_id = ? AND agent_id = ?
		   AND status IN (?, ?)
		   AND expires_at IS NOT NULL AND expires_at <= ?`,
		string(StatusExpired),
		formatDurableTime(now),
		s.listenerID,
		agentID,
		string(StatusQueued),
		string(StatusDispatched),
		formatDurableTime(now),
	); err != nil {
		return fmt.Errorf("expire durable tasks: %w", err)
	}
	return nil
}

func (s *DurableStore) makeTaskRoomTx(
	ctx context.Context,
	tx *sql.Tx,
	agentID string,
) error {
	var count int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM tasks WHERE listener_id = ? AND agent_id = ?`,
		s.listenerID,
		agentID,
	).Scan(&count); err != nil {
		return fmt.Errorf("count durable task history: %w", err)
	}
	if count < s.maxTasksPerAgent {
		return nil
	}

	removeCount := count - s.maxTasksPerAgent + 1
	rows, err := tx.QueryContext(
		ctx,
		`SELECT task_id
		 FROM tasks
		 WHERE listener_id = ? AND agent_id = ?
		   AND status IN (?, ?, ?, ?)
		 ORDER BY seq ASC
		 LIMIT ?`,
		s.listenerID,
		agentID,
		string(StatusCompleted),
		string(StatusFailed),
		string(StatusCancelled),
		string(StatusExpired),
		removeCount,
	)
	if err != nil {
		return fmt.Errorf("select durable task retention candidates: %w", err)
	}
	var taskIDs []string
	for rows.Next() {
		var taskID string
		if err := rows.Scan(&taskID); err != nil {
			rows.Close()
			return fmt.Errorf("scan durable task retention candidate: %w", err)
		}
		taskIDs = append(taskIDs, taskID)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close durable task retention candidates: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate durable task retention candidates: %w", err)
	}
	if len(taskIDs) < removeCount {
		return ErrCapacity
	}
	for _, taskID := range taskIDs {
		if _, err := tx.ExecContext(
			ctx,
			`DELETE FROM tasks WHERE listener_id = ? AND agent_id = ? AND task_id = ?`,
			s.listenerID,
			agentID,
			taskID,
		); err != nil {
			return fmt.Errorf("prune durable terminal task: %w", err)
		}
	}
	return nil
}

func (s *DurableStore) insertTaskResultTx(
	ctx context.Context,
	tx *sql.Tx,
	result Result,
) error {
	var exitCode interface{}
	if result.ExitCode != nil {
		exitCode = *result.ExitCode
	}
	var outputData interface{}
	if len(result.Output.Data) != 0 {
		outputData = string(result.Output.Data)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO task_results (
			listener_id, task_id, schema_version, agent_id, outcome,
			agent_started_at, agent_completed_at, exit_code, stdout, stderr, error, data_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.listenerID,
		result.TaskID,
		result.SchemaVersion,
		result.AgentID,
		string(result.Outcome),
		formatDurableTime(result.StartedAt),
		formatDurableTime(result.CompletedAt),
		exitCode,
		result.Output.Stdout,
		result.Output.Stderr,
		result.Error,
		outputData,
	); err != nil {
		return fmt.Errorf("insert durable task result: %w", err)
	}
	return nil
}

func (s *DurableStore) insertLegacyResultTx(
	ctx context.Context,
	tx *sql.Tx,
	agentID, taskID string,
	result LegacyResult,
) error {
	recordedAt, err := time.Parse(time.RFC3339, result.Timestamp)
	if err != nil {
		recordedAt, err = time.Parse(time.RFC3339Nano, result.Timestamp)
	}
	if err != nil {
		return fmt.Errorf("parse legacy result timestamp: %w", err)
	}
	insert, err := tx.ExecContext(
		ctx,
		`INSERT INTO legacy_results (
			listener_id, agent_id, source_task_id, command, output, recorded_at
		) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(listener_id, source_task_id) DO NOTHING`,
		s.listenerID,
		agentID,
		taskID,
		result.Command,
		result.Output,
		formatDurableTime(recordedAt),
	)
	if err != nil {
		return fmt.Errorf("insert durable legacy result: %w", err)
	}
	inserted, err := insert.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect durable legacy result insert: %w", err)
	}
	if inserted == 0 {
		var listenerID, existingAgentID, command, output, timestamp string
		if err := tx.QueryRowContext(
			ctx,
			`SELECT listener_id, agent_id, command, output, recorded_at
			 FROM legacy_results
			 WHERE listener_id = ? AND source_task_id = ?`,
			s.listenerID,
			taskID,
		).Scan(&listenerID, &existingAgentID, &command, &output, &timestamp); err != nil {
			return fmt.Errorf("query idempotent durable legacy result: %w", err)
		}
		if listenerID != s.listenerID ||
			existingAgentID != agentID ||
			command != result.Command ||
			output != result.Output ||
			timestamp != formatDurableTime(recordedAt) {
			return fmt.Errorf(
				"%w: conflicting repeated legacy result",
				ErrInvalidTransition,
			)
		}
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM legacy_results
		 WHERE seq IN (
		   SELECT seq
		   FROM legacy_results
		   WHERE listener_id = ? AND agent_id = ?
		   ORDER BY seq DESC
		   LIMIT -1 OFFSET ?
		 )`,
		s.listenerID,
		agentID,
		s.maxTasksPerAgent,
	); err != nil {
		return fmt.Errorf("prune durable legacy result history: %w", err)
	}
	return nil
}

func projectDurableLegacyResult(task Task) LegacyResult {
	result := LegacyResult{Command: task.Arguments.Command}
	if task.CompletedAt != nil {
		result.Timestamp = task.CompletedAt.UTC().Format(time.RFC3339)
	} else {
		result.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	if task.Result != nil {
		result.Output = task.Result.Output.Stdout + task.Result.Output.Stderr
		if task.Result.Outcome == OutcomeFailed && task.Result.Error != "" {
			errorOutput := task.Result.Error
			if !strings.HasPrefix(strings.TrimSpace(errorOutput), "Error:") {
				errorOutput = "Error: " + errorOutput
			}
			if result.Output == "" {
				result.Output = errorOutput
			} else {
				result.Output += "\n" + errorOutput
			}
		}
	}
	return result
}

func formatDurableTime(value time.Time) string {
	return normalizeTime(value).Format(durableTimeLayout)
}

func parseDurableTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, err
	}
	return normalizeTime(parsed), nil
}

func parseNullableDurableTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := parseDurableTime(value.String)
	if err != nil {
		return nil, err
	}
	return timePointer(parsed), nil
}

func boolToSQLite(value bool) int {
	if value {
		return 1
	}
	return 0
}

func rollbackDurableTx(tx *sql.Tx) {
	_ = tx.Rollback()
}

func requireOneDurableRow(result sql.Result, operation string) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s: inspect affected rows: %w", operation, err)
	}
	if affected != 1 {
		return fmt.Errorf(
			"%w: %s changed %d rows",
			ErrInvalidTransition,
			operation,
			affected,
		)
	}
	return nil
}
