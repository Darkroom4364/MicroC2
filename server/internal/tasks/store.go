package tasks

import "bytes"
import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const DefaultDispatchLease = 30 * time.Second

// CompletionInfo describes server-internal completion metadata that is not
// part of the public task wire format.
type CompletionInfo struct {
	LegacyOrigin bool
	Applied      bool
}

type Store struct {
	mu               sync.RWMutex
	byID             map[string]*Task
	byAgent          map[string][]string
	lastDispatch     map[string]time.Time
	runningUpdates   map[string]StatusUpdate
	legacyOrigin     map[string]bool
	now              func() time.Time
	dispatchLease    time.Duration
	maxTasksPerAgent int
}

func NewStore() *Store {
	return NewStoreWithClock(time.Now)
}

func NewStoreWithClock(now func() time.Time) *Store {
	return newStoreWithOptions(now, DefaultDispatchLease, MaxTaskHistoryPerAgent)
}

func newStoreWithOptions(
	now func() time.Time,
	dispatchLease time.Duration,
	maxTasksPerAgent int,
) *Store {
	if now == nil {
		now = time.Now
	}
	if dispatchLease <= 0 {
		dispatchLease = DefaultDispatchLease
	}
	if maxTasksPerAgent <= 0 {
		maxTasksPerAgent = MaxTaskHistoryPerAgent
	}
	return &Store{
		byID:             make(map[string]*Task),
		byAgent:          make(map[string][]string),
		lastDispatch:     make(map[string]time.Time),
		runningUpdates:   make(map[string]StatusUpdate),
		legacyOrigin:     make(map[string]bool),
		now:              now,
		dispatchLease:    dispatchLease,
		maxTasksPerAgent: maxTasksPerAgent,
	}
}

func (s *Store) Create(agentID string, request CreateRequest) (Task, error) {
	return s.create(agentID, request, false)
}

func (s *Store) create(agentID string, request CreateRequest, legacyOrigin bool) (Task, error) {
	if err := ValidateIdentifier("agent_id", agentID); err != nil {
		return Task{}, err
	}
	if err := request.validate(); err != nil {
		return Task{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := normalizeTime(s.now())
	s.expireDispatchableLocked(agentID, now)
	if err := s.makeTaskRoomLocked(agentID); err != nil {
		return Task{}, err
	}

	expiresIn := DefaultExpiresIn
	if request.ExpiresInSeconds != nil {
		expiresIn = *request.ExpiresInSeconds
	}
	expiresAt := now.Add(time.Duration(expiresIn) * time.Second)
	task := &Task{
		SchemaVersion:  SchemaVersion,
		ID:             uuid.NewString(),
		AgentID:        agentID,
		Type:           request.Type,
		Arguments:      cloneTaskArguments(request.Arguments),
		TimeoutSeconds: request.TimeoutSeconds,
		Status:         StatusQueued,
		CreatedAt:      now,
		QueuedAt:       now,
		ExpiresAt:      &expiresAt,
	}

	s.byID[task.ID] = task
	s.byAgent[agentID] = append(s.byAgent[agentID], task.ID)
	s.legacyOrigin[task.ID] = legacyOrigin
	return cloneTask(task), nil
}

func (s *Store) CreateLegacyShell(agentID, command string) (Task, error) {
	expiresIn := DefaultExpiresIn
	return s.create(agentID, CreateRequest{
		SchemaVersion:    SchemaVersion,
		Type:             TypeShell,
		Arguments:        ShellArguments{Command: command},
		TimeoutSeconds:   DefaultTimeoutSeconds,
		ExpiresInSeconds: &expiresIn,
	}, true)
}

func (s *Store) List(agentID string) ([]Task, error) {
	if err := ValidateIdentifier("agent_id", agentID); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireDispatchableLocked(agentID, normalizeTime(s.now()))

	ids := s.byAgent[agentID]
	out := make([]Task, 0, len(ids))
	for _, id := range ids {
		if task := s.byID[id]; task != nil {
			out = append(out, cloneTask(task))
		}
	}
	return out, nil
}

func (s *Store) Get(agentID, taskID string) (Task, error) {
	if err := validateIDs(agentID, taskID); err != nil {
		return Task{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	task, err := s.getLocked(agentID, taskID)
	if err != nil {
		return Task{}, err
	}
	return cloneTask(task), nil
}

func (s *Store) DispatchNext(agentID string) (Task, bool, error) {
	return s.dispatchNext(agentID, false)
}

// DispatchNextLegacy returns only tasks created through a deprecated raw
// command adapter. A legacy poll must never consume a typed-origin task because
// it cannot preserve that task's ID or structured result contract.
func (s *Store) DispatchNextLegacy(agentID string) (Task, bool, error) {
	return s.dispatchNext(agentID, true)
}

func (s *Store) dispatchNext(agentID string, legacyOnly bool) (Task, bool, error) {
	if err := ValidateIdentifier("agent_id", agentID); err != nil {
		return Task{}, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := normalizeTime(s.now())
	s.expireDispatchableLocked(agentID, now)

	for _, id := range s.byAgent[agentID] {
		task := s.byID[id]
		if task == nil || task.Status != StatusDispatched || !s.matchesOriginLocked(id, legacyOnly) {
			continue
		}
		lastDelivery := task.DispatchedAt
		if last, ok := s.lastDispatch[id]; ok {
			lastDelivery = &last
		}
		if lastDelivery != nil && now.Before(lastDelivery.Add(s.dispatchLease)) {
			continue
		}
		s.lastDispatch[id] = now
		return cloneTask(task), true, nil
	}

	for _, id := range s.byAgent[agentID] {
		task := s.byID[id]
		if task == nil || task.Status != StatusQueued || !s.matchesOriginLocked(id, legacyOnly) {
			continue
		}
		if err := transition(task, StatusDispatched); err != nil {
			return Task{}, false, err
		}
		task.DispatchedAt = timePointer(now)
		s.lastDispatch[id] = now
		return cloneTask(task), true, nil
	}
	return Task{}, false, nil
}

func (s *Store) MarkRunning(agentID, taskID string, update StatusUpdate) (Task, error) {
	if err := validateIDs(agentID, taskID); err != nil {
		return Task{}, err
	}
	if err := update.validate(agentID, taskID); err != nil {
		return Task{}, err
	}
	update = normalizeStatusUpdate(update)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := normalizeTime(s.now())
	s.expireDispatchableLocked(agentID, now)
	task, err := s.getLocked(agentID, taskID)
	if err != nil {
		return Task{}, err
	}
	if accepted, ok := s.runningUpdates[taskID]; ok {
		if statusUpdatesEqual(accepted, update) {
			return cloneTask(task), nil
		}
		return Task{}, fmt.Errorf("%w: conflicting repeated running update", ErrInvalidTransition)
	}
	if err := transition(task, StatusRunning); err != nil {
		return Task{}, err
	}
	task.StartedAt = timePointer(now)
	s.runningUpdates[taskID] = update
	delete(s.lastDispatch, taskID)
	return cloneTask(task), nil
}

func (s *Store) Complete(agentID string, result Result) (Task, error) {
	task, _, err := s.CompleteWithInfo(agentID, result)
	return task, err
}

func (s *Store) CompleteWithInfo(agentID string, result Result) (Task, CompletionInfo, error) {
	if err := ValidateIdentifier("agent_id", agentID); err != nil {
		return Task{}, CompletionInfo{}, err
	}
	result = normalizeResult(result)
	if err := result.validate(agentID); err != nil {
		return Task{}, CompletionInfo{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	task, err := s.getLocked(agentID, result.TaskID)
	if err != nil {
		return Task{}, CompletionInfo{}, err
	}
	info := CompletionInfo{LegacyOrigin: s.legacyOrigin[task.ID]}
	targetStatus := StatusCompleted
	if result.Outcome == OutcomeFailed {
		targetStatus = StatusFailed
	}
	if task.Status == StatusCompleted || task.Status == StatusFailed {
		if task.Result != nil && resultsEqual(*task.Result, result) {
			return cloneTask(task), info, nil
		}
		return Task{}, CompletionInfo{}, fmt.Errorf(
			"%w: conflicting repeated terminal result",
			ErrInvalidTransition,
		)
	}
	if err := validateResultForTask(task, result); err != nil {
		return Task{}, CompletionInfo{}, err
	}
	runningUpdate, ok := s.runningUpdates[task.ID]
	if !ok {
		return Task{}, CompletionInfo{}, fmt.Errorf(
			"%w: task has no accepted running update",
			ErrInvalidTransition,
		)
	}
	if !result.StartedAt.Equal(runningUpdate.Timestamp) {
		return Task{}, CompletionInfo{}, &ValidationError{
			Field:   "started_at",
			Message: "must match the running status timestamp",
		}
	}
	if err := transition(task, targetStatus); err != nil {
		return Task{}, CompletionInfo{}, err
	}
	completedAt := normalizeTime(s.now())
	if task.StartedAt != nil && completedAt.Before(*task.StartedAt) {
		completedAt = *task.StartedAt
	}
	task.CompletedAt = timePointer(completedAt)
	task.Result = cloneResult(&result)
	info.Applied = true
	return cloneTask(task), info, nil
}

// QueueStats summarizes outstanding and recently failed work in a store.
// It is the machine-readable telemetry view over the same task lifecycle
// state that dispatch and completion mutate; it never guesses from logs.
type QueueStats struct {
	// Pending counts tasks waiting for an agent (queued) or delivered to an
	// agent but not yet completed (dispatched).
	Pending int
	// RecentFailed counts tasks that reached the failed terminal state at or
	// after the caller-supplied window start.
	RecentFailed int
}

// QueueStats aggregates pending and recently failed tasks across all agents
// in the store. failedSince bounds the recent-failure window; pending counts
// are not windowed.
func (s *Store) QueueStats(failedSince time.Time) (QueueStats, error) {
	failedSince = normalizeTime(failedSince)

	s.mu.RLock()
	defer s.mu.RUnlock()
	var stats QueueStats
	for _, task := range s.byID {
		switch task.Status {
		case StatusQueued, StatusDispatched:
			stats.Pending++
		case StatusFailed:
			if task.CompletedAt != nil && !task.CompletedAt.Before(failedSince) {
				stats.RecentFailed++
			}
		}
	}
	return stats, nil
}

func (s *Store) Cancel(agentID, taskID string) (Task, error) {
	if err := validateIDs(agentID, taskID); err != nil {
		return Task{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireDispatchableLocked(agentID, normalizeTime(s.now()))
	task, err := s.getLocked(agentID, taskID)
	if err != nil {
		return Task{}, err
	}
	if err := transition(task, StatusCancelled); err != nil {
		return Task{}, err
	}
	now := s.now().UTC()
	task.CompletedAt = timePointer(now)
	return cloneTask(task), nil
}

// CompleteLegacy correlates a legacy command result to the oldest dispatched
// shell task with the same command. It keeps the deprecated adapter useful
// while all new agent traffic uses task IDs.
func (s *Store) CompleteLegacy(agentID, command, output string) (Task, bool, error) {
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
	now := normalizeTime(s.now())
	s.expireDispatchableLocked(agentID, now)
	var task *Task
	for _, id := range s.byAgent[agentID] {
		candidate := s.byID[id]
		if candidate != nil &&
			candidate.Status == StatusDispatched &&
			s.legacyOrigin[id] &&
			candidate.Type == TypeShell &&
			candidate.Arguments.Command == command {
			task = candidate
			break
		}
	}
	if task == nil {
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
	result := &Result{
		SchemaVersion: SchemaVersion,
		TaskID:        task.ID,
		AgentID:       agentID,
		Outcome:       outcome,
		StartedAt:     now,
		CompletedAt:   now,
		ExitCode:      exitCode,
		Output:        Output{Stdout: output, Stderr: ""},
		Error:         resultError,
	}
	if err := result.validate(agentID); err != nil {
		return Task{}, false, err
	}
	if err := transition(task, StatusRunning); err != nil {
		return Task{}, false, err
	}
	task.StartedAt = timePointer(now)
	if err := transition(task, targetStatus); err != nil {
		return Task{}, false, err
	}
	task.CompletedAt = timePointer(now)
	task.Result = result
	delete(s.lastDispatch, task.ID)
	return cloneTask(task), true, nil
}

func (s *Store) getLocked(agentID, taskID string) (*Task, error) {
	task := s.byID[taskID]
	if task == nil || task.AgentID != agentID {
		return nil, ErrNotFound
	}
	return task, nil
}

func (s *Store) matchesOriginLocked(taskID string, legacyOnly bool) bool {
	return !legacyOnly || s.legacyOrigin[taskID]
}

func (s *Store) expireDispatchableLocked(agentID string, now time.Time) {
	for _, id := range s.byAgent[agentID] {
		task := s.byID[id]
		if task == nil ||
			(task.Status != StatusQueued && task.Status != StatusDispatched) ||
			task.ExpiresAt == nil ||
			task.ExpiresAt.After(now) {
			continue
		}
		if transition(task, StatusExpired) == nil {
			task.CompletedAt = timePointer(now)
			delete(s.lastDispatch, id)
		}
	}
}

func (s *Store) makeTaskRoomLocked(agentID string) error {
	ids := s.byAgent[agentID]
	if len(ids) < s.maxTasksPerAgent {
		return nil
	}

	toRemove := len(ids) - s.maxTasksPerAgent + 1
	retained := make([]string, 0, len(ids)-toRemove)
	for _, id := range ids {
		task := s.byID[id]
		if toRemove > 0 && task != nil && isTerminal(task.Status) {
			s.deleteTaskLocked(id)
			toRemove--
			continue
		}
		retained = append(retained, id)
	}
	s.byAgent[agentID] = retained
	if toRemove > 0 {
		return ErrCapacity
	}
	return nil
}

func (s *Store) deleteTaskLocked(taskID string) {
	delete(s.byID, taskID)
	delete(s.lastDispatch, taskID)
	delete(s.runningUpdates, taskID)
	delete(s.legacyOrigin, taskID)
}

func isTerminal(status Status) bool {
	switch status {
	case StatusCompleted, StatusFailed, StatusCancelled, StatusExpired:
		return true
	default:
		return false
	}
}

func transition(task *Task, next Status) error {
	if !canTransition(task.Status, next) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, task.Status, next)
	}
	task.Status = next
	return nil
}

func validateIDs(agentID, taskID string) error {
	if err := ValidateIdentifier("agent_id", agentID); err != nil {
		return err
	}
	if err := ValidateIdentifier("task_id", taskID); err != nil {
		return err
	}
	return nil
}

func IsValidationError(err error) bool {
	var target *ValidationError
	return errors.As(err, &target)
}

func normalizeStatusUpdate(update StatusUpdate) StatusUpdate {
	update.Timestamp = normalizeTime(update.Timestamp)
	return update
}

func normalizeResult(result Result) Result {
	result.StartedAt = normalizeTime(result.StartedAt)
	result.CompletedAt = normalizeTime(result.CompletedAt)
	if result.ExitCode != nil {
		exitCode := *result.ExitCode
		result.ExitCode = &exitCode
	}
	result.Output.Data = cloneRawMessage(result.Output.Data)
	return result
}

func normalizeTime(value time.Time) time.Time {
	return value.UTC().Round(0)
}

func statusUpdatesEqual(left, right StatusUpdate) bool {
	return left.SchemaVersion == right.SchemaVersion &&
		left.TaskID == right.TaskID &&
		left.AgentID == right.AgentID &&
		left.Status == right.Status &&
		left.Timestamp.Equal(right.Timestamp)
}

func resultsEqual(left, right Result) bool {
	return left.SchemaVersion == right.SchemaVersion &&
		left.TaskID == right.TaskID &&
		left.AgentID == right.AgentID &&
		left.Outcome == right.Outcome &&
		left.StartedAt.Equal(right.StartedAt) &&
		left.CompletedAt.Equal(right.CompletedAt) &&
		exitCodesEqual(left.ExitCode, right.ExitCode) &&
		left.Output.Stdout == right.Output.Stdout &&
		left.Output.Stderr == right.Output.Stderr &&
		bytes.Equal(left.Output.Data, right.Output.Data) &&
		left.Error == right.Error
}

func exitCodesEqual(left, right *int) bool {
	switch {
	case left == nil && right == nil:
		return true
	case left == nil || right == nil:
		return false
	default:
		return *left == *right
	}
}

func timePointer(value time.Time) *time.Time {
	value = normalizeTime(value)
	return &value
}

func cloneTask(task *Task) Task {
	clone := *task
	clone.Arguments = cloneTaskArguments(task.Arguments)
	clone.DispatchedAt = cloneTime(task.DispatchedAt)
	clone.StartedAt = cloneTime(task.StartedAt)
	clone.CompletedAt = cloneTime(task.CompletedAt)
	clone.ExpiresAt = cloneTime(task.ExpiresAt)
	clone.Result = cloneResult(task.Result)
	return clone
}

func cloneResult(result *Result) *Result {
	if result == nil {
		return nil
	}
	clone := *result
	clone.ExitCode = cloneInt(result.ExitCode)
	clone.Output.Data = cloneRawMessage(result.Output.Data)
	return &clone
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
