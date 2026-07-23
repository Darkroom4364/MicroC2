package tasks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// SchemaVersion is the only task contract version currently supported.
	SchemaVersion = 1

	DefaultTimeoutSeconds = 30
	MaxTimeoutSeconds     = 3600
	DefaultExpiresIn      = 300
	MaxExpiresIn          = 604800

	// The task API is intentionally bounded because agent-facing listeners must
	// treat both task output and compromised agents as untrusted input.
	MaxCommandCharacters      = 8 << 10
	MaxResultStreamCharacters = 1 << 20
	MaxResultErrorCharacters  = 8 << 10
	MinResultExitCode         = -1 << 31
	MaxResultExitCode         = 1<<31 - 1
	MaxTaskHistoryPerAgent    = 1024
	MaxTaskCreateBodyBytes    = 64 << 10
	MaxStatusUpdateBodyBytes  = 8 << 10
	// A schema-valid result may contain two 1 MiB character streams. A compact
	// JSON client may encode each astral code point as a 12-byte surrogate
	// pair, so the wire limit must cover that representation plus the bounded
	// result envelope without stranding an agent's outbox.
	MaxTaskResultBodyBytes   = 32 << 20
	MaxLegacyResultBodyBytes = 10 << 20
)

type Type string

const (
	TypeShell Type = "shell"
)

type Status string

const (
	StatusQueued     Status = "queued"
	StatusDispatched Status = "dispatched"
	StatusRunning    Status = "running"
	StatusCompleted  Status = "completed"
	StatusFailed     Status = "failed"
	StatusCancelled  Status = "cancelled"
	StatusExpired    Status = "expired"
)

type Outcome string

const (
	OutcomeCompleted Outcome = "completed"
	OutcomeFailed    Outcome = "failed"
)

var (
	ErrNotFound          = errors.New("task not found")
	ErrInvalidTransition = errors.New("invalid task status transition")
	ErrCapacity          = errors.New("task history capacity reached")
)

// ValidationError identifies a malformed task-contract value.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

type ShellArguments struct {
	Command string `json:"command"`
}

type Output struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

type Result struct {
	SchemaVersion int       `json:"schema_version"`
	TaskID        string    `json:"task_id"`
	AgentID       string    `json:"agent_id"`
	Outcome       Outcome   `json:"outcome"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	ExitCode      *int      `json:"exit_code,omitempty"`
	Output        Output    `json:"output"`
	Error         string    `json:"error,omitempty"`
	errorPresent  bool
}

func (r *Result) UnmarshalJSON(data []byte) error {
	var wire struct {
		SchemaVersion int             `json:"schema_version"`
		TaskID        string          `json:"task_id"`
		AgentID       string          `json:"agent_id"`
		Outcome       Outcome         `json:"outcome"`
		StartedAt     time.Time       `json:"started_at"`
		CompletedAt   time.Time       `json:"completed_at"`
		ExitCode      *int            `json:"exit_code"`
		Output        *rawOutput      `json:"output"`
		Error         json.RawMessage `json:"error"`
	}
	if err := decodeStrictBytes(data, &wire); err != nil {
		return err
	}
	if wire.Output == nil {
		return &ValidationError{Field: "output", Message: "is required"}
	}
	if wire.Output.Stdout == nil {
		return &ValidationError{Field: "output.stdout", Message: "is required"}
	}
	if wire.Output.Stderr == nil {
		return &ValidationError{Field: "output.stderr", Message: "is required"}
	}
	var resultError string
	errorPresent := wire.Error != nil
	if errorPresent {
		if string(wire.Error) == "null" {
			return &ValidationError{Field: "error", Message: "must be a string"}
		}
		if err := json.Unmarshal(wire.Error, &resultError); err != nil {
			return &ValidationError{Field: "error", Message: "must be a string"}
		}
	}
	*r = Result{
		SchemaVersion: wire.SchemaVersion,
		TaskID:        wire.TaskID,
		AgentID:       wire.AgentID,
		Outcome:       wire.Outcome,
		StartedAt:     wire.StartedAt,
		CompletedAt:   wire.CompletedAt,
		ExitCode:      wire.ExitCode,
		Output: Output{
			Stdout: *wire.Output.Stdout,
			Stderr: *wire.Output.Stderr,
		},
		Error:        resultError,
		errorPresent: errorPresent,
	}
	return nil
}

type rawOutput struct {
	Stdout *string `json:"stdout"`
	Stderr *string `json:"stderr"`
}

type Task struct {
	SchemaVersion  int            `json:"schema_version"`
	ID             string         `json:"id"`
	AgentID        string         `json:"agent_id"`
	Type           Type           `json:"type"`
	Arguments      ShellArguments `json:"arguments"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	Status         Status         `json:"status"`
	CreatedAt      time.Time      `json:"created_at"`
	QueuedAt       time.Time      `json:"queued_at"`
	DispatchedAt   *time.Time     `json:"dispatched_at,omitempty"`
	StartedAt      *time.Time     `json:"started_at,omitempty"`
	CompletedAt    *time.Time     `json:"completed_at,omitempty"`
	ExpiresAt      *time.Time     `json:"expires_at,omitempty"`
	Result         *Result        `json:"result,omitempty"`
}

// ResultSummary is the bounded operator-list representation of a task result.
// The potentially large stdout and stderr streams are intentionally available
// only from the task-detail endpoint.
type ResultSummary struct {
	SchemaVersion int       `json:"schema_version"`
	TaskID        string    `json:"task_id"`
	AgentID       string    `json:"agent_id"`
	Outcome       Outcome   `json:"outcome"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	ExitCode      *int      `json:"exit_code,omitempty"`
	Error         string    `json:"error,omitempty"`
}

// TaskSummary retains task metadata and lifecycle timestamps while omitting
// result streams from collection responses.
type TaskSummary struct {
	SchemaVersion  int            `json:"schema_version"`
	ID             string         `json:"id"`
	AgentID        string         `json:"agent_id"`
	Type           Type           `json:"type"`
	Arguments      ShellArguments `json:"arguments"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	Status         Status         `json:"status"`
	CreatedAt      time.Time      `json:"created_at"`
	QueuedAt       time.Time      `json:"queued_at"`
	DispatchedAt   *time.Time     `json:"dispatched_at,omitempty"`
	StartedAt      *time.Time     `json:"started_at,omitempty"`
	CompletedAt    *time.Time     `json:"completed_at,omitempty"`
	ExpiresAt      *time.Time     `json:"expires_at,omitempty"`
	Result         *ResultSummary `json:"result,omitempty"`
}

// Summarize returns a detached collection-safe representation of task.
func Summarize(task Task) TaskSummary {
	summary := TaskSummary{
		SchemaVersion:  task.SchemaVersion,
		ID:             task.ID,
		AgentID:        task.AgentID,
		Type:           task.Type,
		Arguments:      task.Arguments,
		TimeoutSeconds: task.TimeoutSeconds,
		Status:         task.Status,
		CreatedAt:      task.CreatedAt,
		QueuedAt:       task.QueuedAt,
		DispatchedAt:   cloneTime(task.DispatchedAt),
		StartedAt:      cloneTime(task.StartedAt),
		CompletedAt:    cloneTime(task.CompletedAt),
		ExpiresAt:      cloneTime(task.ExpiresAt),
	}
	if task.Result != nil {
		summary.Result = &ResultSummary{
			SchemaVersion: task.Result.SchemaVersion,
			TaskID:        task.Result.TaskID,
			AgentID:       task.Result.AgentID,
			Outcome:       task.Result.Outcome,
			StartedAt:     task.Result.StartedAt,
			CompletedAt:   task.Result.CompletedAt,
			ExitCode:      cloneInt(task.Result.ExitCode),
			Error:         task.Result.Error,
		}
	}
	return summary
}

// CreateRequest is the operator-facing subset of Task. Identity, state, and
// timestamps are assigned by the server.
type CreateRequest struct {
	SchemaVersion    int            `json:"schema_version,omitempty"`
	Type             Type           `json:"type"`
	Arguments        ShellArguments `json:"arguments"`
	TimeoutSeconds   int            `json:"timeout_seconds"`
	ExpiresInSeconds *int           `json:"expires_in_seconds,omitempty"`
}

type StatusUpdate struct {
	SchemaVersion int       `json:"schema_version"`
	TaskID        string    `json:"task_id"`
	AgentID       string    `json:"agent_id"`
	Status        Status    `json:"status"`
	Timestamp     time.Time `json:"timestamp"`
}

func ValidateIdentifier(field, value string) error {
	if value == "" {
		return &ValidationError{Field: field, Message: "is required"}
	}
	if value != strings.TrimSpace(value) {
		return &ValidationError{Field: field, Message: "must not contain surrounding whitespace"}
	}
	if len(value) > 128 {
		return &ValidationError{Field: field, Message: "must be at most 128 bytes"}
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' ||
			r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return &ValidationError{Field: field, Message: "contains unsupported characters"}
	}
	return nil
}

func (r CreateRequest) validate() error {
	if r.SchemaVersion != SchemaVersion {
		return &ValidationError{Field: "schema_version", Message: "must be 1"}
	}
	if r.Type != TypeShell {
		return &ValidationError{Field: "type", Message: `must be "shell"`}
	}
	if strings.TrimSpace(r.Arguments.Command) == "" {
		return &ValidationError{Field: "arguments.command", Message: "is required"}
	}
	if utf8.RuneCountInString(r.Arguments.Command) > MaxCommandCharacters {
		return &ValidationError{
			Field:   "arguments.command",
			Message: fmt.Sprintf("must be at most %d characters", MaxCommandCharacters),
		}
	}
	if r.TimeoutSeconds < 1 || r.TimeoutSeconds > MaxTimeoutSeconds {
		return &ValidationError{Field: "timeout_seconds", Message: "must be between 1 and 3600"}
	}
	if r.ExpiresInSeconds == nil {
		return &ValidationError{Field: "expires_in_seconds", Message: "is required"}
	}
	if *r.ExpiresInSeconds < 1 || *r.ExpiresInSeconds > MaxExpiresIn {
		return &ValidationError{Field: "expires_in_seconds", Message: "must be between 1 and 604800"}
	}
	return nil
}

func (u StatusUpdate) validate(agentID, taskID string) error {
	if u.SchemaVersion != SchemaVersion {
		return &ValidationError{Field: "schema_version", Message: "must be 1"}
	}
	if err := ValidateIdentifier("task_id", u.TaskID); err != nil {
		return err
	}
	if err := ValidateIdentifier("agent_id", u.AgentID); err != nil {
		return err
	}
	if u.TaskID != taskID {
		return &ValidationError{Field: "task_id", Message: "does not match request path"}
	}
	if u.AgentID != agentID {
		return &ValidationError{Field: "agent_id", Message: "does not match request path"}
	}
	if u.Status != StatusRunning {
		return &ValidationError{Field: "status", Message: `must be "running"`}
	}
	if u.Timestamp.IsZero() {
		return &ValidationError{Field: "timestamp", Message: "is required"}
	}
	return nil
}

func (r Result) validate(agentID string) error {
	if r.SchemaVersion != SchemaVersion {
		return &ValidationError{Field: "schema_version", Message: "must be 1"}
	}
	if err := ValidateIdentifier("task_id", r.TaskID); err != nil {
		return err
	}
	if err := ValidateIdentifier("agent_id", r.AgentID); err != nil {
		return err
	}
	if r.AgentID != agentID {
		return &ValidationError{Field: "agent_id", Message: "does not match request path"}
	}
	if r.Outcome != OutcomeCompleted && r.Outcome != OutcomeFailed {
		return &ValidationError{Field: "outcome", Message: `must be "completed" or "failed"`}
	}
	if r.StartedAt.IsZero() {
		return &ValidationError{Field: "started_at", Message: "is required"}
	}
	if r.CompletedAt.IsZero() {
		return &ValidationError{Field: "completed_at", Message: "is required"}
	}
	if r.CompletedAt.Before(r.StartedAt) {
		return &ValidationError{Field: "completed_at", Message: "must not precede started_at"}
	}
	if utf8.RuneCountInString(r.Output.Stdout) > MaxResultStreamCharacters {
		return &ValidationError{
			Field:   "output.stdout",
			Message: fmt.Sprintf("must be at most %d characters", MaxResultStreamCharacters),
		}
	}
	if utf8.RuneCountInString(r.Output.Stderr) > MaxResultStreamCharacters {
		return &ValidationError{
			Field:   "output.stderr",
			Message: fmt.Sprintf("must be at most %d characters", MaxResultStreamCharacters),
		}
	}
	if utf8.RuneCountInString(r.Error) > MaxResultErrorCharacters {
		return &ValidationError{
			Field:   "error",
			Message: fmt.Sprintf("must be at most %d characters", MaxResultErrorCharacters),
		}
	}
	if r.ExitCode != nil &&
		(*r.ExitCode < MinResultExitCode || *r.ExitCode > MaxResultExitCode) {
		return &ValidationError{
			Field:   "exit_code",
			Message: fmt.Sprintf("must be between %d and %d", MinResultExitCode, MaxResultExitCode),
		}
	}
	switch r.Outcome {
	case OutcomeCompleted:
		if r.ExitCode == nil || *r.ExitCode != 0 {
			return &ValidationError{Field: "exit_code", Message: "must be 0 for a completed shell task"}
		}
		if r.errorPresent || r.Error != "" {
			return &ValidationError{Field: "error", Message: "must be omitted for a completed shell task"}
		}
	case OutcomeFailed:
		if strings.TrimSpace(r.Error) == "" {
			return &ValidationError{Field: "error", Message: "is required for a failed shell task"}
		}
	}
	return nil
}

func canTransition(from, to Status) bool {
	switch from {
	case StatusQueued:
		return to == StatusDispatched || to == StatusCancelled || to == StatusExpired
	case StatusDispatched:
		return to == StatusRunning || to == StatusExpired
	case StatusRunning:
		return to == StatusCompleted || to == StatusFailed
	default:
		return false
	}
}

func decodeStrictBytes(data []byte, destination interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("must contain exactly one JSON value")
		}
		return err
	}
	return nil
}
