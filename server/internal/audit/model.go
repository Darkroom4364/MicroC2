package audit

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const (
	// SchemaVersion is the only structured audit contract currently exposed.
	SchemaVersion = 1

	MaxPageLimit     = 500
	MaxPageOffset    = 1_000_000
	DefaultPageLimit = 50
)

type ActorKind string

const (
	ActorOperator ActorKind = "operator"
	ActorAgent    ActorKind = "agent"
	ActorSystem   ActorKind = "system"
)

type Outcome string

const (
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
	OutcomeDenied    Outcome = "denied"
	OutcomeNoop      Outcome = "noop"
)

var ErrInvalidEvent = errors.New("invalid audit event")

// Actor identifies the authenticated principal class responsible for an
// event. The current operator guard can distinguish loopback from shared-token
// access, but it cannot identify an individual human.
type Actor struct {
	Kind ActorKind `json:"kind"`
	ID   string    `json:"id"`
}

// Target identifies the primary object acted upon.
type Target struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Input is the closed, redacted set of fields accepted by the audit store.
// There is deliberately no arbitrary metadata or error-text field.
type Input struct {
	Actor             Actor
	Action            string
	Route             string
	Target            Target
	Outcome           Outcome
	ReasonCode        string
	CausationSequence *int64
	ListenerID        string
	AgentID           string
	TaskID            string
	PayloadBuildID    string
	FileName          string
	TerminalSessionID string
}

// Event is one immutable durable audit record.
type Event struct {
	SchemaVersion     int       `json:"schema_version"`
	Sequence          int64     `json:"sequence"`
	OccurredAt        time.Time `json:"occurred_at"`
	Actor             Actor     `json:"actor"`
	Action            string    `json:"action"`
	Route             string    `json:"route"`
	Target            Target    `json:"target"`
	Outcome           Outcome   `json:"outcome"`
	ReasonCode        string    `json:"reason_code,omitempty"`
	CausationSequence *int64    `json:"causation_sequence,omitempty"`
	ListenerID        string    `json:"listener_id,omitempty"`
	AgentID           string    `json:"agent_id,omitempty"`
	TaskID            string    `json:"task_id,omitempty"`
	PayloadBuildID    string    `json:"payload_build_id,omitempty"`
	FileName          string    `json:"file_name,omitempty"`
	TerminalSessionID string    `json:"terminal_session_id,omitempty"`
}

type PageOptions struct {
	Limit  int
	Offset int
}

// Page is a deterministic newest-first page. Sequence, rather than a
// caller-controlled timestamp, is the ordering authority.
type Page struct {
	SchemaVersion int     `json:"schema_version"`
	Events        []Event `json:"events"`
	Limit         int     `json:"limit"`
	Offset        int     `json:"offset"`
	Total         int     `json:"total"`
	NextOffset    *int    `json:"next_offset"`
}

func (input Input) validate() error {
	switch input.Actor.Kind {
	case ActorOperator, ActorAgent, ActorSystem:
	default:
		return invalidField("actor.kind", string(input.Actor.Kind))
	}
	if err := validateText("actor.id", input.Actor.ID, 128, false); err != nil {
		return err
	}
	if err := validateCode("action", input.Action, 128); err != nil {
		return err
	}
	if err := validateText("route", input.Route, 256, false); err != nil {
		return err
	}
	if err := validateCode("target.kind", input.Target.Kind, 64); err != nil {
		return err
	}
	if err := validateText("target.id", input.Target.ID, 255, false); err != nil {
		return err
	}
	switch input.Outcome {
	case OutcomeSucceeded, OutcomeFailed, OutcomeDenied, OutcomeNoop:
	default:
		return invalidField("outcome", string(input.Outcome))
	}
	if input.ReasonCode != "" {
		if err := validateCode("reason_code", input.ReasonCode, 64); err != nil {
			return err
		}
	}
	if input.CausationSequence != nil && *input.CausationSequence <= 0 {
		return invalidField("causation_sequence", fmt.Sprint(*input.CausationSequence))
	}
	for _, field := range []struct {
		name  string
		value string
		limit int
	}{
		{name: "listener_id", value: input.ListenerID, limit: 128},
		{name: "agent_id", value: input.AgentID, limit: 128},
		{name: "task_id", value: input.TaskID, limit: 128},
		{name: "payload_build_id", value: input.PayloadBuildID, limit: 128},
		{name: "file_name", value: input.FileName, limit: 255},
		{name: "terminal_session_id", value: input.TerminalSessionID, limit: 128},
	} {
		if field.value == "" {
			continue
		}
		if err := validateText(field.name, field.value, field.limit, true); err != nil {
			return err
		}
	}
	return nil
}

func validateCode(field, value string, limit int) error {
	if err := validateText(field, value, limit, false); err != nil {
		return err
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '.' || character == '_' ||
			character == ':' || character == '-' {
			continue
		}
		return invalidField(field, value)
	}
	return nil
}

func validateText(field, value string, limit int, optional bool) error {
	if value == "" {
		if optional {
			return nil
		}
		return invalidField(field, value)
	}
	if len(value) > limit || value != strings.TrimSpace(value) {
		return invalidField(field, value)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return invalidField(field, value)
		}
	}
	return nil
}

func invalidField(field, value string) error {
	return fmt.Errorf("%w: %s has an unsupported value %q", ErrInvalidEvent, field, value)
}
