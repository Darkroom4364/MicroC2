package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"microc2/server/internal/persistence"
)

const auditTimeLayout = time.RFC3339Nano

// Store appends and queries structured audit events in the process-wide
// durable database.
type Store struct {
	database *persistence.Database
	now      func() time.Time
}

func NewStore(database *persistence.Database) (*Store, error) {
	return newStoreWithClock(database, time.Now)
}

func newStoreWithClock(
	database *persistence.Database,
	now func() time.Time,
) (*Store, error) {
	if database == nil || database.SQL() == nil {
		return nil, errors.New("audit store requires an open database")
	}
	if now == nil {
		now = time.Now
	}
	return &Store{database: database, now: now}, nil
}

// Append records an event in its own transaction.
func (s *Store) Append(ctx context.Context, input Input) (Event, error) {
	if s == nil || s.database == nil || s.database.SQL() == nil {
		return Event{}, errors.New("audit store is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := s.database.SQL().BeginTx(ctx, nil)
	if err != nil {
		return Event{}, fmt.Errorf("begin audit append: %w", err)
	}
	defer tx.Rollback()
	event, err := s.AppendTx(ctx, tx, input)
	if err != nil {
		return Event{}, err
	}
	if err := tx.Commit(); err != nil {
		return Event{}, fmt.Errorf("commit audit append: %w", err)
	}
	return event, nil
}

// AppendTx records an event within an existing durable state transaction.
func (s *Store) AppendTx(
	ctx context.Context,
	tx *sql.Tx,
	input Input,
) (Event, error) {
	if s == nil || tx == nil {
		return Event{}, errors.New("audit transaction is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	contextActor, hasContextActor := ActorFromContext(ctx)
	switch {
	case input.Actor == (Actor{}) && hasContextActor:
		input.Actor = contextActor
	case input.Actor != (Actor{}) &&
		hasContextActor &&
		input.Actor != contextActor:
		return Event{}, fmt.Errorf(
			"%w: explicit actor does not match trusted context actor",
			ErrInvalidEvent,
		)
	}
	if err := input.validate(); err != nil {
		return Event{}, err
	}
	occurredAt := s.now().UTC().Round(0)
	result, err := tx.ExecContext(
		ctx,
		`INSERT INTO audit_events (
			schema_version, occurred_at, actor_kind, actor_id,
			action, route, target_kind, target_id, outcome, reason_code,
			causation_sequence, listener_id, agent_id, task_id,
			payload_build_id, file_name, terminal_session_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		SchemaVersion,
		occurredAt.Format(auditTimeLayout),
		string(input.Actor.Kind),
		input.Actor.ID,
		input.Action,
		input.Route,
		input.Target.Kind,
		input.Target.ID,
		string(input.Outcome),
		nullableString(input.ReasonCode),
		input.CausationSequence,
		nullableString(input.ListenerID),
		nullableString(input.AgentID),
		nullableString(input.TaskID),
		nullableString(input.PayloadBuildID),
		nullableString(input.FileName),
		nullableString(input.TerminalSessionID),
	)
	if err != nil {
		return Event{}, fmt.Errorf("insert audit event: %w", err)
	}
	sequence, err := result.LastInsertId()
	if err != nil {
		return Event{}, fmt.Errorf("read audit sequence: %w", err)
	}
	return eventFromInput(sequence, occurredAt, input), nil
}

// Page returns one consistent newest-first snapshot.
func (s *Store) Page(ctx context.Context, options PageOptions) (Page, error) {
	if s == nil || s.database == nil || s.database.SQL() == nil {
		return Page{}, errors.New("audit store is unavailable")
	}
	if options.Limit < 1 || options.Limit > MaxPageLimit {
		return Page{}, fmt.Errorf(
			"audit page limit must be between 1 and %d",
			MaxPageLimit,
		)
	}
	if options.Offset < 0 {
		return Page{}, errors.New("audit page offset must not be negative")
	}
	if options.Offset > MaxPageOffset {
		return Page{}, fmt.Errorf(
			"audit page offset must not exceed %d",
			MaxPageOffset,
		)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tx, err := s.database.SQL().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return Page{}, fmt.Errorf("begin audit page: %w", err)
	}
	defer tx.Rollback()

	var total int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM audit_events`,
	).Scan(&total); err != nil {
		return Page{}, fmt.Errorf("count audit events: %w", err)
	}
	rows, err := tx.QueryContext(
		ctx,
		`SELECT
			seq, schema_version, occurred_at, actor_kind, actor_id,
			action, route, target_kind, target_id, outcome, reason_code,
			causation_sequence, listener_id, agent_id, task_id,
			payload_build_id, file_name, terminal_session_id
		 FROM audit_events
		 ORDER BY seq DESC
		 LIMIT ? OFFSET ?`,
		options.Limit,
		options.Offset,
	)
	if err != nil {
		return Page{}, fmt.Errorf("query audit events: %w", err)
	}
	events := make([]Event, 0, options.Limit)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			_ = rows.Close()
			return Page{}, fmt.Errorf("scan audit event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return Page{}, fmt.Errorf("iterate audit events: %w", err)
	}
	if err := rows.Close(); err != nil {
		return Page{}, fmt.Errorf("close audit events: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Page{}, fmt.Errorf("commit audit page: %w", err)
	}

	var nextOffset *int
	if next := options.Offset + len(events); next < total {
		nextOffset = &next
	}
	return Page{
		SchemaVersion: SchemaVersion,
		Events:        events,
		Limit:         options.Limit,
		Offset:        options.Offset,
		Total:         total,
		NextOffset:    nextOffset,
	}, nil
}

type eventScanner interface {
	Scan(dest ...interface{}) error
}

func scanEvent(scanner eventScanner) (Event, error) {
	var event Event
	var occurredAt, actorKind, outcome string
	var reasonCode sql.NullString
	var causationSequence sql.NullInt64
	var listenerID, agentID, taskID sql.NullString
	var payloadBuildID, fileName, terminalSessionID sql.NullString
	if err := scanner.Scan(
		&event.Sequence,
		&event.SchemaVersion,
		&occurredAt,
		&actorKind,
		&event.Actor.ID,
		&event.Action,
		&event.Route,
		&event.Target.Kind,
		&event.Target.ID,
		&outcome,
		&reasonCode,
		&causationSequence,
		&listenerID,
		&agentID,
		&taskID,
		&payloadBuildID,
		&fileName,
		&terminalSessionID,
	); err != nil {
		return Event{}, err
	}
	parsedTime, err := time.Parse(auditTimeLayout, occurredAt)
	if err != nil {
		return Event{}, fmt.Errorf("parse occurred_at: %w", err)
	}
	event.OccurredAt = parsedTime
	event.Actor.Kind = ActorKind(actorKind)
	event.Outcome = Outcome(outcome)
	event.ReasonCode = reasonCode.String
	if causationSequence.Valid {
		value := causationSequence.Int64
		event.CausationSequence = &value
	}
	event.ListenerID = listenerID.String
	event.AgentID = agentID.String
	event.TaskID = taskID.String
	event.PayloadBuildID = payloadBuildID.String
	event.FileName = fileName.String
	event.TerminalSessionID = terminalSessionID.String
	return event, nil
}

func eventFromInput(sequence int64, occurredAt time.Time, input Input) Event {
	event := Event{
		SchemaVersion:     SchemaVersion,
		Sequence:          sequence,
		OccurredAt:        occurredAt,
		Actor:             input.Actor,
		Action:            input.Action,
		Route:             input.Route,
		Target:            input.Target,
		Outcome:           input.Outcome,
		ReasonCode:        input.ReasonCode,
		CausationSequence: input.CausationSequence,
		ListenerID:        input.ListenerID,
		AgentID:           input.AgentID,
		TaskID:            input.TaskID,
		PayloadBuildID:    input.PayloadBuildID,
		FileName:          input.FileName,
		TerminalSessionID: input.TerminalSessionID,
	}
	return event
}

func nullableString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}
