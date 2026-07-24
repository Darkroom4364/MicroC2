package audit

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"microc2/server/internal/persistence"
)

func TestStoreAppendResolvesContextActorAndPersistsClosedFields(t *testing.T) {
	fixedNow := time.Date(
		2026,
		time.July,
		24,
		14,
		30,
		0,
		123456789,
		time.FixedZone("test", 2*60*60),
	)
	database, store := newAuditTestStore(t, fixedNow)
	defer database.Close()

	actor := Actor{Kind: ActorOperator, ID: "local-loopback"}
	ctx := WithActor(context.Background(), actor)
	root, err := store.Append(ctx, Input{
		Action:     "task.queued",
		Route:      "/api/agents/{agent_id}/tasks",
		Target:     Target{Kind: "task", ID: "task-one"},
		Outcome:    OutcomeSucceeded,
		ReasonCode: "operator_request",
		ListenerID: "listener-one",
		AgentID:    "agent-one",
		TaskID:     "task-one",
	})
	if err != nil {
		t.Fatalf("append root event: %v", err)
	}
	if root.Sequence != 1 || root.SchemaVersion != SchemaVersion {
		t.Fatalf("root identity = (%d, %d), want (1, %d)", root.Sequence, root.SchemaVersion, SchemaVersion)
	}
	if root.Actor != actor {
		t.Fatalf("root actor = %#v, want %#v", root.Actor, actor)
	}
	wantTime := fixedNow.UTC()
	if !root.OccurredAt.Equal(wantTime) || root.OccurredAt.Location() != time.UTC {
		t.Fatalf("root occurred_at = %s, want UTC %s", root.OccurredAt, wantTime)
	}

	child, err := store.Append(ctx, Input{
		Actor:             actor,
		Action:            "task.result_received",
		Route:             "/api/agent/{agent_id}/results",
		Target:            Target{Kind: "task", ID: "task-one"},
		Outcome:           OutcomeFailed,
		ReasonCode:        "agent_reported_failure",
		CausationSequence: &root.Sequence,
		ListenerID:        "listener-one",
		AgentID:           "agent-one",
		TaskID:            "task-one",
		PayloadBuildID:    "payload-one",
		FileName:          "artifact.bin",
		TerminalSessionID: "terminal-one",
	})
	if err != nil {
		t.Fatalf("append causal event: %v", err)
	}

	page, err := store.Page(context.Background(), PageOptions{Limit: 10})
	if err != nil {
		t.Fatalf("page events: %v", err)
	}
	if page.SchemaVersion != SchemaVersion ||
		page.Total != 2 ||
		len(page.Events) != 2 ||
		page.NextOffset != nil {
		t.Fatalf("unexpected page envelope: %#v", page)
	}
	got := page.Events[0]
	if got.Sequence != child.Sequence ||
		got.Actor != actor ||
		got.Action != "task.result_received" ||
		got.Route != "/api/agent/{agent_id}/results" ||
		got.Target != (Target{Kind: "task", ID: "task-one"}) ||
		got.Outcome != OutcomeFailed ||
		got.ReasonCode != "agent_reported_failure" ||
		got.CausationSequence == nil ||
		*got.CausationSequence != root.Sequence ||
		got.ListenerID != "listener-one" ||
		got.AgentID != "agent-one" ||
		got.TaskID != "task-one" ||
		got.PayloadBuildID != "payload-one" ||
		got.FileName != "artifact.bin" ||
		got.TerminalSessionID != "terminal-one" {
		t.Fatalf("persisted event did not round-trip: %#v", got)
	}
}

func TestStoreRejectsActorSpoofingAndMissingActor(t *testing.T) {
	database, store := newAuditTestStore(t, time.Now())
	defer database.Close()

	contextActor := Actor{Kind: ActorOperator, ID: "shared-token"}
	input := validAuditInput()
	input.Actor = Actor{Kind: ActorSystem, ID: "microc2-server"}
	if _, err := store.Append(
		WithActor(context.Background(), contextActor),
		input,
	); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("mismatched explicit/context actor error = %v, want ErrInvalidEvent", err)
	}

	input.Actor = Actor{}
	if _, err := store.Append(context.Background(), input); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("missing actor error = %v, want ErrInvalidEvent", err)
	}
	assertAuditCount(t, database, 0)
}

func TestStoreAppendTxRollsBackWithCallerTransaction(t *testing.T) {
	database, store := newAuditTestStore(t, time.Now())
	defer database.Close()

	tx, err := database.SQL().BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin caller transaction: %v", err)
	}
	event, err := store.AppendTx(context.Background(), tx, validAuditInput())
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("append in caller transaction: %v", err)
	}
	if event.Sequence < 1 {
		_ = tx.Rollback()
		t.Fatalf("transactional event sequence = %d, want positive", event.Sequence)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback caller transaction: %v", err)
	}
	assertAuditCount(t, database, 0)
}

func TestStoreEventsSurviveDatabaseRestart(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "microc2.db")
	database, err := persistence.Open(databasePath)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	store, err := NewStore(database)
	if err != nil {
		t.Fatalf("construct store: %v", err)
	}
	written, err := store.Append(context.Background(), validAuditInput())
	if err != nil {
		t.Fatalf("append before restart: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	reopened, err := persistence.Open(databasePath)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer reopened.Close()
	restartedStore, err := NewStore(reopened)
	if err != nil {
		t.Fatalf("construct restarted store: %v", err)
	}
	page, err := restartedStore.Page(context.Background(), PageOptions{Limit: 10})
	if err != nil {
		t.Fatalf("page after restart: %v", err)
	}
	if page.Total != 1 ||
		len(page.Events) != 1 ||
		page.Events[0].Sequence != written.Sequence ||
		page.Events[0].Action != written.Action {
		t.Fatalf("restarted page = %#v, want written event %#v", page, written)
	}
}

func TestStorePageIsNewestFirstAndStableAcrossOffsets(t *testing.T) {
	database, store := newAuditTestStore(
		t,
		time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC),
	)
	defer database.Close()

	for index := 1; index <= 5; index++ {
		input := validAuditInput()
		input.Action = "audit.test." + strconv.Itoa(index)
		input.Target.ID = "event-" + strconv.Itoa(index)
		if _, err := store.Append(context.Background(), input); err != nil {
			t.Fatalf("append event %d: %v", index, err)
		}
	}

	first, err := store.Page(
		context.Background(),
		PageOptions{Limit: 2, Offset: 0},
	)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if first.Total != 5 ||
		len(first.Events) != 2 ||
		first.Events[0].Sequence != 5 ||
		first.Events[1].Sequence != 4 ||
		first.NextOffset == nil ||
		*first.NextOffset != 2 {
		t.Fatalf("unexpected first page: %#v", first)
	}

	second, err := store.Page(
		context.Background(),
		PageOptions{Limit: 2, Offset: *first.NextOffset},
	)
	if err != nil {
		t.Fatalf("second page: %v", err)
	}
	if second.Total != 5 ||
		len(second.Events) != 2 ||
		second.Events[0].Sequence != 3 ||
		second.Events[1].Sequence != 2 ||
		second.NextOffset == nil ||
		*second.NextOffset != 4 {
		t.Fatalf("unexpected second page: %#v", second)
	}

	last, err := store.Page(
		context.Background(),
		PageOptions{Limit: 2, Offset: *second.NextOffset},
	)
	if err != nil {
		t.Fatalf("last page: %v", err)
	}
	if len(last.Events) != 1 ||
		last.Events[0].Sequence != 1 ||
		last.NextOffset != nil {
		t.Fatalf("unexpected last page: %#v", last)
	}
}

func TestStoreValidatesClosedRedactedContract(t *testing.T) {
	database, store := newAuditTestStore(t, time.Now())
	defer database.Close()

	zero := int64(0)
	tests := []struct {
		name   string
		mutate func(*Input)
	}{
		{
			name: "actor kind",
			mutate: func(input *Input) {
				input.Actor.Kind = ActorKind("guest")
			},
		},
		{
			name: "actor id",
			mutate: func(input *Input) {
				input.Actor.ID = ""
			},
		},
		{
			name: "dynamic action",
			mutate: func(input *Input) {
				input.Action = "Task Queued"
			},
		},
		{
			name: "route control character",
			mutate: func(input *Input) {
				input.Route = "/api/tasks\nX-Secret: value"
			},
		},
		{
			name: "target kind",
			mutate: func(input *Input) {
				input.Target.Kind = ""
			},
		},
		{
			name: "target id",
			mutate: func(input *Input) {
				input.Target.ID = ""
			},
		},
		{
			name: "outcome",
			mutate: func(input *Input) {
				input.Outcome = Outcome("maybe")
			},
		},
		{
			name: "freeform reason",
			mutate: func(input *Input) {
				input.ReasonCode = "raw error text"
			},
		},
		{
			name: "causation sequence",
			mutate: func(input *Input) {
				input.CausationSequence = &zero
			},
		},
		{
			name: "object control character",
			mutate: func(input *Input) {
				input.FileName = "secret\nname"
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			input := validAuditInput()
			testCase.mutate(&input)
			if _, err := store.Append(
				context.Background(),
				input,
			); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("Append error = %v, want ErrInvalidEvent", err)
			}
		})
	}
	assertAuditCount(t, database, 0)

	for _, value := range []interface{}{Input{}, Event{}} {
		valueType := reflect.TypeOf(value)
		for index := 0; index < valueType.NumField(); index++ {
			name := strings.ToLower(valueType.Field(index).Name)
			for _, forbidden := range []string{
				"body",
				"command",
				"details",
				"error",
				"metadata",
				"output",
				"secret",
				"token",
			} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s unexpectedly exposes freeform/sensitive field %q", valueType.Name(), name)
				}
			}
		}
	}

	encoded, err := json.Marshal(Event{
		SchemaVersion: SchemaVersion,
		Sequence:      1,
		OccurredAt:    time.Now().UTC(),
		Actor:         Actor{Kind: ActorSystem, ID: "microc2-server"},
		Action:        "audit.test",
		Route:         "internal:test",
		Target:        Target{Kind: "audit", ID: "test"},
		Outcome:       OutcomeSucceeded,
	})
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	for _, forbidden := range []string{
		`"details"`,
		`"error"`,
		`"metadata"`,
		`"request_body"`,
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("encoded event exposes forbidden field %s: %s", forbidden, encoded)
		}
	}
}

func TestStoreRejectsInvalidPagesAndDanglingCausation(t *testing.T) {
	database, store := newAuditTestStore(t, time.Now())
	defer database.Close()

	for _, options := range []PageOptions{
		{Limit: 0},
		{Limit: -1},
		{Limit: MaxPageLimit + 1},
		{Limit: 1, Offset: -1},
		{Limit: 1, Offset: MaxPageOffset + 1},
	} {
		if _, err := store.Page(context.Background(), options); err == nil {
			t.Fatalf("invalid page %#v unexpectedly succeeded", options)
		}
	}

	missing := int64(999)
	input := validAuditInput()
	input.CausationSequence = &missing
	if _, err := store.Append(context.Background(), input); err == nil {
		t.Fatal("dangling causation unexpectedly inserted")
	}
	assertAuditCount(t, database, 0)
}

func TestActorContextHelpersRejectUnsupportedActors(t *testing.T) {
	actor := Actor{Kind: ActorAgent, ID: "agent-one"}
	ctx := WithActor(context.Background(), actor)
	if got, ok := ActorFromContext(ctx); !ok || got != actor {
		t.Fatalf("ActorFromContext = (%#v, %t), want (%#v, true)", got, ok, actor)
	}
	if got := ActorOr(ctx, DefaultSystemActor()); got != actor {
		t.Fatalf("ActorOr = %#v, want contextual actor %#v", got, actor)
	}
	if _, ok := ActorFromContext(WithActor(
		context.Background(),
		Actor{Kind: ActorKind("guest"), ID: "guest"},
	)); ok {
		t.Fatal("unsupported contextual actor unexpectedly accepted")
	}
	if got := ActorOr(context.Background(), DefaultOperatorActor()); got != DefaultOperatorActor() {
		t.Fatalf("ActorOr fallback = %#v, want %#v", got, DefaultOperatorActor())
	}
}

func newAuditTestStore(
	t *testing.T,
	now time.Time,
) (*persistence.Database, *Store) {
	t.Helper()
	database, err := persistence.Open(filepath.Join(t.TempDir(), "microc2.db"))
	if err != nil {
		t.Fatalf("open audit test database: %v", err)
	}
	store, err := newStoreWithClock(database, func() time.Time { return now })
	if err != nil {
		_ = database.Close()
		t.Fatalf("construct audit test store: %v", err)
	}
	return database, store
}

func validAuditInput() Input {
	return Input{
		Actor:   Actor{Kind: ActorSystem, ID: "microc2-server"},
		Action:  "audit.test",
		Route:   "internal:test",
		Target:  Target{Kind: "audit", ID: "test"},
		Outcome: OutcomeSucceeded,
	}
}

func assertAuditCount(
	t *testing.T,
	database *persistence.Database,
	want int,
) {
	t.Helper()
	var got int
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*) FROM audit_events`,
	).Scan(&got); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if got != want {
		t.Fatalf("audit event count = %d, want %d", got, want)
	}
}
