package tasks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGoldenContractExamplesRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		new      func() interface{}
		validate func(interface{}) error
		required []string
	}{
		{
			name: "create request",
			file: "task-create-request-v1.json",
			new:  func() interface{} { return &CreateRequest{} },
			validate: func(value interface{}) error {
				return value.(*CreateRequest).validate()
			},
			required: []string{"schema_version", "type", "arguments", "timeout_seconds", "expires_in_seconds"},
		},
		{
			name:     "queued task",
			file:     "task-v1.json",
			new:      func() interface{} { return &Task{} },
			required: []string{"schema_version", "id", "agent_id", "type", "arguments", "timeout_seconds", "status", "created_at", "queued_at", "expires_at"},
		},
		{
			name:     "dispatched task",
			file:     "task-dispatched-v1.json",
			new:      func() interface{} { return &Task{} },
			required: []string{"schema_version", "id", "agent_id", "type", "arguments", "timeout_seconds", "status", "created_at", "queued_at", "dispatched_at", "expires_at"},
		},
		{
			name: "completed result",
			file: "task-result-v1.json",
			new:  func() interface{} { return &Result{} },
			validate: func(value interface{}) error {
				result := value.(*Result)
				return result.validate(result.AgentID)
			},
			required: []string{"schema_version", "task_id", "agent_id", "outcome", "started_at", "completed_at", "exit_code", "output"},
		},
		{
			name: "failed result",
			file: "task-result-failed-v1.json",
			new:  func() interface{} { return &Result{} },
			validate: func(value interface{}) error {
				result := value.(*Result)
				return result.validate(result.AgentID)
			},
			required: []string{"schema_version", "task_id", "agent_id", "outcome", "started_at", "completed_at", "exit_code", "output", "error"},
		},
		{
			name: "status update",
			file: "task-status-update-v1.json",
			new:  func() interface{} { return &StatusUpdate{} },
			validate: func(value interface{}) error {
				update := value.(*StatusUpdate)
				return update.validate(update.AgentID, update.TaskID)
			},
			required: []string{"schema_version", "task_id", "agent_id", "status", "timestamp"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join("..", "..", "..", "docs", "schemas", "examples", tt.file)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden example: %v", err)
			}
			value := tt.new()
			if err := json.Unmarshal(data, value); err != nil {
				t.Fatalf("decode golden example: %v", err)
			}
			if tt.validate != nil {
				if err := tt.validate(value); err != nil {
					t.Fatalf("validate golden example: %v", err)
				}
			}
			roundTrip, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("encode golden example: %v", err)
			}
			var fields map[string]interface{}
			if err := json.Unmarshal(roundTrip, &fields); err != nil {
				t.Fatalf("decode round trip: %v", err)
			}
			for _, required := range tt.required {
				if _, ok := fields[required]; !ok {
					t.Fatalf("round trip omitted required field %q: %s", required, roundTrip)
				}
			}
		})
	}
}

func TestResultJSONRequiresCompleteOutputObject(t *testing.T) {
	tests := []string{
		`{"schema_version":1,"task_id":"task-one","agent_id":"agent-one","outcome":"completed","started_at":"2026-07-23T16:30:05Z","completed_at":"2026-07-23T16:30:06Z"}`,
		`{"schema_version":1,"task_id":"task-one","agent_id":"agent-one","outcome":"completed","started_at":"2026-07-23T16:30:05Z","completed_at":"2026-07-23T16:30:06Z","output":{"stderr":""}}`,
		`{"schema_version":1,"task_id":"task-one","agent_id":"agent-one","outcome":"completed","started_at":"2026-07-23T16:30:05Z","completed_at":"2026-07-23T16:30:06Z","output":{"stdout":""}}`,
		`{"schema_version":1,"task_id":"task-one","agent_id":"agent-one","outcome":"completed","started_at":"2026-07-23T16:30:05Z","completed_at":"2026-07-23T16:30:06Z","output":{"stdout":"","stderr":"","extra":true}}`,
	}
	for _, input := range tests {
		var result Result
		if err := json.Unmarshal([]byte(input), &result); err == nil {
			t.Fatalf("expected invalid result JSON to fail: %s", input)
		}
	}
}

func TestCompletedResultRejectsExplicitEmptyError(t *testing.T) {
	const withoutError = `{"schema_version":1,"task_id":"task-one","agent_id":"agent-one","outcome":"completed","started_at":"2026-07-23T16:30:05Z","completed_at":"2026-07-23T16:30:06Z","exit_code":0,"output":{"stdout":"","stderr":""}}`
	const withEmptyError = `{"schema_version":1,"task_id":"task-one","agent_id":"agent-one","outcome":"completed","started_at":"2026-07-23T16:30:05Z","completed_at":"2026-07-23T16:30:06Z","exit_code":0,"output":{"stdout":"","stderr":""},"error":""}`

	var omitted Result
	if err := json.Unmarshal([]byte(withoutError), &omitted); err != nil {
		t.Fatalf("decode completed result without error: %v", err)
	}
	if err := omitted.validate(omitted.AgentID); err != nil {
		t.Fatalf("completed result with omitted error must be valid: %v", err)
	}

	var explicit Result
	if err := json.Unmarshal([]byte(withEmptyError), &explicit); err != nil {
		t.Fatalf("decode completed result with explicit empty error: %v", err)
	}
	if !explicit.errorPresent {
		t.Fatal("completed result did not retain explicit error-field presence")
	}
	if err := explicit.validate(explicit.AgentID); !IsValidationError(err) {
		t.Fatalf("completed result with explicit empty error must be rejected, got %v", err)
	}
}

func TestResultValidationEnforcesOutcomeCoherenceAndCharacterLimits(t *testing.T) {
	startedAt := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(time.Second)
	zero := 0
	one := 1
	valid := Result{
		SchemaVersion: SchemaVersion,
		TaskID:        "task-one",
		AgentID:       "agent-one",
		Outcome:       OutcomeCompleted,
		StartedAt:     startedAt,
		CompletedAt:   completedAt,
		ExitCode:      &zero,
		Output:        Output{},
	}
	if err := valid.validate("agent-one"); err != nil {
		t.Fatalf("valid completed result: %v", err)
	}

	tests := []Result{
		{Outcome: OutcomeCompleted, ExitCode: nil, Error: "", Output: Output{}},
		{Outcome: OutcomeCompleted, ExitCode: &one, Error: "", Output: Output{}},
		{Outcome: OutcomeCompleted, ExitCode: &zero, Error: "unexpected", Output: Output{}},
		{Outcome: OutcomeFailed, ExitCode: nil, Error: " ", Output: Output{}},
	}
	for i, changes := range tests {
		candidate := valid
		candidate.Outcome = changes.Outcome
		candidate.ExitCode = changes.ExitCode
		candidate.Error = changes.Error
		if err := candidate.validate("agent-one"); !IsValidationError(err) {
			t.Fatalf("case %d: expected outcome coherence error, got %v", i, err)
		}
	}

	failedWithZero := valid
	failedWithZero.Outcome = OutcomeFailed
	failedWithZero.ExitCode = &zero
	failedWithZero.Error = "capture failed"
	if err := failedWithZero.validate("agent-one"); err != nil {
		t.Fatalf("failed result may retain exit code zero for capture failures: %v", err)
	}
	for _, boundary := range []int{MinResultExitCode, MaxResultExitCode} {
		candidate := failedWithZero
		candidate.ExitCode = &boundary
		if err := candidate.validate("agent-one"); err != nil {
			t.Fatalf("boundary exit code %d must be valid: %v", boundary, err)
		}
	}
	for _, outside := range []int{MinResultExitCode - 1, MaxResultExitCode + 1} {
		candidate := failedWithZero
		candidate.ExitCode = &outside
		if err := candidate.validate("agent-one"); !IsValidationError(err) {
			t.Fatalf("out-of-range exit code %d must be rejected, got %v", outside, err)
		}
	}

	oversized := valid
	oversized.Output.Stdout = strings.Repeat("界", MaxResultStreamCharacters+1)
	if err := oversized.validate("agent-one"); !IsValidationError(err) {
		t.Fatalf("expected oversized Unicode stdout error, got %v", err)
	}
	oversized = valid
	oversized.Error = strings.Repeat("界", MaxResultErrorCharacters+1)
	oversized.Outcome = OutcomeFailed
	oversized.ExitCode = nil
	if err := oversized.validate("agent-one"); !IsValidationError(err) {
		t.Fatalf("expected oversized Unicode error field rejection, got %v", err)
	}
}

func TestTaskResultBodyLimitCoversGoEscapedSchemaPayload(t *testing.T) {
	exitCode := 1
	result := Result{
		SchemaVersion: SchemaVersion,
		TaskID:        strings.Repeat("t", 128),
		AgentID:       strings.Repeat("a", 128),
		Outcome:       OutcomeFailed,
		StartedAt:     time.Date(2026, 7, 23, 16, 30, 5, 0, time.UTC),
		CompletedAt:   time.Date(2026, 7, 23, 16, 30, 6, 0, time.UTC),
		ExitCode:      &exitCode,
		Output: Output{
			Stdout: strings.Repeat("\x00", MaxResultStreamCharacters),
			Stderr: strings.Repeat("\x00", MaxResultStreamCharacters),
		},
		Error: strings.Repeat("\x00", MaxResultErrorCharacters),
	}
	if err := result.validate(result.AgentID); err != nil {
		t.Fatalf("worst-case result must remain contract-valid: %v", err)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal worst-case result: %v", err)
	}
	if len(encoded) > MaxTaskResultBodyBytes {
		t.Fatalf(
			"schema-valid result encodes to %d bytes, above body cap %d",
			len(encoded),
			MaxTaskResultBodyBytes,
		)
	}
}

func TestIdentifierValidationUsesCanonicalASCIIAlphabet(t *testing.T) {
	for _, valid := range []string{"agent-AZ_09.:value", "task-one"} {
		if err := ValidateIdentifier("id", valid); err != nil {
			t.Fatalf("canonical identifier %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{"agent/one", "agént", "agent one", "agent\none"} {
		if err := ValidateIdentifier("id", invalid); !IsValidationError(err) {
			t.Fatalf("non-canonical identifier %q accepted", invalid)
		}
	}
}

func TestV1ContractConformanceVectors(t *testing.T) {
	corpusPath := filepath.Join("..", "..", "..", "docs", "schemas", "contract-vectors-v1.json")
	data, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read contract vectors corpus: %v", err)
	}

	type vectorEntry struct {
		ID           string          `json:"id"`
		SchemaTarget string          `json:"schema_target"`
		Expected     string          `json:"expected"`
		Value        json.RawMessage `json:"value"`
	}
	var raw struct {
		SchemaVersion int           `json:"schema_version"`
		Vectors       []vectorEntry `json:"vectors"`
	}
	if err := decodeStrictBytes(data, &raw); err != nil {
		t.Fatalf("decode contract vectors corpus: %v", err)
	}

	if raw.SchemaVersion != 1 {
		t.Fatalf("corpus schema_version must be 1, got %d", raw.SchemaVersion)
	}
	if len(raw.Vectors) == 0 {
		t.Fatal("corpus vectors must be nonempty")
	}

	seen := make(map[string]bool)
	for _, v := range raw.Vectors {
		if v.ID == "" {
			t.Fatal("vector id must be nonempty")
		}
		if seen[v.ID] {
			t.Fatalf("duplicate vector id %q", v.ID)
		}
		seen[v.ID] = true

		switch v.SchemaTarget {
		case "task-result-v1.schema.json", "task-status-update-v1.schema.json":
		default:
			t.Fatalf("unknown schema_target %q in vector %q", v.SchemaTarget, v.ID)
		}

		switch v.Expected {
		case "accept", "reject":
		default:
			t.Fatalf("invalid expected value %q in vector %q", v.Expected, v.ID)
		}

		if len(v.Value) == 0 || !json.Valid(v.Value) {
			t.Fatalf("vector %q has missing or invalid JSON value", v.ID)
		}
	}

	for _, v := range raw.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			var accepted bool
			switch v.SchemaTarget {
			case "task-result-v1.schema.json":
				var result Result
				if err := json.Unmarshal(v.Value, &result); err != nil {
					accepted = false
				} else {
					err := result.validate(result.AgentID)
					accepted = err == nil
				}
			case "task-status-update-v1.schema.json":
				var update StatusUpdate
				if err := decodeStrictBytes(v.Value, &update); err != nil {
					accepted = false
				} else {
					err := update.validate(update.AgentID, update.TaskID)
					accepted = err == nil
				}
			}
			wantAccept := v.Expected == "accept"
			if accepted != wantAccept {
				t.Fatalf("vector %q target %s: expected accepted=%v, got accepted=%v", v.ID, v.SchemaTarget, wantAccept, accepted)
			}
		})
	}
}
