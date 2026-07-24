package enrollment

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"microc2/server/internal/persistence"
)

type testEnvironment struct {
	database *persistence.Database
	store    *Store
}

func newTestEnvironment(t *testing.T) *testEnvironment {
	t.Helper()
	return openTestEnvironment(t, filepath.Join(t.TempDir(), "microc2.db"))
}

func openTestEnvironment(t *testing.T, path string) *testEnvironment {
	t.Helper()
	database, err := persistence.Open(path)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	store, err := NewStore(context.Background(), database)
	if err != nil {
		_ = database.Close()
		t.Fatalf("create enrollment store: %v", err)
	}
	var tick atomic.Int64
	store.now = func() time.Time {
		return time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC).
			Add(time.Duration(tick.Add(1)) * time.Nanosecond)
	}
	t.Cleanup(func() {
		_ = database.Close()
	})
	return &testEnvironment{database: database, store: store}
}

func (environment *testEnvironment) insertListener(t *testing.T, listenerID string) {
	t.Helper()
	now := "2026-07-24T12:00:00Z"
	config := []byte(`{"protocol":"http"}`)
	sum := sha256.Sum256(config)
	if _, err := environment.database.SQL().Exec(
		`INSERT INTO listeners (
			id, name, config_json, config_sha256, status, last_error,
			created_at, updated_at, deleted_at
		) VALUES (?, ?, ?, ?, 'STOPPED', '', ?, ?, NULL)`,
		listenerID,
		"listener-"+listenerID,
		config,
		fmt.Sprintf("%x", sum),
		now,
		now,
	); err != nil {
		t.Fatalf("insert listener %q: %v", listenerID, err)
	}
}

func (environment *testEnvironment) insertBuild(
	t *testing.T,
	buildID string,
	listenerID string,
	state string,
) {
	t.Helper()
	if _, err := environment.database.SQL().Exec(
		`INSERT INTO payload_builds (
			id, payload_id, listener_id, mutation_seed, filename,
			relative_path, size, sha256, created_at, state,
			state_detail, provenance_json
		) VALUES (?, ?, ?, '', ?, ?, 0, '', ?, ?, '', '{}')`,
		buildID,
		"payload-"+buildID,
		listenerID,
		buildID+".bin",
		"payloads/"+buildID+".bin",
		"2026-07-24T12:00:00Z",
		state,
	); err != nil {
		t.Fatalf("insert payload build %q: %v", buildID, err)
	}
}

func (environment *testEnvironment) setBuildState(
	t *testing.T,
	buildID string,
	state string,
) {
	t.Helper()
	if _, err := environment.database.SQL().Exec(
		`UPDATE payload_builds SET state = ? WHERE id = ?`,
		state,
		buildID,
	); err != nil {
		t.Fatalf("set payload build %q state: %v", buildID, err)
	}
}

func (environment *testEnvironment) readyBuild(
	t *testing.T,
	buildID string,
	listenerID string,
	maxSessions int,
) BootstrapCredential {
	t.Helper()
	environment.insertBuild(t, buildID, listenerID, "building")
	bootstrap, err := GenerateBootstrapCredential()
	if err != nil {
		t.Fatalf("generate bootstrap credential: %v", err)
	}
	if err := environment.store.ActivatePayloadCredential(
		context.Background(),
		PayloadCredentialActivation{
			PayloadBuildID:  buildID,
			ListenerID:      listenerID,
			BootstrapSHA256: bootstrap.SHA256,
			MaxSessions:     maxSessions,
		},
	); err != nil {
		t.Fatalf("activate payload credential: %v", err)
	}
	environment.setBuildState(t, buildID, "completed")
	return bootstrap
}

func (environment *testEnvironment) enroll(
	t *testing.T,
	listenerID string,
	agentID string,
	buildID string,
	bootstrap string,
) Enrollment {
	t.Helper()
	enrollment, err := environment.store.Enroll(
		context.Background(),
		EnrollRequest{
			ListenerID:     listenerID,
			AgentID:        agentID,
			PayloadBuildID: buildID,
			Bootstrap:      bootstrap,
		},
	)
	if err != nil {
		t.Fatalf("enroll agent %q: %v", agentID, err)
	}
	return enrollment
}

func assertUnauthorized(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("error = %v, want ErrUnauthorized", err)
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(err.Error(), secret) {
			t.Fatal("authentication error leaked credential material")
		}
	}
}

func countRows(t *testing.T, database *sql.DB, query string, args ...any) int {
	t.Helper()
	var count int
	if err := database.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatalf("count durable rows: %v", err)
	}
	return count
}
