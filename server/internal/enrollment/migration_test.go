package enrollment

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestEnrollmentMigrationKeepsRawCredentialsOutOfSQLite(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	bootstrap := environment.readyBuild(t, "build-one", "listener-one", 1)
	enrolled := environment.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)

	var storedHash []byte
	if err := environment.database.SQL().QueryRow(
		`SELECT bootstrap_sha256
		 FROM payload_bootstrap_credentials
		 WHERE payload_build_id = 'build-one'`,
	).Scan(&storedHash); err != nil {
		t.Fatalf("read stored bootstrap hash: %v", err)
	}
	if len(storedHash) != sha256.Size ||
		string(storedHash) == bootstrap.Public ||
		!constantBytesEqual(storedHash, bootstrap.SHA256[:]) {
		t.Fatal("database did not contain only the expected fixed-size bootstrap hash")
	}

	var (
		sessionID  []byte
		generation int64
	)
	if err := environment.database.SQL().QueryRow(
		`SELECT session_id, current_generation
		 FROM agent_enrollment_sessions
		 WHERE listener_id = 'listener-one' AND agent_id = 'agent-one'`,
	).Scan(&sessionID, &generation); err != nil {
		t.Fatalf("read stored session material: %v", err)
	}
	if len(sessionID) != SessionIDBytes ||
		generation != 1 ||
		strings.Contains(string(sessionID), enrolled.Credential) {
		t.Fatal("database stored a raw session credential")
	}

	var allocatedAt string
	if err := environment.database.SQL().QueryRow(
		`SELECT allocated_at
		 FROM payload_enrollment_allocations
		 WHERE payload_build_id = 'build-one'
		   AND listener_id = 'listener-one'
		   AND agent_id = 'agent-one'`,
	).Scan(&allocatedAt); err != nil {
		t.Fatalf("read monotonic payload enrollment allocation: %v", err)
	}
	if allocatedAt == "" {
		t.Fatal("payload enrollment allocation omitted its timestamp")
	}
	if _, err := environment.database.SQL().Exec(
		`UPDATE payload_enrollment_allocations
		 SET agent_id = 'agent-two'
		 WHERE payload_build_id = 'build-one'
		   AND listener_id = 'listener-one'
		   AND agent_id = 'agent-one'`,
	); err == nil {
		t.Fatal("payload enrollment allocation unexpectedly mutated")
	}
	if _, err := environment.database.SQL().Exec(
		`DELETE FROM payload_enrollment_allocations
		 WHERE payload_build_id = 'build-one'
		   AND listener_id = 'listener-one'
		   AND agent_id = 'agent-one'`,
	); err == nil {
		t.Fatal("payload enrollment allocation unexpectedly deleted")
	}
}

func TestEnrollmentMigrationEnforcesSingletonKeyAndImmutableActivation(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	bootstrap := environment.readyBuild(t, "build-one", "listener-one", 3)

	var key []byte
	if err := environment.database.SQL().QueryRow(
		`SELECT hmac_key FROM enrollment_server_keys WHERE singleton = 1`,
	).Scan(&key); err != nil {
		t.Fatalf("read singleton key: %v", err)
	}
	if len(key) != sha256.Size {
		t.Fatalf("server key bytes = %d, want %d", len(key), sha256.Size)
	}
	if _, err := environment.database.SQL().Exec(
		`INSERT INTO enrollment_server_keys (singleton, hmac_key, created_at)
		 VALUES (2, ?, '2026-07-24T12:00:00Z')`,
		make([]byte, sha256.Size),
	); err == nil {
		t.Fatal("second server key unexpectedly inserted")
	}
	if _, err := environment.database.SQL().Exec(
		`UPDATE enrollment_server_keys SET hmac_key = ? WHERE singleton = 1`,
		make([]byte, sha256.Size),
	); err == nil {
		t.Fatal("server key unexpectedly mutated")
	}
	if _, err := environment.database.SQL().Exec(
		`DELETE FROM enrollment_server_keys WHERE singleton = 1`,
	); err == nil {
		t.Fatal("server key unexpectedly deleted")
	}

	if _, err := environment.database.SQL().Exec(
		`UPDATE payload_bootstrap_credentials
		 SET max_sessions = 4
		 WHERE payload_build_id = 'build-one'`,
	); err == nil {
		t.Fatal("immutable payload allowance unexpectedly changed")
	}
	if _, err := environment.database.SQL().Exec(
		`UPDATE payload_bootstrap_credentials
		 SET bootstrap_sha256 = ?
		 WHERE payload_build_id = 'build-one'`,
		bootstrap.SHA256[:],
	); err == nil {
		t.Fatal("immutable bootstrap hash unexpectedly accepted an update")
	}
}

func TestActivationIsIdempotentOnlyForExactLiveRecord(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	environment.insertBuild(t, "build-one", "listener-one", "building")
	bootstrap, err := GenerateBootstrapCredential()
	if err != nil {
		t.Fatalf("generate bootstrap: %v", err)
	}
	activation := PayloadCredentialActivation{
		PayloadBuildID:  "build-one",
		ListenerID:      "listener-one",
		BootstrapSHA256: bootstrap.SHA256,
		MaxSessions:     2,
	}
	if err := environment.store.ActivatePayloadCredential(
		context.Background(),
		activation,
	); err != nil {
		t.Fatalf("activate credential: %v", err)
	}
	if err := environment.store.ActivatePayloadCredential(
		context.Background(),
		activation,
	); err != nil {
		t.Fatalf("repeat exact activation: %v", err)
	}
	activation.MaxSessions = 3
	if err := environment.store.ActivatePayloadCredential(
		context.Background(),
		activation,
	); err != ErrConflict {
		t.Fatalf("changed activation error = %v, want ErrConflict", err)
	}
}

func TestEnrollmentMigrationEnforcesSessionChecksBindingsAndIndexes(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	environment.insertListener(t, "listener-two")
	firstBootstrap := environment.readyBuild(t, "build-one", "listener-one", 1)
	environment.readyBuild(t, "build-two", "listener-two", 1)
	environment.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-one",
		firstBootstrap.Public,
	)

	for name, statement := range map[string]string{
		"nonconsecutive pending generation": `
			UPDATE agent_enrollment_sessions
			SET pending_generation = current_generation + 2
			WHERE listener_id = 'listener-one' AND agent_id = 'agent-one'`,
		"short session identifier": `
			UPDATE agent_enrollment_sessions
			SET session_id = X'01'
			WHERE listener_id = 'listener-one' AND agent_id = 'agent-one'`,
		"empty confirmation timestamp": `
			UPDATE agent_enrollment_sessions
			SET session_confirmed_at = ''
			WHERE listener_id = 'listener-one' AND agent_id = 'agent-one'`,
		"cross-listener payload binding": `
			UPDATE agent_enrollment_sessions
			SET payload_build_id = 'build-two'
			WHERE listener_id = 'listener-one' AND agent_id = 'agent-one'`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := environment.database.SQL().Exec(statement); err == nil {
				t.Fatal("invalid durable session mutation unexpectedly succeeded")
			}
		})
	}

	for _, index := range []string{
		"idx_agents_agent_id",
		"idx_agent_enrollment_listener_active",
		"idx_agent_enrollment_build_active",
	} {
		if got := countRows(
			t,
			environment.database.SQL(),
			`SELECT COUNT(*)
			 FROM sqlite_master
			 WHERE type = 'index' AND name = ?`,
			index,
		); got != 1 {
			t.Fatalf("required index %q count = %d, want 1", index, got)
		}
	}
}
