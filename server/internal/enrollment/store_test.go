package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

func TestEnrollResumesAfterLostResponseAndEnforcesBuildCapacity(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	bootstrap := environment.readyBuild(t, "build-one", "listener-one", 1)

	first := environment.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)
	if first.Resumed || first.Reenrolled {
		t.Fatalf("new enrollment flags = resumed:%v reenrolled:%v", first.Resumed, first.Reenrolled)
	}
	second := environment.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)
	if !second.Resumed || second.Reenrolled {
		t.Fatalf("resumed enrollment flags = resumed:%v reenrolled:%v", second.Resumed, second.Reenrolled)
	}
	if second.Credential != first.Credential ||
		second.SessionID != first.SessionID {
		t.Fatal("lost-response retry did not return the identical durable credential")
	}
	if got := countRows(
		t,
		environment.database.SQL(),
		`SELECT COUNT(*) FROM agent_enrollment_sessions`,
	); got != 1 {
		t.Fatalf("session rows = %d, want 1", got)
	}
	if _, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		second.Credential,
	); err != nil {
		t.Fatalf("confirm resumed session: %v", err)
	}
	_, err := environment.store.Enroll(
		context.Background(),
		EnrollRequest{
			ListenerID:     "listener-one",
			AgentID:        "agent-one",
			PayloadBuildID: "build-one",
			Bootstrap:      bootstrap.Public,
		},
	)
	assertUnauthorized(t, err, bootstrap.Public)

	_, err = environment.store.Enroll(
		context.Background(),
		EnrollRequest{
			ListenerID:     "listener-one",
			AgentID:        "agent-two",
			PayloadBuildID: "build-one",
			Bootstrap:      bootstrap.Public,
		},
	)
	if !errors.Is(err, ErrEnrollmentCapacity) {
		t.Fatalf("second agent error = %v, want ErrEnrollmentCapacity", err)
	}
}

func TestRevocationDoesNotRefundPayloadEnrollmentCapacity(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	bootstrap := environment.readyBuild(t, "build-one", "listener-one", 1)
	first := environment.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)

	if err := environment.store.RevokeSession(
		context.Background(),
		"listener-one",
		"agent-one",
	); err != nil {
		t.Fatalf("revoke first identity: %v", err)
	}
	_, err := environment.store.Enroll(
		context.Background(),
		EnrollRequest{
			ListenerID:     "listener-one",
			AgentID:        "agent-two",
			PayloadBuildID: "build-one",
			Bootstrap:      bootstrap.Public,
		},
	)
	if !errors.Is(err, ErrEnrollmentCapacity) {
		t.Fatalf(
			"replacement identity after revocation error = %v, want capacity",
			err,
		)
	}

	if err := environment.store.RequireReenrollment(
		context.Background(),
		"listener-one",
		"agent-one",
	); err != nil {
		t.Fatalf("authorize same-identity re-enrollment: %v", err)
	}
	reenrolled := environment.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)
	if !reenrolled.Reenrolled ||
		reenrolled.SessionID == first.SessionID ||
		reenrolled.Credential == first.Credential {
		t.Fatal("same-identity re-enrollment did not reuse its durable allocation")
	}
	if got := countRows(
		t,
		environment.database.SQL(),
		`SELECT COUNT(*) FROM payload_enrollment_allocations
		 WHERE payload_build_id = 'build-one'`,
	); got != 1 {
		t.Fatalf("monotonic payload allocations = %d, want 1", got)
	}
}

func TestConcurrentEnrollmentCannotExceedBuildCapacity(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	bootstrap := environment.readyBuild(t, "build-one", "listener-one", 1)

	const contenders = 8
	start := make(chan struct{})
	results := make(chan error, contenders)
	var waitGroup sync.WaitGroup
	for index := 0; index < contenders; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			<-start
			_, err := environment.store.Enroll(
				context.Background(),
				EnrollRequest{
					ListenerID:     "listener-one",
					AgentID:        fmt.Sprintf("agent-%d", index),
					PayloadBuildID: "build-one",
					Bootstrap:      bootstrap.Public,
				},
			)
			results <- err
		}(index)
	}
	close(start)
	waitGroup.Wait()
	close(results)

	var succeeded, capacity int
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrEnrollmentCapacity):
			capacity++
		default:
			t.Fatalf("concurrent enrollment error = %v", err)
		}
	}
	if succeeded != 1 || capacity != contenders-1 {
		t.Fatalf("succeeded=%d capacity=%d, want 1/%d", succeeded, capacity, contenders-1)
	}
}

func TestEnrollmentRequiresCorrectCompletedBuildCredential(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	environment.insertListener(t, "listener-two")

	environment.insertBuild(t, "building-build", "listener-one", "building")
	buildingBootstrap, err := GenerateBootstrapCredential()
	if err != nil {
		t.Fatalf("generate building bootstrap: %v", err)
	}
	if err := environment.store.ActivatePayloadCredential(
		context.Background(),
		PayloadCredentialActivation{
			PayloadBuildID:  "building-build",
			ListenerID:      "listener-one",
			BootstrapSHA256: buildingBootstrap.SHA256,
			MaxSessions:     2,
		},
	); err != nil {
		t.Fatalf("activate building payload: %v", err)
	}

	_, err = environment.store.Enroll(
		context.Background(),
		EnrollRequest{
			ListenerID:     "listener-one",
			AgentID:        "agent-one",
			PayloadBuildID: "building-build",
			Bootstrap:      buildingBootstrap.Public,
		},
	)
	assertUnauthorized(t, err, buildingBootstrap.Public)

	environment.setBuildState(t, "building-build", "completed")
	enrolled := environment.enroll(
		t,
		"listener-one",
		"agent-one",
		"building-build",
		buildingBootstrap.Public,
	)

	wrong, err := GenerateBootstrapCredential()
	if err != nil {
		t.Fatalf("generate wrong bootstrap: %v", err)
	}
	_, err = environment.store.Enroll(
		context.Background(),
		EnrollRequest{
			ListenerID:     "listener-one",
			AgentID:        "agent-two",
			PayloadBuildID: "building-build",
			Bootstrap:      wrong.Public,
		},
	)
	assertUnauthorized(t, err, wrong.Public)

	_, err = environment.store.Enroll(
		context.Background(),
		EnrollRequest{
			ListenerID:     "listener-two",
			AgentID:        "agent-one",
			PayloadBuildID: "building-build",
			Bootstrap:      buildingBootstrap.Public,
		},
	)
	assertUnauthorized(t, err, buildingBootstrap.Public)

	if _, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		enrolled.Credential,
	); err != nil {
		t.Fatalf("authenticate completed-build session: %v", err)
	}

	environment.insertBuild(t, "failed-build", "listener-one", "failed")
	failedBootstrap, err := GenerateBootstrapCredential()
	if err != nil {
		t.Fatalf("generate failed bootstrap: %v", err)
	}
	err = environment.store.ActivatePayloadCredential(
		context.Background(),
		PayloadCredentialActivation{
			PayloadBuildID:  "failed-build",
			ListenerID:      "listener-one",
			BootstrapSHA256: failedBootstrap.SHA256,
			MaxSessions:     1,
		},
	)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("failed-build activation error = %v, want ErrConflict", err)
	}
}

func TestDuplicateAgentIDsAreListenerScoped(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	environment.insertListener(t, "listener-two")
	firstBootstrap := environment.readyBuild(t, "build-one", "listener-one", 2)
	secondBootstrap := environment.readyBuild(t, "build-two", "listener-two", 2)

	first := environment.enroll(
		t,
		"listener-one",
		"duplicate-agent",
		"build-one",
		firstBootstrap.Public,
	)
	second := environment.enroll(
		t,
		"listener-two",
		"duplicate-agent",
		"build-two",
		secondBootstrap.Public,
	)
	if first.SessionID == second.SessionID {
		t.Fatal("listener-scoped duplicate IDs unexpectedly share a session")
	}
	if got := countRows(
		t,
		environment.database.SQL(),
		`SELECT COUNT(*)
		 FROM agent_enrollment_sessions
		 WHERE agent_id = 'duplicate-agent'`,
	); got != 2 {
		t.Fatalf("duplicate scoped session rows = %d, want 2", got)
	}

	_, err := environment.store.Authenticate(
		context.Background(),
		"listener-two",
		"duplicate-agent",
		first.Credential,
	)
	assertUnauthorized(t, err, first.Credential)
	if _, err := environment.store.Authenticate(
		context.Background(),
		"listener-two",
		"duplicate-agent",
		second.Credential,
	); err != nil {
		t.Fatalf("authenticate second scoped identity: %v", err)
	}
}

func TestAuthenticateRejectsMalformedWrongUnknownStaleAndCrossAgentTokens(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	bootstrap := environment.readyBuild(t, "build-one", "listener-one", 4)
	enrolled := environment.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)

	for name, token := range map[string]string{
		"malformed": "not-a-session",
		"wrong mac": tamperCredential(t, enrolled.Credential),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := environment.store.Authenticate(
				context.Background(),
				"listener-one",
				"agent-one",
				token,
			)
			assertUnauthorized(t, err, token)
		})
	}

	var unknownID [SessionIDBytes]byte
	unknownID[0] = 0x42
	unknown := encodeSessionCredential(
		environment.store.key,
		unknownID,
		1,
		"listener-one",
		"agent-one",
		"build-one",
	)
	_, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		unknown,
	)
	assertUnauthorized(t, err, unknown)

	_, err = environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-two",
		enrolled.Credential,
	)
	assertUnauthorized(t, err, enrolled.Credential)

	rotation, err := environment.store.Rotate(
		context.Background(),
		"listener-one",
		"agent-one",
	)
	if err != nil || rotation.PendingGeneration != 2 {
		t.Fatalf("rotate session: rotation=%+v err=%v", rotation, err)
	}
	currentAuth, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		enrolled.Credential,
	)
	if err != nil {
		t.Fatalf("authenticate current during rotation: %v", err)
	}
	if currentAuth.ReplacementCredential == "" || currentAuth.Promoted {
		t.Fatal("current rotation authentication did not return only the pending credential")
	}
	promoted, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		currentAuth.ReplacementCredential,
	)
	if err != nil || !promoted.Promoted || promoted.Generation != 2 {
		t.Fatalf("promote pending credential: promoted=%v generation=%d err=%v", promoted.Promoted, promoted.Generation, err)
	}
	_, err = environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		enrolled.Credential,
	)
	assertUnauthorized(t, err, enrolled.Credential)
}

func TestRotationIsStableUntilPendingCredentialPromotes(t *testing.T) {
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

	first, err := environment.store.Rotate(
		context.Background(),
		"listener-one",
		"agent-one",
	)
	if err != nil {
		t.Fatalf("rotate session: %v", err)
	}
	second, err := environment.store.Rotate(
		context.Background(),
		"listener-one",
		"agent-one",
	)
	if err != nil {
		t.Fatalf("repeat session rotation: %v", err)
	}
	if first.PendingGeneration != 2 ||
		second.PendingGeneration != first.PendingGeneration ||
		!second.AlreadyPending {
		t.Fatalf("rotation results first=%+v second=%+v", first, second)
	}

	firstDelivery, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		enrolled.Credential,
	)
	if err != nil {
		t.Fatalf("deliver pending credential: %v", err)
	}
	secondDelivery, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		enrolled.Credential,
	)
	if err != nil {
		t.Fatalf("redeliver pending credential: %v", err)
	}
	if firstDelivery.ReplacementCredential == "" ||
		firstDelivery.ReplacementCredential != secondDelivery.ReplacementCredential {
		t.Fatal("pending rotation credential was not stable across response loss")
	}
	parsed, err := ParseSessionCredential(firstDelivery.ReplacementCredential)
	if err != nil || parsed.Generation != 2 {
		t.Fatalf("parse pending rotation credential: parsed=%+v err=%v", parsed, err)
	}

	promoted, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		firstDelivery.ReplacementCredential,
	)
	if err != nil || !promoted.Promoted {
		t.Fatalf("promote rotation: promoted=%v err=%v", promoted.Promoted, err)
	}
	again, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		firstDelivery.ReplacementCredential,
	)
	if err != nil || again.Promoted || again.ReplacementCredential != "" {
		t.Fatalf(
			"authenticate promoted current: promoted=%v replacement_present=%v err=%v",
			again.Promoted,
			again.ReplacementCredential != "",
			err,
		)
	}
}

func TestConfirmedSessionRejectsBootstrapReplayAcrossRotation(t *testing.T) {
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

	var confirmedBefore *string
	if err := environment.database.SQL().QueryRow(
		`SELECT session_confirmed_at
		 FROM agent_enrollment_sessions
		 WHERE listener_id = 'listener-one' AND agent_id = 'agent-one'`,
	).Scan(&confirmedBefore); err != nil {
		t.Fatalf("read initial confirmation state: %v", err)
	}
	if confirmedBefore != nil {
		t.Fatal("new enrollment was confirmed before session-token authentication")
	}
	if _, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		enrolled.Credential,
	); err != nil {
		t.Fatalf("confirm enrolled session: %v", err)
	}
	if err := environment.database.SQL().QueryRow(
		`SELECT session_confirmed_at
		 FROM agent_enrollment_sessions
		 WHERE listener_id = 'listener-one' AND agent_id = 'agent-one'`,
	).Scan(&confirmedBefore); err != nil {
		t.Fatalf("read confirmed session state: %v", err)
	}
	if confirmedBefore == nil {
		t.Fatal("successful authentication did not durably confirm the session")
	}
	assertBootstrapReplayRejected(
		t,
		environment,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)

	if _, err := environment.store.Rotate(
		context.Background(),
		"listener-one",
		"agent-one",
	); err != nil {
		t.Fatalf("rotate confirmed session: %v", err)
	}
	assertBootstrapReplayRejected(
		t,
		environment,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)
	current, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		enrolled.Credential,
	)
	if err != nil || current.ReplacementCredential == "" {
		t.Fatalf(
			"deliver rotated credential: replacement_present=%v err=%v",
			current.ReplacementCredential != "",
			err,
		)
	}
	assertBootstrapReplayRejected(
		t,
		environment,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)
	if _, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		current.ReplacementCredential,
	); err != nil {
		t.Fatalf("promote rotated credential: %v", err)
	}
	assertBootstrapReplayRejected(
		t,
		environment,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)

	var confirmedAfter *string
	if err := environment.database.SQL().QueryRow(
		`SELECT session_confirmed_at
		 FROM agent_enrollment_sessions
		 WHERE listener_id = 'listener-one' AND agent_id = 'agent-one'`,
	).Scan(&confirmedAfter); err != nil {
		t.Fatalf("read post-rotation confirmation state: %v", err)
	}
	if confirmedAfter == nil || *confirmedAfter != *confirmedBefore {
		t.Fatal("rotation reopened or replaced the durable confirmation boundary")
	}
}

func TestRevocationRequiresExplicitReenrollmentAndReplacesSession(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	firstBootstrap := environment.readyBuild(t, "build-one", "listener-one", 2)
	secondBootstrap := environment.readyBuild(t, "build-two", "listener-one", 2)
	first := environment.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-one",
		firstBootstrap.Public,
	)

	if err := environment.store.RevokeSession(
		context.Background(),
		"listener-one",
		"agent-one",
	); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	_, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		first.Credential,
	)
	assertUnauthorized(t, err, first.Credential)
	_, err = environment.store.Enroll(
		context.Background(),
		EnrollRequest{
			ListenerID:     "listener-one",
			AgentID:        "agent-one",
			PayloadBuildID: "build-one",
			Bootstrap:      firstBootstrap.Public,
		},
	)
	assertUnauthorized(t, err, firstBootstrap.Public)

	if err := environment.store.RequireReenrollment(
		context.Background(),
		"listener-one",
		"agent-one",
	); err != nil {
		t.Fatalf("enable explicit re-enrollment: %v", err)
	}
	second := environment.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-two",
		secondBootstrap.Public,
	)
	if !second.Reenrolled || second.Resumed {
		t.Fatalf("re-enrollment flags = resumed:%v reenrolled:%v", second.Resumed, second.Reenrolled)
	}
	if second.SessionID == first.SessionID ||
		second.Credential == first.Credential ||
		second.PayloadBuildID != "build-two" {
		t.Fatal("explicit re-enrollment did not replace session and build binding")
	}
	resumed := environment.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-two",
		secondBootstrap.Public,
	)
	if !resumed.Resumed || resumed.Credential != second.Credential {
		t.Fatal("unconfirmed re-enrollment did not preserve its response-loss window")
	}
	if _, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		second.Credential,
	); err != nil {
		t.Fatalf("authenticate re-enrolled session: %v", err)
	}
	assertBootstrapReplayRejected(
		t,
		environment,
		"listener-one",
		"agent-one",
		"build-two",
		secondBootstrap.Public,
	)
	_, err = environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		first.Credential,
	)
	assertUnauthorized(t, err, first.Credential)

	var (
		reenrollmentRequired *string
		revokedAt            *string
		lastReenrolledAt     *string
	)
	if err := environment.database.SQL().QueryRow(
		`SELECT reenrollment_required_at, revoked_at, last_reenrolled_at
		 FROM agent_enrollment_sessions
		 WHERE listener_id = 'listener-one' AND agent_id = 'agent-one'`,
	).Scan(&reenrollmentRequired, &revokedAt, &lastReenrolledAt); err != nil {
		t.Fatalf("read re-enrollment timestamps: %v", err)
	}
	if reenrollmentRequired != nil || revokedAt != nil || lastReenrolledAt == nil {
		t.Fatalf(
			"timestamps required=%v revoked=%v reenrolled=%v",
			reenrollmentRequired,
			revokedAt,
			lastReenrolledAt,
		)
	}
}

func TestRevokeAfterReenrollmentRequestDisablesBootstrapAgain(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	bootstrap := environment.readyBuild(t, "build-one", "listener-one", 1)
	environment.enroll(t, "listener-one", "agent-one", "build-one", bootstrap.Public)

	if err := environment.store.RequireReenrollment(
		context.Background(),
		"listener-one",
		"agent-one",
	); err != nil {
		t.Fatalf("require re-enrollment: %v", err)
	}
	if err := environment.store.RevokeSession(
		context.Background(),
		"listener-one",
		"agent-one",
	); err != nil {
		t.Fatalf("revoke after re-enrollment request: %v", err)
	}
	_, err := environment.store.Enroll(
		context.Background(),
		EnrollRequest{
			ListenerID:     "listener-one",
			AgentID:        "agent-one",
			PayloadBuildID: "build-one",
			Bootstrap:      bootstrap.Public,
		},
	)
	assertUnauthorized(t, err, bootstrap.Public)
}

func TestPayloadCredentialRevocationBlocksBootstrapButNotExistingSession(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	bootstrap := environment.readyBuild(t, "build-one", "listener-one", 2)
	enrolled := environment.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)

	if err := environment.store.RevokePayloadCredential(
		context.Background(),
		"build-one",
	); err != nil {
		t.Fatalf("revoke payload credential: %v", err)
	}
	var revokedAt string
	if err := environment.database.SQL().QueryRow(
		`SELECT revoked_at
		 FROM payload_bootstrap_credentials
		 WHERE payload_build_id = 'build-one'`,
	).Scan(&revokedAt); err != nil {
		t.Fatalf("read payload credential revocation: %v", err)
	}
	if err := environment.store.RevokePayloadCredential(
		context.Background(),
		"build-one",
	); err != nil {
		t.Fatalf("repeat payload credential revocation: %v", err)
	}
	var repeatedRevokedAt string
	if err := environment.database.SQL().QueryRow(
		`SELECT revoked_at
		 FROM payload_bootstrap_credentials
		 WHERE payload_build_id = 'build-one'`,
	).Scan(&repeatedRevokedAt); err != nil {
		t.Fatalf("read repeated payload credential revocation: %v", err)
	}
	if repeatedRevokedAt != revokedAt {
		t.Fatal("idempotent payload revocation changed its durable timestamp")
	}

	_, err := environment.store.Enroll(
		context.Background(),
		EnrollRequest{
			ListenerID:     "listener-one",
			AgentID:        "agent-one",
			PayloadBuildID: "build-one",
			Bootstrap:      bootstrap.Public,
		},
	)
	assertUnauthorized(t, err, bootstrap.Public)
	_, err = environment.store.Enroll(
		context.Background(),
		EnrollRequest{
			ListenerID:     "listener-one",
			AgentID:        "agent-two",
			PayloadBuildID: "build-one",
			Bootstrap:      bootstrap.Public,
		},
	)
	assertUnauthorized(t, err, bootstrap.Public)
	if _, err := environment.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		enrolled.Credential,
	); err != nil {
		t.Fatalf("existing session after payload revocation: %v", err)
	}
}

func TestListenerSessionCapIsEnforced(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	firstBootstrap := environment.readyBuild(t, "build-one", "listener-one", MaxPayloadSessions)
	secondBootstrap := environment.readyBuild(t, "build-two", "listener-one", MaxPayloadSessions)

	tx, err := environment.database.SQL().Begin()
	if err != nil {
		t.Fatalf("begin listener-cap fixture transaction: %v", err)
	}
	defer tx.Rollback()
	now := "2026-07-24T12:00:00Z"
	for index := 0; index < MaxListenerSessions; index++ {
		var sessionID [SessionIDBytes]byte
		binary.BigEndian.PutUint64(sessionID[SessionIDBytes-8:], uint64(index+1))
		if _, err := tx.Exec(
			`INSERT INTO agent_enrollment_sessions (
				session_id, listener_id, agent_id, payload_build_id,
				current_generation, pending_generation,
				bootstrap_consumed_at, reenrollment_required_at,
				last_reenrolled_at, revoked_at, created_at, updated_at
			) VALUES (?, 'listener-one', ?, 'build-one', 1, NULL, ?, NULL, NULL, NULL, ?, ?)`,
			sessionID[:],
			fmt.Sprintf("seed-agent-%04d", index),
			now,
			now,
			now,
		); err != nil {
			t.Fatalf("insert listener-cap row %d: %v", index, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit listener-cap fixture: %v", err)
	}

	_, err = environment.store.Enroll(
		context.Background(),
		EnrollRequest{
			ListenerID:     "listener-one",
			AgentID:        "overflow-agent",
			PayloadBuildID: "build-two",
			Bootstrap:      secondBootstrap.Public,
		},
	)
	if !errors.Is(err, ErrEnrollmentCapacity) {
		t.Fatalf("listener overflow error = %v, want ErrEnrollmentCapacity", err)
	}

	// Keep the first credential live in the fixture so the optimizer cannot
	// discard its credential join as unreachable.
	if firstBootstrap.Public == "" {
		t.Fatal("first bootstrap unexpectedly empty")
	}
}

func TestSessionCredentialsSurviveRestartWithPendingRotation(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "microc2.db")
	first := openTestEnvironment(t, databasePath)
	first.insertListener(t, "listener-one")
	bootstrap := first.readyBuild(t, "build-one", "listener-one", 1)
	enrolled := first.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)
	if _, err := first.store.Rotate(
		context.Background(),
		"listener-one",
		"agent-one",
	); err != nil {
		t.Fatalf("rotate before restart: %v", err)
	}
	before, err := first.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		enrolled.Credential,
	)
	if err != nil || before.ReplacementCredential == "" {
		t.Fatalf(
			"read pending before restart: replacement_present=%v err=%v",
			before.ReplacementCredential != "",
			err,
		)
	}
	if err := first.database.Close(); err != nil {
		t.Fatalf("close first database: %v", err)
	}

	second := openTestEnvironment(t, databasePath)
	after, err := second.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		enrolled.Credential,
	)
	if err != nil {
		t.Fatalf("authenticate current after restart: %v", err)
	}
	if after.ReplacementCredential != before.ReplacementCredential {
		t.Fatal("server key or pending rotation changed across restart")
	}
	promoted, err := second.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		after.ReplacementCredential,
	)
	if err != nil || !promoted.Promoted {
		t.Fatalf("promote pending after restart: promoted=%v err=%v", promoted.Promoted, err)
	}
}

func TestBootstrapEnrollmentResumeSurvivesRestart(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "microc2.db")
	first := openTestEnvironment(t, databasePath)
	first.insertListener(t, "listener-one")
	bootstrap := first.readyBuild(t, "build-one", "listener-one", 1)
	enrolled := first.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)
	if err := first.database.Close(); err != nil {
		t.Fatalf("close first database: %v", err)
	}

	second := openTestEnvironment(t, databasePath)
	resumed := second.enroll(
		t,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)
	if !resumed.Resumed ||
		resumed.SessionID != enrolled.SessionID ||
		resumed.Credential != enrolled.Credential {
		t.Fatal("restart resume changed the durable enrollment credential")
	}
	if _, err := second.store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		resumed.Credential,
	); err != nil {
		t.Fatalf("confirm resumed session: %v", err)
	}
	if err := second.database.Close(); err != nil {
		t.Fatalf("close second database: %v", err)
	}

	third := openTestEnvironment(t, databasePath)
	assertBootstrapReplayRejected(
		t,
		third,
		"listener-one",
		"agent-one",
		"build-one",
		bootstrap.Public,
	)
}

func TestRotateRefusesGenerationOverflow(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	bootstrap := environment.readyBuild(t, "build-one", "listener-one", 1)
	environment.enroll(t, "listener-one", "agent-one", "build-one", bootstrap.Public)

	if _, err := environment.database.SQL().Exec(
		`UPDATE agent_enrollment_sessions
		 SET current_generation = 9223372036854775807
		 WHERE listener_id = 'listener-one' AND agent_id = 'agent-one'`,
	); err != nil {
		t.Fatalf("set maximum generation: %v", err)
	}
	_, err := environment.store.Rotate(
		context.Background(),
		"listener-one",
		"agent-one",
	)
	if !errors.Is(err, ErrGenerationExhausted) {
		t.Fatalf("rotation overflow error = %v, want ErrGenerationExhausted", err)
	}
}

func tamperCredential(t *testing.T, credential string) string {
	t.Helper()
	parts := splitCredential(t, credential)
	mac, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		t.Fatalf("decode credential mac: %v", err)
	}
	mac[0] ^= 0x80
	parts[3] = base64.RawURLEncoding.EncodeToString(mac)
	return parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3]
}

func assertBootstrapReplayRejected(
	t *testing.T,
	environment *testEnvironment,
	listenerID string,
	agentID string,
	buildID string,
	bootstrap string,
) {
	t.Helper()
	_, err := environment.store.Enroll(
		context.Background(),
		EnrollRequest{
			ListenerID:     listenerID,
			AgentID:        agentID,
			PayloadBuildID: buildID,
			Bootstrap:      bootstrap,
		},
	)
	assertUnauthorized(t, err, bootstrap)
}

func TestActivationRejectsEmptyHashAndInvalidAllowance(t *testing.T) {
	environment := newTestEnvironment(t)
	environment.insertListener(t, "listener-one")
	environment.insertBuild(t, "build-one", "listener-one", "building")

	for name, activation := range map[string]PayloadCredentialActivation{
		"empty hash": {
			PayloadBuildID: "build-one",
			ListenerID:     "listener-one",
			MaxSessions:    1,
		},
		"zero allowance": {
			PayloadBuildID:  "build-one",
			ListenerID:      "listener-one",
			BootstrapSHA256: sha256.Sum256([]byte("bootstrap")),
			MaxSessions:     0,
		},
		"excessive allowance": {
			PayloadBuildID:  "build-one",
			ListenerID:      "listener-one",
			BootstrapSHA256: sha256.Sum256([]byte("bootstrap")),
			MaxSessions:     MaxPayloadSessions + 1,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := environment.store.ActivatePayloadCredential(
				context.Background(),
				activation,
			); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("activation error = %v, want ErrInvalidArgument", err)
			}
		})
	}
}
