package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"microc2/server/internal/persistence"
)

const maximumIdentifierBytes = 512

const sessionIDGenerationAttempts = 8

var dummyVerificationValue = sha256.Sum256([]byte("microc2 enrollment dummy verification"))

// Store owns the durable enrollment state and the process-local copy of the
// persisted HMAC key.
type Store struct {
	db     *sql.DB
	key    [sha256.Size]byte
	random io.Reader
	now    func() time.Time
}

// NewStore atomically initializes or loads the singleton HMAC key. Reopening a
// database therefore preserves all issued static session credentials.
func NewStore(ctx context.Context, database *persistence.Database) (*Store, error) {
	if database == nil || database.SQL() == nil {
		return nil, fmt.Errorf("%w: database is required", ErrInvalidArgument)
	}
	key, err := loadOrCreateServerKey(ctx, database.SQL(), rand.Reader, time.Now)
	if err != nil {
		return nil, err
	}
	return &Store{
		db:     database.SQL(),
		key:    key,
		random: rand.Reader,
		now:    time.Now,
	}, nil
}

func loadOrCreateServerKey(
	ctx context.Context,
	db *sql.DB,
	random io.Reader,
	now func() time.Time,
) ([sha256.Size]byte, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("begin enrollment key transaction: %w", err)
	}
	defer rollback(tx)

	var stored []byte
	err = tx.QueryRowContext(
		ctx,
		`SELECT hmac_key
		 FROM enrollment_server_keys
		 WHERE singleton = 1`,
	).Scan(&stored)
	switch {
	case err == nil:
		if len(stored) != sha256.Size {
			return [sha256.Size]byte{}, errors.New("stored enrollment key is invalid")
		}
		var key [sha256.Size]byte
		copy(key[:], stored)
		if err := tx.Commit(); err != nil {
			return [sha256.Size]byte{}, fmt.Errorf("commit enrollment key load: %w", err)
		}
		return key, nil
	case !errors.Is(err, sql.ErrNoRows):
		return [sha256.Size]byte{}, fmt.Errorf("load enrollment key: %w", err)
	}

	var key [sha256.Size]byte
	if _, err := io.ReadFull(random, key[:]); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("generate enrollment key: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO enrollment_server_keys (singleton, hmac_key, created_at)
		 VALUES (1, ?, ?)`,
		key[:],
		formatTimestamp(now()),
	); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("persist enrollment key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("commit enrollment key initialization: %w", err)
	}
	return key, nil
}

// ActivatePayloadCredential persists only a bootstrap hash and immutable
// allowance. A building payload may be activated immediately before its build
// row transitions to completed; Enroll independently requires completed state.
func (s *Store) ActivatePayloadCredential(
	ctx context.Context,
	activation PayloadCredentialActivation,
) error {
	if err := validateActivation(activation); err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin payload credential activation: %w", err)
	}
	defer rollback(tx)

	var listenerID, state string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT listener_id, state
		 FROM payload_builds
		 WHERE id = ?`,
		activation.PayloadBuildID,
	).Scan(&listenerID, &state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("read payload build for activation: %w", err)
	}
	if !constantStringEqual(listenerID, activation.ListenerID) {
		return ErrConflict
	}
	if state != "building" && state != "completed" {
		return ErrConflict
	}

	var (
		storedListener string
		storedHash     []byte
		storedMax      int
		revokedAt      sql.NullString
	)
	err = tx.QueryRowContext(
		ctx,
		`SELECT listener_id, bootstrap_sha256, max_sessions, revoked_at
		 FROM payload_bootstrap_credentials
		 WHERE payload_build_id = ?`,
		activation.PayloadBuildID,
	).Scan(&storedListener, &storedHash, &storedMax, &revokedAt)
	switch {
	case err == nil:
		if !constantStringEqual(storedListener, activation.ListenerID) ||
			!constantBytesEqual(storedHash, activation.BootstrapSHA256[:]) ||
			storedMax != activation.MaxSessions ||
			revokedAt.Valid {
			return ErrConflict
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit idempotent payload credential activation: %w", err)
		}
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("read payload credential activation: %w", err)
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO payload_bootstrap_credentials (
			payload_build_id, listener_id, bootstrap_sha256,
			max_sessions, activated_at, revoked_at
		) VALUES (?, ?, ?, ?, ?, NULL)`,
		activation.PayloadBuildID,
		activation.ListenerID,
		activation.BootstrapSHA256[:],
		activation.MaxSessions,
		formatTimestamp(s.now()),
	); err != nil {
		return fmt.Errorf("activate payload credential: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit payload credential activation: %w", err)
	}
	return nil
}

// RevokePayloadCredential prevents new bootstrap enrollments and resumes. It
// does not silently revoke sessions that were already enrolled.
func (s *Store) RevokePayloadCredential(ctx context.Context, payloadBuildID string) error {
	if err := validateIdentifier(payloadBuildID); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin payload credential revocation: %w", err)
	}
	defer rollback(tx)

	var exists int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT EXISTS (
			SELECT 1
			FROM payload_bootstrap_credentials
			WHERE payload_build_id = ?
		)`,
		payloadBuildID,
	).Scan(&exists); err != nil {
		return fmt.Errorf("read payload credential revocation: %w", err)
	}
	if exists == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE payload_bootstrap_credentials
		 SET revoked_at = COALESCE(revoked_at, ?)
		 WHERE payload_build_id = ?`,
		formatTimestamp(s.now()),
		payloadBuildID,
	); err != nil {
		return fmt.Errorf("revoke payload credential: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit payload credential revocation: %w", err)
	}
	return nil
}

// Enroll verifies a completed build's bootstrap credential and atomically
// creates, resumes, or explicitly replaces one listener-scoped agent session.
func (s *Store) Enroll(ctx context.Context, request EnrollRequest) (Enrollment, error) {
	if validateIdentifier(request.ListenerID) != nil ||
		validateIdentifier(request.AgentID) != nil ||
		validateIdentifier(request.PayloadBuildID) != nil {
		s.dummyCredentialComparison(request.Bootstrap)
		return Enrollment{}, ErrUnauthorized
	}
	bootstrapHash, bootstrapSyntaxValid := bootstrapDigestForVerification(request.Bootstrap)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, fmt.Errorf("begin agent enrollment: %w", err)
	}
	defer rollback(tx)

	var (
		credentialListener string
		storedHash         []byte
		maxSessions        int
		credentialRevoked  sql.NullString
		buildListener      string
		buildState         string
	)
	err = tx.QueryRowContext(
		ctx,
		`SELECT
			credential.listener_id,
			credential.bootstrap_sha256,
			credential.max_sessions,
			credential.revoked_at,
			build.listener_id,
			build.state
		 FROM payload_bootstrap_credentials AS credential
		 JOIN payload_builds AS build
		   ON build.id = credential.payload_build_id
		  AND build.listener_id = credential.listener_id
		 WHERE credential.payload_build_id = ?`,
		request.PayloadBuildID,
	).Scan(
		&credentialListener,
		&storedHash,
		&maxSessions,
		&credentialRevoked,
		&buildListener,
		&buildState,
	)
	if errors.Is(err, sql.ErrNoRows) {
		_ = subtle.ConstantTimeCompare(bootstrapHash[:], dummyVerificationValue[:])
		return Enrollment{}, ErrUnauthorized
	}
	if err != nil {
		return Enrollment{}, fmt.Errorf("read payload enrollment credential: %w", err)
	}

	hashMatches := constantBytesEqual(storedHash, bootstrapHash[:])
	listenerMatches := constantStringEqual(credentialListener, request.ListenerID)
	buildListenerMatches := constantStringEqual(buildListener, request.ListenerID)
	if !bootstrapSyntaxValid || !hashMatches || !listenerMatches ||
		!buildListenerMatches || credentialRevoked.Valid ||
		buildState != "completed" {
		return Enrollment{}, ErrUnauthorized
	}

	existing, found, err := querySessionByIdentity(
		ctx,
		tx,
		request.ListenerID,
		request.AgentID,
	)
	if err != nil {
		return Enrollment{}, err
	}
	if found && !existing.revokedAt.Valid &&
		!existing.reenrollmentRequiredAt.Valid {
		if existing.sessionConfirmedAt.Valid ||
			!constantStringEqual(existing.payloadBuildID, request.PayloadBuildID) {
			return Enrollment{}, ErrUnauthorized
		}
		enrollment := s.enrollmentFor(existing, true, false)
		if err := tx.Commit(); err != nil {
			return Enrollment{}, fmt.Errorf("commit resumed agent enrollment: %w", err)
		}
		return enrollment, nil
	}
	if found && !existing.reenrollmentRequiredAt.Valid {
		// Revocation alone is final. Only a later explicit management action may
		// enable bootstrap re-enrollment.
		return Enrollment{}, ErrUnauthorized
	}

	now := formatTimestamp(s.now())
	if err := reserveEnrollmentCapacity(
		ctx,
		tx,
		request.ListenerID,
		request.AgentID,
		request.PayloadBuildID,
		maxSessions,
		now,
	); err != nil {
		return Enrollment{}, err
	}

	sessionID, err := s.generateUniqueSessionID(ctx, tx)
	if err != nil {
		return Enrollment{}, err
	}
	session := durableSession{
		sessionID:         sessionID,
		listenerID:        request.ListenerID,
		agentID:           request.AgentID,
		payloadBuildID:    request.PayloadBuildID,
		currentGeneration: 1,
	}

	if found {
		result, err := tx.ExecContext(
			ctx,
			`UPDATE agent_enrollment_sessions
			 SET session_id = ?,
			     payload_build_id = ?,
			     current_generation = 1,
			     pending_generation = NULL,
			     bootstrap_consumed_at = ?,
			     session_confirmed_at = NULL,
			     reenrollment_required_at = NULL,
			     last_reenrolled_at = ?,
			     revoked_at = NULL,
			     updated_at = ?
			 WHERE listener_id = ?
			   AND agent_id = ?`,
			sessionID[:],
			request.PayloadBuildID,
			now,
			now,
			now,
			request.ListenerID,
			request.AgentID,
		)
		if err != nil {
			return Enrollment{}, fmt.Errorf("replace agent enrollment session: %w", err)
		}
		if !affectedAny(result) {
			return Enrollment{}, errors.New("agent enrollment session disappeared")
		}
	} else {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO agent_enrollment_sessions (
				session_id, listener_id, agent_id, payload_build_id,
				current_generation, pending_generation,
				bootstrap_consumed_at, session_confirmed_at,
				reenrollment_required_at,
				last_reenrolled_at, revoked_at, created_at, updated_at
			) VALUES (?, ?, ?, ?, 1, NULL, ?, NULL, NULL, NULL, NULL, ?, ?)`,
			sessionID[:],
			request.ListenerID,
			request.AgentID,
			request.PayloadBuildID,
			now,
			now,
			now,
		); err != nil {
			return Enrollment{}, fmt.Errorf("persist agent enrollment session: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return Enrollment{}, fmt.Errorf("commit agent enrollment: %w", err)
	}
	return s.enrollmentFor(session, false, found), nil
}

// Authenticate validates a bearer against its path binding and durable state.
// A pending generation is promoted on first use. Until then, current-generation
// requests carry the stable pending replacement credential.
func (s *Store) Authenticate(
	ctx context.Context,
	listenerID string,
	agentID string,
	credential string,
) (Authentication, error) {
	parsed, syntaxValid := parseSessionCredential(credential)
	if !syntaxValid || validateIdentifier(listenerID) != nil ||
		validateIdentifier(agentID) != nil {
		s.dummySessionComparison(listenerID, agentID, parsed)
		return Authentication{}, ErrUnauthorized
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Authentication{}, fmt.Errorf("begin session authentication: %w", err)
	}
	defer rollback(tx)

	session, found, err := querySessionByID(ctx, tx, parsed.sessionID)
	if err != nil {
		return Authentication{}, err
	}
	if !found {
		expected := sessionMAC(
			s.key,
			parsed.sessionID,
			parsed.generation,
			listenerID,
			agentID,
			"unknown-build",
		)
		_ = subtle.ConstantTimeCompare(expected[:], parsed.mac[:])
		return Authentication{}, ErrUnauthorized
	}

	expected := sessionMAC(
		s.key,
		parsed.sessionID,
		parsed.generation,
		listenerID,
		agentID,
		session.payloadBuildID,
	)
	macMatches := subtle.ConstantTimeCompare(expected[:], parsed.mac[:]) == 1
	listenerMatches := constantStringEqual(session.listenerID, listenerID)
	agentMatches := constantStringEqual(session.agentID, agentID)
	currentMatches := parsed.generation == session.currentGeneration
	pendingMatches := session.pendingGeneration.Valid &&
		parsed.generation == session.pendingGeneration.Int64
	if !macMatches || !listenerMatches || !agentMatches ||
		(!currentMatches && !pendingMatches) ||
		session.revokedAt.Valid || session.reenrollmentRequiredAt.Valid {
		return Authentication{}, ErrUnauthorized
	}

	authentication := Authentication{
		Principal: principalFor(session, parsed.generation),
	}
	now := formatTimestamp(s.now())
	if pendingMatches {
		result, err := tx.ExecContext(
			ctx,
			`UPDATE agent_enrollment_sessions
			 SET current_generation = pending_generation,
			     pending_generation = NULL,
			     session_confirmed_at = COALESCE(session_confirmed_at, ?),
			     updated_at = ?
			 WHERE session_id = ?
			   AND pending_generation = ?`,
			now,
			now,
			parsed.sessionID[:],
			parsed.generation,
		)
		if err != nil {
			return Authentication{}, fmt.Errorf("promote session credential: %w", err)
		}
		if !affectedAny(result) {
			return Authentication{}, ErrUnauthorized
		}
		authentication.Promoted = true
	} else {
		if !session.sessionConfirmedAt.Valid {
			result, err := tx.ExecContext(
				ctx,
				`UPDATE agent_enrollment_sessions
				 SET session_confirmed_at = ?,
				     updated_at = ?
				 WHERE session_id = ?
				   AND current_generation = ?
				   AND session_confirmed_at IS NULL`,
				now,
				now,
				parsed.sessionID[:],
				parsed.generation,
			)
			if err != nil {
				return Authentication{}, fmt.Errorf(
					"confirm agent session credential: %w",
					err,
				)
			}
			if !affectedAny(result) {
				return Authentication{}, ErrUnauthorized
			}
		}
		if session.pendingGeneration.Valid {
			authentication.ReplacementCredential = encodeSessionCredential(
				s.key,
				session.sessionID,
				session.pendingGeneration.Int64,
				session.listenerID,
				session.agentID,
				session.payloadBuildID,
			)
		}
	}

	if err := tx.Commit(); err != nil {
		return Authentication{}, fmt.Errorf("commit session authentication: %w", err)
	}
	return authentication, nil
}

// Rotate installs one pending generation. Repeated calls are idempotent and do
// not expose the pending credential; Authenticate delivers it to the agent.
func (s *Store) Rotate(
	ctx context.Context,
	listenerID string,
	agentID string,
) (Rotation, error) {
	if validateIdentifier(listenerID) != nil || validateIdentifier(agentID) != nil {
		return Rotation{}, ErrInvalidArgument
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Rotation{}, fmt.Errorf("begin session rotation: %w", err)
	}
	defer rollback(tx)

	session, found, err := querySessionByIdentity(ctx, tx, listenerID, agentID)
	if err != nil {
		return Rotation{}, err
	}
	if !found {
		return Rotation{}, ErrNotFound
	}
	if session.revokedAt.Valid || session.reenrollmentRequiredAt.Valid {
		return Rotation{}, ErrConflict
	}
	if session.pendingGeneration.Valid {
		if err := tx.Commit(); err != nil {
			return Rotation{}, fmt.Errorf("commit existing session rotation: %w", err)
		}
		return Rotation{
			PendingGeneration: session.pendingGeneration.Int64,
			AlreadyPending:    true,
		}, nil
	}
	if session.currentGeneration == math.MaxInt64 {
		return Rotation{}, ErrGenerationExhausted
	}
	pending := session.currentGeneration + 1
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE agent_enrollment_sessions
		 SET pending_generation = ?,
		     updated_at = ?
		 WHERE session_id = ?`,
		pending,
		formatTimestamp(s.now()),
		session.sessionID[:],
	); err != nil {
		return Rotation{}, fmt.Errorf("install pending session rotation: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Rotation{}, fmt.Errorf("commit session rotation: %w", err)
	}
	return Rotation{PendingGeneration: pending}, nil
}

// RevokeSession immediately invalidates all generations and clears any prior
// re-enrollment authorization.
func (s *Store) RevokeSession(
	ctx context.Context,
	listenerID string,
	agentID string,
) error {
	if validateIdentifier(listenerID) != nil || validateIdentifier(agentID) != nil {
		return ErrInvalidArgument
	}
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE agent_enrollment_sessions
		 SET revoked_at = COALESCE(revoked_at, ?),
		     reenrollment_required_at = NULL,
		     pending_generation = NULL,
		     updated_at = ?
		 WHERE listener_id = ?
		   AND agent_id = ?`,
		formatTimestamp(s.now()),
		formatTimestamp(s.now()),
		listenerID,
		agentID,
	)
	if err != nil {
		return fmt.Errorf("revoke agent session: %w", err)
	}
	if !affectedAny(result) {
		return ErrNotFound
	}
	return nil
}

// RequireReenrollment invalidates the current session and explicitly enables
// the next valid bootstrap to replace it. It may follow RevokeSession; without
// this distinct management action, a revoked identity cannot self-reactivate.
func (s *Store) RequireReenrollment(
	ctx context.Context,
	listenerID string,
	agentID string,
) error {
	if validateIdentifier(listenerID) != nil || validateIdentifier(agentID) != nil {
		return ErrInvalidArgument
	}
	now := formatTimestamp(s.now())
	result, err := s.db.ExecContext(
		ctx,
		`UPDATE agent_enrollment_sessions
		 SET reenrollment_required_at = COALESCE(reenrollment_required_at, ?),
		     pending_generation = NULL,
		     updated_at = ?
		 WHERE listener_id = ?
		   AND agent_id = ?`,
		now,
		now,
		listenerID,
		agentID,
	)
	if err != nil {
		return fmt.Errorf("require agent re-enrollment: %w", err)
	}
	if !affectedAny(result) {
		return ErrNotFound
	}
	return nil
}

type durableSession struct {
	sessionID              [SessionIDBytes]byte
	listenerID             string
	agentID                string
	payloadBuildID         string
	currentGeneration      int64
	pendingGeneration      sql.NullInt64
	bootstrapConsumedAt    string
	sessionConfirmedAt     sql.NullString
	reenrollmentRequiredAt sql.NullString
	lastReenrolledAt       sql.NullString
	revokedAt              sql.NullString
	createdAt              string
	updatedAt              string
}

func querySessionByIdentity(
	ctx context.Context,
	tx *sql.Tx,
	listenerID string,
	agentID string,
) (durableSession, bool, error) {
	return scanSession(tx.QueryRowContext(
		ctx,
		`SELECT
			session_id, listener_id, agent_id, payload_build_id,
			current_generation, pending_generation,
			bootstrap_consumed_at, session_confirmed_at,
			reenrollment_required_at,
			last_reenrolled_at, revoked_at, created_at, updated_at
		 FROM agent_enrollment_sessions
		 WHERE listener_id = ?
		   AND agent_id = ?`,
		listenerID,
		agentID,
	))
}

func querySessionByID(
	ctx context.Context,
	tx *sql.Tx,
	sessionID [SessionIDBytes]byte,
) (durableSession, bool, error) {
	return scanSession(tx.QueryRowContext(
		ctx,
		`SELECT
			session_id, listener_id, agent_id, payload_build_id,
			current_generation, pending_generation,
			bootstrap_consumed_at, session_confirmed_at,
			reenrollment_required_at,
			last_reenrolled_at, revoked_at, created_at, updated_at
		 FROM agent_enrollment_sessions
		 WHERE session_id = ?`,
		sessionID[:],
	))
}

type rowScanner interface {
	Scan(...any) error
}

func scanSession(row rowScanner) (durableSession, bool, error) {
	var (
		session durableSession
		rawID   []byte
	)
	err := row.Scan(
		&rawID,
		&session.listenerID,
		&session.agentID,
		&session.payloadBuildID,
		&session.currentGeneration,
		&session.pendingGeneration,
		&session.bootstrapConsumedAt,
		&session.sessionConfirmedAt,
		&session.reenrollmentRequiredAt,
		&session.lastReenrolledAt,
		&session.revokedAt,
		&session.createdAt,
		&session.updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return durableSession{}, false, nil
	}
	if err != nil {
		return durableSession{}, false, fmt.Errorf("read agent enrollment session: %w", err)
	}
	if len(rawID) != SessionIDBytes {
		return durableSession{}, false, errors.New("stored agent session identifier is invalid")
	}
	copy(session.sessionID[:], rawID)
	return session, true, nil
}

func reserveEnrollmentCapacity(
	ctx context.Context,
	tx *sql.Tx,
	listenerID string,
	agentID string,
	payloadBuildID string,
	maxSessions int,
	allocatedAt string,
) error {
	var alreadyAllocated int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT EXISTS (
			SELECT 1
			FROM payload_enrollment_allocations
		 WHERE payload_build_id = ?
		   AND listener_id = ?
		   AND agent_id = ?
		)`,
		payloadBuildID,
		listenerID,
		agentID,
	).Scan(&alreadyAllocated); err != nil {
		return fmt.Errorf("read payload enrollment allocation: %w", err)
	}
	if alreadyAllocated == 0 {
		var buildCount int
		if err := tx.QueryRowContext(
			ctx,
			`SELECT COUNT(*)
			 FROM payload_enrollment_allocations
			 WHERE payload_build_id = ?
			   AND listener_id = ?`,
			payloadBuildID,
			listenerID,
		).Scan(&buildCount); err != nil {
			return fmt.Errorf("count payload enrollment allocations: %w", err)
		}
		if buildCount >= maxSessions {
			return ErrEnrollmentCapacity
		}
	}

	var listenerCount int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM agent_enrollment_sessions
		 WHERE listener_id = ?
		   AND revoked_at IS NULL
		   AND reenrollment_required_at IS NULL`,
		listenerID,
	).Scan(&listenerCount); err != nil {
		return fmt.Errorf("count active listener sessions: %w", err)
	}
	if listenerCount >= MaxListenerSessions {
		return ErrEnrollmentCapacity
	}
	if alreadyAllocated == 0 {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO payload_enrollment_allocations (
				payload_build_id, listener_id, agent_id, allocated_at
			) VALUES (?, ?, ?, ?)`,
			payloadBuildID,
			listenerID,
			agentID,
			allocatedAt,
		); err != nil {
			return fmt.Errorf("reserve payload enrollment allocation: %w", err)
		}
	}
	return nil
}

func (s *Store) enrollmentFor(
	session durableSession,
	resumed bool,
	reenrolled bool,
) Enrollment {
	principal := principalFor(session, session.currentGeneration)
	return Enrollment{
		Principal: principal,
		Credential: encodeSessionCredential(
			s.key,
			session.sessionID,
			session.currentGeneration,
			session.listenerID,
			session.agentID,
			session.payloadBuildID,
		),
		Resumed:    resumed,
		Reenrolled: reenrolled,
	}
}

func principalFor(session durableSession, generation int64) Principal {
	return Principal{
		SessionID:      base64SessionID(session.sessionID),
		ListenerID:     session.listenerID,
		AgentID:        session.agentID,
		PayloadBuildID: session.payloadBuildID,
		Generation:     generation,
	}
}

func base64SessionID(sessionID [SessionIDBytes]byte) string {
	return base64RawURL(sessionID[:])
}

func base64RawURL(value []byte) string {
	// Kept behind a helper so durable code never treats an opaque session ID as
	// a bearer credential.
	return base64.RawURLEncoding.EncodeToString(value)
}

func (s *Store) generateSessionID() ([SessionIDBytes]byte, error) {
	var sessionID [SessionIDBytes]byte
	if _, err := io.ReadFull(s.random, sessionID[:]); err != nil {
		return [SessionIDBytes]byte{}, fmt.Errorf("generate session identifier: %w", err)
	}
	return sessionID, nil
}

func (s *Store) generateUniqueSessionID(
	ctx context.Context,
	tx *sql.Tx,
) ([SessionIDBytes]byte, error) {
	for attempt := 0; attempt < sessionIDGenerationAttempts; attempt++ {
		sessionID, err := s.generateSessionID()
		if err != nil {
			return [SessionIDBytes]byte{}, err
		}
		var exists int
		if err := tx.QueryRowContext(
			ctx,
			`SELECT EXISTS (
				SELECT 1
				FROM agent_enrollment_sessions
				WHERE session_id = ?
			)`,
			sessionID[:],
		).Scan(&exists); err != nil {
			return [SessionIDBytes]byte{}, fmt.Errorf(
				"check session identifier uniqueness: %w",
				err,
			)
		}
		if exists == 0 {
			return sessionID, nil
		}
	}
	return [SessionIDBytes]byte{}, errors.New(
		"could not allocate a unique session identifier",
	)
}

func (s *Store) dummyCredentialComparison(credential string) {
	digest, _ := bootstrapDigestForVerification(credential)
	_ = subtle.ConstantTimeCompare(digest[:], dummyVerificationValue[:])
}

func (s *Store) dummySessionComparison(
	listenerID string,
	agentID string,
	parsed parsedSessionCredential,
) {
	if parsed.generation < 1 {
		parsed.generation = 1
		copy(parsed.sessionID[:], dummyVerificationValue[:])
		copy(parsed.mac[:], dummyVerificationValue[:])
	}
	expected := sessionMAC(
		s.key,
		parsed.sessionID,
		parsed.generation,
		listenerID,
		agentID,
		"unknown-build",
	)
	_ = subtle.ConstantTimeCompare(expected[:], parsed.mac[:])
}

func validateActivation(activation PayloadCredentialActivation) error {
	if validateIdentifier(activation.PayloadBuildID) != nil ||
		validateIdentifier(activation.ListenerID) != nil ||
		activation.MaxSessions < 1 ||
		activation.MaxSessions > MaxPayloadSessions ||
		activation.BootstrapSHA256 == ([sha256.Size]byte{}) {
		return ErrInvalidArgument
	}
	return nil
}

func validateIdentifier(value string) error {
	if len(value) == 0 || len(value) > maximumIdentifierBytes {
		return ErrInvalidArgument
	}
	return nil
}

func formatTimestamp(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func affectedAny(result sql.Result) bool {
	count, err := result.RowsAffected()
	return err == nil && count > 0
}

func rollback(tx *sql.Tx) {
	if tx != nil {
		_ = tx.Rollback()
	}
}
