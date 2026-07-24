// Package enrollment implements durable, listener-scoped agent enrollment and
// bearer-session authentication.
package enrollment

import (
	"errors"
)

const (
	// BootstrapCredentialBytes is the entropy carried by a payload bootstrap
	// credential before unpadded base64url encoding.
	BootstrapCredentialBytes = 32

	// SessionIDBytes is the size of the opaque identifier embedded in a signed
	// session credential.
	SessionIDBytes = 32

	// MaxPayloadSessions is the largest immutable enrollment allowance for one
	// payload build.
	MaxPayloadSessions = 64

	// MaxListenerSessions is the hard process-independent active-session cap
	// for one listener.
	MaxListenerSessions = 4096
)

var (
	// ErrUnauthorized deliberately covers every credential, binding, session
	// state, and token-generation failure. Callers must not turn the underlying
	// distinction into an agent-visible response.
	ErrUnauthorized = errors.New("agent authentication failed")

	// ErrEnrollmentCapacity is returned after a valid bootstrap credential
	// reaches either its build allowance or the listener-wide hard cap.
	ErrEnrollmentCapacity = errors.New("agent enrollment capacity reached")

	// ErrInvalidArgument identifies an invalid trusted-caller input. It is not
	// returned for untrusted bearer or bootstrap credential parsing.
	ErrInvalidArgument = errors.New("invalid enrollment argument")

	// ErrConflict identifies a valid management operation that conflicts with
	// durable enrollment state.
	ErrConflict = errors.New("enrollment state conflict")

	// ErrNotFound identifies a missing record requested by a trusted management
	// operation.
	ErrNotFound = errors.New("enrollment record not found")

	// ErrGenerationExhausted prevents the signed-token generation counter from
	// wrapping.
	ErrGenerationExhausted = errors.New("session generation exhausted")
)

// BootstrapCredential contains the one-time build output and the only form
// that may be persisted. Public must be delivered to the payload exactly once;
// SHA256 is safe to store in SQLite.
type BootstrapCredential struct {
	Public string
	SHA256 [32]byte
}

// PayloadCredentialActivation binds a bootstrap hash to exactly one persisted
// payload build and listener. MaxSessions is immutable after activation.
type PayloadCredentialActivation struct {
	PayloadBuildID  string
	ListenerID      string
	BootstrapSHA256 [32]byte
	MaxSessions     int
}

// EnrollRequest is presented by an agent that does not yet have a session
// credential, or that was explicitly marked for re-enrollment.
type EnrollRequest struct {
	ListenerID     string
	AgentID        string
	PayloadBuildID string
	Bootstrap      string
}

// Principal is the durable identity established by a valid session
// credential.
type Principal struct {
	SessionID      string
	ListenerID     string
	AgentID        string
	PayloadBuildID string
	Generation     int64
}

// Enrollment returns the signed credential an agent must use after bootstrap.
// Resumed means an identical, already-active enrollment was recovered after a
// possible response loss. Reenrolled means an operator-authorized
// re-enrollment replaced the prior opaque session.
type Enrollment struct {
	Principal
	Credential string
	Resumed    bool
	Reenrolled bool
}

// Authentication is returned for a valid session bearer. When a rotation is
// pending, authenticating with the current generation returns the same
// ReplacementCredential until the agent uses it. Authenticating with that
// pending credential promotes it atomically and sets Promoted.
type Authentication struct {
	Principal
	ReplacementCredential string
	Promoted              bool
}

// Rotation reports durable rotation state without exposing the pending bearer
// to an operator-facing management route.
type Rotation struct {
	PendingGeneration int64
	AlreadyPending    bool
}

// ParsedSessionCredential is the non-secret routing portion of a strictly
// parsed s1 credential. Parsing alone does not authenticate it.
type ParsedSessionCredential struct {
	SessionID  string
	Generation int64
}
