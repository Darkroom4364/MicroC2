package handlers

import (
	"crypto/subtle"
	"log"
	"net/http"

	"microc2/server/internal/audit"
	"microc2/server/internal/common"
)

// OperatorTokenHeader is the HTTP header used to present the operator token.
const OperatorTokenHeader = "X-Operator-Token"

const (
	loopbackOperatorActorID    = "loopback"
	sharedTokenOperatorActorID = "shared-token"
)

// OperatorGuard restricts access to operator-facing routes (web UI, operator
// API, file drop, log stream, and server terminal).
//
// Safe-lab default: loopback clients are always allowed, so local
// thesis-style testing keeps working out of the box. Non-loopback clients
// must present the configured operator token; if no token is configured,
// non-loopback access is denied entirely.
type OperatorGuard struct {
	token          string
	allowedOrigins []string
}

// NewOperatorGuard creates a guard with the given shared token and allowed
// browser origins. An empty token means loopback-only operator access.
func NewOperatorGuard(token string, allowedOrigins []string) *OperatorGuard {
	return &OperatorGuard{token: token, allowedOrigins: allowedOrigins}
}

// Wrap returns middleware that enforces the guard on every request.
func (g *OperatorGuard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, authorized := g.authorizedActor(r)
		if !authorized {
			log.Printf("[SECURITY] Denied unauthorized operator request")
			http.Error(w, "Forbidden: operator access requires a loopback client or a valid operator token", http.StatusForbidden)
			return
		}
		if !common.IsOriginAllowed(r.Header.Get("Origin"), r, g.allowedOrigins) {
			log.Printf("[SECURITY] Denied operator request from an untrusted origin")
			http.Error(w, "Forbidden: operator origin is not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(
			w,
			r.WithContext(audit.WithActor(r.Context(), actor)),
		)
	})
}

// Authorized reports whether the request may reach operator routes.
func (g *OperatorGuard) Authorized(r *http.Request) bool {
	_, authorized := g.authorizedActor(r)
	return authorized
}

func (g *OperatorGuard) authorizedActor(r *http.Request) (audit.Actor, bool) {
	if common.IsLoopbackHost(r.RemoteAddr) {
		return audit.Actor{
			Kind: audit.ActorOperator,
			ID:   loopbackOperatorActorID,
		}, true
	}
	if g.token == "" {
		return audit.Actor{}, false
	}
	provided := r.Header.Get(OperatorTokenHeader)
	if provided == "" {
		return audit.Actor{}, false
	}
	if subtle.ConstantTimeCompare([]byte(provided), []byte(g.token)) != 1 {
		return audit.Actor{}, false
	}
	return audit.Actor{
		Kind: audit.ActorOperator,
		ID:   sharedTokenOperatorActorID,
	}, true
}

// CheckOrigin validates the Origin header for operator WebSocket upgrades
// (log stream and terminal), blocking cross-site WebSocket hijacking from
// origins that are not configured or same-host.
func (g *OperatorGuard) CheckOrigin(r *http.Request) bool {
	allowed := common.IsOriginAllowed(r.Header.Get("Origin"), r, g.allowedOrigins)
	if !allowed {
		log.Printf("[SECURITY] Denied WebSocket request from an untrusted origin")
	}
	return allowed
}
