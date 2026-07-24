package ws

import (
	"context"
	"log"
	"net/http"

	"github.com/google/uuid"

	"microc2/server/internal/audit"
	"microc2/server/internal/websocket"
)

const (
	terminalRoute          = "/ws/terminal"
	terminalTargetKind     = "terminal_session"
	terminalAccessAction   = "terminal.access.requested"
	terminalOpenAction     = "terminal.session.opened"
	terminalCloseAction    = "terminal.session.closed"
	terminalDisabledReason = "feature_disabled"
)

// New creates a new websocket handler with the provided log streamer
//
// Pre-conditions:
//   - logStreamer is a properly initialized LogStreamer instance
//   - checkOrigin validates WebSocket upgrade origins; if nil, the default
//     same-origin policy is used
//
// Post-conditions:
//   - Returns a configured websocket Handler instance
//   - Terminal handler is initialized but disabled
func New(logStreamer *websocket.LogStreamer, checkOrigin func(*http.Request) bool) *Handler {
	return NewWithTerminalPolicy(logStreamer, checkOrigin, false, nil)
}

// NewWithTerminalPolicy creates a WebSocket handler with an explicit server
// terminal policy and durable audit store. An enabled terminal without a
// working auditor fails closed before WebSocket upgrade.
func NewWithTerminalPolicy(
	logStreamer *websocket.LogStreamer,
	checkOrigin func(*http.Request) bool,
	enableTerminal bool,
	auditor *audit.Store,
) *Handler {
	return &Handler{
		logStreamer:     logStreamer,
		terminalHandler: websocket.NewTerminalHandler(checkOrigin),
		terminalEnabled: enableTerminal,
		terminalAuditor: auditor,
	}
}

// HandleLogStream handles websocket connections for streaming server logs
//
// Pre-conditions:
//   - Valid HTTP request and response writer
//   - Client supports WebSocket protocol
//
// Post-conditions:
//   - Websocket connection established for log streaming
//   - Log entries are streamed to the client until connection closed
//   - Resources are properly cleaned up on disconnect
func (h *Handler) HandleLogStream(w http.ResponseWriter, r *http.Request) {
	h.logStreamer.HandleConnection(w, r)
}

// HandleTerminal handles websocket connections for terminal sessions
//
// Pre-conditions:
//   - Valid HTTP request and response writer
//   - Client supports WebSocket protocol
//
// Post-conditions:
//   - Websocket connection established for terminal interaction
//   - Client commands are executed and results returned
//   - Terminal session is maintained until connection closed
//   - Resources are properly cleaned up on disconnect
func (h *Handler) HandleTerminal(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := audit.ActorFromContext(r.Context())
	if !ok {
		log.Printf("[SECURITY] Denied server terminal request without a trusted operator actor")
		http.Error(w, "Forbidden: terminal access requires an authenticated operator", http.StatusForbidden)
		return
	}
	if h.terminalAuditor == nil {
		log.Printf("[ERROR] Server terminal audit store is unavailable")
		http.Error(w, "Server terminal is unavailable", http.StatusServiceUnavailable)
		return
	}

	sessionID := uuid.NewString()
	auditContext := context.WithoutCancel(r.Context())
	requestInput := audit.Input{
		Actor:  actor,
		Action: terminalAccessAction,
		Route:  terminalRoute,
		Target: audit.Target{
			Kind: terminalTargetKind,
			ID:   sessionID,
		},
		Outcome:           audit.OutcomeSucceeded,
		TerminalSessionID: sessionID,
	}
	if !h.terminalEnabled {
		requestInput.Outcome = audit.OutcomeDenied
		requestInput.ReasonCode = terminalDisabledReason
		if _, err := h.terminalAuditor.Append(auditContext, requestInput); err != nil {
			log.Printf("[ERROR] Failed to audit denied server terminal access")
			http.Error(w, "Server terminal is unavailable", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "Forbidden: server terminal is disabled", http.StatusForbidden)
		return
	}

	requested, err := h.terminalAuditor.Append(auditContext, requestInput)
	if err != nil {
		log.Printf("[ERROR] Failed to audit server terminal access request")
		http.Error(w, "Server terminal is unavailable", http.StatusServiceUnavailable)
		return
	}

	var openedSequence int64
	h.terminalHandler.HandleConnectionWithLifecycle(
		w,
		r,
		func() error {
			causation := requested.Sequence
			opened, err := h.terminalAuditor.Append(auditContext, audit.Input{
				Actor:  actor,
				Action: terminalOpenAction,
				Route:  terminalRoute,
				Target: audit.Target{
					Kind: terminalTargetKind,
					ID:   sessionID,
				},
				Outcome:           audit.OutcomeSucceeded,
				CausationSequence: &causation,
				TerminalSessionID: sessionID,
			})
			if err != nil {
				log.Printf("[ERROR] Failed to audit opened server terminal session")
				return err
			}
			openedSequence = opened.Sequence
			return nil
		},
		func() {
			causation := openedSequence
			if _, err := h.terminalAuditor.Append(auditContext, audit.Input{
				Actor:  actor,
				Action: terminalCloseAction,
				Route:  terminalRoute,
				Target: audit.Target{
					Kind: terminalTargetKind,
					ID:   sessionID,
				},
				Outcome:           audit.OutcomeSucceeded,
				CausationSequence: &causation,
				TerminalSessionID: sessionID,
			}); err != nil {
				log.Printf("[ERROR] Failed to audit closed server terminal session")
			}
		},
	)
}
