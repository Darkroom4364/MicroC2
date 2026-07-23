package ws

import (
	"net/http"

	"microc2/server/internal/websocket"
)

// New creates a new websocket handler with the provided log streamer
//
// Pre-conditions:
//   - logStreamer is a properly initialized LogStreamer instance
//   - checkOrigin validates WebSocket upgrade origins; if nil, the default
//     same-host/loopback-only policy is used
//
// Post-conditions:
//   - Returns a configured websocket Handler instance
//   - Terminal handler is initialized
func New(logStreamer *websocket.LogStreamer, checkOrigin func(*http.Request) bool) *Handler {
	return &Handler{
		logStreamer:     logStreamer,
		terminalHandler: websocket.NewTerminalHandler(checkOrigin),
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
	h.terminalHandler.HandleConnection(w, r)
}
