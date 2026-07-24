package ws

import (
	"microc2/server/internal/audit"
	"microc2/server/internal/websocket"
)

// Handler manages websocket connections for the server application
// It provides handlers for log streaming and terminal sessions.
type Handler struct {
	logStreamer     *websocket.LogStreamer
	terminalHandler *websocket.TerminalHandler
	terminalEnabled bool
	terminalAuditor *audit.Store
}
