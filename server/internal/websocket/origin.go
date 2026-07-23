package websocket

import (
	"net/http"

	"microc2/server/internal/common"
)

// DefaultOriginCheck is the fallback WebSocket origin policy used when no
// explicit checker is configured: it allows non-browser clients (no Origin
// header) and same-host origins, and rejects everything else.
func DefaultOriginCheck(r *http.Request) bool {
	return common.IsOriginAllowed(r.Header.Get("Origin"), r.Host, nil)
}
