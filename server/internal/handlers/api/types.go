package api

import (
	"microc2/server/internal/enrollment"
	"microc2/server/internal/filestore"
	"microc2/server/internal/listeners" // Updated from `networking`
	"microc2/server/internal/protocols" // Updated from `networking`
	"microc2/server/pkg/communication"
)

// APIHandler handles API requests and responses
type APIHandler struct {
	serverManager *communication.ServerManager
}

// FileHandlers manages HTTP endpoints for file operations
// It coordinates file uploads, downloads, listings, and deletions
// using the underlying filestore system.
type FileHandlers struct {
	fileStore *filestore.FileStore
}

// ListenerHandlers manages HTTP handlers for listener operations
type ListenerHandlers struct {
	manager       *listeners.ListenerManager
	enrollment    *enrollment.Store
	enrollmentErr error
}

// SOCKS5Handler handles SOCKS5 management API endpoints
type SOCKS5Handler struct {
	protocol *protocols.SOCKS5Protocol
}
