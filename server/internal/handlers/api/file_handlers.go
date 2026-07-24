package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"microc2/server/internal/audit"
	"microc2/server/internal/common"
	"microc2/server/internal/filestore"
	"microc2/server/internal/handlers/api/payload"
	"microc2/server/internal/listeners" // Updated from `networking`
	"microc2/server/internal/persistence"
)

// NewFileHandlers creates a new file handlers instance
//
// Pre-conditions:
//   - fileStore is a properly initialized FileStore instance
//
// Post-conditions:
//   - Returns a configured FileHandlers instance ready to handle HTTP requests
func NewFileHandlers(fileStore *filestore.FileStore) *FileHandlers {
	return NewAuditedFileHandlers(fileStore, nil)
}

// NewAuditedFileHandlers creates file-drop handlers that fail closed before
// external side effects when the durable audit authorization cannot be
// recorded.
func NewAuditedFileHandlers(
	fileStore *filestore.FileStore,
	auditStore *audit.Store,
) *FileHandlers {
	return &FileHandlers{
		fileStore: fileStore,
		audit:     auditStore,
	}
}

// HandleFileUpload processes file upload requests
//
// Pre-conditions:
//   - Request is a POST multipart/form/data request
//   - Request contains one or more files in the "files" field
//
// Post-conditions:
//   - Uploaded files are saved to the file store
//   - Returns 200 OK on success
//   - Returns appropriate error status on failure
func (h *FileHandlers) HandleFileUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requested, err := h.appendFileAudit(r, audit.Input{
		Action:  "file.upload.requested",
		Route:   "POST /api/file_drop/upload",
		Target:  audit.Target{Kind: "file_drop", ID: "upload"},
		Outcome: audit.OutcomeSucceeded,
	})
	if err != nil {
		http.Error(w, "File upload audit is unavailable", http.StatusServiceUnavailable)
		return
	}

	files, uploadErr := h.fileStore.HandleUploadWithInfo(r)
	for _, file := range files {
		causation := requested.Sequence
		if _, err := h.appendFileAudit(r, audit.Input{
			Action:            "file.upload",
			Route:             "POST /api/file_drop/upload",
			Target:            audit.Target{Kind: "file", ID: file.Name},
			Outcome:           audit.OutcomeSucceeded,
			CausationSequence: optionalAuditSequence(causation),
			FileName:          file.Name,
		}); err != nil {
			log.Printf("[ERROR] Failed to record committed file upload")
			http.Error(w, "File upload audit is unavailable", http.StatusInternalServerError)
			return
		}
	}
	if uploadErr != nil {
		causation := requested.Sequence
		reason := "upload_failed"
		status := http.StatusInternalServerError
		var maxBytesError *http.MaxBytesError
		switch {
		case errors.As(uploadErr, &maxBytesError):
			reason = "request_too_large"
			status = http.StatusRequestEntityTooLarge
		case errors.Is(uploadErr, filestore.ErrInvalidFileName):
			reason = "invalid_file_name"
			status = http.StatusBadRequest
		}
		if _, auditErr := h.appendFileAudit(r, audit.Input{
			Action:            "file.upload",
			Route:             "POST /api/file_drop/upload",
			Target:            audit.Target{Kind: "file_drop", ID: "upload"},
			Outcome:           audit.OutcomeFailed,
			ReasonCode:        reason,
			CausationSequence: optionalAuditSequence(causation),
		}); auditErr != nil {
			log.Printf("[ERROR] Failed to record rejected file upload")
			http.Error(w, "File upload audit is unavailable", http.StatusInternalServerError)
			return
		}
		if status == http.StatusBadRequest {
			http.Error(w, "Invalid file name", status)
			return
		}
		if status == http.StatusRequestEntityTooLarge {
			http.Error(w, "Upload request is too large", status)
			return
		}
		http.Error(w, "Failed to upload file", status)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HandleFileList returns a list of files in the file store
//
// Pre-conditions:
//   - Request is a GET request
//
// Post-conditions:
//   - Response contains a JSON array of file information objects
//   - Each object includes file name, size, and modification time
//   - Returns appropriate error status on failure
func (h *FileHandlers) HandleFileList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	files, err := h.fileStore.ListFiles()
	if err != nil {
		log.Print("[ERROR] Failed to list file-drop contents")
		http.Error(w, "Failed to list files", http.StatusInternalServerError)
		return
	}
	if _, err := h.appendFileAudit(r, audit.Input{
		Action:  "file.list",
		Route:   "GET /api/file_drop/list",
		Target:  audit.Target{Kind: "file_drop", ID: "collection"},
		Outcome: audit.OutcomeSucceeded,
	}); err != nil {
		http.Error(w, "File list audit is unavailable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

// HandleFileDownload serves a file for download
//
// Pre-conditions:
//   - Request is a GET request
//   - Request URL contains the file name after "/api/file_drop/download/"
//
// Post-conditions:
//   - Requested file is served for download if it exists
//   - Appropriate Content-Disposition and Content-Type headers are set
//   - Returns 404 Not Found if the file doesn't exist
//   - Returns appropriate error status on other failures
func (h *FileHandlers) HandleFileDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fileName := strings.TrimPrefix(r.URL.Path, "/api/file_drop/download/")
	if fileName == "" {
		http.Error(w, "File name is required", http.StatusBadRequest)
		return
	}

	file, info, err := h.fileStore.OpenFile(fileName)
	if err != nil {
		if errors.Is(err, filestore.ErrInvalidFileName) {
			http.Error(w, "Invalid file name", http.StatusBadRequest)
			return
		}
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()
	modified, err := time.Parse(time.RFC3339, info.Modified)
	if err != nil {
		http.Error(w, "File metadata is invalid", http.StatusInternalServerError)
		return
	}
	requested, err := h.appendFileAudit(r, audit.Input{
		Action:   "file.download.requested",
		Route:    "GET /api/file_drop/download/{file_name}",
		Target:   audit.Target{Kind: "file", ID: info.Name},
		Outcome:  audit.OutcomeSucceeded,
		FileName: info.Name,
	})
	if err != nil {
		http.Error(w, "File download audit is unavailable", http.StatusServiceUnavailable)
		return
	}
	disposition := mime.FormatMediaType(
		"attachment",
		map[string]string{"filename": info.Name},
	)
	w.Header().Set("Content-Disposition", disposition)
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	trackedWriter := &fileDownloadResponseWriter{ResponseWriter: w}
	http.ServeContent(trackedWriter, r, info.Name, modified, file)

	outcome := audit.OutcomeSucceeded
	reasonCode := ""
	switch {
	case trackedWriter.writeErr != nil:
		outcome = audit.OutcomeFailed
		reasonCode = "response_write_failed"
	case trackedWriter.statusCode >= http.StatusBadRequest:
		outcome = audit.OutcomeFailed
		reasonCode = "response_rejected"
	}
	if _, err := h.appendFileAudit(r, audit.Input{
		Action:            "file.download",
		Route:             "GET /api/file_drop/download/{file_name}",
		Target:            audit.Target{Kind: "file", ID: info.Name},
		Outcome:           outcome,
		ReasonCode:        reasonCode,
		CausationSequence: optionalAuditSequence(requested.Sequence),
		FileName:          info.Name,
	}); err != nil {
		log.Printf("[ERROR] Failed to record completed file download")
	}
}

// HandleFileDelete deletes a file from the file store
//
// Pre-conditions:
//   - Request is a DELETE request
//   - Request URL contains the file name after "/api/file_drop/delete/"
//
// Post-conditions:
//   - Requested file is deleted if it exists
//   - Returns 200 OK on success
//   - Returns 404 Not Found if the file doesn't exist
//   - Returns appropriate error status on other failures
func (h *FileHandlers) HandleFileDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fileName := strings.TrimPrefix(r.URL.Path, "/api/file_drop/delete/")
	if fileName == "" {
		http.Error(w, "File name is required", http.StatusBadRequest)
		return
	}
	if err := filestore.ValidateFileName(fileName); err != nil {
		http.Error(w, "Invalid file name", http.StatusBadRequest)
		return
	}
	requested, err := h.appendFileAudit(r, audit.Input{
		Action:   "file.delete.requested",
		Route:    "DELETE /api/file_drop/delete/{file_name}",
		Target:   audit.Target{Kind: "file", ID: fileName},
		Outcome:  audit.OutcomeSucceeded,
		FileName: fileName,
	})
	if err != nil {
		http.Error(w, "File delete audit is unavailable", http.StatusServiceUnavailable)
		return
	}

	err = h.fileStore.DeleteFile(fileName)
	if err != nil {
		reason := "delete_failed"
		if errors.Is(err, filestore.ErrInvalidFileName) {
			reason = "invalid_file_name"
		} else if errors.Is(err, os.ErrNotExist) {
			reason = "not_found"
		}
		if _, auditErr := h.appendFileAudit(r, audit.Input{
			Action:            "file.delete",
			Route:             "DELETE /api/file_drop/delete/{file_name}",
			Target:            audit.Target{Kind: "file", ID: fileName},
			Outcome:           audit.OutcomeFailed,
			ReasonCode:        reason,
			CausationSequence: optionalAuditSequence(requested.Sequence),
			FileName:          fileName,
		}); auditErr != nil {
			http.Error(w, "File delete audit is unavailable", http.StatusInternalServerError)
			return
		}
		if errors.Is(err, filestore.ErrInvalidFileName) {
			http.Error(w, "Invalid file name", http.StatusBadRequest)
		} else if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "File not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to delete file", http.StatusInternalServerError)
		}
		return
	}
	if _, err := h.appendFileAudit(r, audit.Input{
		Action:            "file.delete",
		Route:             "DELETE /api/file_drop/delete/{file_name}",
		Target:            audit.Target{Kind: "file", ID: fileName},
		Outcome:           audit.OutcomeSucceeded,
		CausationSequence: optionalAuditSequence(requested.Sequence),
		FileName:          fileName,
	}); err != nil {
		http.Error(w, "File delete audit is unavailable", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *FileHandlers) appendFileAudit(
	r *http.Request,
	input audit.Input,
) (audit.Event, error) {
	if h.audit == nil {
		return audit.Event{}, nil
	}
	input.Actor = audit.ActorOr(r.Context(), audit.DefaultOperatorActor())
	return h.audit.Append(context.WithoutCancel(r.Context()), input)
}

type fileDownloadResponseWriter struct {
	http.ResponseWriter
	statusCode int
	writeErr   error
}

func (w *fileDownloadResponseWriter) WriteHeader(statusCode int) {
	if w.statusCode == 0 {
		w.statusCode = statusCode
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *fileDownloadResponseWriter) Write(content []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	written, err := w.ResponseWriter.Write(content)
	if err == nil && written != len(content) {
		err = io.ErrShortWrite
	}
	if err != nil && w.writeErr == nil {
		w.writeErr = err
	}
	return written, err
}

func optionalAuditSequence(sequence int64) *int64 {
	if sequence <= 0 {
		return nil
	}
	value := sequence
	return &value
}

// PayloadHandlerSetup creates and initializes a new payload handler
func PayloadHandlerSetup(
	payloadsDir string,
	agentSourceDir string,
	manager *listeners.ListenerManager,
	database *persistence.Database,
	transportPolicy common.AgentTransportPolicy,
) (*payload.PayloadHandler, error) {
	return payload.NewProductionPayloadHandler(
		payloadsDir,
		agentSourceDir,
		managerListenerLookup{manager: manager},
		database,
		transportPolicy,
	)
}

type managerListenerLookup struct {
	manager *listeners.ListenerManager
}

func (lookup managerListenerLookup) LookupListener(
	listenerID string,
) (listeners.ListenerConfig, error) {
	if lookup.manager == nil {
		return listeners.ListenerConfig{}, errors.New("listener manager is unavailable")
	}
	listener, err := lookup.manager.GetListener(listenerID)
	if err != nil {
		return listeners.ListenerConfig{}, err
	}
	return listener.Snapshot().Config, nil
}
