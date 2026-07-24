package api

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"microc2/server/internal/audit"
	"microc2/server/internal/filestore"
	"microc2/server/internal/persistence"
)

func TestAuditedFileLifecycleRecordsTargetsWithoutContent(t *testing.T) {
	root := t.TempDir()
	database, err := persistence.Open(filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	auditStore, err := audit.NewStore(database)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	fileStore, err := filestore.New(filepath.Join(root, "files"))
	if err != nil {
		t.Fatalf("create file store: %v", err)
	}
	handler := NewAuditedFileHandlers(fileStore, auditStore)

	const secretContent = "file-content-canary-must-not-be-audited"
	uploadRequest := auditedMultipartRequest(
		t,
		"/api/file_drop/upload",
		"evidence.txt",
		secretContent,
	)
	uploadResponse := httptest.NewRecorder()
	handler.HandleFileUpload(uploadResponse, uploadRequest)
	if uploadResponse.Code != http.StatusOK {
		t.Fatalf(
			"upload status = %d: %s",
			uploadResponse.Code,
			uploadResponse.Body.String(),
		)
	}

	downloadRequest := auditedFileRequest(
		http.MethodGet,
		"/api/file_drop/download/evidence.txt",
	)
	downloadResponse := httptest.NewRecorder()
	handler.HandleFileDownload(downloadResponse, downloadRequest)
	if downloadResponse.Code != http.StatusOK ||
		downloadResponse.Body.String() != secretContent {
		t.Fatalf(
			"download response = %d %q",
			downloadResponse.Code,
			downloadResponse.Body.String(),
		)
	}

	deleteRequest := auditedFileRequest(
		http.MethodDelete,
		"/api/file_drop/delete/evidence.txt",
	)
	deleteResponse := httptest.NewRecorder()
	handler.HandleFileDelete(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusOK {
		t.Fatalf(
			"delete status = %d: %s",
			deleteResponse.Code,
			deleteResponse.Body.String(),
		)
	}

	page, err := auditStore.Page(
		uploadRequest.Context(),
		audit.PageOptions{Limit: 20},
	)
	if err != nil {
		t.Fatalf("list audit page: %v", err)
	}
	var actions []string
	for index := len(page.Events) - 1; index >= 0; index-- {
		event := page.Events[index]
		actions = append(actions, event.Action)
		if event.Actor != (audit.Actor{
			Kind: audit.ActorOperator,
			ID:   "loopback",
		}) {
			t.Fatalf("unexpected file actor: %#v", event.Actor)
		}
	}
	gotActions := strings.Join(actions, ",")
	if gotActions != strings.Join([]string{
		"file.upload.requested",
		"file.upload",
		"file.download.requested",
		"file.download",
		"file.delete.requested",
		"file.delete",
	}, ",") {
		t.Fatalf("file audit actions = %q", gotActions)
	}

	var leaked int
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*)
		 FROM audit_events
		 WHERE actor_id LIKE '%' || ? || '%'
		    OR action LIKE '%' || ? || '%'
		    OR route LIKE '%' || ? || '%'
		    OR target_id LIKE '%' || ? || '%'
		    OR COALESCE(reason_code, '') LIKE '%' || ? || '%'`,
		secretContent,
		secretContent,
		secretContent,
		secretContent,
		secretContent,
	).Scan(&leaked); err != nil {
		t.Fatalf("search audit rows for file content: %v", err)
	}
	if leaked != 0 {
		t.Fatal("file content leaked into structured audit fields")
	}
}

func TestAuditedFileUploadRejectsOversizedMultipartRequest(t *testing.T) {
	root := t.TempDir()
	database, err := persistence.Open(filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	auditStore, err := audit.NewStore(database)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	fileStore, err := filestore.New(filepath.Join(root, "files"))
	if err != nil {
		t.Fatalf("create file store: %v", err)
	}
	handler := NewAuditedFileHandlers(fileStore, auditStore)

	request := auditedFileRequest(
		http.MethodPost,
		"/api/file_drop/upload",
	)
	request.Body = io.NopCloser(strings.NewReader("oversized"))
	request.ContentLength = filestore.MaxUploadRequestBytes + 1
	request.Header.Set("Content-Type", "multipart/form-data; boundary=test")
	response := httptest.NewRecorder()
	handler.HandleFileUpload(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf(
			"oversized upload status = %d, want 413: %s",
			response.Code,
			response.Body.String(),
		)
	}

	page, err := auditStore.Page(
		request.Context(),
		audit.PageOptions{Limit: 10},
	)
	if err != nil {
		t.Fatalf("page oversized upload audit: %v", err)
	}
	if page.Total != 2 ||
		page.Events[0].Action != "file.upload" ||
		page.Events[0].Outcome != audit.OutcomeFailed ||
		page.Events[0].ReasonCode != "request_too_large" ||
		page.Events[1].Action != "file.upload.requested" ||
		page.Events[0].CausationSequence == nil ||
		*page.Events[0].CausationSequence != page.Events[1].Sequence {
		t.Fatalf("unexpected oversized upload audit chain: %#v", page.Events)
	}
}

func TestAuditedFileDownloadRecordsResponseWriteFailure(t *testing.T) {
	root := t.TempDir()
	database, err := persistence.Open(filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	auditStore, err := audit.NewStore(database)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	filesDir := filepath.Join(root, "files")
	fileStore, err := filestore.New(filesDir)
	if err != nil {
		t.Fatalf("create file store: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(filesDir, "evidence.txt"),
		[]byte("evidence"),
		0o600,
	); err != nil {
		t.Fatalf("write file: %v", err)
	}
	handler := NewAuditedFileHandlers(fileStore, auditStore)
	request := auditedFileRequest(
		http.MethodGet,
		"/api/file_drop/download/evidence.txt",
	)
	response := &failingFileResponseWriter{header: make(http.Header)}
	handler.HandleFileDownload(response, request)

	page, err := auditStore.Page(
		request.Context(),
		audit.PageOptions{Limit: 10},
	)
	if err != nil {
		t.Fatalf("page failed download audit: %v", err)
	}
	if page.Total != 2 ||
		page.Events[0].Action != "file.download" ||
		page.Events[0].Outcome != audit.OutcomeFailed ||
		page.Events[0].ReasonCode != "response_write_failed" ||
		page.Events[1].Action != "file.download.requested" ||
		page.Events[0].CausationSequence == nil ||
		*page.Events[0].CausationSequence != page.Events[1].Sequence {
		t.Fatalf("unexpected failed download audit chain: %#v", page.Events)
	}
}

type failingFileResponseWriter struct {
	header http.Header
	status int
}

func (w *failingFileResponseWriter) Header() http.Header {
	return w.header
}

func (w *failingFileResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *failingFileResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("injected client write failure")
}

func auditedMultipartRequest(
	t *testing.T,
	path string,
	name string,
	content string,
) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("files", name)
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		t.Fatalf("write multipart file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart body: %v", err)
	}
	request := auditedFileRequest(http.MethodPost, path)
	request.Body = io.NopCloser(bytes.NewReader(body.Bytes()))
	request.ContentLength = int64(body.Len())
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func auditedFileRequest(method, path string) *http.Request {
	request := httptest.NewRequest(method, path, nil)
	return request.WithContext(audit.WithActor(
		request.Context(),
		audit.Actor{Kind: audit.ActorOperator, ID: "loopback"},
	))
}
