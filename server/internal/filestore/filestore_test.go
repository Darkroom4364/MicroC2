package filestore

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateFileName(t *testing.T) {
	valid := []string{"loot.txt", "screenshot-01.png", "archive.tar.gz"}
	for _, name := range valid {
		if err := ValidateFileName(name); err != nil {
			t.Errorf("expected %q to be valid, got %v", name, err)
		}
	}

	invalid := []string{
		"", ".", "..",
		"../secret", "sub/dir.txt", "/etc/passwd",
		"..\\windows\\system32", "a/b", "nul\x00byte",
	}
	for _, name := range invalid {
		err := ValidateFileName(name)
		if !errors.Is(err, ErrInvalidFileName) {
			t.Errorf("expected %q to be rejected with ErrInvalidFileName, got %v", name, err)
		}
	}
}

func TestServeFileRejectsTraversal(t *testing.T) {
	fs := newTestStore(t)

	// A file outside the store that must never be served.
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("top secret"), 0644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/file_drop/download/../secret.txt", nil)
	err := fs.ServeFile("../secret.txt", rec, req)
	if !errors.Is(err, ErrInvalidFileName) {
		t.Fatalf("expected ErrInvalidFileName, got %v", err)
	}
}

func TestServeFileServesBasename(t *testing.T) {
	fs := newTestStore(t)
	if err := os.WriteFile(filepath.Join(fs.baseDir, "loot.txt"), []byte("data"), 0644); err != nil {
		t.Fatalf("write store file: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/file_drop/download/loot.txt", nil)
	if err := fs.ServeFile("loot.txt", rec, req); err != nil {
		t.Fatalf("expected basename to be served, got %v", err)
	}
	if rec.Body.String() != "data" {
		t.Fatalf("unexpected body %q", rec.Body.String())
	}
}

func TestDeleteFileRejectsTraversal(t *testing.T) {
	fs := newTestStore(t)
	outsideDir := t.TempDir()
	victim := filepath.Join(outsideDir, "victim.txt")
	if err := os.WriteFile(victim, []byte("keep me"), 0644); err != nil {
		t.Fatalf("write victim file: %v", err)
	}

	rel, err := filepath.Rel(fs.baseDir, victim)
	if err != nil {
		t.Fatalf("compute relative path: %v", err)
	}
	if err := fs.DeleteFile(rel); !errors.Is(err, ErrInvalidFileName) {
		t.Fatalf("expected ErrInvalidFileName for %q, got %v", rel, err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("victim file must not be deleted: %v", err)
	}
}

func TestHandleUploadSanitizesTraversalFilename(t *testing.T) {
	fs := newTestStore(t)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("files", "../evil.sh")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write([]byte("pwn")); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/file_drop/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	if err := fs.HandleUpload(req); err != nil {
		t.Fatalf("expected sanitized upload to succeed, got %v", err)
	}
	// The file must land inside the store under its plain basename.
	if _, err := os.Stat(filepath.Join(fs.baseDir, "evil.sh")); err != nil {
		t.Fatalf("expected upload stored as basename inside the store: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fs.baseDir, "..", "evil.sh")); !os.IsNotExist(err) {
		t.Fatal("traversal upload must not create a file outside the store")
	}
}

func TestHandleUploadAcceptsBasename(t *testing.T) {
	fs := newTestStore(t)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("files", "loot.txt")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write([]byte("data")); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/file_drop/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	if err := fs.HandleUpload(req); err != nil {
		t.Fatalf("expected basename upload to succeed, got %v", err)
	}
	content, err := os.ReadFile(filepath.Join(fs.baseDir, "loot.txt"))
	if err != nil || string(content) != "data" {
		t.Fatalf("uploaded file mismatch: content=%q err=%v", content, err)
	}
}

func newTestStore(t *testing.T) *FileStore {
	t.Helper()
	fs, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("create file store: %v", err)
	}
	return fs
}
