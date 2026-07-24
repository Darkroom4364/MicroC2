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

func TestHandleUploadWithInfoReportsCommittedFiles(t *testing.T) {
	fs := newTestStore(t)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for name, content := range map[string]string{
		"first.txt":  "one",
		"second.txt": "second",
	} {
		part, err := writer.CreateFormFile("files", name)
		if err != nil {
			t.Fatalf("create form file %s: %v", name, err)
		}
		if _, err := part.Write([]byte(content)); err != nil {
			t.Fatalf("write form file %s: %v", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/file_drop/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	uploaded, err := fs.HandleUploadWithInfo(req)
	if err != nil {
		t.Fatalf("upload with metadata: %v", err)
	}
	if len(uploaded) != 2 {
		t.Fatalf("uploaded metadata count = %d, want 2", len(uploaded))
	}
	byName := make(map[string]FileInfo, len(uploaded))
	for _, info := range uploaded {
		byName[info.Name] = info
	}
	if byName["first.txt"].Size != 3 || byName["second.txt"].Size != 6 {
		t.Fatalf("unexpected upload metadata: %#v", byName)
	}
	stagingFiles, err := filepath.Glob(
		filepath.Join(fs.baseDir, ".microc2-upload-*"),
	)
	if err != nil {
		t.Fatalf("glob upload staging files: %v", err)
	}
	if len(stagingFiles) != 0 {
		t.Fatalf("upload left staging files behind: %v", stagingFiles)
	}
}

func TestHandleUploadAtomicallyReplacesSymlinkWithoutFollowingIt(t *testing.T) {
	fs := newTestStore(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("keep outside"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	destination := filepath.Join(fs.baseDir, "evidence.txt")
	if err := os.Symlink(outside, destination); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("files", "evidence.txt")
	if err != nil {
		t.Fatalf("create upload part: %v", err)
	}
	if _, err := part.Write([]byte("new evidence")); err != nil {
		t.Fatalf("write upload part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart body: %v", err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/file_drop/upload",
		&body,
	)
	request.Header.Set("Content-Type", writer.FormDataContentType())

	if _, err := fs.HandleUploadWithInfo(request); err != nil {
		t.Fatalf("upload over destination symlink: %v", err)
	}
	outsideContent, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("read outside file: %v", err)
	}
	if string(outsideContent) != "keep outside" {
		t.Fatalf("outside file was overwritten: %q", outsideContent)
	}
	destinationInfo, err := os.Lstat(destination)
	if err != nil {
		t.Fatalf("inspect uploaded destination: %v", err)
	}
	if destinationInfo.Mode()&os.ModeSymlink != 0 ||
		!destinationInfo.Mode().IsRegular() {
		t.Fatalf("destination was not replaced by a regular file: %v", destinationInfo.Mode())
	}
	destinationContent, err := os.ReadFile(destination)
	if err != nil {
		t.Fatalf("read uploaded destination: %v", err)
	}
	if string(destinationContent) != "new evidence" {
		t.Fatalf("uploaded destination content = %q", destinationContent)
	}
}

func TestListFilesOmitsSymlinksAndNonRegularEntries(t *testing.T) {
	fs := newTestStore(t)
	if err := os.WriteFile(
		filepath.Join(fs.baseDir, "regular.txt"),
		[]byte("data"),
		0o600,
	); err != nil {
		t.Fatalf("write regular file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(fs.baseDir, "directory"), 0o700); err != nil {
		t.Fatalf("create directory: %v", err)
	}
	if err := os.Symlink(
		filepath.Join(fs.baseDir, "regular.txt"),
		filepath.Join(fs.baseDir, "linked.txt"),
	); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	files, err := fs.ListFiles()
	if err != nil {
		t.Fatalf("list files: %v", err)
	}
	if len(files) != 1 || files[0].Name != "regular.txt" {
		t.Fatalf("listed unsafe filesystem entries: %#v", files)
	}
}

func TestOpenFileReturnsVerifiedRegularFile(t *testing.T) {
	fs := newTestStore(t)
	path := filepath.Join(fs.baseDir, "loot.txt")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	file, info, err := fs.OpenFile("loot.txt")
	if err != nil {
		t.Fatalf("open regular file: %v", err)
	}
	defer file.Close()
	if info.Name != "loot.txt" || info.Size != 4 {
		t.Fatalf("unexpected file info: %#v", info)
	}
}

func TestOpenFileRejectsSymlink(t *testing.T) {
	fs := newTestStore(t)
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	link := filepath.Join(fs.baseDir, "linked.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	if _, _, err := fs.OpenFile("linked.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open symlink error = %v, want os.ErrNotExist", err)
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
