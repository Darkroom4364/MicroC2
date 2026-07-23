package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestStaticRoutesKeepCompatibilityAssetsButDenyPrivateTrees(t *testing.T) {
	staticDir := t.TempDir()
	writeStaticTestFile(t, staticDir, "app.css")
	writeStaticTestFile(t, staticDir, filepath.Join("listeners", "config.json"))
	writeStaticTestFile(t, staticDir, filepath.Join("payloads", "payload.bin"))
	writeStaticTestFile(t, staticDir, filepath.Join("listeners-backup", "readme.txt"))
	writeStaticTestFile(t, staticDir, filepath.Join("payload-assets", "readme.txt"))

	handler := &StaticHandler{
		staticDir: staticDir,
		webDir:    t.TempDir(),
	}
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	tests := []struct {
		path       string
		wantStatus int
	}{
		{path: "/static/app.css", wantStatus: http.StatusOK},
		{path: "/static/listeners", wantStatus: http.StatusNotFound},
		{path: "/static/listeners/", wantStatus: http.StatusNotFound},
		{path: "/static/listeners/config.json", wantStatus: http.StatusNotFound},
		{path: "/static/LISTENERS/config.json", wantStatus: http.StatusNotFound},
		{path: "/static/payloads", wantStatus: http.StatusNotFound},
		{path: "/static/payloads/", wantStatus: http.StatusNotFound},
		{path: "/static/payloads/payload.bin", wantStatus: http.StatusNotFound},
		{path: "/static/listeners-backup/readme.txt", wantStatus: http.StatusOK},
		{path: "/static/payload-assets/readme.txt", wantStatus: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()

			mux.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf(
					"GET %s status = %d, want %d",
					test.path,
					response.Code,
					test.wantStatus,
				)
			}
		})
	}
}

func TestStaticRoutesDenySymlinkAliasesIntoPrivateTrees(t *testing.T) {
	staticDir := t.TempDir()
	writeStaticTestFile(t, staticDir, filepath.Join("listeners", "config.json"))
	writeStaticTestFile(t, staticDir, filepath.Join("payloads", "payload.bin"))
	writeStaticTestFile(t, staticDir, filepath.Join("public-assets", "app.css"))
	if err := os.Symlink(
		filepath.Join(staticDir, "listeners"),
		filepath.Join(staticDir, "listener-alias"),
	); err != nil {
		t.Skipf("create listener alias: %v", err)
	}
	if err := os.Symlink(
		filepath.Join(staticDir, "payloads"),
		filepath.Join(staticDir, "payload-alias"),
	); err != nil {
		t.Skipf("create payload alias: %v", err)
	}
	if err := os.Symlink(
		filepath.Join(staticDir, "public-assets"),
		filepath.Join(staticDir, "public-alias"),
	); err != nil {
		t.Skipf("create public alias: %v", err)
	}

	handler := &StaticHandler{
		staticDir: staticDir,
		webDir:    t.TempDir(),
	}
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	tests := []struct {
		path       string
		wantStatus int
	}{
		{path: "/static/listener-alias/config.json", wantStatus: http.StatusNotFound},
		{path: "/static/payload-alias/payload.bin", wantStatus: http.StatusNotFound},
		{path: "/static/public-alias/app.css", wantStatus: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()

			mux.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf(
					"GET %s status = %d, want %d",
					test.path,
					response.Code,
					test.wantStatus,
				)
			}
		})
	}
}

func writeStaticTestFile(t *testing.T, root, relative string) {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create test directory: %v", err)
	}
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}
}
