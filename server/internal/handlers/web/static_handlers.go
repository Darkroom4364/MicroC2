package web

import (
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// New creates a new static file handler instance
//
// Pre-conditions:
//   - staticDir is a valid directory path containing static assets
//
// Post-conditions:
//   - Returns a properly configured StaticHandler instance
//   - webDir is set to the web subdirectory relative to staticDir
func New(staticDir string) (*StaticHandler, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	exeDir := filepath.Dir(exePath)
	webDir := filepath.Join(exeDir, "web")
	return &StaticHandler{
		staticDir: staticDir,
		webDir:    webDir,
	}, nil
}

// HandleRoot redirects the root path to /home and serves static files
//
// Pre-conditions:
//   - Valid HTTP request and response writer
//   - webDir exists and contains necessary files
//
// Post-conditions:
//   - Redirects root path to /home/
//   - Serves requested static files from web directory
//   - Returns 404 Not Found for non-existent files
func (h *StaticHandler) HandleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		// Redirect root to /home/
		http.Redirect(w, r, "/home/", http.StatusMovedPermanently)
		return
	}

	// Serve other static files from the web directory
	if _, err := os.Stat(filepath.Join(h.webDir, r.URL.Path)); err == nil {
		http.ServeFile(w, r, filepath.Join(h.webDir, r.URL.Path))
		return
	}
	http.NotFound(w, r)
}

// RegisterRoutes sets up routes for static file serving on the provided mux.
//
// Pre-conditions:
//   - staticDir and webDir exist and contain necessary files
//
// Post-conditions:
//   - Routes are registered with the HTTP server
//   - /static/ paths are served from staticDir
//   - /home/ paths are served from webDir
func (h *StaticHandler) RegisterRoutes(mux *http.ServeMux) {
	// Handle /static/ paths for backward compatibility
	fs := http.FileServer(http.Dir(h.staticDir))
	staticFiles := http.StripPrefix("/static/", fs)
	mux.Handle("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		private, err := isPrivateStaticPath(h.staticDir, r.URL.Path)
		if err != nil || private {
			http.NotFound(w, r)
			return
		}
		staticFiles.ServeHTTP(w, r)
	}))

	// Serve web assets from the web directory
	webFs := http.FileServer(http.Dir(h.webDir))
	mux.Handle("/home/", http.StripPrefix("/home/", webFs))
}

// SetupStaticRoutes registers static routes on the default mux for legacy callers.
func (h *StaticHandler) SetupStaticRoutes() {
	h.RegisterRoutes(http.DefaultServeMux)
}

func isPrivateStaticPath(staticDir, requestPath string) (bool, error) {
	relative := strings.TrimPrefix(requestPath, "/static/")
	relative = strings.ReplaceAll(relative, `\`, "/")
	cleaned := strings.TrimPrefix(path.Clean("/"+relative), "/")
	lower := strings.ToLower(cleaned)
	if lower == "listeners" ||
		strings.HasPrefix(lower, "listeners/") ||
		lower == "payloads" ||
		strings.HasPrefix(lower, "payloads/") {
		return true, nil
	}

	absoluteStatic, err := filepath.Abs(staticDir)
	if err != nil {
		return false, err
	}
	requestedPath := filepath.Join(absoluteStatic, filepath.FromSlash(cleaned))
	resolvedRequested, err := filepath.EvalSymlinks(requestedPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	resolvedStatic, err := filepath.EvalSymlinks(absoluteStatic)
	if err != nil {
		return false, err
	}
	withinStatic, err := resolvedPathWithin(resolvedStatic, resolvedRequested)
	if err != nil {
		return false, err
	}
	if !withinStatic {
		// http.FileServer follows symlinks. Never let a compatibility alias
		// escape the configured static root.
		return true, nil
	}

	for _, privateDirectory := range []string{"listeners", "payloads"} {
		privateRoot := filepath.Join(absoluteStatic, privateDirectory)
		resolvedPrivate, err := filepath.EvalSymlinks(privateRoot)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		withinPrivate, err := resolvedPathWithin(
			resolvedPrivate,
			resolvedRequested,
		)
		if err != nil {
			return false, err
		}
		if withinPrivate {
			return true, nil
		}
	}
	return false, nil
}

func resolvedPathWithin(directory, candidate string) (bool, error) {
	relative, err := filepath.Rel(directory, candidate)
	if err != nil {
		return false, err
	}
	if relative == "." ||
		(relative != ".." &&
			!filepath.IsAbs(relative) &&
			!strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		return true, nil
	}

	directoryInfo, err := os.Stat(directory)
	if err != nil {
		return false, err
	}
	current := candidate
	for {
		info, statErr := os.Stat(current)
		if statErr != nil {
			return false, statErr
		}
		if os.SameFile(directoryInfo, info) {
			return true, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false, nil
		}
		current = parent
	}
}
