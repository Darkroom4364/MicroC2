package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"microc2/server/config"
	"microc2/server/internal/audit"
	"microc2/server/internal/behaviour"
	"microc2/server/internal/common"
	"microc2/server/internal/filestore"
	"microc2/server/internal/handlers"
	"microc2/server/internal/handlers/api"
	"microc2/server/internal/handlers/web"
	"microc2/server/internal/handlers/ws"
	"microc2/server/internal/persistence"
	"microc2/server/internal/websocket"
	"microc2/server/pkg/communication"
)

// main is the entry point of the MicroC2 server application
//
// Pre-conditions:
//   - Configuration file exists at the specified path or default location
//   - Required directories are accessible with proper permissions
//
// Post-conditions:
//   - Server is initialized with configured handlers and services
//   - Server starts listening on the configured port
//   - Log files are properly set up and streamed
func main() {
	// Parse and validate configuration before opening configured outputs or
	// creating runtime state.
	configPath := flag.String("config", "config/settings.yaml", "Path to configuration file")
	flag.Parse()
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Set up logging only after logging.file has been resolved and validated.
	logFile, err := os.OpenFile(cfg.Logging.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("Failed to open configured log file: %v", err)
	}
	defer logFile.Close()
	if err := logFile.Chmod(0600); err != nil {
		log.Fatalf("Failed to secure configured log file: %v", err)
	}

	// Create and configure log streamer
	logStreamer := websocket.NewLogStreamer(logFile)
	log.SetOutput(logStreamer)

	httpsAddr := ":" + cfg.Server.Port
	var httpAddr string
	if cfg.Server.Redirect.Enabled {
		httpAddr = ":" + cfg.Server.Redirect.HTTPPort
	}
	boundListeners, err := bindServerListeners(
		httpsAddr,
		httpAddr,
		cfg.Server.Redirect.Enabled,
		net.Listen,
	)
	if err != nil {
		log.Fatalf("Failed to bind configured operator listeners: %v", err)
	}
	defer boundListeners.close()

	stateDatabase, err := persistence.Open(cfg.Storage.Path)
	if err != nil {
		log.Fatalf("Failed to initialize durable state: %v", err)
	}
	defer stateDatabase.Close()
	log.Printf("[CONFIG] Durable state database: %s", stateDatabase.Path())
	auditStore, err := audit.NewStore(stateDatabase)
	if err != nil {
		log.Fatalf("Failed to initialize structured audit store: %v", err)
	}

	// Set up the operator guard: loopback clients always pass; non-loopback
	// clients need the configured operator token. Also enforces the origin
	// policy for operator WebSockets.
	operatorGuard := handlers.NewOperatorGuard(cfg.Security.OperatorToken, cfg.Security.OperatorAllowedOrigins)
	logStreamer.SetCheckOrigin(operatorGuard.CheckOrigin)
	if cfg.Security.OperatorToken == "" {
		log.Printf("[SECURITY] No operator token configured: operator API and terminal are restricted to loopback clients")
	} else {
		log.Printf("[SECURITY] Operator token configured: non-loopback operator access requires the %s header", handlers.OperatorTokenHeader)
	}
	if cfg.Security.EnableServerTerminal {
		log.Printf("[SECURITY WARNING] Browser-accessible server terminal is explicitly enabled")
	} else {
		log.Printf("[SECURITY] Browser-accessible server terminal is disabled")
	}

	// An empty origin list disables cross-origin browser access. The wildcard
	// remains an explicit escape hatch in the configured list.
	corsOrigins := cfg.Security.CORSOrigins
	behaviour.SetDefaultAllowedOrigins(corsOrigins)

	// Create required directories
	listenersDir := filepath.Join(cfg.Server.StaticDir, "listeners")
	if err := os.MkdirAll(listenersDir, 0700); err != nil {
		log.Fatalf("Failed to create listeners directory: %v", err)
	}
	log.Printf("[CONFIG] Created listeners directory: %s", listenersDir)

	// Initialize components
	fileStore, err := filestore.New(cfg.Server.UploadDir)
	if err != nil {
		log.Fatalf("Failed to initialize file store: %v", err)
	}

	// Set up server configuration
	serverConfig := &communication.ServerConfig{
		UploadDir:    cfg.Server.UploadDir,
		Port:         cfg.Server.Port,
		StaticDir:    cfg.Server.StaticDir,
		ProtocolType: "http",
		TLSCertFile:  cfg.Server.TLS.CertFile,
		TLSKeyFile:   cfg.Server.TLS.KeyFile,
		CORSOrigins:  corsOrigins,
		Database:     stateDatabase,
	}

	// Create and start server manager
	agentTransportPolicy := common.AgentTransportPolicy{
		AllowInsecureIsolatedLab: cfg.Security.AgentTransport.AllowInsecureIsolatedLab,
	}
	if agentTransportPolicy.AllowInsecureIsolatedLab {
		log.Printf(
			"[SECURITY WARNING] Plaintext HTTP agent listeners are enabled; " +
				"use this override only on an isolated lab network",
		)
	}
	serverManager, err := communication.NewProductionServerManager(
		serverConfig,
		agentTransportPolicy,
	)
	if err != nil {
		log.Fatalf("Failed to create server manager: %v", err)
	}

	// Initialize handlers
	fileHandlers := api.NewAuditedFileHandlers(fileStore, auditStore)
	staticHandlers, err := web.New(cfg.Server.StaticDir)
	if err != nil {
		log.Fatalf("Failed to initialize static handlers: %v", err)
	}
	wsHandlers := ws.NewWithTerminalPolicy(
		logStreamer,
		operatorGuard.CheckOrigin,
		cfg.Security.EnableServerTerminal,
		auditStore,
	)
	listenerHandlers := api.NewListenerHandlers(serverManager.GetListenerManager())

	// Initialize payload handler
	payloadDir := filepath.Join(cfg.Server.StaticDir, "payloads")
	agentSourceDir := "../agent" // Relative path to agent source code
	payloadHandler, err := api.PayloadHandlerSetup(
		payloadDir,
		agentSourceDir,
		serverManager.GetListenerManager(),
		stateDatabase,
		agentTransportPolicy,
	)
	if err != nil {
		log.Fatalf("Failed to initialize payload handler: %v", err)
	}
	operatorMux := http.NewServeMux()

	// Set up HTTP routes
	staticHandlers.RegisterRoutes(operatorMux)

	// Set up file handling routes
	operatorMux.HandleFunc("/api/file_drop/upload", fileHandlers.HandleFileUpload)
	operatorMux.HandleFunc("/api/file_drop/list", fileHandlers.HandleFileList)
	operatorMux.HandleFunc("/api/file_drop/download/", fileHandlers.HandleFileDownload)
	operatorMux.HandleFunc("/api/file_drop/delete/", fileHandlers.HandleFileDelete)

	// Set up WebSocket routes
	operatorMux.HandleFunc("/ws/logs", wsHandlers.HandleLogStream)
	operatorMux.HandleFunc("/ws/terminal", wsHandlers.HandleTerminal)

	// Set up listener management routes
	listenerHandlers.RegisterRoutes(operatorMux)

	// Set up payload generator routes
	payloadHandler.RegisterRoutes(operatorMux)

	// Set up root route to redirect / to /home/
	operatorMux.HandleFunc("/", staticHandlers.HandleRoot)

	// Set up API routes
	apiHandler := api.NewAPIHandler(serverManager)
	operatorMux.HandleFunc("/api/", apiHandler.HandleRequest)

	// Start the server
	log.Printf("[STARTUP] Starting operator server with authenticated HTTP listener management...")
	log.Printf("[CONFIG] Upload directory: %s", cfg.Server.UploadDir)
	log.Printf("[CONFIG] Static directory: %s", cfg.Server.StaticDir)
	log.Printf("[CONFIG] File Drop directory: %s/file_drop", cfg.Server.StaticDir)
	log.Printf("[CONFIG] Payloads directory: %s", payloadDir)
	log.Printf("[NETWORK] HTTPS port: %s", cfg.Server.Port)

	// --- HTTPS Support ---
	certFile := cfg.Server.TLS.CertFile
	keyFile := cfg.Server.TLS.KeyFile

	// Start HTTP to HTTPS redirect server if enabled
	if cfg.Server.Redirect.Enabled {
		redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := httpsRedirectTarget(r, cfg.Server.Port)
			logHTTPSRedirect(r.URL.String(), target)
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
		redirectServer := &http.Server{
			Addr:              httpAddr,
			Handler:           redirectHandler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		go func() {
			log.Printf("[STARTUP] Starting HTTP redirect server on %s -> HTTPS %s", httpAddr, httpsAddr)
			if err := redirectServer.Serve(boundListeners.redirect); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("[ERROR] HTTP redirect server error: %v", err)
			}
		}()
	}

	// Start HTTPS server
	log.Printf("[STARTUP] Starting HTTPS server on %s ...", httpsAddr)
	operatorServer := &http.Server{
		Addr:    httpsAddr,
		Handler: operatorGuard.Wrap(operatorMux),
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := operatorServer.ServeTLS(
		boundListeners.https,
		certFile,
		keyFile,
	); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[ERROR] HTTPS server error: %v", err)
	}
	// Remove or comment out the old serverManager.Start() call:
	// if err := serverManager.Start(); err != nil {
	// 	log.Fatalf("[ERROR] Server error: %v", err)
	// }
}

type operatorListeners struct {
	https    net.Listener
	redirect net.Listener
}

func (listeners operatorListeners) close() {
	if listeners.redirect != nil {
		_ = listeners.redirect.Close()
	}
	if listeners.https != nil {
		_ = listeners.https.Close()
	}
}

func bindServerListeners(
	httpsAddr string,
	redirectAddr string,
	redirectEnabled bool,
	listen func(network, address string) (net.Listener, error),
) (operatorListeners, error) {
	httpsListener, err := listen("tcp", httpsAddr)
	if err != nil {
		return operatorListeners{}, fmt.Errorf(
			"bind HTTPS listener %s: %w",
			httpsAddr,
			err,
		)
	}
	listeners := operatorListeners{https: httpsListener}
	if !redirectEnabled {
		return listeners, nil
	}

	redirectListener, err := listen("tcp", redirectAddr)
	if err != nil {
		_ = httpsListener.Close()
		return operatorListeners{}, fmt.Errorf(
			"bind HTTP redirect listener %s: %w",
			redirectAddr,
			err,
		)
	}
	listeners.redirect = redirectListener
	return listeners, nil
}

func httpsRedirectTarget(r *http.Request, httpsPort string) string {
	host := "localhost"
	if r != nil {
		host = redirectHostname(r.Host)
	}
	requestURI := "/"
	if r != nil && r.URL != nil {
		if uri := r.URL.RequestURI(); uri != "" {
			requestURI = uri
		}
	}
	return "https://" + net.JoinHostPort(host, httpsPort) + requestURI
}

func logHTTPSRedirect(requestURL, target string) {
	// Both values are stripped of control and non-graphic runes below.
	// foxguard: ignore[go/taint-log-injection]
	log.Printf(
		"[REDIRECT] %s -> %s",
		sanitizeLogValue(requestURL),
		sanitizeLogValue(target),
	)
}

// sanitizeLogValue keeps untrusted redirect diagnostics on one printable log
// line. In particular, URL.String can retain control characters from RawQuery.
func sanitizeLogValue(value string) string {
	return strings.Map(func(character rune) rune {
		if !unicode.IsGraphic(character) {
			return -1
		}
		return character
	}, value)
}

func redirectHostname(hostport string) string {
	if hostport == "" {
		return "localhost"
	}
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		host := strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")
		if net.ParseIP(strings.SplitN(host, "%", 2)[0]) != nil {
			return host
		}
	}
	if net.ParseIP(hostport) != nil || !strings.Contains(hostport, ":") {
		return hostport
	}
	return "localhost"
}
