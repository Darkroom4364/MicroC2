package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

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
	"microc2/server/internal/protocols" // Updated from `networking`
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
	// Set up logging
	logFile, err := os.OpenFile("server.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	// Create and configure log streamer
	logStreamer := websocket.NewLogStreamer(logFile)
	log.SetOutput(logStreamer)

	// Parse command line flags
	configPath := flag.String("config", "config/settings.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
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

	// Configure CORS origins for agent polling routes (wildcard only when
	// explicitly configured).
	var corsOrigins []string
	if cfg.Security.EnableCORS {
		corsOrigins = cfg.Security.CORSOrigins
	}
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
		ProtocolType: cfg.Communication.Protocol,
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

	// Set up SOCKS5 management routes if protocol is SOCKS5
	if cfg.Communication.Protocol == "socks5" {
		if socks5Protocol, ok := serverManager.GetProtocol().(*protocols.SOCKS5Protocol); ok {
			socks5Handler := api.NewSOCKS5Handler(socks5Protocol)
			for route, handler := range socks5Handler.RegisterRoutes() {
				operatorMux.HandleFunc(route, handler)
			}
		}
	}

	// Start the server
	log.Printf("[STARTUP] Starting server with %s protocol...", cfg.Communication.Protocol)
	log.Printf("[CONFIG] Upload directory: %s", cfg.Server.UploadDir)
	log.Printf("[CONFIG] Static directory: %s", cfg.Server.StaticDir)
	log.Printf("[CONFIG] File Drop directory: %s/file_drop", cfg.Server.StaticDir)
	log.Printf("[CONFIG] Payloads directory: %s", payloadDir)
	log.Printf("[NETWORK] Port: %s", cfg.Server.Port)

	// --- HTTPS Support ---
	certFile := cfg.Server.TLS.CertFile
	keyFile := cfg.Server.TLS.KeyFile

	// Determine ports based on redirect configuration
	var httpAddr, httpsAddr string
	if cfg.Server.Redirect.Enabled {
		httpAddr = ":" + cfg.Server.Redirect.HTTPPort
		httpsAddr = ":" + cfg.Server.HTTPSPort
	} else {
		// If redirect is disabled, use main port for HTTPS
		httpsAddr = ":" + cfg.Server.Port
	}

	// Start HTTP to HTTPS redirect server if enabled
	if cfg.Server.Redirect.Enabled {
		go func() {
			log.Printf("[STARTUP] Starting HTTP redirect server on %s -> HTTPS %s", httpAddr, httpsAddr)

			redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Build target URL, handling both with and without port in Host header
				host := r.Host
				if host == "" {
					host = "localhost" + httpsAddr
				}

				// Remove HTTP port and replace with HTTPS port
				if host == "localhost:"+cfg.Server.Redirect.HTTPPort {
					host = "localhost" + httpsAddr
				}

				target := "https://" + host + r.URL.RequestURI()
				log.Printf("[REDIRECT] %s -> %s", r.URL.String(), target)
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
			if err := redirectServer.ListenAndServe(); err != nil {
				log.Printf("[ERROR] HTTP redirect server error: %v", err)
			}
		}()
	}

	// Start HTTPS server
	log.Printf("[STARTUP] Starting HTTPS server on %s ...", httpsAddr)
	operatorServer := &http.Server{
		Addr:              httpsAddr,
		Handler:           operatorGuard.Wrap(operatorMux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := operatorServer.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatalf("[ERROR] HTTPS server error: %v", err)
	}
	// Remove or comment out the old serverManager.Start() call:
	// if err := serverManager.Start(); err != nil {
	// 	log.Fatalf("[ERROR] Server error: %v", err)
	// }
}
