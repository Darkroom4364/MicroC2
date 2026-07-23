package communication

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"microc2/server/internal/behaviour"
	"microc2/server/internal/common"
	"microc2/server/internal/listeners"
	"microc2/server/internal/protocols"
)

type ServerManager struct {
	protocol        common.Protocol
	config          *ServerConfig
	listenerManager *listeners.ListenerManager
}

type ServerConfig struct {
	UploadDir    string
	Port         string
	StaticDir    string
	ProtocolType string
	// CORSOrigins configures the CORS allow list for agent polling routes.
	CORSOrigins []string
}

func NewServerManager(config *ServerConfig) (*ServerManager, error) {
	if err := os.MkdirAll(config.UploadDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create upload directory: %v", err)
	}

	baseConfig := common.BaseProtocolConfig{
		UploadDir:      config.UploadDir,
		Port:           config.Port,
		AllowedOrigins: config.CORSOrigins,
	}

	var protocol common.Protocol
	switch config.ProtocolType {
	case "http":
		protocol = behaviour.NewHTTPPollingProtocol(baseConfig)
	case "socks5":
		protocol = protocols.NewSOCKS5Protocol(baseConfig)
	default:
		return nil, fmt.Errorf("unsupported protocol type: %s", config.ProtocolType)
	}

	if err := protocol.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize protocol: %v", err)
	}

	listenerManager := listeners.NewListenerManager(protocol)

	return &ServerManager{
		protocol:        protocol,
		config:          config,
		listenerManager: listenerManager,
	}, nil
}

// GetProtocol returns the current protocol instance
func (sm *ServerManager) GetProtocol() common.Protocol {
	return sm.protocol
}

func (sm *ServerManager) Start() error {
	mux := http.NewServeMux()

	// Register protocol-specific routes
	for path, handler := range sm.protocol.GetRoutes() {
		// Skip routes that might conflict with API handlers
		if strings.HasPrefix(path, "/api/agent/") {
			log.Printf("[ROUTES] Skipping protocol route %s to avoid conflicts with API handlers", path)
			continue
		}
		mux.HandleFunc(path, handler)
	}

	if httpProto, ok := sm.protocol.(*behaviour.HTTPPollingProtocol); ok {
		mux.HandleFunc("/api/agent/", httpProto.HandleAgentRequests)
	}

	log.Printf("[STARTUP] Server initializing with %s protocol...", sm.config.ProtocolType)
	log.Printf("[CONFIG] Upload directory: %s", sm.config.UploadDir)
	log.Printf("[CONFIG] Static directory: %s", sm.config.StaticDir)
	log.Printf("[CONFIG] File Drop directory: %s/file_drop", sm.config.StaticDir)
	log.Printf("[NETWORK] Port: %s", sm.config.Port)

	server := &http.Server{
		Addr:              ":" + sm.config.Port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return server.ListenAndServe()
}

func (sm *ServerManager) GetListenerManager() *listeners.ListenerManager {
	return sm.listenerManager
}
