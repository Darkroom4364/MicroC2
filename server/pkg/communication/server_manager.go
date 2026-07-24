package communication

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"microc2/server/internal/behaviour"
	"microc2/server/internal/common"
	"microc2/server/internal/listeners"
	"microc2/server/internal/persistence"
	"microc2/server/internal/protocols"
)

type ServerManager struct {
	protocol             common.Protocol
	config               *ServerConfig
	listenerManager      *listeners.ListenerManager
	agentTransportPolicy common.AgentTransportPolicy
	requireAgentAuth     bool
}

type ServerConfig struct {
	UploadDir    string
	Port         string
	StaticDir    string
	ProtocolType string
	// TLSCertFile and TLSKeyFile are the authoritative server TLS paths.
	// HTTPS agent listeners inherit them unless an explicit listener override
	// is supplied.
	TLSCertFile string
	TLSKeyFile  string
	// CORSOrigins configures the CORS allow list for agent polling routes.
	CORSOrigins []string
	// Database is the process-wide durable state database. Nil retains the
	// in-memory implementation used by focused unit tests.
	Database *persistence.Database
}

// NewServerManager creates a server manager with the production-safe transport
// policy. Focused tests that require plaintext HTTP must explicitly call
// NewServerManagerForIsolatedLab.
func NewServerManager(config *ServerConfig) (*ServerManager, error) {
	return newServerManager(config, common.AgentTransportPolicy{}, true)
}

// NewServerManagerForIsolatedLab creates a server manager whose listener
// policy explicitly permits plaintext HTTP.
func NewServerManagerForIsolatedLab(config *ServerConfig) (*ServerManager, error) {
	return newServerManager(
		config,
		common.IsolatedLabAgentTransportPolicy(),
		false,
	)
}

// NewProductionServerManager creates a server manager with the explicitly
// configured production agent-transport policy. The zero value fails closed.
func NewProductionServerManager(
	config *ServerConfig,
	agentTransportPolicy common.AgentTransportPolicy,
) (*ServerManager, error) {
	return newServerManager(config, agentTransportPolicy, true)
}

func newServerManager(
	config *ServerConfig,
	agentTransportPolicy common.AgentTransportPolicy,
	requireAgentAuth bool,
) (*ServerManager, error) {
	if err := os.MkdirAll(config.UploadDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create upload directory: %v", err)
	}

	baseConfig := common.BaseProtocolConfig{
		UploadDir:      config.UploadDir,
		Port:           config.Port,
		AllowedOrigins: config.CORSOrigins,
	}

	var (
		protocol common.Protocol
		err      error
	)
	switch config.ProtocolType {
	case "http":
		switch {
		case requireAgentAuth && config.Database == nil:
			return nil, errors.New(
				"authenticated agent server requires durable storage",
			)
		case requireAgentAuth:
			protocol, err =
				behaviour.NewAuthenticatedHTTPPollingProtocolWithPersistence(
					baseConfig,
					config.Database,
					"operator-default",
				)
			if err != nil {
				return nil, fmt.Errorf(
					"load authenticated default protocol state: %w",
					err,
				)
			}
		case config.Database == nil:
			protocol = behaviour.NewHTTPPollingProtocol(baseConfig)
		default:
			protocol, err = behaviour.NewHTTPPollingProtocolWithPersistence(
				baseConfig,
				config.Database,
				"operator-default",
			)
			if err != nil {
				return nil, fmt.Errorf("load durable default protocol state: %w", err)
			}
		}
	case "socks5":
		protocol = protocols.NewSOCKS5Protocol(baseConfig)
	default:
		return nil, fmt.Errorf("unsupported protocol type: %s", config.ProtocolType)
	}

	if err := protocol.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize protocol: %v", err)
	}

	var listenerManager *listeners.ListenerManager
	if requireAgentAuth {
		listenerManager, err =
			listeners.NewProductionListenerManagerWithTLSDefaults(
				protocol,
				filepath.Join(config.StaticDir, "listeners"),
				config.Database,
				agentTransportPolicy,
				listeners.TLSConfig{
					CertFile: config.TLSCertFile,
					KeyFile:  config.TLSKeyFile,
				},
			)
	} else {
		listenerManager, err =
			listeners.NewListenerManagerWithPersistenceForIsolatedLab(
				protocol,
				filepath.Join(config.StaticDir, "listeners"),
				config.Database,
			)
	}
	if err != nil {
		return nil, fmt.Errorf("load listener manager: %w", err)
	}

	return &ServerManager{
		protocol:             protocol,
		config:               config,
		listenerManager:      listenerManager,
		agentTransportPolicy: agentTransportPolicy,
		requireAgentAuth:     requireAgentAuth,
	}, nil
}

// GetProtocol returns the current protocol instance
func (sm *ServerManager) GetProtocol() common.Protocol {
	return sm.protocol
}

func (sm *ServerManager) Start() error {
	if strings.EqualFold(sm.config.ProtocolType, "http") {
		if err := sm.agentTransportPolicy.ValidateListener("http", false); err != nil {
			return fmt.Errorf("start plaintext agent server: %w", err)
		}
		if sm.requireAgentAuth {
			httpProtocol, ok := sm.protocol.(*behaviour.HTTPPollingProtocol)
			if !ok || !httpProtocol.RequiresAgentAuthentication() {
				return errors.New(
					"agent server protocol does not enforce authenticated enrollment",
				)
			}
		}
	}

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

// GetDatabase exposes the immutable process-wide persistence handle to
// operator repositories that must query historical state independently of
// live listener runtime objects.
func (sm *ServerManager) GetDatabase() *persistence.Database {
	if sm == nil || sm.config == nil {
		return nil
	}
	return sm.config.Database
}
