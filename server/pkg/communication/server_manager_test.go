package communication

import (
	"errors"
	"path/filepath"
	"testing"

	"microc2/server/internal/common"
	"microc2/server/internal/persistence"
)

func TestDefaultServerManagerRefusesPlaintextAgentServerStart(t *testing.T) {
	root := t.TempDir()
	database := openServerManagerTestDatabase(t, root)
	manager, err := NewServerManager(
		&ServerConfig{
			UploadDir:    filepath.Join(root, "uploads"),
			Port:         "0",
			StaticDir:    filepath.Join(root, "static"),
			ProtocolType: "http",
			Database:     database,
		},
	)
	if err != nil {
		t.Fatalf("create default server manager: %v", err)
	}

	err = manager.Start()
	if !errors.Is(err, common.ErrInsecureHTTPAgentTransport) {
		t.Fatalf("plaintext server start error = %v, want transport rejection", err)
	}
}

func TestProductionServerManagerRefusesPlaintextAgentServerStart(t *testing.T) {
	root := t.TempDir()
	database := openServerManagerTestDatabase(t, root)
	manager, err := NewProductionServerManager(
		&ServerConfig{
			UploadDir:    filepath.Join(root, "uploads"),
			Port:         "0",
			StaticDir:    filepath.Join(root, "static"),
			ProtocolType: "http",
			Database:     database,
		},
		common.AgentTransportPolicy{},
	)
	if err != nil {
		t.Fatalf("create production server manager: %v", err)
	}

	err = manager.Start()
	if !errors.Is(err, common.ErrInsecureHTTPAgentTransport) {
		t.Fatalf("plaintext server start error = %v, want transport rejection", err)
	}
}

func openServerManagerTestDatabase(
	t *testing.T,
	root string,
) *persistence.Database {
	t.Helper()
	database, err := persistence.Open(filepath.Join(root, "microc2.db"))
	if err != nil {
		t.Fatalf("open server-manager test database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close server-manager test database: %v", err)
		}
	})
	return database
}
