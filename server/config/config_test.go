package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigDefaultsDurableStorageOutsideStaticRoot(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	configPath := filepath.Join(root, "settings.yaml")
	writeTestConfig(t, configPath, "", filepath.Join(root, "static"))

	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.Storage.Path != "data/microc2.db" {
		t.Fatalf("default storage path = %q, want data/microc2.db", loaded.Storage.Path)
	}
}

func TestLoadConfigRejectsDatabaseInsideWebStaticRoot(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	staticDir := filepath.Join(root, "static")
	configPath := filepath.Join(root, "settings.yaml")
	writeTestConfig(
		t,
		configPath,
		filepath.Join(staticDir, "state", "microc2.db"),
		staticDir,
	)

	if _, err := LoadConfig(configPath); err == nil {
		t.Fatal("database inside static directory was accepted")
	}
}

func TestLoadConfigRejectsEmptyWebStaticRoot(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	configPath := filepath.Join(root, "settings.yaml")
	writeTestConfig(
		t,
		configPath,
		filepath.Join(root, "state", "microc2.db"),
		"",
	)

	if _, err := LoadConfig(configPath); err == nil {
		t.Fatal("empty static directory was accepted")
	}
}

func TestLoadConfigRejectsDatabaseInsideSymlinkedStaticRoot(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	realStaticDir := filepath.Join(root, "real-static")
	if err := os.MkdirAll(realStaticDir, 0o755); err != nil {
		t.Fatalf("create real static directory: %v", err)
	}
	staticDir := filepath.Join(root, "static")
	if err := os.Symlink(realStaticDir, staticDir); err != nil {
		t.Skipf("create static directory symlink: %v", err)
	}
	configPath := filepath.Join(root, "settings.yaml")
	writeTestConfig(
		t,
		configPath,
		filepath.Join(realStaticDir, "state", "microc2.db"),
		staticDir,
	)

	if _, err := LoadConfig(configPath); err == nil {
		t.Fatal("database inside symlinked static directory was accepted")
	}
}

func TestLoadConfigRejectsStoragePathSymlinkedIntoStaticRoot(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	staticDir := filepath.Join(root, "static")
	staticStateDir := filepath.Join(staticDir, "state")
	if err := os.MkdirAll(staticStateDir, 0o755); err != nil {
		t.Fatalf("create static state directory: %v", err)
	}
	stateLink := filepath.Join(root, "state")
	if err := os.Symlink(staticStateDir, stateLink); err != nil {
		t.Skipf("create storage directory symlink: %v", err)
	}
	configPath := filepath.Join(root, "settings.yaml")
	writeTestConfig(
		t,
		configPath,
		filepath.Join(stateLink, "microc2.db"),
		staticDir,
	)

	if _, err := LoadConfig(configPath); err == nil {
		t.Fatal("storage path symlinked into static directory was accepted")
	}
}

func TestPathWithinDirectoryRejectsCaseAliasOnInsensitiveFilesystems(t *testing.T) {
	root := t.TempDir()
	staticDir := filepath.Join(root, "static")
	candidate := filepath.Join(root, "STATIC", "state", "microc2.db")

	within, err := pathWithinDirectoryWithCaseFolding(
		staticDir,
		candidate,
		true,
	)
	if err != nil {
		t.Fatalf("compare case-aliased paths: %v", err)
	}
	if !within {
		t.Fatalf(
			"case-aliased storage path %q was not contained by %q",
			candidate,
			staticDir,
		)
	}
}

func writeTestConfig(t *testing.T, path, storagePath, staticDir string) {
	t.Helper()
	storageBlock := ""
	if storagePath != "" {
		storageBlock = fmt.Sprintf("storage:\n  path: %q\n", storagePath)
	}
	content := fmt.Sprintf(
		"%sserver:\n  uploadDir: %q\n  staticDir: %q\ncommunication:\n  protocol: http\n",
		storageBlock,
		filepath.Join(filepath.Dir(path), "uploads"),
		staticDir,
	)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}
