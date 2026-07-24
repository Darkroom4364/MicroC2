package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

func TestLoadConfigDefaultsAgentTransportToSecure(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	configPath := filepath.Join(root, "settings.yaml")
	writeTestConfig(t, configPath, "", filepath.Join(root, "static"))

	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.Security.AgentTransport.AllowInsecureIsolatedLab {
		t.Fatal("plaintext HTTP agent transport was enabled by default")
	}
}

func TestLoadConfigDisablesServerTerminalByDefault(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	configPath := filepath.Join(root, "settings.yaml")
	writeTestConfig(t, configPath, "", filepath.Join(root, "static"))

	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.Security.EnableServerTerminal {
		t.Fatal("server terminal was enabled by default")
	}
}

func TestLoadConfigAllowsExplicitServerTerminalEnablement(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	configPath := filepath.Join(root, "settings.yaml")
	writeTestConfig(t, configPath, "", filepath.Join(root, "static"))

	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read test config: %v", err)
	}
	content = append(
		content,
		[]byte("security:\n  enableServerTerminal: true\n")...,
	)
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatalf("write terminal override: %v", err)
	}

	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !loaded.Security.EnableServerTerminal {
		t.Fatal("explicit server terminal enablement was ignored")
	}
}

func TestLoadConfigAllowsExplicitInsecureIsolatedLabOverride(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	configPath := filepath.Join(root, "settings.yaml")
	writeTestConfig(t, configPath, "", filepath.Join(root, "static"))

	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read test config: %v", err)
	}
	content = append(
		content,
		[]byte("security:\n  agentTransport:\n    allowInsecureIsolatedLab: true\n")...,
	)
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatalf("write transport override: %v", err)
	}

	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !loaded.Security.AgentTransport.AllowInsecureIsolatedLab {
		t.Fatal("explicit isolated-lab transport override was ignored")
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

func TestPathWithinDirectoryTreatsDifferentWindowsVolumesAsOutside(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows volume semantics")
	}

	within, err := pathWithinDirectoryWithCaseFolding(
		`C:\microc2\static`,
		`D:\microc2\data\microc2.db`,
		true,
	)
	if err != nil {
		t.Fatalf("compare paths on different Windows volumes: %v", err)
	}
	if within {
		t.Fatal("path on a different Windows volume was treated as contained")
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
