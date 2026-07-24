package config

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestLoadConfigRejectsUnknownFieldsBeforeCreatingDirectories(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	configPath := filepath.Join(root, "settings.yaml")
	staticDir := filepath.Join(root, "static")
	uploadDir := filepath.Join(root, "uploads")
	writeTestConfig(t, configPath, filepath.Join(root, "state.db"), staticDir)
	appendTestConfig(t, configPath, "communication:\n  protocol: http\n")

	if _, err := LoadConfig(configPath); err == nil ||
		!strings.Contains(err.Error(), "field communication not found") {
		t.Fatalf("unknown config field error = %v", err)
	}
	assertPathDoesNotExist(t, staticDir)
	assertPathDoesNotExist(t, uploadDir)
}

func TestLoadConfigRejectsInvalidSettingsBeforeCreatingDirectories(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	tests := []struct {
		name        string
		transform   func(string) string
		wantMessage string
	}{
		{
			name: "operator port outside range",
			transform: func(content string) string {
				return strings.Replace(content, `port: "8443"`, `port: "70000"`, 1)
			},
			wantMessage: "server.port must be an integer between 1 and 65535",
		},
		{
			name: "redirect missing port",
			transform: func(content string) string {
				return strings.Replace(
					content,
					"  tls:\n",
					"  redirect:\n    enabled: true\n  tls:\n",
					1,
				)
			},
			wantMessage: "server.redirect.httpPort is required",
		},
		{
			name: "redirect port collides",
			transform: func(content string) string {
				return strings.Replace(
					content,
					"  tls:\n",
					"  redirect:\n    enabled: true\n    httpPort: \"8443\"\n  tls:\n",
					1,
				)
			},
			wantMessage: "server.redirect.httpPort must differ from server.port",
		},
		{
			name: "disabled redirect retains ignored port",
			transform: func(content string) string {
				return strings.Replace(
					content,
					"  tls:\n",
					"  redirect:\n    enabled: false\n    httpPort: \"8080\"\n  tls:\n",
					1,
				)
			},
			wantMessage: "server.redirect.httpPort must be empty when redirects are disabled",
		},
		{
			name: "certificate and key do not pair",
			transform: func(content string) string {
				return strings.Replace(content, "server.key", "server.crt", 1)
			},
			wantMessage: "load server TLS certificate and key",
		},
		{
			name: "wildcard origin cannot shadow named origins",
			transform: func(content string) string {
				return content +
					"security:\n" +
					"  corsOrigins: [\"*\", \"https://operator.lab\"]\n"
			},
			wantMessage: "security.corsOrigins[0] wildcard must be the only configured origin",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "settings.yaml")
			staticDir := filepath.Join(root, "static")
			uploadDir := filepath.Join(root, "uploads")
			writeTestConfig(t, configPath, filepath.Join(root, "state.db"), staticDir)
			rewriteTestConfig(t, configPath, test.transform)

			if _, err := LoadConfig(configPath); err == nil ||
				!strings.Contains(err.Error(), test.wantMessage) {
				t.Fatalf("config error = %v, want substring %q", err, test.wantMessage)
			}
			assertPathDoesNotExist(t, staticDir)
			assertPathDoesNotExist(t, uploadDir)
		})
	}
}

func TestLoadConfigValidatesBrowserOriginsBeforeCreatingDirectories(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	tests := []struct {
		name      string
		field     string
		configKey string
		value     string
	}{
		{
			name:      "CORS origin requires scheme",
			field:     "security.corsOrigins[0]",
			configKey: "corsOrigins",
			value:     "operator.lab",
		},
		{
			name:      "operator origin rejects path",
			field:     "security.operatorAllowedOrigins[0]",
			configKey: "operatorAllowedOrigins",
			value:     "https://operator.lab/path",
		},
		{
			name:      "operator origin rejects non-HTTP scheme",
			field:     "security.operatorAllowedOrigins[0]",
			configKey: "operatorAllowedOrigins",
			value:     "ftp://operator.lab",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "settings.yaml")
			staticDir := filepath.Join(root, "static")
			uploadDir := filepath.Join(root, "uploads")
			writeTestConfig(
				t,
				configPath,
				filepath.Join(root, "state.db"),
				staticDir,
			)
			appendTestConfig(
				t,
				configPath,
				fmt.Sprintf(
					"security:\n  %s: [%q]\n",
					test.configKey,
					test.value,
				),
			)

			if _, err := LoadConfig(configPath); err == nil ||
				!strings.Contains(err.Error(), test.field) {
				t.Fatalf("origin validation error = %v, want field %q", err, test.field)
			}
			assertPathDoesNotExist(t, staticDir)
			assertPathDoesNotExist(t, uploadDir)
		})
	}
}

func TestLoadConfigAcceptsCanonicalAndWildcardBrowserOrigins(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	configPath := filepath.Join(root, "settings.yaml")
	writeTestConfig(
		t,
		configPath,
		filepath.Join(root, "state.db"),
		filepath.Join(root, "static"),
	)
	appendTestConfig(
		t,
		configPath,
		"security:\n"+
			"  corsOrigins: [\"*\"]\n"+
			"  operatorAllowedOrigins: [\"https://operator.lab\"]\n",
	)

	if _, err := LoadConfig(configPath); err != nil {
		t.Fatalf("load canonical browser origins: %v", err)
	}
}

func TestLoadConfigAcceptsDistinctRedirectAndOperatorPorts(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	configPath := filepath.Join(root, "settings.yaml")
	writeTestConfig(
		t,
		configPath,
		filepath.Join(root, "state.db"),
		filepath.Join(root, "static"),
	)
	rewriteTestConfig(t, configPath, func(content string) string {
		return strings.Replace(
			content,
			"  tls:\n",
			"  redirect:\n    enabled: true\n    httpPort: \"8080\"\n  tls:\n",
			1,
		)
	})

	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load redirect config: %v", err)
	}
	if loaded.Server.Port != "8443" ||
		!loaded.Server.Redirect.Enabled ||
		loaded.Server.Redirect.HTTPPort != "8080" {
		t.Fatalf("unexpected resolved ports: %#v", loaded.Server)
	}
}

func TestLoadConfigRejectsPrivateRuntimePathsInsideStaticDirectory(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	tests := []struct {
		name        string
		rewrite     func(string, string, string) string
		wantMessage string
	}{
		{
			name: "uploads",
			rewrite: func(content, root, staticDir string) string {
				return strings.Replace(
					content,
					fmt.Sprintf("uploadDir: %q", filepath.Join(root, "uploads")),
					fmt.Sprintf("uploadDir: %q", filepath.Join(staticDir, "uploads")),
					1,
				)
			},
			wantMessage: "server upload directory must be outside",
		},
		{
			name: "log",
			rewrite: func(content, _, staticDir string) string {
				return strings.Replace(
					content,
					`file: "server.log"`,
					fmt.Sprintf("file: %q", filepath.Join(staticDir, "server.log")),
					1,
				)
			},
			wantMessage: "logging file must be outside",
		},
		{
			name: "TLS certificate",
			rewrite: func(content, root, staticDir string) string {
				return strings.Replace(
					content,
					fmt.Sprintf("certFile: %q", filepath.Join(root, "server.crt")),
					fmt.Sprintf("certFile: %q", filepath.Join(staticDir, "server.crt")),
					1,
				)
			},
			wantMessage: "server TLS certificate must be outside",
		},
		{
			name: "TLS private key",
			rewrite: func(content, root, staticDir string) string {
				return strings.Replace(
					content,
					fmt.Sprintf("keyFile: %q", filepath.Join(root, "server.key")),
					fmt.Sprintf("keyFile: %q", filepath.Join(staticDir, "server.key")),
					1,
				)
			},
			wantMessage: "server TLS private key must be outside",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "settings.yaml")
			staticDir := filepath.Join(root, "static")
			writeTestConfig(t, configPath, filepath.Join(root, "state.db"), staticDir)
			if strings.HasPrefix(test.name, "TLS ") {
				if err := os.MkdirAll(staticDir, 0o755); err != nil {
					t.Fatalf("create static directory: %v", err)
				}
				sourceName := "server.crt"
				if test.name == "TLS private key" {
					sourceName = "server.key"
				}
				sourcePath := filepath.Join(root, sourceName)
				destinationPath := filepath.Join(staticDir, sourceName)
				if err := os.Rename(sourcePath, destinationPath); err != nil {
					t.Fatalf("move TLS material beneath static directory: %v", err)
				}
			}
			rewriteTestConfig(t, configPath, func(content string) string {
				return test.rewrite(content, root, staticDir)
			})

			if _, err := LoadConfig(configPath); err == nil ||
				!strings.Contains(err.Error(), test.wantMessage) {
				t.Fatalf("config error = %v, want substring %q", err, test.wantMessage)
			}
			if !strings.HasPrefix(test.name, "TLS ") {
				assertPathDoesNotExist(t, staticDir)
			}
		})
	}
}

func TestLoadConfigDefaultsAuthoritativeOperatorSettings(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	configPath := filepath.Join(root, "settings.yaml")
	writeTestConfig(
		t,
		configPath,
		filepath.Join(root, "state.db"),
		filepath.Join(root, "static"),
	)
	rewriteTestConfig(t, configPath, func(content string) string {
		content = strings.Replace(content, "  port: \"8443\"\n", "", 1)
		return strings.Replace(content, "logging:\n  file: \"server.log\"\n", "", 1)
	})

	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("load defaulted config: %v", err)
	}
	if loaded.Server.Port != "8443" {
		t.Fatalf("server port = %q, want 8443", loaded.Server.Port)
	}
	if loaded.Logging.File != "server.log" {
		t.Fatalf("logging file = %q, want server.log", loaded.Logging.File)
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

func TestLoadConfigRejectsTLSKeySymlinkedIntoStaticRoot(t *testing.T) {
	t.Setenv("MICROC2_STORAGE_PATH", "")
	root := t.TempDir()
	staticDir := filepath.Join(root, "static")
	if err := os.MkdirAll(staticDir, 0o755); err != nil {
		t.Fatalf("create static directory: %v", err)
	}
	configPath := filepath.Join(root, "settings.yaml")
	writeTestConfig(
		t,
		configPath,
		filepath.Join(root, "state", "microc2.db"),
		staticDir,
	)

	originalKey := filepath.Join(root, "server.key")
	staticKey := filepath.Join(staticDir, "server.key")
	if err := os.Rename(originalKey, staticKey); err != nil {
		t.Fatalf("move TLS key beneath static directory: %v", err)
	}
	keyLink := filepath.Join(root, "tls-key")
	if err := os.Symlink(staticKey, keyLink); err != nil {
		t.Skipf("create TLS key symlink: %v", err)
	}
	rewriteTestConfig(t, configPath, func(content string) string {
		return strings.Replace(
			content,
			fmt.Sprintf("keyFile: %q", originalKey),
			fmt.Sprintf("keyFile: %q", keyLink),
			1,
		)
	})

	if _, err := LoadConfig(configPath); err == nil ||
		!strings.Contains(err.Error(), "server TLS private key must be outside") {
		t.Fatalf("symlinked TLS key error = %v", err)
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
	certFile, keyFile := writeTestTLSCertificate(t, filepath.Dir(path))
	storageBlock := ""
	if storagePath != "" {
		storageBlock = fmt.Sprintf("storage:\n  path: %q\n", storagePath)
	}
	content := fmt.Sprintf(
		"%sserver:\n  port: \"8443\"\n  uploadDir: %q\n  staticDir: %q\n  tls:\n    certFile: %q\n    keyFile: %q\nlogging:\n  file: \"server.log\"\n",
		storageBlock,
		filepath.Join(filepath.Dir(path), "uploads"),
		staticDir,
		certFile,
		keyFile,
	)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func writeTestTLSCertificate(t *testing.T, root string) (string, string) {
	t.Helper()
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {},
	))
	certificate := tlsServer.TLS.Certificates[0]
	tlsServer.Close()

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatalf("marshal test TLS key: %v", err)
	}

	certFile := filepath.Join(root, "server.crt")
	keyFile := filepath.Join(root, "server.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Certificate[0],
	}), 0o600); err != nil {
		t.Fatalf("write test TLS certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}), 0o600); err != nil {
		t.Fatalf("write test TLS key: %v", err)
	}
	return certFile, keyFile
}

func appendTestConfig(t *testing.T, path, addition string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open config for append: %v", err)
	}
	if _, err := file.WriteString(addition); err != nil {
		_ = file.Close()
		t.Fatalf("append config: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close appended config: %v", err)
	}
}

func rewriteTestConfig(t *testing.T, path string, transform func(string) string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config for rewrite: %v", err)
	}
	if err := os.WriteFile(path, []byte(transform(string(content))), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
}

func assertPathDoesNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("path %q exists after rejected config (stat error %v)", path, err)
	}
}
