package listeners

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"microc2/server/internal/common"
	"microc2/server/internal/persistence"
)

func TestProductionTransportPolicyRejectsHTTPWithoutOverride(t *testing.T) {
	manager, err := NewProductionListenerManager(
		nil,
		filepath.Join(t.TempDir(), "listeners"),
		nil,
		common.AgentTransportPolicy{},
	)
	if err != nil {
		t.Fatalf("create production listener manager: %v", err)
	}

	_, err = manager.CreateListener(ListenerConfig{
		Name:     "plaintext",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     12345,
	})
	if !errors.Is(err, common.ErrInsecureHTTPAgentTransport) {
		t.Fatalf("HTTP listener error = %v, want insecure transport rejection", err)
	}
	if got := manager.ListListeners(); len(got) != 0 {
		t.Fatalf("rejected HTTP listener was registered: %#v", got)
	}
}

func TestDefaultConstructorsRejectHTTPWithoutOverride(t *testing.T) {
	withTempWorkingDir(t)

	manager := NewListenerManager(nil)
	_, err := manager.CreateListener(ListenerConfig{
		Name:     "default-plaintext",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     12345,
	})
	if !errors.Is(err, common.ErrInsecureHTTPAgentTransport) {
		t.Fatalf("default manager HTTP error = %v, want transport rejection", err)
	}

	_, err = NewListener(ListenerConfig{
		ID:       "default-listener",
		Name:     "default-listener",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     12345,
	})
	if !errors.Is(err, common.ErrInsecureHTTPAgentTransport) {
		t.Fatalf("default listener HTTP error = %v, want transport rejection", err)
	}
}

func TestProductionTransportPolicyAllowsExplicitIsolatedLabHTTP(t *testing.T) {
	database := openListenerManagerTestDatabase(t)
	manager, err := NewProductionListenerManager(
		nil,
		filepath.Join(t.TempDir(), "listeners"),
		database,
		common.AgentTransportPolicy{AllowInsecureIsolatedLab: true},
	)
	if err != nil {
		t.Fatalf("create isolated-lab listener manager: %v", err)
	}

	listener, err := manager.CreateListener(ListenerConfig{
		Name:     "lab-http",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     freeTCPPort(t),
	})
	if err != nil {
		t.Fatalf("explicit isolated-lab HTTP listener was rejected: %v", err)
	}
	if err := manager.DeleteListener(listener.Config.ID); err != nil {
		t.Fatalf("delete isolated-lab HTTP listener: %v", err)
	}
}

func TestHTTPListenerRejectsTLSConfigurationInIsolatedLab(t *testing.T) {
	config := ListenerConfig{
		ID:       "mismatched-http-tls",
		Name:     "mismatched-http-tls",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     freeTCPPort(t),
		TLSConfig: &TLSConfig{
			CertFile: "server.crt",
			KeyFile:  "server.key",
		},
	}

	manager := NewListenerManagerForIsolatedLab(nil)
	if _, err := manager.CreateListener(config); err == nil ||
		!strings.Contains(err.Error(), `requires protocol "https"`) {
		t.Fatalf(
			"manager HTTP/TLS mismatch error = %v, want protocol rejection",
			err,
		)
	}
	if got := manager.ListListeners(); len(got) != 0 {
		t.Fatalf("mismatched HTTP/TLS listener was registered: %#v", got)
	}

	if _, err := NewListenerForIsolatedLab(config); err == nil ||
		!strings.Contains(err.Error(), `requires protocol "https"`) {
		t.Fatalf(
			"standalone HTTP/TLS mismatch error = %v, want protocol rejection",
			err,
		)
	}
}

func TestProductionTransportPolicyAcceptsHTTPSWithTLS12Minimum(t *testing.T) {
	database := openListenerManagerTestDatabase(t)
	manager, err := NewProductionListenerManager(
		nil,
		filepath.Join(t.TempDir(), "listeners"),
		database,
		common.AgentTransportPolicy{},
	)
	if err != nil {
		t.Fatalf("create production listener manager: %v", err)
	}
	certFile, keyFile := writeTestTLSCertificate(t)

	listener, err := manager.CreateListener(ListenerConfig{
		Name:     "secure-https",
		Protocol: "https",
		BindHost: "127.0.0.1",
		Port:     freeTCPPort(t),
		TLSConfig: &TLSConfig{
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	})
	if err != nil {
		t.Fatalf("HTTPS listener was rejected: %v", err)
	}
	listener.mu.RLock()
	serverTLSConfig := listener.server.TLSConfig
	listener.mu.RUnlock()
	if serverTLSConfig == nil {
		t.Fatal("HTTPS listener has no TLS configuration")
	}
	if serverTLSConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf(
			"HTTPS minimum TLS version = %x, want at least TLS 1.2",
			serverTLSConfig.MinVersion,
		)
	}
	if err := manager.DeleteListener(listener.Config.ID); err != nil {
		t.Fatalf("delete HTTPS listener: %v", err)
	}
}

func openListenerManagerTestDatabase(t *testing.T) *persistence.Database {
	t.Helper()
	database, err := persistence.Open(
		filepath.Join(t.TempDir(), "microc2.db"),
	)
	if err != nil {
		t.Fatalf("open listener-manager test database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close listener-manager test database: %v", err)
		}
	})
	return database
}

func TestProductionTransportPolicyRejectsRequireClientCert(t *testing.T) {
	manager, err := NewProductionListenerManager(
		nil,
		filepath.Join(t.TempDir(), "listeners"),
		nil,
		common.AgentTransportPolicy{},
	)
	if err != nil {
		t.Fatalf("create production listener manager: %v", err)
	}

	_, err = manager.CreateListener(ListenerConfig{
		Name:     "unsupported-mtls",
		Protocol: "https",
		BindHost: "127.0.0.1",
		Port:     12345,
		TLSConfig: &TLSConfig{
			CertFile:          "unused.crt",
			KeyFile:           "unused.key",
			RequireClientCert: true,
		},
	})
	if !errors.Is(err, common.ErrClientCertificateValidationUnavailable) {
		t.Fatalf("requireClientCert error = %v, want unsupported mTLS rejection", err)
	}
}

func TestAddListenerRejectsAlreadyActiveRuntime(t *testing.T) {
	withTempWorkingDir(t)

	manager := NewListenerManagerForIsolatedLab(nil)
	listener, err := NewListenerForIsolatedLab(ListenerConfig{
		ID:       "already-active",
		Name:     "already-active",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     freeTCPPort(t),
	})
	if err != nil {
		t.Fatalf("create isolated-lab listener: %v", err)
	}
	if err := listener.Start(); err != nil {
		t.Fatalf("start isolated-lab listener: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Stop()
	})

	err = manager.AddListener(listener)
	if err == nil || !strings.Contains(err.Error(), "must be stopped") {
		t.Fatalf("add active listener error = %v, want stopped-state rejection", err)
	}
	if got := manager.ListListeners(); len(got) != 0 {
		t.Fatalf("active listener was imported: %#v", got)
	}
}

func TestHTTPListenerLifecycle(t *testing.T) {
	withTempWorkingDir(t)

	manager := NewListenerManagerForIsolatedLab(nil)
	port := freeTCPPort(t)
	config := ListenerConfig{
		Name:     "lifecycle",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     port,
	}

	listener, err := manager.CreateListener(config)
	if err != nil {
		t.Fatalf("CreateListener failed: %v", err)
	}
	if listener.GetStatus() != StatusActive {
		t.Fatalf("expected active listener, got %s", listener.GetStatus())
	}

	assertHTTPReachable(t, port)

	if err := manager.StopListener(listener.Config.ID); err != nil {
		t.Fatalf("StopListener failed: %v", err)
	}
	if listener.GetStatus() != StatusStopped {
		t.Fatalf("expected stopped listener, got %s", listener.GetStatus())
	}
	assertTCPClosed(t, port)

	if err := manager.StartListener(listener.Config.ID); err != nil {
		t.Fatalf("StartListener failed: %v", err)
	}
	if listener.GetStatus() != StatusActive {
		t.Fatalf("expected restarted listener to be active, got %s", listener.GetStatus())
	}
	assertHTTPReachable(t, port)

	if err := manager.DeleteListener(listener.Config.ID); err != nil {
		t.Fatalf("DeleteListener failed: %v", err)
	}
	if _, err := manager.GetListener(listener.Config.ID); err == nil {
		t.Fatal("expected deleted listener to be absent from registry")
	}
	if _, err := os.Stat(filepath.Join("static", "listeners", "lifecycle")); !os.IsNotExist(err) {
		t.Fatalf("expected listener directory to be removed, got err=%v", err)
	}
	assertTCPClosed(t, port)
}

func TestCreateListenerBindFailureDoesNotRegister(t *testing.T) {
	withTempWorkingDir(t)

	held := listenOnFreePort(t)
	defer held.Close()
	port := held.Addr().(*net.TCPAddr).Port

	manager := NewListenerManagerForIsolatedLab(nil)
	_, err := manager.CreateListener(ListenerConfig{
		Name:     "conflict",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     port,
	})
	if err == nil {
		t.Fatal("expected create to fail while port is already bound")
	}
	if got := manager.ListListeners(); len(got) != 0 {
		t.Fatalf("expected failed listener not to be registered, got %d listener(s)", len(got))
	}
	if _, statErr := os.Stat(filepath.Join("static", "listeners", "conflict")); !os.IsNotExist(statErr) {
		t.Fatalf("expected listener directory cleanup after bind failure, got err=%v", statErr)
	}
}

func TestCreateListenerRejectsDuplicateName(t *testing.T) {
	withTempWorkingDir(t)

	manager := NewListenerManagerForIsolatedLab(nil)
	first, err := manager.CreateListener(ListenerConfig{
		Name:     "duplicate",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     freeTCPPort(t),
	})
	if err != nil {
		t.Fatalf("CreateListener first failed: %v", err)
	}
	t.Cleanup(func() {
		_ = manager.DeleteListener(first.Config.ID)
	})

	_, err = manager.CreateListener(ListenerConfig{
		Name:     "duplicate",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     freeTCPPort(t),
	})
	if err == nil {
		t.Fatal("expected duplicate listener name to be rejected")
	}
	if got := len(manager.ListListeners()); got != 1 {
		t.Fatalf("expected only the first listener to remain registered, got %d", got)
	}
}

func TestCreateListenerRejectsUnsafeStorageName(t *testing.T) {
	withTempWorkingDir(t)

	manager := NewListenerManagerForIsolatedLab(nil)
	for _, name := range []string{
		"../escape",
		`..\escape`,
		".",
		" padded ",
		"é",
		"e\u0301",
		"trailing.",
		"bad:name",
		`bad"name`,
		"bad|name",
		"CON",
		"CON.txt",
		"con",
		"PRN",
		"AUX",
		"NUL",
		"COM1",
		"com9",
		"LPT1",
		"lpt9",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := manager.CreateListener(ListenerConfig{
				Name:     name,
				Protocol: "http",
				BindHost: "127.0.0.1",
				Port:     12345,
			})
			if err == nil {
				t.Fatalf("unsafe listener name %q was accepted", name)
			}
		})
	}
	for _, name := range []string{
		"listener",
		"Listener_01",
		"http-prod",
		"base - http",
		"prod.http",
		"prod@lab",
		"_prod",
		"-prod",
		".prod",
		"@prod",
		"COM0",
		"LPT10",
	} {
		if err := validateListenerIdentity(ListenerConfig{
			ID:   "portable-name-test",
			Name: name,
		}); err != nil {
			t.Fatalf("portable listener name %q was rejected: %v", name, err)
		}
	}
	if _, err := os.Stat("escape"); !os.IsNotExist(err) {
		t.Fatalf("unsafe listener name created an escaped path: %v", err)
	}
}

func TestAllAgentsUsesUnambiguousScopedKeys(t *testing.T) {
	withTempWorkingDir(t)

	manager := NewListenerManagerForIsolatedLab(nil)
	addAgent := func(listenerID, name, agentID string, port int) {
		t.Helper()
		listener, err := NewListenerForIsolatedLab(ListenerConfig{
			ID:       listenerID,
			Name:     name,
			Protocol: "http",
			BindHost: "127.0.0.1",
			Port:     port,
		})
		if err != nil {
			t.Fatalf("create listener %s: %v", listenerID, err)
		}
		heartbeat, err := json.Marshal(map[string]string{
			"id":       agentID,
			"os":       "linux",
			"hostname": listenerID,
			"ip":       "127.0.0.1",
		})
		if err != nil {
			t.Fatalf("marshal heartbeat: %v", err)
		}
		if err := listener.Protocol.HandleAgentHeartbeat(heartbeat); err != nil {
			t.Fatalf("register agent %s: %v", agentID, err)
		}
		if err := manager.AddListener(listener); err != nil {
			t.Fatalf("add listener %s: %v", listenerID, err)
		}
	}
	addAgent("scope", "scope-listener", "agent", 49011)
	addAgent("other", "other-listener", "agent", 49012)
	addAgent("unique", "unique-listener", "scope:agent", 49013)

	agents := manager.AllAgents()
	if len(agents) != 3 {
		t.Fatalf("agent map count = %d, want 3: %#v", len(agents), agents)
	}
	for _, key := range []string{"scope/agent", "other/agent", "scope:agent"} {
		if _, exists := agents[key]; !exists {
			t.Fatalf("agent map is missing unambiguous key %q: %#v", key, agents)
		}
	}
}

func TestCreateHTTPSListenerWithMissingCertDoesNotRegister(t *testing.T) {
	withTempWorkingDir(t)

	manager := NewListenerManagerForIsolatedLab(nil)
	_, err := manager.CreateListener(ListenerConfig{
		Name:     "bad-tls",
		Protocol: "https",
		BindHost: "127.0.0.1",
		Port:     freeTCPPort(t),
		TLSConfig: &TLSConfig{
			CertFile: "missing.crt",
			KeyFile:  "missing.key",
		},
	})
	if err == nil {
		t.Fatal("expected HTTPS listener with missing certificate to fail")
	}
	if got := manager.ListListeners(); len(got) != 0 {
		t.Fatalf("expected failed TLS listener not to be registered, got %d listener(s)", len(got))
	}
	if _, statErr := os.Stat(filepath.Join("static", "listeners", "bad-tls")); !os.IsNotExist(statErr) {
		t.Fatalf("expected listener directory cleanup after TLS failure, got err=%v", statErr)
	}
}

func TestConcurrentStartAndDeleteDoesNotLeavePortOpen(t *testing.T) {
	withTempWorkingDir(t)

	manager := NewListenerManagerForIsolatedLab(nil)
	port := freeTCPPort(t)
	listener, err := manager.CreateListener(ListenerConfig{
		Name:     "concurrent",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     port,
	})
	if err != nil {
		t.Fatalf("CreateListener failed: %v", err)
	}
	if err := manager.StopListener(listener.Config.ID); err != nil {
		t.Fatalf("StopListener failed: %v", err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	var startErr, deleteErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		startErr = manager.StartListener(listener.Config.ID)
	}()
	go func() {
		defer wg.Done()
		<-start
		deleteErr = manager.DeleteListener(listener.Config.ID)
	}()
	close(start)
	wg.Wait()

	if startErr != nil && !strings.Contains(startErr.Error(), "not found") {
		t.Fatalf("unexpected StartListener error: %v", startErr)
	}
	if deleteErr != nil {
		t.Fatalf("DeleteListener failed: %v", deleteErr)
	}
	if _, err := manager.GetListener(listener.Config.ID); err == nil {
		t.Fatal("expected listener to be deleted")
	}
	assertTCPClosed(t, port)
}

func TestListListenersJSONDuringLifecycle(t *testing.T) {
	withTempWorkingDir(t)

	manager := NewListenerManagerForIsolatedLab(nil)
	listener, err := manager.CreateListener(ListenerConfig{
		Name:     "json-race",
		Protocol: "http",
		BindHost: "127.0.0.1",
		Port:     freeTCPPort(t),
	})
	if err != nil {
		t.Fatalf("CreateListener failed: %v", err)
	}
	t.Cleanup(func() {
		_ = manager.DeleteListener(listener.Config.ID)
	})

	done := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					if _, err := json.Marshal(manager.ListListeners()); err != nil {
						t.Errorf("marshal listeners failed: %v", err)
						return
					}
				}
			}
		}()
	}

	for i := 0; i < 10; i++ {
		if err := manager.StopListener(listener.Config.ID); err != nil {
			t.Fatalf("StopListener failed: %v", err)
		}
		if err := manager.StartListener(listener.Config.ID); err != nil {
			t.Fatalf("StartListener failed: %v", err)
		}
	}
	close(done)
	wg.Wait()
}

func withTempWorkingDir(t *testing.T) {
	t.Helper()
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	temp := t.TempDir()
	if err := os.Chdir(temp); err != nil {
		t.Fatalf("chdir temp failed: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Fatalf("restore working directory failed: %v", err)
		}
	})
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener := listenOnFreePort(t)
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func listenOnFreePort(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	return listener
}

func assertHTTPReachable(t *testing.T, port int) {
	t.Helper()
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	client := http.Client{Timeout: time.Second}
	var lastErr error
	for i := 0; i < 20; i++ {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		lastErr = err
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("listener was not reachable at %s: %v", url, lastErr)
}

func assertTCPClosed(t *testing.T, port int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err != nil {
			return
		}
		conn.Close()
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("expected %s to be closed", addr)
}

func writeTestTLSCertificate(t *testing.T) (string, string) {
	t.Helper()
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {},
	))
	certificate := tlsServer.TLS.Certificates[0]
	tlsServer.Close()

	keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatalf("marshal test TLS private key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Certificate[0],
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	certFile := filepath.Join(t.TempDir(), "listener.crt")
	keyFile := filepath.Join(filepath.Dir(certFile), "listener.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write test TLS certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write test TLS private key: %v", err)
	}
	return certFile, keyFile
}
