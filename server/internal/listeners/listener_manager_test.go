package listeners

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHTTPListenerLifecycle(t *testing.T) {
	withTempWorkingDir(t)

	manager := NewListenerManager(nil)
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

	manager := NewListenerManager(nil)
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

	manager := NewListenerManager(nil)
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

func TestCreateHTTPSListenerWithMissingCertDoesNotRegister(t *testing.T) {
	withTempWorkingDir(t)

	manager := NewListenerManager(nil)
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

	manager := NewListenerManager(nil)
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

	manager := NewListenerManager(nil)
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
