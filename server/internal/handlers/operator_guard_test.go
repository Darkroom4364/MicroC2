package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"microc2/server/internal/audit"
)

const testOperatorToken = "test-token"

func TestOperatorGuardAllowsLoopbackWithoutToken(t *testing.T) {
	guard := NewOperatorGuard("", nil)
	req := httptest.NewRequest(http.MethodGet, "/api/agents/list", nil)
	req.RemoteAddr = "127.0.0.1:55555"

	if !guard.Authorized(req) {
		t.Fatal("expected loopback request to be authorized without a token")
	}
}

func TestOperatorGuardDeniesRemoteWithoutToken(t *testing.T) {
	guard := NewOperatorGuard("", nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agents/list", nil)
	req.RemoteAddr = "192.168.1.20:55555"

	called := false
	guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(rec, req)

	if called {
		t.Fatal("expected wrapped handler not to be called for unauthorized remote request")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for remote request without token, got %d", rec.Code)
	}
}

func TestOperatorGuardAllowsRemoteWithToken(t *testing.T) {
	guard := NewOperatorGuard(testOperatorToken, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/agents/list", nil)
	req.RemoteAddr = "192.168.1.20:55555"
	req.Header.Set(OperatorTokenHeader, testOperatorToken)

	called := false
	guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if !called || rec.Code != http.StatusOK {
		t.Fatalf("expected remote request with valid token to pass, called=%v code=%d", called, rec.Code)
	}
}

func TestOperatorGuardPropagatesTrustedLoopbackActor(t *testing.T) {
	guard := NewOperatorGuard(testOperatorToken, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/agents/list", nil)
	req.RemoteAddr = "127.0.0.1:55555"
	req.Header.Set(OperatorTokenHeader, "wrong-token")
	req = req.WithContext(audit.WithActor(req.Context(), audit.Actor{
		Kind: audit.ActorSystem,
		ID:   "forged-caller-context",
	}))

	var got audit.Actor
	guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		got, ok = audit.ActorFromContext(r.Context())
		if !ok {
			t.Fatal("guard did not propagate an audit actor")
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), req)

	want := audit.Actor{
		Kind: audit.ActorOperator,
		ID:   loopbackOperatorActorID,
	}
	if got != want {
		t.Fatalf("loopback audit actor = %#v, want %#v", got, want)
	}
}

func TestOperatorGuardPropagatesTrustedSharedTokenActor(t *testing.T) {
	guard := NewOperatorGuard(testOperatorToken, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/agents/list", nil)
	req.RemoteAddr = "192.168.1.20:55555"
	req.Header.Set(OperatorTokenHeader, testOperatorToken)

	var got audit.Actor
	guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		got, ok = audit.ActorFromContext(r.Context())
		if !ok {
			t.Fatal("guard did not propagate an audit actor")
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), req)

	want := audit.Actor{
		Kind: audit.ActorOperator,
		ID:   sharedTokenOperatorActorID,
	}
	if got != want {
		t.Fatalf("shared-token audit actor = %#v, want %#v", got, want)
	}
	if got.ID == testOperatorToken {
		t.Fatal("operator credential was reused as the audit actor ID")
	}
}

func TestOperatorGuardDoesNotPropagateActorWhenAuthorizationFails(t *testing.T) {
	guard := NewOperatorGuard(testOperatorToken, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/agents/list", nil)
	req.RemoteAddr = "192.168.1.20:55555"
	req.Header.Set(OperatorTokenHeader, "wrong-token")

	called := false
	guard.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	})).ServeHTTP(httptest.NewRecorder(), req)
	if called {
		t.Fatal("unauthorized request reached the guarded handler")
	}
	if actor, ok := guard.authorizedActor(req); ok || actor != (audit.Actor{}) {
		t.Fatalf("unauthorized request resolved actor %#v, authorized=%v", actor, ok)
	}
}

func TestOperatorGuardDeniesRemoteWithWrongToken(t *testing.T) {
	guard := NewOperatorGuard(testOperatorToken, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/agents/list", nil)
	req.RemoteAddr = "192.168.1.20:55555"
	req.Header.Set(OperatorTokenHeader, "wrong-token")

	if guard.Authorized(req) {
		t.Fatal("expected remote request with wrong token to be denied")
	}
}

func TestOperatorGuardDeniesDisallowedBrowserOrigin(t *testing.T) {
	guard := NewOperatorGuard("", []string{"https://operator.lab:9443"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://localhost:8443/api/file_drop/upload", nil)
	req.RemoteAddr = "127.0.0.1:55555"
	req.Host = "localhost:8443"
	req.Header.Set("Origin", "https://evil.example")

	called := false
	guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(rec, req)

	if called {
		t.Fatal("expected wrapped handler not to be called for a disallowed browser origin")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed browser origin, got %d", rec.Code)
	}
}

func TestOperatorGuardAllowsConfiguredBrowserOrigin(t *testing.T) {
	guard := NewOperatorGuard("", []string{"https://operator.lab:9443"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://localhost:8443/api/file_drop/upload", nil)
	req.RemoteAddr = "127.0.0.1:55555"
	req.Host = "localhost:8443"
	req.Header.Set("Origin", "https://operator.lab:9443")

	guard.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected configured browser origin to pass, got %d", rec.Code)
	}
}

func TestOperatorGuardCheckOrigin(t *testing.T) {
	guard := NewOperatorGuard("", []string{"https://operator.lab:9443"})

	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{"no origin header", "", true},
		{"same host origin", "https://example.com:8443", true},
		{"unconfigured loopback origin", "http://localhost:9090", false},
		{"configured origin", "https://operator.lab:9443", true},
		{"configured host with wrong scheme", "http://operator.lab:9443", false},
		{"cross-site origin", "https://evil.example", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.com:8443/ws/terminal", nil)
			req.Host = "example.com:8443"
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if got := guard.CheckOrigin(req); got != tt.want {
				t.Fatalf("CheckOrigin with Origin %q = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}
