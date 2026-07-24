package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"microc2/server/internal/audit"
	"microc2/server/internal/enrollment"
	"microc2/server/internal/listeners"
	"microc2/server/internal/persistence"
)

func TestAgentSessionManagementRoutesNeverExposeCredentials(t *testing.T) {
	database, err := persistence.Open(filepath.Join(t.TempDir(), "microc2.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	store, err := enrollment.NewStore(context.Background(), database)
	if err != nil {
		t.Fatalf("create enrollment store: %v", err)
	}
	bootstrap := activateAPITestPayload(
		t,
		database,
		store,
		"listener-one",
		"payload-one",
	)
	enrolled, err := store.Enroll(context.Background(), enrollment.EnrollRequest{
		ListenerID:     "listener-one",
		AgentID:        "agent-one",
		PayloadBuildID: "payload-one",
		Bootstrap:      bootstrap.Public,
	})
	if err != nil {
		t.Fatalf("enroll API test agent: %v", err)
	}

	handler := &ListenerHandlers{enrollment: store}
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	path := "/api/listeners/listener-one/agents/agent-one/session/"
	operator := audit.Actor{
		Kind: audit.ActorOperator,
		ID:   "shared-token:session-operator",
	}
	operatorContext := audit.WithActor(context.Background(), operator)

	response := serveListenerManagementRequestWithContext(
		operatorContext,
		mux,
		http.MethodPost,
		path+"rotate",
		"",
	)
	if response.Code != http.StatusOK {
		t.Fatalf("rotate status = %d: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), enrolled.Credential) ||
		strings.Contains(response.Body.String(), "s1.") ||
		strings.Contains(response.Body.String(), bootstrap.Public) {
		t.Fatalf("rotation response exposed a credential: %s", response.Body.String())
	}
	var rotation map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &rotation); err != nil {
		t.Fatalf("decode rotation response: %v", err)
	}
	if rotation["status"] != "rotation_pending" ||
		rotation["pending_generation"] != float64(2) {
		t.Fatalf("unexpected rotation response: %#v", rotation)
	}
	authentication, err := store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		enrolled.Credential,
	)
	if err != nil {
		t.Fatalf("authenticate current credential after rotation: %v", err)
	}
	if authentication.ReplacementCredential == "" {
		t.Fatal("agent authentication did not receive pending replacement")
	}

	response = serveListenerManagementRequestWithContext(
		operatorContext,
		mux,
		http.MethodPost,
		path+"revoke",
		"",
	)
	if response.Code != http.StatusOK {
		t.Fatalf("revoke status = %d: %s", response.Code, response.Body.String())
	}
	if _, err := store.Authenticate(
		context.Background(),
		"listener-one",
		"agent-one",
		enrolled.Credential,
	); err == nil {
		t.Fatal("revoked credential remained authenticated")
	}

	response = serveListenerManagementRequestWithContext(
		operatorContext,
		mux,
		http.MethodPost,
		path+"re-enroll",
		"",
	)
	if response.Code != http.StatusOK {
		t.Fatalf("re-enroll status = %d: %s", response.Code, response.Body.String())
	}
	reenrolled, err := store.Enroll(
		context.Background(),
		enrollment.EnrollRequest{
			ListenerID:     "listener-one",
			AgentID:        "agent-one",
			PayloadBuildID: "payload-one",
			Bootstrap:      bootstrap.Public,
		},
	)
	if err != nil {
		t.Fatalf("explicitly re-enroll agent: %v", err)
	}
	if reenrolled.Credential == enrolled.Credential {
		t.Fatal("re-enrollment reused the revoked session credential")
	}

	auditStore, err := audit.NewStore(database)
	if err != nil {
		t.Fatalf("create audit reader: %v", err)
	}
	page, err := auditStore.Page(
		context.Background(),
		audit.PageOptions{Limit: 10},
	)
	if err != nil {
		t.Fatalf("page agent-session audit events: %v", err)
	}
	if page.Total != 3 || len(page.Events) != 3 {
		t.Fatalf(
			"agent-session audit event count = %d/%d, want 3/3: %#v",
			page.Total,
			len(page.Events),
			page.Events,
		)
	}
	for index, want := range []struct {
		action string
		route  string
	}{
		{
			action: "agent.session.require_reenrollment",
			route:  "POST /api/listeners/{listener_id}/agents/{agent_id}/session/re-enroll",
		},
		{
			action: "agent.session.revoke",
			route:  "POST /api/listeners/{listener_id}/agents/{agent_id}/session/revoke",
		},
		{
			action: "agent.session.rotate",
			route:  "POST /api/listeners/{listener_id}/agents/{agent_id}/session/rotate",
		},
	} {
		event := page.Events[index]
		if event.Actor != operator ||
			event.Action != want.action ||
			event.Route != want.route ||
			event.Target != (audit.Target{Kind: "agent", ID: "agent-one"}) ||
			event.Outcome != audit.OutcomeSucceeded ||
			event.ListenerID != "listener-one" ||
			event.AgentID != "agent-one" {
			t.Fatalf("unexpected agent-session audit event %d: %#v", index, event)
		}
	}
	serialized, err := json.Marshal(page.Events)
	if err != nil {
		t.Fatalf("marshal agent-session audit events: %v", err)
	}
	for name, secret := range map[string]string{
		"bootstrap credential":       bootstrap.Public,
		"session credential":         enrolled.Credential,
		"pending session credential": authentication.ReplacementCredential,
		"session id":                 enrolled.SessionID,
	} {
		if bytes.Contains(serialized, []byte(secret)) {
			t.Fatalf("agent-session audit events exposed %s: %s", name, serialized)
		}
	}
}

func TestAgentSessionManagementRoutesRejectAmbiguousRequests(t *testing.T) {
	handler := &ListenerHandlers{}
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	for _, testCase := range []struct {
		name   string
		method string
		path   string
		body   string
		status int
	}{
		{
			name:   "method",
			method: http.MethodGet,
			path:   "/api/listeners/listener-one/agents/agent-one/session/rotate",
			status: http.StatusMethodNotAllowed,
		},
		{
			name:   "body",
			method: http.MethodPost,
			path:   "/api/listeners/listener-one/agents/agent-one/session/rotate",
			body:   "{}",
			status: http.StatusBadRequest,
		},
		{
			name:   "query",
			method: http.MethodPost,
			path:   "/api/listeners/listener-one/agents/agent-one/session/rotate?force=1",
			status: http.StatusBadRequest,
		},
		{
			name:   "malformed path",
			method: http.MethodPost,
			path:   "/api/listeners/listener-one/agents/agent-one/session/unknown",
			status: http.StatusBadRequest,
		},
		{
			name:   "store unavailable",
			method: http.MethodPost,
			path:   "/api/listeners/listener-one/agents/agent-one/session/rotate",
			status: http.StatusServiceUnavailable,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			response := serveListenerManagementRequest(
				mux,
				testCase.method,
				testCase.path,
				testCase.body,
			)
			if response.Code != testCase.status {
				t.Fatalf(
					"status = %d, want %d: %s",
					response.Code,
					testCase.status,
					response.Body.String(),
				)
			}
		})
	}
}

func TestCreateListenerRejectsNonAuthoritativeJSON(t *testing.T) {
	handler := newListenerHandlerForTest(t)

	for _, test := range []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{
			name: "unknown field",
			body: `{
				"name":"unknown-field",
				"protocol":"http",
				"host":"127.0.0.1",
				"port":12345,
				"host_header":"ignored.example"
			}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "unknown field",
		},
		{
			name: "trailing JSON value",
			body: `{
				"name":"trailing-value",
				"protocol":"http",
				"host":"127.0.0.1",
				"port":12345
			} {}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "exactly one JSON value",
		},
		{
			name:       "oversized body",
			body:       `{"padding":"` + strings.Repeat("a", maxListenerCreateRequestBytes) + `"}`,
			wantStatus: http.StatusRequestEntityTooLarge,
			wantError:  "request body too large",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/listeners/create",
				strings.NewReader(test.body),
			)
			response := httptest.NewRecorder()

			handler.HandleCreateListener(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf(
					"status = %d, want %d; body=%q",
					response.Code,
					test.wantStatus,
					response.Body.String(),
				)
			}
			if !strings.Contains(response.Body.String(), test.wantError) {
				t.Fatalf(
					"response body = %q, want %q",
					response.Body.String(),
					test.wantError,
				)
			}
		})
	}
}

func TestCreateListenerRejectsInactiveSettingsBeforeSideEffects(t *testing.T) {
	manager, err := listeners.NewListenerManagerWithPersistenceForIsolatedLab(
		nil,
		filepath.Join(t.TempDir(), "listeners"),
		nil,
	)
	if err != nil {
		t.Fatalf("create listener manager: %v", err)
	}
	handler := NewListenerHandlers(manager)

	for _, test := range []struct {
		name      string
		bindHost  string
		extraJSON string
		wantError string
	}{
		{
			name:      "caller supplied id",
			extraJSON: `,"id":"caller-selected"`,
			wantError: "id is server-generated",
		},
		{
			name:      "multiple advertised hosts",
			extraJSON: `,"hosts":["one.example","two.example"]`,
			wantError: "supports one advertised host",
		},
		{
			name:      "invalid advertised host",
			extraJSON: `,"hosts":["https://c2.example"]`,
			wantError: "invalid listener advertised host",
		},
		{
			name:      "unspecified endpoint without advertised host",
			bindHost:  "0.0.0.0",
			wantError: "hosts[0] is required",
		},
		{
			name:      "invalid bind host",
			bindHost:  "https://127.0.0.1",
			extraJSON: `,"hosts":["c2.example"]`,
			wantError: "invalid listener bind host",
		},
		{
			name:      "bind host surrounding whitespace",
			bindHost:  " 127.0.0.1",
			extraJSON: `,"hosts":["c2.example"]`,
			wantError: "surrounding whitespace",
		},
		{
			name:      "host rotation",
			extraJSON: `,"host_rotation":"round-robin"`,
			wantError: "host_rotation is not implemented",
		},
		{
			name:      "custom URI",
			extraJSON: `,"uris":["/custom"]`,
			wantError: "custom URIs are not implemented",
		},
		{
			name:      "custom header",
			extraJSON: `,"headers":{"X-Test":"value"}`,
			wantError: "custom headers are not implemented",
		},
		{
			name:      "user agent",
			extraJSON: `,"user_agent":"custom-agent"`,
			wantError: "user_agent is not implemented",
		},
		{
			name:      "proxy",
			extraJSON: `,"proxy":{"type":"http","host":"proxy.example","port":8080}`,
			wantError: "proxy configuration is not implemented",
		},
		{
			name:      "SOCKS5 listener config",
			extraJSON: `,"socks5_config":{}`,
			wantError: "SOCKS5 configuration is not implemented",
		},
		{
			name:      "DNS protocol",
			extraJSON: "",
			wantError: "DNS over HTTPS listener protocol is not implemented",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocol := "http"
			if test.name == "DNS protocol" {
				protocol = "dns"
			}
			bindHost := test.bindHost
			if bindHost == "" {
				bindHost = "127.0.0.1"
			}
			body := `{
				"name":"unsupported-setting",
				"protocol":"` + protocol + `",
				"host":"` + bindHost + `",
				"port":12345` + test.extraJSON + `
			}`
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/listeners/create",
				strings.NewReader(body),
			)
			response := httptest.NewRecorder()

			handler.HandleCreateListener(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf(
					"status = %d, want 400; body=%q",
					response.Code,
					response.Body.String(),
				)
			}
			if !strings.Contains(response.Body.String(), test.wantError) {
				t.Fatalf(
					"response body = %q, want %q",
					response.Body.String(),
					test.wantError,
				)
			}
			if got := len(manager.ListListeners()); got != 0 {
				t.Fatalf("rejected request registered %d listener(s)", got)
			}
		})
	}
}

func newListenerHandlerForTest(t *testing.T) *ListenerHandlers {
	t.Helper()
	manager, err := listeners.NewListenerManagerWithPersistenceForIsolatedLab(
		nil,
		filepath.Join(t.TempDir(), "listeners"),
		nil,
	)
	if err != nil {
		t.Fatalf("create listener manager: %v", err)
	}
	return NewListenerHandlers(manager)
}

func activateAPITestPayload(
	t *testing.T,
	database *persistence.Database,
	store *enrollment.Store,
	listenerID string,
	payloadID string,
) enrollment.BootstrapCredential {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := database.SQL().Exec(
		`INSERT INTO payload_builds (
			id, payload_id, listener_id, mutation_seed, filename,
			relative_path, size, sha256, created_at, state,
			state_detail, provenance_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		payloadID,
		payloadID,
		listenerID,
		"0123456789abcdef",
		"agent",
		"release/"+payloadID+"/agent",
		1,
		strings.Repeat("a", 64),
		now,
		"completed",
		"",
		[]byte("{}"),
	); err != nil {
		t.Fatalf("insert API test payload: %v", err)
	}
	bootstrap, err := enrollment.GenerateBootstrapCredential()
	if err != nil {
		t.Fatalf("generate API test bootstrap: %v", err)
	}
	if err := store.ActivatePayloadCredential(
		context.Background(),
		enrollment.PayloadCredentialActivation{
			PayloadBuildID:  payloadID,
			ListenerID:      listenerID,
			BootstrapSHA256: bootstrap.SHA256,
			MaxSessions:     1,
		},
	); err != nil {
		t.Fatalf("activate API test bootstrap: %v", err)
	}
	return bootstrap
}

func serveListenerManagementRequest(
	handler http.Handler,
	method string,
	path string,
	body string,
) *httptest.ResponseRecorder {
	return serveListenerManagementRequestWithContext(
		context.Background(),
		handler,
		method,
		path,
		body,
	)
}

func serveListenerManagementRequestWithContext(
	ctx context.Context,
	handler http.Handler,
	method string,
	path string,
	body string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request = request.WithContext(ctx)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
