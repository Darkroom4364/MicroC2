package ws

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gorilla "github.com/gorilla/websocket"

	"microc2/server/internal/audit"
	"microc2/server/internal/persistence"
)

var testTerminalActor = audit.Actor{
	Kind: audit.ActorOperator,
	ID:   "loopback",
}

func TestNewDefaultsTerminalToDisabled(t *testing.T) {
	handler := New(nil, func(*http.Request) bool { return true })
	if handler.terminalEnabled {
		t.Fatal("legacy WebSocket constructor enabled the server terminal")
	}
}

func TestTerminalDisabledByPolicyIsDeniedAndAudited(t *testing.T) {
	store, _ := newTerminalAuditStore(t)
	handler := NewWithTerminalPolicy(
		nil,
		func(*http.Request) bool { return true },
		false,
		store,
	)
	recorder := httptest.NewRecorder()
	request := trustedTerminalRequest(
		httptest.NewRequest(http.MethodGet, terminalRoute, nil),
	)

	handler.HandleTerminal(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("disabled terminal status = %d, want 403", recorder.Code)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf(
			"disabled terminal Cache-Control = %q, want no-store",
			recorder.Header().Get("Cache-Control"),
		)
	}
	events := terminalAuditEvents(t, store)
	if len(events) != 1 {
		t.Fatalf("disabled terminal events = %d, want 1", len(events))
	}
	event := events[0]
	if event.Actor != testTerminalActor ||
		event.Action != terminalAccessAction ||
		event.Route != terminalRoute ||
		event.Target.Kind != terminalTargetKind ||
		event.Target.ID == "" ||
		event.Outcome != audit.OutcomeDenied ||
		event.ReasonCode != terminalDisabledReason ||
		event.TerminalSessionID != event.Target.ID {
		t.Fatalf("unexpected disabled terminal event: %#v", event)
	}
}

func TestTerminalRejectsRequestWithoutTrustedActor(t *testing.T) {
	store, _ := newTerminalAuditStore(t)
	handler := NewWithTerminalPolicy(
		nil,
		func(*http.Request) bool { return true },
		true,
		store,
	)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, terminalRoute, nil)

	handler.HandleTerminal(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("untrusted terminal status = %d, want 403", recorder.Code)
	}
	if events := terminalAuditEvents(t, store); len(events) != 0 {
		t.Fatalf("untrusted terminal request wrote %d audit events", len(events))
	}
}

func TestTerminalAuditsAuthorizedRequestBeforeUpgrade(t *testing.T) {
	store, _ := newTerminalAuditStore(t)
	handler := NewWithTerminalPolicy(
		nil,
		func(*http.Request) bool { return true },
		true,
		store,
	)
	recorder := httptest.NewRecorder()
	request := trustedTerminalRequest(
		httptest.NewRequest(http.MethodGet, terminalRoute, nil),
	)

	handler.HandleTerminal(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("non-WebSocket terminal status = %d, want 400", recorder.Code)
	}
	events := terminalAuditEvents(t, store)
	if len(events) != 1 {
		t.Fatalf("failed-upgrade terminal events = %d, want 1", len(events))
	}
	if events[0].Action != terminalAccessAction ||
		events[0].Outcome != audit.OutcomeSucceeded {
		t.Fatalf("unexpected access-request event: %#v", events[0])
	}
}

func TestTerminalAuditsOpenAndCloseWithoutCommandContent(t *testing.T) {
	store, _ := newTerminalAuditStore(t)
	handler := NewWithTerminalPolicy(
		nil,
		func(*http.Request) bool { return true },
		true,
		store,
	)
	connection, serverDone := dialTerminalInMemory(t, http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		handler.HandleTerminal(w, trustedTerminalRequest(r))
	}))
	if _, _, err := connection.ReadMessage(); err != nil {
		connection.Close()
		t.Fatalf("read terminal greeting: %v", err)
	}
	if err := connection.WriteMessage(gorilla.TextMessage, []byte("pwd")); err != nil {
		connection.Close()
		t.Fatalf("write terminal command: %v", err)
	}
	if _, _, err := connection.ReadMessage(); err != nil {
		connection.Close()
		t.Fatalf("read terminal command response: %v", err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close terminal client: %v", err)
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("serve in-memory terminal: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("terminal handler did not finish after client close")
	}

	events := terminalAuditEvents(t, store)
	if len(events) != 3 {
		t.Fatalf("terminal lifecycle events = %d, want 3: %#v", len(events), events)
	}
	closed, opened, requested := events[0], events[1], events[2]
	if requested.Action != terminalAccessAction ||
		opened.Action != terminalOpenAction ||
		closed.Action != terminalCloseAction {
		t.Fatalf(
			"terminal actions newest-first = %q, %q, %q",
			closed.Action,
			opened.Action,
			requested.Action,
		)
	}
	if requested.TerminalSessionID == "" ||
		opened.TerminalSessionID != requested.TerminalSessionID ||
		closed.TerminalSessionID != requested.TerminalSessionID {
		t.Fatalf("terminal session correlation is inconsistent: %#v", events)
	}
	if opened.CausationSequence == nil ||
		*opened.CausationSequence != requested.Sequence ||
		closed.CausationSequence == nil ||
		*closed.CausationSequence != opened.Sequence {
		t.Fatalf("terminal causation chain is inconsistent: %#v", events)
	}
	for _, event := range events {
		if event.Actor != testTerminalActor ||
			event.Route != terminalRoute ||
			event.Outcome != audit.OutcomeSucceeded {
			t.Fatalf("unexpected terminal lifecycle event: %#v", event)
		}
		encodedFields := event.Action + event.Route + event.Target.ID +
			event.ReasonCode + event.TerminalSessionID
		if strings.Contains(encodedFields, "pwd") {
			t.Fatalf("terminal event retained command content: %#v", event)
		}
	}
}

func TestEnabledTerminalFailsClosedWhenAuditStoreIsUnavailable(t *testing.T) {
	store, database := newTerminalAuditStore(t)
	if err := database.Close(); err != nil {
		t.Fatalf("close audit database: %v", err)
	}
	handler := NewWithTerminalPolicy(
		nil,
		func(*http.Request) bool { return true },
		true,
		store,
	)
	recorder := httptest.NewRecorder()
	request := trustedTerminalRequest(
		httptest.NewRequest(http.MethodGet, terminalRoute, nil),
	)

	handler.HandleTerminal(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("terminal audit failure status = %d, want 503", recorder.Code)
	}
}

func newTerminalAuditStore(
	t *testing.T,
) (*audit.Store, *persistence.Database) {
	t.Helper()
	database, err := persistence.Open(
		filepath.Join(t.TempDir(), "microc2.db"),
	)
	if err != nil {
		t.Fatalf("open audit database: %v", err)
	}
	t.Cleanup(func() {
		_ = database.Close()
	})
	store, err := audit.NewStore(database)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	return store, database
}

func trustedTerminalRequest(r *http.Request) *http.Request {
	return r.WithContext(audit.WithActor(r.Context(), testTerminalActor))
}

func terminalAuditEvents(t *testing.T, store *audit.Store) []audit.Event {
	t.Helper()
	page, err := store.Page(context.Background(), audit.PageOptions{
		Limit:  100,
		Offset: 0,
	})
	if err != nil {
		t.Fatalf("page terminal audit events: %v", err)
	}
	return page.Events
}

type pipeResponseWriter struct {
	header      http.Header
	connection  net.Conn
	reader      *bufio.Reader
	writer      *bufio.Writer
	wroteHeader bool
}

func (w *pipeResponseWriter) Header() http.Header {
	return w.header
}

func (w *pipeResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	_, _ = fmt.Fprintf(w.writer, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	for name, values := range w.header {
		for _, value := range values {
			_, _ = fmt.Fprintf(w.writer, "%s: %s\r\n", name, value)
		}
	}
	_, _ = w.writer.WriteString("\r\n")
	_ = w.writer.Flush()
}

func (w *pipeResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.writer.Write(body)
}

func (w *pipeResponseWriter) Hijack() (
	net.Conn,
	*bufio.ReadWriter,
	error,
) {
	return w.connection, bufio.NewReadWriter(w.reader, w.writer), nil
}

func dialTerminalInMemory(
	t *testing.T,
	handler http.Handler,
) (*gorilla.Conn, <-chan error) {
	t.Helper()
	serverConnection, clientConnection := net.Pipe()
	deadline := time.Now().Add(2 * time.Second)
	if err := serverConnection.SetDeadline(deadline); err != nil {
		t.Fatalf("set server pipe deadline: %v", err)
	}
	if err := clientConnection.SetDeadline(deadline); err != nil {
		t.Fatalf("set client pipe deadline: %v", err)
	}
	serverDone := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverConnection)
		writer := bufio.NewWriter(serverConnection)
		request, err := http.ReadRequest(reader)
		if err != nil {
			_ = serverConnection.Close()
			serverDone <- fmt.Errorf("read WebSocket request: %w", err)
			return
		}
		request.RemoteAddr = "127.0.0.1:50000"
		handler.ServeHTTP(&pipeResponseWriter{
			header:     make(http.Header),
			connection: serverConnection,
			reader:     reader,
			writer:     writer,
		}, request)
		_ = serverConnection.Close()
		serverDone <- nil
	}()

	target, err := url.Parse("ws://microc2.test" + terminalRoute)
	if err != nil {
		t.Fatalf("parse terminal URL: %v", err)
	}
	connection, _, err := gorilla.NewClient(
		clientConnection,
		target,
		nil,
		0,
		0,
	)
	if err != nil {
		_ = clientConnection.Close()
		if serverErr := <-serverDone; serverErr != nil {
			t.Fatalf("dial terminal: %v (server: %v)", err, serverErr)
		}
		t.Fatalf("dial terminal: %v", err)
	}
	return connection, serverDone
}
