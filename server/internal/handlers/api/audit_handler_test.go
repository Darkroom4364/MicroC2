package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"microc2/server/internal/audit"
	"microc2/server/internal/persistence"
)

func TestAuditAPIIsBoundedNewestFirstAndNoStore(t *testing.T) {
	database, err := persistence.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	store, err := audit.NewStore(database)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	for _, action := range []string{"listener.create", "task.queued", "task.dispatched"} {
		if _, err := store.Append(context.Background(), audit.Input{
			Actor:   audit.Actor{Kind: audit.ActorSystem, ID: "test"},
			Action:  action,
			Route:   "internal:test",
			Target:  audit.Target{Kind: "test", ID: action},
			Outcome: audit.OutcomeSucceeded,
		}); err != nil {
			t.Fatalf("append %s: %v", action, err)
		}
	}
	handler := &APIHandler{audit: store}
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/audit/events?limit=2&offset=0",
		nil,
	)
	response := httptest.NewRecorder()
	handler.HandleRequest(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("audit page status = %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	var page audit.Page
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode audit page: %v", err)
	}
	if page.SchemaVersion != audit.SchemaVersion ||
		page.Limit != 2 ||
		page.Offset != 0 ||
		page.Total != 3 ||
		page.NextOffset == nil ||
		*page.NextOffset != 2 ||
		len(page.Events) != 2 {
		t.Fatalf("unexpected audit page: %#v", page)
	}
	if page.Events[0].Action != "task.dispatched" ||
		page.Events[1].Action != "task.queued" ||
		page.Events[0].Sequence <= page.Events[1].Sequence {
		t.Fatalf("audit page is not newest-first: %#v", page.Events)
	}
}

func TestAuditAPIRejectsUnboundedAndAmbiguousQueries(t *testing.T) {
	handler := &APIHandler{}
	for _, path := range []string{
		"/api/audit/events?limit=0",
		"/api/audit/events?limit=101",
		"/api/audit/events?offset=-1",
		"/api/audit/events?offset=1000001",
		"/api/audit/events?limit=1&limit=2",
		"/api/audit/events?unknown=1",
	} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			response := httptest.NewRecorder()
			handler.HandleRequest(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf(
					"GET %s status = %d, want 400: %s",
					path,
					response.Code,
					response.Body.String(),
				)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("GET %s omitted no-store", path)
			}
		})
	}

	request := httptest.NewRequest(http.MethodPost, "/api/audit/events", nil)
	response := httptest.NewRecorder()
	handler.HandleRequest(response, request)
	if response.Code != http.StatusMethodNotAllowed ||
		response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST audit response = %d headers=%v", response.Code, response.Header())
	}
}
