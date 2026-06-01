package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOperatorAPIDoesNotServeAgentPollingRoutes(t *testing.T) {
	handler := NewAPIHandler(nil)
	req := httptest.NewRequest(http.MethodPost, "/api/agent/test/heartbeat", nil)
	rec := httptest.NewRecorder()

	handler.HandleRequest(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected operator API to reject agent polling route with 404, got %d", rec.Code)
	}
}
