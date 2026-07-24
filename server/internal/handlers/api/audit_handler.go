package api

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"

	"microc2/server/internal/audit"
)

const (
	defaultAuditPageLimit = 50
	maxAuditPageLimit     = 100
)

func (h *APIHandler) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	options, err := parseAuditPageOptions(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "Invalid audit query: "+err.Error(), http.StatusBadRequest)
		return
	}
	if h.auditErr != nil || h.audit == nil {
		http.Error(w, "Audit history is unavailable", http.StatusServiceUnavailable)
		return
	}
	page, err := h.audit.Page(r.Context(), options)
	if err != nil {
		http.Error(w, "Audit history is unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func parseAuditPageOptions(rawQuery string) (audit.PageOptions, error) {
	options := audit.PageOptions{
		Limit:  defaultAuditPageLimit,
		Offset: 0,
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return audit.PageOptions{}, fmt.Errorf("malformed query string: %w", err)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key != "limit" && key != "offset" {
			return audit.PageOptions{}, fmt.Errorf(
				"unknown query parameter %q",
				key,
			)
		}
		if len(values[key]) != 1 {
			return audit.PageOptions{}, fmt.Errorf(
				"query parameter %q must be provided exactly once",
				key,
			)
		}
	}
	if values.Has("limit") {
		limit, err := parseTaskQueryInteger("limit", values.Get("limit"))
		if err != nil {
			return audit.PageOptions{}, err
		}
		if limit < 1 || limit > maxAuditPageLimit {
			return audit.PageOptions{}, fmt.Errorf(
				"query parameter %q must be between 1 and %d",
				"limit",
				maxAuditPageLimit,
			)
		}
		options.Limit = limit
	}
	if values.Has("offset") {
		offset, err := parseTaskQueryInteger("offset", values.Get("offset"))
		if err != nil {
			return audit.PageOptions{}, err
		}
		if offset < 0 || offset > audit.MaxPageOffset {
			return audit.PageOptions{}, fmt.Errorf(
				"query parameter %q must be between 0 and %d",
				"offset",
				audit.MaxPageOffset,
			)
		}
		options.Offset = offset
	}
	return options, nil
}
