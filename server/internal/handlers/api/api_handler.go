package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log" // Updated from `networking`
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	// Updated from `networking`

	"microc2/server/internal/audit"
	"microc2/server/internal/behaviour"
	"microc2/server/internal/listeners"
	"microc2/server/internal/modules"
	"microc2/server/internal/tasks"
	"microc2/server/pkg/communication"
)

const scopedAgentKeyDelimiter = "/"

func NewAPIHandler(manager *communication.ServerManager) *APIHandler {
	handler := &APIHandler{
		serverManager: manager,
	}
	if manager != nil && manager.GetDatabase() != nil {
		handler.audit, handler.auditErr = audit.NewStore(manager.GetDatabase())
	}
	return handler
}

func (h *APIHandler) HandleRequest(w http.ResponseWriter, r *http.Request) {
	// log.Printf("[DEBUG] HandleRequest called: %s %s", r.Method, r.URL.Path)
	if r.URL.Path == "/api/audit/events" {
		h.handleAuditEvents(w, r)
		return
	}
	if r.URL.Path == "/api/modules" {
		h.handleModuleCatalog(w, r)
		return
	}
	if r.URL.Path == "/api/agents/list" {
		h.handleListAgents(w, r)
		return
	}

	if r.Method == http.MethodPost && r.URL.Path == "/api/agents/command" {
		h.handleQueueAgentCommandFromBody(w, r)
		return
	}
	if matched, valid, agentID := parseOperatorModuleTaskRoute(r.URL.Path); matched {
		if !valid {
			http.Error(w, "Invalid module task request path", http.StatusBadRequest)
			return
		}
		h.handleModuleTasks(w, r, agentID)
		return
	}

	if matched, valid, agentID, taskID, cancel := parseOperatorTaskRoute(r.URL.Path); matched {
		if !valid {
			http.Error(w, "Invalid task request path", http.StatusBadRequest)
			return
		}
		if cancel {
			h.handleCancelTask(w, r, agentID, taskID)
			return
		}
		if taskID != "" {
			h.handleTaskDetail(w, r, agentID, taskID)
			return
		}
		h.handleTasks(w, r, agentID)
		return
	}

	// Handle POST /api/agents/{AgentID}/command
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/agents/") && strings.HasSuffix(r.URL.Path, "/command") {
		AgentID, ok := parseAgentPathID(r.URL.Path, "/api/agents/", "/command")
		if !ok {
			http.Error(w, "Invalid agent ID", http.StatusBadRequest)
			return
		}
		h.handleQueueAgentCommand(w, r, AgentID)
		return
	}

	// Add GET /api/agents/{AgentID}/results endpoint
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/agents/") && strings.HasSuffix(r.URL.Path, "/results") {
		AgentID, ok := parseAgentPathID(r.URL.Path, "/api/agents/", "/results")
		if !ok {
			http.Error(w, "Invalid agent ID", http.StatusBadRequest)
			return
		}
		h.handleGetAgentResults(w, r, AgentID)
		return
	}

	// Default handler for API requests
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"error":"unknown operator API route"}`))
}

func (h *APIHandler) handleModuleCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "Module catalog does not accept query parameters", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, modules.DefaultRegistry().Catalog())
}

func parseAgentPathID(path, prefix, suffix string) (string, bool) {
	trimmed := strings.TrimPrefix(path, prefix)
	agentID := strings.TrimSuffix(trimmed, suffix)
	agentID = strings.TrimSuffix(agentID, "/")
	if strings.Contains(agentID, "/") || tasks.ValidateIdentifier("agent_id", agentID) != nil {
		return "", false
	}
	return agentID, true
}

func parseOperatorTaskRoute(path string) (matched, valid bool, agentID, taskID string, cancel bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 4 || parts[0] != "api" || parts[1] != "agents" || parts[3] != "tasks" {
		return false, false, "", "", false
	}
	if err := tasks.ValidateIdentifier("agent_id", parts[2]); err != nil {
		return true, false, "", "", false
	}
	switch {
	case len(parts) == 4:
		return true, true, parts[2], "", false
	case len(parts) == 5:
		if err := tasks.ValidateIdentifier("task_id", parts[4]); err != nil {
			return true, false, "", "", false
		}
		return true, true, parts[2], parts[4], false
	case len(parts) == 6 && parts[5] == "cancel":
		if err := tasks.ValidateIdentifier("task_id", parts[4]); err != nil {
			return true, false, "", "", false
		}
		return true, true, parts[2], parts[4], true
	default:
		return true, false, "", "", false
	}
}
func parseOperatorModuleTaskRoute(path string) (matched, valid bool, agentID string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 4 || parts[0] != "api" || parts[1] != "agents" || parts[3] != "module-tasks" {
		return false, false, ""
	}
	if err := tasks.ValidateIdentifier("agent_id", parts[2]); err != nil {
		return true, false, ""
	}
	return true, true, parts[2]
}

type taskProtocol interface {
	CreateTask(agentID string, request tasks.CreateRequest) (tasks.Task, error)
	CreateModuleTask(agentID string, request tasks.ModuleCreateRequest) (tasks.Task, error)
	ListTasks(agentID string) ([]tasks.Task, error)
	CancelTask(agentID, taskID string) (tasks.Task, error)
	GetTask(agentID, taskID string) (tasks.Task, error)
	GetResultsPage(agentID string, offset, limit int) ([]map[string]interface{}, int)
	QueueLegacyShellTask(agentID, command string) (tasks.Task, error)
	AgentLastSeen(agentID string) (time.Time, bool)
}

type taskCreateContextProtocol interface {
	CreateTaskContext(context.Context, string, tasks.CreateRequest) (tasks.Task, error)
}

type moduleTaskCreateContextProtocol interface {
	CreateModuleTaskContext(
		context.Context,
		string,
		tasks.ModuleCreateRequest,
	) (tasks.Task, error)
}

type taskCancelContextProtocol interface {
	CancelTaskContext(context.Context, string, string) (tasks.Task, error)
}

type legacyTaskQueueContextProtocol interface {
	QueueLegacyShellTaskContext(
		context.Context,
		string,
		string,
	) (tasks.Task, error)
}

type taskSummaryProtocol interface {
	ListTaskSummariesPage(
		agentID string,
		offset, limit int,
	) ([]tasks.TaskSummary, int, error)
}

type boundedLegacyResultProtocol interface {
	ListLegacyResultsPage(
		agentID string,
		offset, limit, maxEncodedBytes int,
	) ([]tasks.LegacyResult, int, bool, error)
}

const (
	defaultTaskListLimit  = 50
	maxTaskListLimit      = 100
	defaultAgentListLimit = 100
	maxAgentListLimit     = 500
)

type taskListOptions struct {
	limit  int
	offset int
}

type taskListEnvelope struct {
	SchemaVersion int                 `json:"schema_version"`
	Tasks         []tasks.TaskSummary `json:"tasks"`
	Limit         int                 `json:"limit"`
	Offset        int                 `json:"offset"`
	Total         int                 `json:"total"`
	NextOffset    *int                `json:"next_offset"`
}

func (h *APIHandler) handleTasks(w http.ResponseWriter, r *http.Request, agentID string) {
	switch r.Method {
	case http.MethodPost:
		if err := rejectTaskQuery(r.URL.RawQuery); err != nil {
			writeTaskQueryError(w, err)
			return
		}
		protocol, err := h.resolveActiveAgentTaskProtocol(agentID)
		if err != nil {
			writeAgentResolutionError(w, err)
			return
		}
		var request tasks.CreateRequest
		if err := decodeStrictJSON(w, r, &request, tasks.MaxTaskCreateBodyBytes); err != nil {
			writeJSONDecodeError(w, "Invalid task request", err)
			return
		}
		var task tasks.Task
		if actorAware, ok := protocol.(taskCreateContextProtocol); ok {
			task, err = actorAware.CreateTaskContext(r.Context(), agentID, request)
		} else {
			task, err = protocol.CreateTask(agentID, request)
		}
		if err != nil {
			writeTaskError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, task)
	case http.MethodGet:
		options, err := parseTaskListOptions(r.URL.RawQuery)
		if err != nil {
			writeTaskQueryError(w, err)
			return
		}
		page, err := h.listAgentTaskPage(agentID, options)
		if err != nil {
			if errors.Is(err, errAgentNotFound) {
				writeAgentResolutionError(w, err)
			} else {
				writeTaskError(w, err)
			}
			return
		}
		writeJSON(w, http.StatusOK, page)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
func (h *APIHandler) handleModuleTasks(
	w http.ResponseWriter,
	r *http.Request,
	agentID string,
) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := rejectTaskQuery(r.URL.RawQuery); err != nil {
		writeTaskQueryError(w, err)
		return
	}
	protocol, err := h.resolveActiveAgentTaskProtocol(agentID)
	if err != nil {
		writeAgentResolutionError(w, err)
		return
	}
	var request tasks.ModuleCreateRequest
	if err := decodeStrictJSON(w, r, &request, tasks.MaxTaskCreateBodyBytes); err != nil {
		writeJSONDecodeError(w, "Invalid module task request", err)
		return
	}
	var task tasks.Task
	if actorAware, ok := protocol.(moduleTaskCreateContextProtocol); ok {
		task, err = actorAware.CreateModuleTaskContext(r.Context(), agentID, request)
	} else {
		task, err = protocol.CreateModuleTask(agentID, request)
	}
	if err != nil {
		writeTaskError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, task)
}

func (h *APIHandler) handleTaskDetail(
	w http.ResponseWriter,
	r *http.Request,
	agentID string,
	taskID string,
) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := rejectTaskQuery(r.URL.RawQuery); err != nil {
		writeTaskQueryError(w, err)
		return
	}
	task, err := h.getAgentTask(agentID, taskID)
	if err != nil {
		if errors.Is(err, errAmbiguousTaskOwnership) {
			writeAgentResolutionError(w, err)
		} else {
			writeTaskError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, task)
}

func (h *APIHandler) handleCancelTask(w http.ResponseWriter, r *http.Request, agentID, taskID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := rejectTaskQuery(r.URL.RawQuery); err != nil {
		writeTaskQueryError(w, err)
		return
	}
	task, err := h.cancelAgentTask(r.Context(), agentID, taskID)
	if err != nil {
		if errors.Is(err, errAmbiguousTaskOwnership) {
			writeAgentResolutionError(w, err)
		} else {
			writeTaskError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, task)
}

func parseTaskListOptions(rawQuery string) (taskListOptions, error) {
	options := taskListOptions{
		limit:  defaultTaskListLimit,
		offset: 0,
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return taskListOptions{}, fmt.Errorf("malformed query string: %w", err)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key != "limit" && key != "offset" {
			return taskListOptions{}, fmt.Errorf("unknown query parameter %q", key)
		}
		if len(values[key]) != 1 {
			return taskListOptions{}, fmt.Errorf(
				"query parameter %q must be provided exactly once",
				key,
			)
		}
	}
	if values.Has("limit") {
		limit, err := parseTaskQueryInteger("limit", values.Get("limit"))
		if err != nil {
			return taskListOptions{}, err
		}
		if limit < 1 || limit > maxTaskListLimit {
			return taskListOptions{}, fmt.Errorf(
				"query parameter %q must be between 1 and %d",
				"limit",
				maxTaskListLimit,
			)
		}
		options.limit = limit
	}
	if values.Has("offset") {
		offset, err := parseTaskQueryInteger("offset", values.Get("offset"))
		if err != nil {
			return taskListOptions{}, err
		}
		options.offset = offset
	}
	return options, nil
}

func parseTaskQueryInteger(name, value string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("query parameter %q must be a nonnegative integer", name)
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("query parameter %q must be a nonnegative integer", name)
		}
	}
	parsed, err := strconv.ParseUint(value, 10, strconv.IntSize)
	if err != nil {
		return 0, fmt.Errorf("query parameter %q is out of range", name)
	}
	return int(parsed), nil
}

func rejectTaskQuery(rawQuery string) error {
	if rawQuery == "" {
		return nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return fmt.Errorf("malformed query string: %w", err)
	}
	if len(values) == 0 {
		return errors.New("query parameters are not supported")
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return fmt.Errorf("query parameter %q is not supported", keys[0])
}

func summarizeTaskPage(all []tasks.Task, options taskListOptions) taskListEnvelope {
	start := options.offset
	if start > len(all) {
		start = len(all)
	}
	end := start + options.limit
	if end > len(all) {
		end = len(all)
	}
	summaries := make([]tasks.TaskSummary, 0, end-start)
	for _, task := range all[start:end] {
		summaries = append(summaries, tasks.Summarize(task))
	}
	var nextOffset *int
	if end < len(all) {
		next := end
		nextOffset = &next
	}
	return taskListEnvelope{
		SchemaVersion: tasks.SchemaVersion,
		Tasks:         summaries,
		Limit:         options.limit,
		Offset:        options.offset,
		Total:         len(all),
		NextOffset:    nextOffset,
	}
}

func writeTaskQueryError(w http.ResponseWriter, err error) {
	http.Error(w, "Invalid task query: "+err.Error(), http.StatusBadRequest)
}

const activeAgentWindow = 5 * time.Minute

var (
	errAgentNotFound           = errors.New("agent not found")
	errAgentInactive           = errors.New("agent has no active listener session")
	errAmbiguousAgentOwnership = errors.New("agent is active on multiple listeners")
	errAmbiguousTaskOwnership  = errors.New("task exists on multiple listeners")
)

type agentTaskProtocolRef struct {
	listenerID string
	status     listeners.ListenerStatus
	protocol   taskProtocol
	lastSeen   time.Time
	knownAgent bool
}

// durableHistoryTaskProtocol exposes one persisted listener scope for
// historical reads and cancellation. Its zero last-seen value and stopped
// status ensure it can never be selected for new task dispatch.
type durableHistoryTaskProtocol struct {
	agentID string
	store   *tasks.DurableStore
}

func (p *durableHistoryTaskProtocol) CreateTask(
	agentID string,
	request tasks.CreateRequest,
) (tasks.Task, error) {
	// DurableStore.Create validates task fields and inserts them into SQLite;
	// it does not create a filesystem path.
	// foxguard: ignore[go/taint-path-traversal]
	return p.store.Create(agentID, request)
}

func (p *durableHistoryTaskProtocol) CreateTaskContext(
	ctx context.Context,
	agentID string,
	request tasks.CreateRequest,
) (tasks.Task, error) {
	return p.store.CreateContext(ctx, agentID, request)
}
func (p *durableHistoryTaskProtocol) CreateModuleTask(
	agentID string,
	request tasks.ModuleCreateRequest,
) (tasks.Task, error) {
	return p.store.CreateModule(agentID, request)
}

func (p *durableHistoryTaskProtocol) CreateModuleTaskContext(
	ctx context.Context,
	agentID string,
	request tasks.ModuleCreateRequest,
) (tasks.Task, error) {
	return p.store.CreateModuleContext(ctx, agentID, request)
}

func (p *durableHistoryTaskProtocol) ListTasks(agentID string) ([]tasks.Task, error) {
	return p.store.List(agentID)
}

func (p *durableHistoryTaskProtocol) CancelTask(agentID, taskID string) (tasks.Task, error) {
	return p.store.Cancel(agentID, taskID)
}

func (p *durableHistoryTaskProtocol) CancelTaskContext(
	ctx context.Context,
	agentID, taskID string,
) (tasks.Task, error) {
	return p.store.CancelContext(ctx, agentID, taskID)
}

func (p *durableHistoryTaskProtocol) GetTask(agentID, taskID string) (tasks.Task, error) {
	return p.store.Get(agentID, taskID)
}

func (p *durableHistoryTaskProtocol) GetResultsPage(
	agentID string,
	offset, limit int,
) ([]map[string]interface{}, int) {
	page, total, _, err := p.ListLegacyResultsPage(
		agentID,
		offset,
		limit,
		tasks.MaxLegacyResultPageBytes,
	)
	if err != nil {
		return []map[string]interface{}{}, 0
	}
	results := make([]map[string]interface{}, 0, len(page))
	for _, result := range page {
		results = append(results, legacyResultMap(result))
	}
	return results, total
}

func (p *durableHistoryTaskProtocol) QueueLegacyShellTask(
	agentID, command string,
) (tasks.Task, error) {
	return p.store.CreateLegacyShell(agentID, command)
}

func (p *durableHistoryTaskProtocol) QueueLegacyShellTaskContext(
	ctx context.Context,
	agentID, command string,
) (tasks.Task, error) {
	return p.store.CreateLegacyShellContext(ctx, agentID, command)
}

func (p *durableHistoryTaskProtocol) AgentLastSeen(agentID string) (time.Time, bool) {
	return time.Time{}, agentID == p.agentID
}

func (p *durableHistoryTaskProtocol) ListTaskSummariesPage(
	agentID string,
	offset, limit int,
) ([]tasks.TaskSummary, int, error) {
	return p.store.ListTaskSummariesPage(agentID, offset, limit)
}

func (p *durableHistoryTaskProtocol) ListLegacyResultsPage(
	agentID string,
	offset, limit, maxEncodedBytes int,
) ([]tasks.LegacyResult, int, bool, error) {
	return p.store.GetLegacyResultsPage(
		agentID,
		offset,
		limit,
		maxEncodedBytes,
	)
}

func (h *APIHandler) agentTaskProtocolRefs(
	agentID string,
) ([]agentTaskProtocolRef, error) {
	if h.serverManager == nil {
		return nil, nil
	}
	refs := make([]agentTaskProtocolRef, 0)
	indexByListenerID := make(map[string]int)
	if manager := h.serverManager.GetListenerManager(); manager != nil {
		for _, listener := range manager.ListListeners() {
			if listener.Protocol == nil {
				continue
			}
			protocol, ok := listener.Protocol.(taskProtocol)
			if !ok {
				continue
			}
			lastSeen, knownAgent := protocol.AgentLastSeen(agentID)
			listenerID := listener.Snapshot().Config.ID
			indexByListenerID[listenerID] = len(refs)
			refs = append(refs, agentTaskProtocolRef{
				listenerID: listenerID,
				status:     listener.GetStatus(),
				protocol:   protocol,
				lastSeen:   lastSeen,
				knownAgent: knownAgent,
			})
		}
	}

	database := h.serverManager.GetDatabase()
	if database != nil {
		rows, err := database.SQL().Query(
			`SELECT listener_id FROM agents WHERE agent_id = ?
			 UNION
			 SELECT listener_id FROM tasks WHERE agent_id = ?
			 ORDER BY listener_id`,
			agentID,
			agentID,
		)
		if err != nil {
			return nil, fmt.Errorf("enumerate durable agent listener scopes: %w", err)
		}
		var historicalListenerIDs []string
		for rows.Next() {
			var listenerID string
			if err := rows.Scan(&listenerID); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("scan durable agent listener scope: %w", err)
			}
			if index, exists := indexByListenerID[listenerID]; exists {
				refs[index].knownAgent = true
				continue
			}
			historicalListenerIDs = append(historicalListenerIDs, listenerID)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("iterate durable agent listener scopes: %w", err)
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("close durable agent listener scopes: %w", err)
		}
		for _, listenerID := range historicalListenerIDs {
			store, err := tasks.NewDurableStore(database, listenerID, time.Now)
			if err != nil {
				return nil, fmt.Errorf(
					"open durable agent listener scope %q: %w",
					listenerID,
					err,
				)
			}
			indexByListenerID[listenerID] = len(refs)
			refs = append(refs, agentTaskProtocolRef{
				listenerID: listenerID,
				status:     listeners.StatusStopped,
				protocol: &durableHistoryTaskProtocol{
					agentID: agentID,
					store:   store,
				},
				knownAgent: true,
			})
		}
	}
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].listenerID < refs[j].listenerID
	})
	return refs, nil
}

func (h *APIHandler) resolveActiveAgentTaskProtocol(agentID string) (taskProtocol, error) {
	now := time.Now()
	var active []taskProtocol
	knownAgent := false
	refs, err := h.agentTaskProtocolRefs(agentID)
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		if !ref.knownAgent {
			continue
		}
		knownAgent = true
		if ref.status != listeners.StatusActive || now.Sub(ref.lastSeen) > activeAgentWindow {
			continue
		}
		active = append(active, ref.protocol)
	}
	switch len(active) {
	case 0:
		if knownAgent {
			return nil, errAgentInactive
		}
		return nil, errAgentNotFound
	case 1:
		return active[0], nil
	default:
		return nil, errAmbiguousAgentOwnership
	}
}

func (h *APIHandler) listAgentTaskPage(
	agentID string,
	options taskListOptions,
) (taskListEnvelope, error) {
	refs, err := h.agentTaskProtocolRefs(agentID)
	if err != nil {
		return taskListEnvelope{}, err
	}

	maxInt := int(^uint(0) >> 1)
	candidateLimit := options.offset
	if options.limit > maxInt-candidateLimit {
		candidateLimit = maxInt
	} else {
		candidateLimit += options.limit
	}
	var combined []tasks.TaskSummary
	total := 0
	knownAgent := false
	for _, ref := range refs {
		if ref.knownAgent {
			knownAgent = true
		}

		var (
			summaries     []tasks.TaskSummary
			listenerTotal int
		)
		if pager, ok := ref.protocol.(taskSummaryProtocol); ok {
			summaries, listenerTotal, err = pager.ListTaskSummariesPage(
				agentID,
				0,
				candidateLimit,
			)
		} else {
			var agentTasks []tasks.Task
			agentTasks, err = ref.protocol.ListTasks(agentID)
			if err == nil {
				sort.Slice(agentTasks, func(i, j int) bool {
					if agentTasks[i].CreatedAt.Equal(agentTasks[j].CreatedAt) {
						return agentTasks[i].ID > agentTasks[j].ID
					}
					return agentTasks[i].CreatedAt.After(agentTasks[j].CreatedAt)
				})
				listenerTotal = len(agentTasks)
				pageLimit := candidateLimit
				if pageLimit > listenerTotal {
					pageLimit = listenerTotal
				}
				summaries = make([]tasks.TaskSummary, 0, pageLimit)
				for _, task := range agentTasks[:pageLimit] {
					summaries = append(summaries, tasks.Summarize(task))
				}
			}
		}
		if err != nil {
			return taskListEnvelope{}, err
		}
		if listenerTotal < 0 || listenerTotal > maxInt-total {
			return taskListEnvelope{}, errors.New(
				"listener returned an invalid task count",
			)
		}
		maxSummaries := candidateLimit
		if maxSummaries > listenerTotal {
			maxSummaries = listenerTotal
		}
		if len(summaries) > maxSummaries {
			return taskListEnvelope{}, fmt.Errorf(
				"listener returned %d task summaries, expected at most %d",
				len(summaries),
				maxSummaries,
			)
		}
		total += listenerTotal
		if listenerTotal > 0 {
			knownAgent = true
			combined = append(combined, summaries...)
		}
	}
	if !knownAgent {
		return taskListEnvelope{}, errAgentNotFound
	}
	sort.Slice(combined, func(i, j int) bool {
		if combined[i].CreatedAt.Equal(combined[j].CreatedAt) {
			return combined[i].ID > combined[j].ID
		}
		return combined[i].CreatedAt.After(combined[j].CreatedAt)
	})

	start := options.offset
	if start > len(combined) {
		start = len(combined)
	}
	end := start + options.limit
	if end > len(combined) {
		end = len(combined)
	}
	page := make([]tasks.TaskSummary, end-start)
	copy(page, combined[start:end])
	var nextOffset *int
	if endOffset := options.offset + len(page); endOffset < total {
		next := endOffset
		nextOffset = &next
	}
	return taskListEnvelope{
		SchemaVersion: tasks.SchemaVersion,
		Tasks:         page,
		Limit:         options.limit,
		Offset:        options.offset,
		Total:         total,
		NextOffset:    nextOffset,
	}, nil
}

func (h *APIHandler) getAgentTask(agentID, taskID string) (tasks.Task, error) {
	var found []tasks.Task
	refs, err := h.agentTaskProtocolRefs(agentID)
	if err != nil {
		return tasks.Task{}, err
	}
	for _, ref := range refs {
		task, err := ref.protocol.GetTask(agentID, taskID)
		if err == nil {
			found = append(found, task)
			continue
		}
		if !errors.Is(err, tasks.ErrNotFound) {
			return tasks.Task{}, err
		}
	}
	switch len(found) {
	case 0:
		return tasks.Task{}, tasks.ErrNotFound
	case 1:
		return found[0], nil
	default:
		return tasks.Task{}, errAmbiguousTaskOwnership
	}
}

func (h *APIHandler) cancelAgentTask(
	ctx context.Context,
	agentID, taskID string,
) (tasks.Task, error) {
	var owners []taskProtocol
	refs, err := h.agentTaskProtocolRefs(agentID)
	if err != nil {
		return tasks.Task{}, err
	}
	for _, ref := range refs {
		if _, err := ref.protocol.GetTask(agentID, taskID); err == nil {
			owners = append(owners, ref.protocol)
		} else if !errors.Is(err, tasks.ErrNotFound) {
			return tasks.Task{}, err
		}
	}
	switch len(owners) {
	case 0:
		return tasks.Task{}, tasks.ErrNotFound
	case 1:
		if actorAware, ok := owners[0].(taskCancelContextProtocol); ok {
			return actorAware.CancelTaskContext(ctx, agentID, taskID)
		}
		return owners[0].CancelTask(agentID, taskID)
	default:
		return tasks.Task{}, errAmbiguousTaskOwnership
	}
}

func (h *APIHandler) handleListAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	options, err := parseAgentListOptions(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "Invalid agent query: "+err.Error(), http.StatusBadRequest)
		return
	}
	agents, total, err := h.allAgents(options)
	if err != nil {
		log.Printf("[ERROR] Failed to load durable agent history: %v", err)
		http.Error(w, "Agent history unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.Itoa(total))
	w.Header().Set("X-Limit", strconv.Itoa(options.limit))
	w.Header().Set("X-Offset", strconv.Itoa(options.offset))
	if next := options.offset + len(agents); next < total {
		w.Header().Set("X-Next-Offset", strconv.Itoa(next))
	}
	if err := json.NewEncoder(w).Encode(agents); err != nil {
		log.Printf("[ERROR] Failed to encode agent history: %v", err)
	}
}

type agentListOptions struct {
	limit  int
	offset int
}

func parseAgentListOptions(rawQuery string) (agentListOptions, error) {
	options := agentListOptions{
		limit:  defaultAgentListLimit,
		offset: 0,
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return agentListOptions{}, fmt.Errorf("malformed query string: %w", err)
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key != "limit" && key != "offset" {
			return agentListOptions{}, fmt.Errorf("unknown query parameter %q", key)
		}
		if len(values[key]) != 1 {
			return agentListOptions{}, fmt.Errorf(
				"query parameter %q must be provided exactly once",
				key,
			)
		}
	}
	if values.Has("limit") {
		limit, err := parseTaskQueryInteger("limit", values.Get("limit"))
		if err != nil {
			return agentListOptions{}, err
		}
		if limit < 1 || limit > maxAgentListLimit {
			return agentListOptions{}, fmt.Errorf(
				"query parameter %q must be between 1 and %d",
				"limit",
				maxAgentListLimit,
			)
		}
		options.limit = limit
	}
	if values.Has("offset") {
		offset, err := parseTaskQueryInteger("offset", values.Get("offset"))
		if err != nil {
			return agentListOptions{}, err
		}
		options.offset = offset
	}
	return options, nil
}

func (h *APIHandler) allAgents(
	options agentListOptions,
) (map[string]interface{}, int, error) {
	if h.serverManager == nil {
		return map[string]interface{}{}, 0, nil
	}
	database := h.serverManager.GetDatabase()
	if database == nil {
		manager := h.serverManager.GetListenerManager()
		if manager == nil {
			return map[string]interface{}{}, 0, nil
		}
		all := manager.AllAgents()
		keys := make([]string, 0, len(all))
		for key := range all {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		total := len(keys)
		start := options.offset
		if start > total {
			start = total
		}
		end := start + options.limit
		if end > total {
			end = total
		}
		page := make(map[string]interface{}, end-start)
		for _, key := range keys[start:end] {
			page[key] = all[key]
		}
		return page, total, nil
	}

	var total int
	if err := database.SQL().QueryRow(
		`SELECT COUNT(*) FROM agents`,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count durable agents: %w", err)
	}
	rows, err := database.SQL().Query(
		`SELECT listener_id, agent_id, payload_id, os, hostname, ip,
		        ip_list_json, last_commands_json, last_seen_at,
		        COUNT(*) OVER (PARTITION BY agent_id)
		 FROM agents
		 ORDER BY last_seen_at DESC, listener_id, agent_id
		 LIMIT ? OFFSET ?`,
		options.limit,
		options.offset,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("query durable agents: %w", err)
	}
	type scopedAgent struct {
		listenerID string
		agentID    string
		agent      *behaviour.Agent
		idCount    int
	}
	var persisted []scopedAgent
	for rows.Next() {
		var (
			agent        behaviour.Agent
			listenerID   string
			ipListJSON   []byte
			commandsJSON []byte
			lastSeen     string
			idCount      int
		)
		if err := rows.Scan(
			&listenerID,
			&agent.ID,
			&agent.PayloadID,
			&agent.OS,
			&agent.Hostname,
			&agent.IP,
			&ipListJSON,
			&commandsJSON,
			&lastSeen,
			&idCount,
		); err != nil {
			_ = rows.Close()
			return nil, 0, fmt.Errorf("scan durable agent: %w", err)
		}
		if err := json.Unmarshal(ipListJSON, &agent.IPList); err != nil {
			_ = rows.Close()
			return nil, 0, fmt.Errorf("decode durable agent IP list: %w", err)
		}
		if err := json.Unmarshal(commandsJSON, &agent.Commands); err != nil {
			_ = rows.Close()
			return nil, 0, fmt.Errorf("decode durable agent command list: %w", err)
		}
		agent.LastSeen, err = time.Parse(time.RFC3339Nano, lastSeen)
		if err != nil {
			_ = rows.Close()
			return nil, 0, fmt.Errorf("decode durable agent last_seen: %w", err)
		}
		agent.ListenerID = listenerID
		agentCopy := agent
		persisted = append(persisted, scopedAgent{
			listenerID: listenerID,
			agentID:    agent.ID,
			agent:      &agentCopy,
			idCount:    idCount,
		})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, 0, fmt.Errorf("iterate durable agents: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, 0, fmt.Errorf("close durable agents: %w", err)
	}

	agents := make(map[string]interface{}, len(persisted))
	for _, persistedAgent := range persisted {
		key := persistedAgent.agentID
		if persistedAgent.idCount > 1 {
			key = persistedAgent.listenerID + scopedAgentKeyDelimiter + persistedAgent.agentID
		}
		agents[key] = persistedAgent.agent
	}
	return agents, total, nil
}

type queueCommandRequest struct {
	AgentID string `json:"agent_id,omitempty"`
	Command string `json:"command"`
}

func (h *APIHandler) handleQueueAgentCommandFromBody(w http.ResponseWriter, r *http.Request) {
	var req queueCommandRequest
	if err := decodeStrictJSON(w, r, &req, tasks.MaxTaskCreateBodyBytes); err != nil {
		writeJSONDecodeError(w, "Invalid command request", err)
		return
	}
	if err := tasks.ValidateIdentifier("agent_id", req.AgentID); err != nil {
		writeTaskError(w, err)
		return
	}
	if req.Command == "" {
		log.Printf("[DEBUG] Invalid command request")
		http.Error(w, "Invalid command request", http.StatusBadRequest)
		return
	}

	h.queueAgentCommandResponse(r.Context(), w, req.AgentID, req.Command)
}

// handleQueueAgentCommand handles POST /api/agents/{AgentID}/command
func (h *APIHandler) handleQueueAgentCommand(w http.ResponseWriter, r *http.Request, AgentID string) {
	// log.Printf("[DEBUG] handleQueueAgentCommand entered for AgentID=%s", AgentID)
	var req queueCommandRequest
	if err := decodeStrictJSON(w, r, &req, tasks.MaxTaskCreateBodyBytes); err != nil {
		writeJSONDecodeError(w, "Invalid command", err)
		return
	}
	if req.Command == "" {
		log.Printf("[DEBUG] Invalid path-based command request")
		http.Error(w, "Invalid command", http.StatusBadRequest)
		return
	}
	// log.Printf("[DEBUG] handleQueueAgentCommand: AgentID=%s, command=%s", AgentID, req.Command)

	h.queueAgentCommandResponse(r.Context(), w, AgentID, req.Command)
}

func (h *APIHandler) queueAgentCommandResponse(
	ctx context.Context,
	w http.ResponseWriter,
	AgentID, command string,
) {
	protocol, err := h.resolveActiveAgentTaskProtocol(AgentID)
	if err != nil {
		writeAgentResolutionError(w, err)
		return
	}
	var task tasks.Task
	if actorAware, ok := protocol.(legacyTaskQueueContextProtocol); ok {
		task, err = actorAware.QueueLegacyShellTaskContext(ctx, AgentID, command)
	} else {
		task, err = protocol.QueueLegacyShellTask(AgentID, command)
	}
	if err != nil {
		writeTaskError(w, err)
		return
	}
	w.Header().Set("Deprecation", "true")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "queued",
		"task_id": task.ID,
	})
}

type legacyResultPage struct {
	body       []byte
	count      int
	total      int
	nextOffset *int
}

// handleGetAgentResults preserves the deprecated bare-array response while
// bounding both the number of retained results read and the encoded response.
func (h *APIHandler) handleGetAgentResults(
	w http.ResponseWriter,
	r *http.Request,
	agentID string,
) {
	w.Header().Set("Deprecation", "true")
	w.Header().Set(
		"Link",
		fmt.Sprintf("</api/agents/%s/tasks>; rel=\"successor-version\"", agentID),
	)

	options, err := parseTaskListOptions(r.URL.RawQuery)
	if err != nil {
		writeResultQueryError(w, err)
		return
	}
	page, knownAgent, err := h.legacyResultPage(agentID, options)
	if err != nil {
		log.Print("[ERROR] Failed to page legacy results")
		http.Error(w, "Result pagination failed", http.StatusInternalServerError)
		return
	}
	if !knownAgent {
		http.Error(w, "Agent or results not found", http.StatusNotFound)
		return
	}

	w.Header().Set("X-Result-Limit", strconv.Itoa(options.limit))
	w.Header().Set("X-Result-Offset", strconv.Itoa(options.offset))
	w.Header().Set("X-Result-Count", strconv.Itoa(page.count))
	w.Header().Set("X-Result-Total", strconv.Itoa(page.total))
	if page.nextOffset != nil {
		w.Header().Set("X-Next-Offset", strconv.Itoa(*page.nextOffset))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(page.body); err != nil {
		log.Print("[ERROR] Failed to write legacy results response")
	}
}

func (h *APIHandler) legacyResultPage(
	agentID string,
	options taskListOptions,
) (legacyResultPage, bool, error) {
	refs, err := h.agentTaskProtocolRefs(agentID)
	if err != nil {
		return legacyResultPage{}, false, err
	}
	knownAgent := false
	total := 0
	remainingOffset := options.offset
	remainingLimit := options.limit
	candidates := make([]map[string]interface{}, 0, options.limit)
	encodedCandidateSize := len("[]\n")
	bodyTruncated := false
	maxInt := int(^uint(0) >> 1)

	for _, ref := range refs {
		if ref.knownAgent {
			knownAgent = true
		}

		localOffset := 0
		fetchLimit := 0
		if remainingLimit > 0 && !bodyTruncated {
			localOffset = remainingOffset
			fetchLimit = remainingLimit
		}
		var (
			results           []map[string]interface{}
			listenerTotal     int
			listenerTruncated bool
		)
		if pager, ok := ref.protocol.(boundedLegacyResultProtocol); ok {
			pageBudget := tasks.MaxLegacyResultPageBytes
			if encodedCandidateSize > len("[]\n") {
				remainingBytes := tasks.MaxLegacyResultPageBytes - encodedCandidateSize
				if remainingBytes < len("[]\n") {
					fetchLimit = 0
					bodyTruncated = remainingLimit > 0
				} else {
					// A standalone page has two more framing bytes than the
					// incremental contribution to an existing non-empty array.
					// Using the smaller remaining budget is conservative.
					pageBudget = remainingBytes
				}
			}
			page, durableTotal, truncated, pageErr := pager.ListLegacyResultsPage(
				agentID,
				localOffset,
				fetchLimit,
				pageBudget,
			)
			if pageErr != nil {
				return legacyResultPage{}, knownAgent, pageErr
			}
			listenerTotal = durableTotal
			listenerTruncated = truncated
			results = make([]map[string]interface{}, 0, len(page))
			for _, result := range page {
				results = append(results, legacyResultMap(result))
			}
		} else {
			results, listenerTotal = ref.protocol.GetResultsPage(
				agentID,
				localOffset,
				fetchLimit,
			)
		}
		if listenerTotal < 0 || listenerTotal > maxInt-total {
			return legacyResultPage{}, knownAgent, errors.New(
				"listener returned an invalid result count",
			)
		}
		total += listenerTotal
		if listenerTotal > 0 {
			knownAgent = true
		}

		if remainingOffset >= listenerTotal {
			if len(results) != 0 {
				return legacyResultPage{}, knownAgent, errors.New(
					"listener returned results beyond its reported count",
				)
			}
			remainingOffset -= listenerTotal
			continue
		}

		available := listenerTotal - localOffset
		expected := fetchLimit
		if expected > available {
			expected = available
		}
		if len(results) > expected ||
			(len(results) < expected && !listenerTruncated) {
			return legacyResultPage{}, knownAgent, fmt.Errorf(
				"listener returned %d results, expected at most %d",
				len(results),
				expected,
			)
		}
		for _, result := range results {
			encoded, err := json.Marshal(result)
			if err != nil {
				return legacyResultPage{}, knownAgent, fmt.Errorf(
					"measure legacy result candidate: %w",
					err,
				)
			}
			separatorSize := 0
			if len(candidates) > 0 {
				separatorSize = 1
			}
			used := encodedCandidateSize + separatorSize
			if used > tasks.MaxLegacyResultPageBytes ||
				len(encoded) > tasks.MaxLegacyResultPageBytes-used {
				bodyTruncated = true
				break
			}
			candidates = append(candidates, result)
			encodedCandidateSize = used + len(encoded)
		}
		remainingOffset = 0
		remainingLimit -= len(results)
		if listenerTruncated {
			bodyTruncated = true
		}
	}

	body, count, err := encodeLegacyResultArray(
		candidates,
		tasks.MaxLegacyResultPageBytes,
	)
	if err != nil {
		return legacyResultPage{}, knownAgent, err
	}
	if count == 0 && bodyTruncated && options.offset < total {
		return legacyResultPage{}, knownAgent, errors.New(
			"one legacy result exceeds the response body budget",
		)
	}

	end := options.offset
	if count > maxInt-end {
		return legacyResultPage{}, knownAgent, errors.New(
			"result continuation offset overflowed",
		)
	}
	end += count
	var nextOffset *int
	if end < total {
		next := end
		nextOffset = &next
	}
	return legacyResultPage{
		body:       body,
		count:      count,
		total:      total,
		nextOffset: nextOffset,
	}, knownAgent, nil
}

func legacyResultMap(result tasks.LegacyResult) map[string]interface{} {
	return map[string]interface{}{
		"command":   result.Command,
		"output":    result.Output,
		"timestamp": result.Timestamp,
	}
}

func encodeLegacyResultArray(
	results []map[string]interface{},
	maxBytes int,
) ([]byte, int, error) {
	if maxBytes < len("[]\n") {
		return nil, 0, errors.New("legacy result body budget is too small")
	}

	encodedResults := make([][]byte, 0, len(results))
	encodedSize := len("[]\n")
	for _, result := range results {
		encoded, err := json.Marshal(result)
		if err != nil {
			return nil, 0, fmt.Errorf("encode legacy result: %w", err)
		}
		separatorSize := 0
		if len(encodedResults) > 0 {
			separatorSize = 1
		}
		if len(encoded) > maxBytes-encodedSize-separatorSize {
			if len(encodedResults) == 0 {
				return nil, 0, errors.New(
					"one legacy result exceeds the response body budget",
				)
			}
			break
		}
		encodedResults = append(encodedResults, encoded)
		encodedSize += separatorSize + len(encoded)
	}

	body := make([]byte, 0, encodedSize)
	body = append(body, '[')
	for index, encoded := range encodedResults {
		if index > 0 {
			body = append(body, ',')
		}
		body = append(body, encoded...)
	}
	body = append(body, ']', '\n')
	return body, len(encodedResults), nil
}

func writeResultQueryError(w http.ResponseWriter, err error) {
	http.Error(w, "Invalid result query: "+err.Error(), http.StatusBadRequest)
}

func decodeStrictJSON(
	w http.ResponseWriter,
	r *http.Request,
	destination interface{},
	maxBytes int64,
) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func writeJSONDecodeError(w http.ResponseWriter, message string, err error) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		http.Error(w, message+": request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	http.Error(w, message+": "+err.Error(), http.StatusBadRequest)
}

func writeAgentResolutionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errAgentNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, errAgentInactive),
		errors.Is(err, errAmbiguousAgentOwnership),
		errors.Is(err, errAmbiguousTaskOwnership):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, "Agent task routing failed", http.StatusInternalServerError)
	}
}

func writeTaskError(w http.ResponseWriter, err error) {
	switch {
	case tasks.IsValidationError(err):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, tasks.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, tasks.ErrInvalidTransition):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, tasks.ErrCapacity):
		http.Error(w, err.Error(), http.StatusTooManyRequests)
	default:
		http.Error(w, "Task operation failed", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("[ERROR] Failed to encode API response: %v", err)
	}
}
