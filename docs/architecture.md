# MicroC2 Architecture

MicroC2 is an academic C2 research testbed for controlled, authorized lab
environments. The current implementation is a Go management server, a Rust
agent, and a static browser UI. It is useful as a prototype and research base,
but several security, persistence, tasking, and transport boundaries are still
being stabilized.

This document describes the repository as it exists today. It deliberately marks
partially wired features and prototype assumptions so future work can start from
the real implementation rather than the original thesis target alone.

## Runtime Topology

```text
Operator browser
  |  HTTPS + WebSocket
  v
Go server / operator API
  |  creates listeners, queues typed tasks, stores files and payload builds
  v
HTTP(S) listener instances
  |  polling endpoints
  v
Rust agents
  |  heartbeat, task poll, status update, result submission
  v
In-memory task/result state on the server
```

The server process now keeps an explicit operator mux for the browser UI,
operator APIs, and WebSockets. Agent polling routes stay on listener-owned muxes
bound to listener ports. Operator routes use a loopback-or-shared-token guard
and explicit browser-origin checks. This is a safe lab baseline rather than a
multi-user authorization system.

## Repository Layout

| Path | Role |
| --- | --- |
| `server/cmd/server.go` | Server entry point, config loading, route registration, TLS startup. |
| `server/config/` | YAML config types and defaults for the Go server. |
| `server/internal/listeners/` | Listener lifecycle, configuration persistence, start/stop/delete logic. |
| `server/internal/behaviour/` | HTTP polling protocol used by active agents. |
| `server/internal/handlers/api/` | Operator APIs for agents, listeners, payloads, file drop, and SOCKS5 management. |
| `server/internal/handlers/web/` | Static UI serving. |
| `server/internal/handlers/ws/` and `server/internal/websocket/` | Log streaming and server terminal WebSockets. |
| `server/internal/filestore/` | Operator file-drop storage helper. |
| `server/internal/protocols/` | SOCKS5 server/protocol experiments. |
| `server/web/` | Static HTML, CSS, and JavaScript operator UI. |
| `agent/src/main.rs` | Agent bootstrap, OPSEC-gated main loop, SOCKS5/pivot task setup. |
| `agent/src/config.rs` and `agent/build.rs` | Build-time embedded config, fallback config loading, HTTP client setup. |
| `agent/src/commands/` | HTTP polling, shell command execution, result submission, command obfuscation helpers. |
| `agent/src/opsec.rs` | Adaptive OPSEC scoring and mode transitions. |
| `agent/src/dormant.rs` and `agent/src/state.rs` | In-memory state protection helpers. |
| `agent/src/file_handling/` | Upload/download helpers, not fully wired into active dispatch yet. |
| `agent/src/networking/` | Egress helper, SOCKS5 client, and pivot frame/server code. |

## Server

The server starts from `server/cmd/server.go`. Startup loads
`server/config/settings.yaml`, opens `server.log`, initializes the file store,
creates a communication manager, registers HTTP routes, and starts an HTTPS
server using the configured certificate and key. When redirect support is
enabled, a separate HTTP listener redirects to the configured HTTPS port.
Current implementation note: `server.tls.enabled` exists in configuration, but
the entry point always starts the main server with `ListenAndServeTLS`.

The operator server uses an explicit `http.ServeMux`. Unknown `/api/*` paths
return `404`, so unsupported operator calls and accidental agent endpoint calls
are visible during development.

### Route Surfaces

| Surface | Served by | Route families |
| --- | --- | --- |
| Operator UI | operator web/API port | `/`, `/home/`, `/static/` |
| Operator API | operator web/API port | `/api/agents/*`, `/api/listeners/*`, `/api/payload/*`, `/api/file_drop/*`, `/api/socks5/*` |
| Operator WebSockets | operator web/API port | `/ws/logs`, `/ws/terminal` |
| Agent listener API | listener ports | `/api/agent/{agent_id}/heartbeat`, `/tasks`, `/tasks/{task_id}/status`, `/results`, plus deprecated `/command` and `/result` adapters |

### Operator Routes

| Route | Current owner | Purpose |
| --- | --- | --- |
| `/home/` | `internal/handlers/web` | Static UI pages and assets. |
| `/static/` | `internal/handlers/web` | Static files and generated artifacts. |
| `/api/listeners/create` | `internal/handlers/api` | Create and start a listener. |
| `/api/listeners/list` | `internal/handlers/api` | List listeners. |
| `/api/listeners/{id}` | `internal/handlers/api` | Get or delete a listener. |
| `/api/listeners/{id}/start` | `internal/handlers/api` | Start a stopped listener. |
| `/api/listeners/{id}/stop` | `internal/handlers/api` | Stop a running listener. |
| `/api/agents/list` | `internal/handlers/api` | Aggregate agents across listeners. |
| `/api/agents/{id}/tasks` | `internal/handlers/api` | `POST` a typed task or `GET` a bounded, paginated page of newest-first task summaries. |
| `/api/agents/{id}/tasks/{task_id}` | `internal/handlers/api` | Get one full Task v1 resource, including terminal stdout/stderr. |
| `/api/agents/{id}/tasks/{task_id}/cancel` | `internal/handlers/api` | Cancel a queued task before it is dispatched. |
| `/api/agents/command` | `internal/handlers/api` | Deprecated adapter from an `agent_id` plus raw command to a v1 shell task. |
| `/api/agents/{id}/command` | `internal/handlers/api` | Deprecated adapter from a raw command to a v1 shell task. |
| `/api/agents/{id}/results` | `internal/handlers/api` | Deprecated bare-array result adapter with strict `limit`/`offset` pagination and a 16 MiB encoded-page ceiling; response headers expose count, total, and continuation offset. |
| `/api/file_drop/upload` | `internal/handlers/api` | Upload operator files into the server file store. |
| `/api/file_drop/list` | `internal/handlers/api` | List operator file-drop contents. |
| `/api/file_drop/download/{name}` | `internal/handlers/api` | Download a file-drop item. |
| `/api/file_drop/delete/{name}` | `internal/handlers/api` | Delete a file-drop item. |
| `/api/payload/generate` | `internal/handlers/api/payload` | Build an agent payload from a listener and payload config. |
| `/api/payload/download/{id}` | `internal/handlers/api/payload` | Download a generated payload tracked in memory. |
| `/ws/logs` | `internal/handlers/ws` | Stream recent and live server logs. |
| `/ws/terminal` | `internal/handlers/ws` | Browser-accessible shell on the server host. |

The operator guard allows loopback clients or a configured shared token and
checks browser origins for HTTP and WebSocket routes. It is not actor-aware
authentication or authorization. The server terminal can execute shell commands
on the host running MicroC2 and remains a local, controlled-lab capability.

### Typed Task Contract

The v1 wire formats are defined by:

- [Create Task Request v1](schemas/task-create-request-v1.schema.json)
- [Task v1](schemas/task-v1.schema.json)
- [Task summary v1](schemas/task-summary-v1.schema.json)
- [Task page v1](schemas/task-page-v1.schema.json)
- [Task status update v1](schemas/task-status-update-v1.schema.json)
- [Task result v1](schemas/task-result-v1.schema.json)
- [Task result summary v1](schemas/task-result-summary-v1.schema.json)

The operator creation body contains `schema_version`, `type`, typed
`arguments`, `timeout_seconds`, and `expires_in_seconds`. A successful
`POST /api/agents/{agent_id}/tasks` returns `202 Accepted` with the complete
Task v1 resource. The server owns task IDs, agent correlation, lifecycle status,
and queue timestamps. The agent owns the correlated terminal Task Result v1,
including outcome, execution timestamps, exit code, and separate stdout/stderr.

`GET /api/agents/{agent_id}/tasks` returns Task Page v1 with explicit `limit`,
`offset`, `total`, and `next_offset` fields. Pages contain at most 100
newest-first Task Summary v1 resources. A summary keeps lifecycle and terminal
metadata but never includes stdout or stderr; clients retrieve those bounded
streams from `GET /api/agents/{agent_id}/tasks/{task_id}` on demand. This keeps
periodic dashboard polling independent of retained output volume.

Typed result submissions have a 32 MiB transport-body cap. That covers compact
JSON encodings of both schema-maximum result streams, including clients that
escape astral code points as surrogate pairs; optional JSON whitespace still
counts toward the transport cap.

Task status moves through `queued`, `dispatched`, `running`, and a terminal
`completed`, `failed`, `cancelled`, or `expired` state. `expires_at` is the
latest server-authorized start time, so both queued and dispatched tasks expire
before execution. A short internal delivery lease allows the same task ID to be
redelivered if a poll response is lost; exact running acknowledgements and
terminal results are idempotent. The agent retains unacknowledged work and
completed results in a bounded in-memory outbox so transport retries do not
repeat shell side effects.

Legacy operator `/command` routes are deprecated compatibility adapters; new
callers must use the typed `/tasks` resource.

### Agent Listener Routes

HTTP(S) listener instances use `server/internal/behaviour/http_polling.go`.
Each listener exposes routes under `/api/agent/{agent_id}/...` on the listener's
bound host and port.

| Route | Method | Purpose |
| --- | --- | --- |
| `/api/agent/{agent_id}/heartbeat` | `POST` | Agent reports ID, OS, host, IPs, and last-seen data. |
| `/api/agent/{agent_id}/tasks` | `GET` | Dispatch the next Task v1 resource, or return `204 No Content`. |
| `/api/agent/{agent_id}/tasks/{task_id}/status` | `POST` | Accept a Task Status Update v1; the initial contract supports `running`. |
| `/api/agent/{agent_id}/results` | `POST` | Accept a terminal Task Result v1 correlated by task and agent ID. |
| `/api/agent/{agent_id}/command` | `GET` | Deprecated raw-command poll adapter; it dispatches only tasks created through legacy operator routes. |
| `/api/agent/{agent_id}/result` | `POST` | Deprecated raw-result adapter into the typed lifecycle store. |

Runtime agent IDs currently provide correlation, not authentication. Until
authenticated enrollment tracked by #104 lands, listener ports must be exposed
only inside an isolated, authorized lab; an untrusted client that learns an
agent ID could otherwise poll its task or forge a status/result. Verified TLS
protects transport confidentiality but does not by itself bind a request to an
enrolled runtime identity.

The active protocol stores agents, task queues, lifecycle state, and results in
memory.
Server restart loses this state. Durable storage is a Phase 1 roadmap item.

### Listener Lifecycle

`ListenerManager` owns listener creation, listing, start, stop, delete, and
port-conflict checks. Listener configs are written as JSON under
`static/listeners/{listener_name}/config.json` and loaded at startup without
auto-starting the listeners.

HTTP and HTTPS listener protocols are implemented. DNS and DNS-over-HTTPS are
explicitly rejected as not implemented. SOCKS5 code exists under
`server/internal/protocols`, but the primary listener creation path supports
HTTP(S) today.

### Payload Builder

The payload generator is a server-side wrapper around the Rust agent build
script. It requires a selected listener, derives the connection URL from that
listener, writes an agent `config.json`, invokes `agent/build.sh`, and tracks the
generated payload in memory for download.

Listener, payload/build, and runtime agent IDs are distinct. A selected listener
provides connection configuration, each build receives its own payload ID, and
each execution enrolls with a runtime agent ID. Build provenance is present but
still partial; issue #99 tracks supported-profile validation, canonical output
paths, and the complete inspectable manifest.

### Storage

Current storage is intentionally simple:

- Listener configs: JSON files under `static/listeners/`.
- Operator uploads: configured server upload directory, default `uploads`.
- Payload artifacts: `static/payloads/{debug,release}/{payload_id}`.
- Server logs: `server.log`, streamed to `/ws/logs`.
- Agent registry, task queues, lifecycle state, results, and generated payload registry:
  in-memory Go maps.

There is no database or migration layer yet.

## Agent

The Rust agent loads an embedded build-time config generated by `agent/build.rs`.
If no valid embedded config exists, it falls back to `.config/config.json` beside
the executable. Config includes the server URL, payload ID, protocol, sleep and
jitter settings, SOCKS5 settings, TLS verification behavior, user-agent, and
OPSEC threshold parameters.

At runtime the agent:

1. Runs a Windows-only dormant startup gate before initialization.
2. Loads config and creates the HTTP client.
3. Starts SOCKS5/pivot background tasks when configured.
4. Enters an OPSEC assessment loop.
5. Sends heartbeat data when allowed.
6. Polls for one typed task at a time.
7. Retains the task until an exact running acknowledgement is accepted.
8. Dispatches by task type and executes shell tasks with their configured
   process-group/job-object timeout and bounded output capture.
9. Retains and retries the exact correlated result until the listener accepts
   it, without executing the task again.

Shell Task v1 is the active end-to-end format. File transfer, pivot control, and
future modules must add explicit task types and schemas rather than parse
operator-provided raw command strings.

### OPSEC Engine

`agent/src/opsec.rs` is the strongest current research component. It keeps an
encrypted in-memory OPSEC state and uses a score-driven mode system:

| Mode | Current behavior |
| --- | --- |
| `BackgroundOpsec` | Normal communication and command processing. |
| `ReducedActivity` | Heartbeat-only behavior with longer sleeps; command work is deferred. |
| `FullOpsec` | No C2 communication; only periodic reassessment. |

Signals include business hours, user activity, process/window analysis signals,
C2 instability, recent noisy commands, correlation bonuses, hysteresis, and
configurable minimum mode durations. Windows has WinAPI-backed idle/window
checks. Non-Windows platforms use simpler user/process heuristics and do not
currently implement window title checks.

### File Transfer And Pivot Modules

File upload/download helpers exist under `agent/src/file_handling/`, and
SOCKS5/pivot types exist under `agent/src/networking/`. The active task loop
does not yet expose typed file transfer or pivot operations. `pivot_start` and
`pivot_stop` helper functions exist but are not wired into the typed dispatch
path. Issue #88 tracks extending the v1 foundation after #98, and #71 tracks
SOCKS5/pivot maturity.

## Static UI

The UI is static HTML/CSS/JavaScript served by the Go server. Current pages
cover:

- Dashboard and typed shell task submission/paginated history.
- Listener creation and lifecycle actions.
- Payload generation and download.
- File drop upload, list, download, and delete.
- Server terminal.

The UI submits shell tasks through the operator `/tasks` endpoint, polls bounded
summary pages, and loads stdout/stderr from an individual task only on operator
request. Agent, listener, command, result, and error values are inserted with
DOM `textContent`, not interpreted as HTML. It does not currently have a
separate frontend build system. A few UI paths are ahead of the backend:

- agent removal calls `DELETE /api/agents/{id}`, which has no real handler yet;
- listener and file-drop JavaScript reference EventSource streams that are not
  registered by the server.

## Current Prototype Gaps

The main remaining gaps are tracked as issues:

- #98: complete and stabilize the typed task/result transition.
- #97: persist agents, task lifecycles, results, payloads, and listener events.
- #100: add structured, durable audit events.
- #88: add file transfer and pivot controls as typed task families after #98.
- #99: finish payload validation and manifests; current provenance is partial.
- #65: finish the agent configuration system and optional OPSEC feature gating.

Until those are complete, MicroC2 should be treated as a controlled lab research
prototype rather than a hardened multi-user operations platform.
