# MicroC2 Architecture

MicroC2 is an academic C2 research testbed for controlled, authorized lab
environments. The current implementation is a Go management server, a Rust
agent, and a static browser UI. It is useful as a prototype and research base,
but several security, evidence/reporting, task-family, and transport boundaries
are still being stabilized.

This document describes the repository as it exists today. It deliberately marks
partially wired features and prototype assumptions so future work can start from
the real implementation rather than the original thesis target alone.

## Runtime Topology

```text
Operator browser
  |  HTTPS + WebSocket
  v
Go server / operator API
  |-- SQLite: listeners/events, agents, tasks/results, payload metadata
  |-- filesystem: listener configs, payload artifacts, uploads, logs
  |  creates listeners and queues typed tasks
  v
HTTP(S) listener instances
  |  polling endpoints
  v
Rust agents
  |  heartbeat, task poll, status update, result submission
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
| `server/internal/persistence/` | Process-wide SQLite bootstrap, durability settings, and embedded migrations. |
| `server/internal/enrollment/` | Bootstrap verification, durable listener-scoped sessions, rotation, revocation, and re-enrollment. |
| `server/internal/tasks/` | Typed in-memory test store and listener-scoped durable task/result store. |
| `server/internal/listeners/` | Listener lifecycle, configuration persistence, start/stop/delete logic. |
| `server/internal/behaviour/` | HTTP polling protocol used by active agents. |
| `server/internal/handlers/api/` | Operator APIs for agents, listeners, payloads, audit records, and file drop. |
| `server/internal/handlers/web/` | Static UI serving. |
| `server/internal/handlers/ws/` and `server/internal/websocket/` | Log streaming and server terminal WebSockets. |
| `server/internal/filestore/` | Operator file-drop storage helper. |
| `server/internal/protocols/` | SOCKS5 server/protocol experiments. |
| `server/web/` | Static HTML, CSS, and JavaScript operator UI. |
| `agent/src/main.rs` | Agent bootstrap, OPSEC-gated main loop, and optional outbound SOCKS5 egress setup. |
| `agent/src/config.rs` and `agent/build.rs` | Strict build-time embedded config and HTTP client setup. |
| `agent/src/commands/` | HTTP polling, shell command execution, result submission, command obfuscation helpers. |
| `agent/src/opsec.rs` | Adaptive OPSEC scoring and mode transitions. |
| `agent/src/dormant.rs` and `agent/src/state.rs` | In-memory state protection helpers. |
| `agent/src/file_handling/` | Upload/download helpers, not fully wired into active dispatch yet. |
| `agent/src/networking/` | Egress helper, SOCKS5 client, and pivot frame/server code. |

## Server

The server starts from `server/cmd/server.go`. Startup loads
`server/config/settings.yaml`, opens the process-wide SQLite database and
the configured log file, initializes the file store, creates a communication manager,
reconciles listeners and payload records, registers HTTP routes, and starts an
HTTPS server using the configured certificate and key. When redirect support
is enabled, a separate HTTP listener redirects to the configured HTTPS port.

The YAML file is strict: unknown fields, retired fields, trailing documents,
invalid ports, unreadable TLS material, unsafe path overlap, and contradictory
redirect settings fail before runtime directories are created or traffic is
served. Its supported surface is:

| Field | Runtime effect |
| --- | --- |
| `storage.path` | SQLite state path; `MICROC2_STORAGE_PATH` overrides it when set. |
| `server.port` | Sole operator HTTPS port; defaults to `8443`. |
| `server.uploadDir` | Operator file-drop root. |
| `server.staticDir` | Static UI root and private listener/payload parent. |
| `server.tls.certFile`, `server.tls.keyFile` | Mandatory operator TLS certificate and key, both outside `server.staticDir`; HTTPS agent listeners inherit them unless an explicit listener override is supplied. |
| `server.redirect.enabled`, `server.redirect.httpPort` | Optional HTTP-to-HTTPS redirect; the HTTP port must be empty when disabled. |
| `security.enableServerTerminal` | Explicitly enables the lab-only server shell. |
| `security.agentTransport.allowInsecureIsolatedLab` | Permits plain HTTP agent listeners only for an isolated lab. |
| `security.corsOrigins` | Agent-listener CORS allow list; empty disables cross-origin access. |
| `security.operatorToken` | Shared remote-operator token; `MICROC2_OPERATOR_TOKEN` supplies it when YAML is empty. |
| `security.operatorAllowedOrigins` | Origin allow list for remote operator HTTP/WebSocket access. |
| `logging.file` | Server log path; defaults to `server.log`. |

The operator server uses an explicit `http.ServeMux`. Unknown `/api/*` paths
return `404`, so unsupported operator calls and accidental agent endpoint calls
are visible during development.

### Route Surfaces

| Surface | Served by | Route families |
| --- | --- | --- |
| Operator UI | operator web/API port | `/`, `/home/`, `/static/` |
| Operator API | operator web/API port | `/api/modules`, `/api/agents/*`, `/api/listeners/*`, `/api/payload/*`, `/api/file_drop/*` |
| Operator WebSockets | operator web/API port | `/ws/logs`, `/ws/terminal` |
| Agent listener API | listener ports | `/api/agent/{agent_id}/heartbeat`, `/tasks`, `/tasks/{task_id}/status`, `/results`, plus deprecated `/command` and `/result` adapters |

### Operator Routes

| Route | Current owner | Purpose |
| --- | --- | --- |
| `/home/` | `internal/handlers/web` | Static UI pages and assets. |
| `/static/` | `internal/handlers/web` | Compatibility static files, excluding the private `listeners` and `payloads` trees. |
| `/api/listeners/create` | `internal/handlers/api` | Create and start a listener. |
| `/api/listeners/list` | `internal/handlers/api` | List listeners. |
| `/api/listeners/{id}` | `internal/handlers/api` | Get or delete a listener. |
| `/api/listeners/{id}/start` | `internal/handlers/api` | Start a stopped listener. |
| `/api/listeners/{id}/stop` | `internal/handlers/api` | Stop a running listener. |
| `/api/listeners/{id}/events` | `internal/handlers/api` | List the listener's durable lifecycle events in sequence order. |
| `/api/listeners/{id}/agents/{agent_id}/session/rotate` | `internal/handlers/api` | Begin two-phase session-credential rotation; returns metadata, never a bearer. |
| `/api/listeners/{id}/agents/{agent_id}/session/revoke` | `internal/handlers/api` | Immediately revoke an agent session. |
| `/api/listeners/{id}/agents/{agent_id}/session/re-enroll` | `internal/handlers/api` | Explicitly authorize the next valid bootstrap to replace the session. |
| `/api/agents/list` | `internal/handlers/api` | Aggregate agents across listeners. |
| `/api/modules` | `internal/handlers/api` | Retrieve the bounded catalog of compile-time registered agent modules and their safety metadata. |
| `/api/agents/{id}/tasks` | `internal/handlers/api` | `POST` a closed shell Task v1 request or `GET` a bounded, paginated page of newest-first task summaries. |
| `/api/agents/{id}/module-tasks` | `internal/handlers/api` | `POST` the closed governed capability-inventory request; the server derives and durably stores policy before queueing. |
| `/api/agents/{id}/tasks/{task_id}` | `internal/handlers/api` | Get one full Task v1 resource, including terminal stdout/stderr and module evidence when present. |
| `/api/agents/{id}/tasks/{task_id}/cancel` | `internal/handlers/api` | Cancel a queued task before it is dispatched. |
| `/api/agents/command` | `internal/handlers/api` | Deprecated adapter from an `agent_id` plus raw command to a v1 shell task. |
| `/api/agents/{id}/command` | `internal/handlers/api` | Deprecated adapter from a raw command to a v1 shell task. |
| `/api/agents/{id}/results` | `internal/handlers/api` | Deprecated bare-array result adapter with strict `limit`/`offset` pagination and a 16 MiB encoded-page ceiling; response headers expose count, total, and continuation offset. |
| `/api/audit/events` | `internal/handlers/api` | Retrieve a bounded, newest-first page of Audit Event v1 records. |
| `/api/health` | `internal/handlers/api` | Liveness probe; see [health-telemetry.md](health-telemetry.md). |
| `/api/ready` | `internal/handlers/api` | Readiness probe with per-dependency checks. |
| `/api/telemetry` | `internal/handlers/api` | Listener runtime status, sanitized error classes, agent counts, queue depth, and recent task/build failure indicators. |
| `/api/file_drop/upload` | `internal/handlers/api` | Upload operator files into the server file store with a 32 MiB total request cap and same-directory atomic staging. |
| `/api/file_drop/list` | `internal/handlers/api` | List operator file-drop contents. |
| `/api/file_drop/download/{name}` | `internal/handlers/api` | Download a verified regular file with causal request/completion audit events. |
| `/api/file_drop/delete/{name}` | `internal/handlers/api` | Delete a file-drop item. |
| `/api/payload/generate` | `internal/handlers/api/payload` | Build an agent payload from a listener and payload config. |
| `/api/payload/download/{id}` | `internal/handlers/api/payload` | Revalidate and download a generated payload tracked by durable metadata. |
| `/api/payload/{id}/enrollment/revoke` | `internal/handlers/api/payload` | Idempotently retire future bootstrap enrollment while preserving issued sessions. |
| `/ws/logs` | `internal/handlers/ws` | Stream recent and live server logs. |
| `/ws/terminal` | `internal/handlers/ws` | Browser-accessible shell on the server host; disabled unless `security.enableServerTerminal` is explicitly true. |

The operator guard allows loopback clients or a configured shared token and
checks browser origins for HTTP and WebSocket routes. Accepted requests carry a
trusted audit actor identifying loopback or shared-token authentication. This
is audit attribution, not individual-user authentication or authorization. The
server terminal can execute shell commands on the host running MicroC2, is
disabled by default, and remains a local, controlled-lab capability when
enabled. Requested, denied, opened, and closed terminal access is audited;
commands and output are never audit fields.

### Structured Audit Contract

The normative contracts are:

- [Audit Event v1](schemas/audit-event-v1.schema.json)
- [Audit Page v1](schemas/audit-page-v1.schema.json)

Audit events are durable, newest-first by monotonic sequence, and use a closed
redacted field set. Listener and agent-session lifecycle, payload
build/download/artifact-reconciliation, file-drop actions, terminal access, and
task queue/dispatch/running/result/cancellation paths emit events. Task and
payload rows retain their causal root sequences, and listener lifecycle records
link to their matching audit events. See
[storage.md](storage.md#structured-audit-events) for transaction, retention,
and redaction semantics.

### Typed Task Contract

The v1 wire formats are defined by:

- [Create Task Request v1](schemas/task-create-request-v1.schema.json)
- [Module Task Create Request v1](schemas/module-task-create-request-v1.schema.json)
- [Task v1](schemas/task-v1.schema.json)
- [Task summary v1](schemas/task-summary-v1.schema.json)
- [Task page v1](schemas/task-page-v1.schema.json)
- [Task status update v1](schemas/task-status-update-v1.schema.json)
- [Task result v1](schemas/task-result-v1.schema.json)
- [Task result summary v1](schemas/task-result-summary-v1.schema.json)
- [Module catalog v1](schemas/module-catalog-v1.schema.json)
- [Capability inventory input v1](schemas/module-capability-inventory-input-v1.schema.json)
- [Capability inventory output v1](schemas/module-capability-inventory-output-v1.schema.json)

`POST /api/agents/{agent_id}/tasks` accepts only the shell Create Task Request
v1: `schema_version`, `type: "shell"`, one bounded `arguments.command`,
`timeout_seconds`, and `expires_in_seconds`. Governed work is created only at
`POST /api/agents/{agent_id}/module-tasks` with the closed Module Task Create
Request v1: `module_id: "agent.capability_inventory.v1"`, exact empty `input`,
a 1–5 second timeout, and a bounded expiry. It rejects shell fields,
acknowledgements, policy, and arbitrary metadata.

The server derives the module's read-only/self, evidence-required,
no-approval policy from its compiled registry and persists it outside Task v1
and the agent wire. Module eligibility requires a current authenticated
heartbeat advertisement, including after restart. Successful module evidence
must be closed `output.data` no larger than 1024 bytes; failed results carry no
accepted evidence. A successful creation returns `202 Accepted` with the
unchanged Task v1 resource.

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

Legacy operator `/command` routes are deprecated arbitrary-shell compatibility
adapters. New shell callers use `/tasks`; governed inventory callers use
`/module-tasks`.

### Agent Listener Routes

HTTP(S) listener instances use `server/internal/behaviour/http_polling.go`.
Each listener exposes routes under `/api/agent/{agent_id}/...` on the listener's
bound host and port.

| Route | Method | Purpose |
| --- | --- | --- |
| `/api/agent/{agent_id}/heartbeat` | `POST` | Authenticate or enroll, then report ID, listener/payload binding, OS, host, IPs, and last-seen data. |
| `/api/agent/{agent_id}/tasks` | `GET` | Dispatch the next Task v1 resource, or return `204 No Content`. |
| `/api/agent/{agent_id}/tasks/{task_id}/status` | `POST` | Accept a Task Status Update v1; the initial contract supports `running`. |
| `/api/agent/{agent_id}/results` | `POST` | Accept a terminal Task Result v1 correlated by task and agent ID. |
| `/api/agent/{agent_id}/command` | `GET` | Deprecated raw-command poll adapter; it dispatches only tasks created through legacy operator routes. |
| `/api/agent/{agent_id}/result` | `POST` | Deprecated raw-result adapter into the typed lifecycle store. |

Every non-preflight agent route requires a bearer credential bound to the
listener, runtime agent ID, payload/build ID, opaque session, and generation.
The first heartbeat exchanges a per-build bootstrap for a session credential;
task polls, status updates, typed results, and legacy adapters accept only a
valid session credential after a fresh authenticated heartbeat in the current
server process. Cross-agent, cross-listener, stale, revoked, and
post-confirmation bootstrap replays fail closed. See
[agent-enrollment.md](agent-enrollment.md) for confirmation, rotation, and
recovery semantics.

The active protocol stores agents, task queues, lifecycle state, and results in
listener-scoped SQLite records. Server restart preserves this history. A
persisted agent is historical and inactive until a fresh post-start heartbeat;
durable presence is not treated as proof that a runtime is currently connected.
Queued and dispatched task recovery respects expiry and the persisted delivery
lease. Running work is never automatically re-executed, exact retries remain
idempotent, and terminal state is immutable. See [storage.md](storage.md) for
the complete restart contract.

### Listener Lifecycle

`ListenerManager` owns listener creation, listing, start, stop, delete, and
port-conflict checks. SQLite holds the authoritative checksummed listener
config. Redacted compatibility projections are written with restrictive
permissions under
`{server.staticDir}/listeners/{listener_name}/config.json`; missing or stale
projections are rebuilt from SQLite. Valid disk-only configs are imported once
in deterministic order, but cannot overwrite durable state. Startup does not
auto-start listener sockets. A listener last recorded as `ACTIVE` or `ERROR` is
reconciled to `STOPPED` with one `recovered_stopped` event, while a deleted
listener tombstone prevents a stale config file from resurrecting it.

HTTP and HTTPS listener protocols are implemented. DNS and DNS-over-HTTPS are
explicitly rejected as not implemented. SOCKS5 code exists under
`server/internal/protocols`, but the primary listener creation path supports
HTTP(S) today. Production composition rejects plain HTTP unless the explicit
isolated-lab policy is enabled, and generated payloads always verify HTTPS
servers through the system trust store. `requireClientCert` is rejected until
CA-backed mTLS verification exists.

The authoritative listener request surface is intentionally smaller than its
legacy persistence struct. Name, HTTP(S) protocol, bind host, port, at most one
validated advertised DNS name or IP, and an optional HTTPS certificate/key
override are effective. Without an advertised host, the bind host must itself
be a specific advertiseable address. HTTPS listeners otherwise inherit the
operator server TLS pair. Caller-selected IDs, multiple hosts/host rotation,
custom URIs/headers/user-agents, listener-side proxy or SOCKS5 configuration,
and DNS-over-HTTPS are rejected before persistence or socket creation. Unknown
and trailing JSON input is also rejected.

### Payload Builder

The payload generator is a server-side wrapper around the Rust agent build
script. It requires a selected listener, derives the connection URL from that
listener, invokes `agent/build.sh`, and tracks the generated payload's metadata,
size, SHA-256 digest, relative artifact path, and provenance in SQLite. Each
build also receives a fresh random enrollment bootstrap through the build
subprocess environment. Only its SHA-256 digest is persisted; the raw value is
embedded in the payload and excluded from logs, responses, provenance, and
sidecar configuration. The artifact itself remains under the configured
payload root with owner-only directory and artifact permissions.

Listener, payload/build, and runtime agent IDs are distinct. A selected listener
provides connection configuration, each build receives its own payload ID, and
each execution enrolls with a runtime agent ID. Issue #99 now defines the
supported profiles, canonical output path, and complete versioned manifest; see
[Payload build contract](payload-builds.md). A source revision and mutation seed
reproduce mutation choices, but cannot recreate the exact production artifact
without its deliberately unrecorded random bootstrap secret. The build row begins in
`building`, then transitions to `completed` or `failed`; startup turns a
leftover build into `interrupted` without resuming it. Startup and download-time
revalidation keep a completed indexed artifact in `completed`, `missing`, or
`corrupt` state. Missing, corrupt, failed, or interrupted records remain
available for diagnosis, but their download endpoint returns `410 Gone`.
Direct static access to payload artifacts is denied.

### Storage

The development implementation uses one process-wide SQLite database alongside
filesystem artifacts:

- Durable database: configured by `storage.path`, default
  `data/microc2.db`, with `MICROC2_STORAGE_PATH` as the environment override.
- SQLite records: listeners and lifecycle events, historical agents, typed
  tasks and results, legacy result projections, payload-build metadata,
  structured audit events, bootstrap hashes/allowances, the enrollment HMAC
  key, and durable sessions.
- Listener compatibility configs: redacted, regenerable JSON projections under
  `{server.staticDir}/listeners/`.
- Operator uploads: configured server upload directory, default `uploads`.
- Payload artifacts:
  `{server.staticDir}/payloads/{debug,release}/{payload_id}`.
- Server logs: configured by `logging.file`, default `server.log`, and streamed
  to `/ws/logs`.

The database must be outside the web-served static root. Embedded, checksummed
migrations are applied transactionally and startup refuses a modified or future
migration ledger. MicroC2 uses a full-synchronous SQLite rollback journal, not
WAL, with a single database connection and a single-server-process ownership
model. See [storage.md](storage.md) for restart semantics, permissions, backup,
restore, and upgrade guidance.

## Agent

The Rust agent loads one embedded build-time config generated by
`agent/build.rs`; it does not accept a runtime sidecar or command-line C2
override. Config includes the server URL, listener and payload IDs, the embedded
bootstrap credential, protocol, sleep and jitter settings, optional outbound
SOCKS5 proxy settings, TLS verification behavior, user-agent, mutation-seed
metadata, and OPSEC threshold parameters. Unknown or contradictory fields fail
startup. Secret-aware debug formatting redacts the bootstrap.

At runtime the agent:

1. Runs a Windows-only dormant startup gate before initialization.
2. Loads config and creates the HTTP client.
3. Resolves its runtime ID and loads a matching tuple-bound session from the
   current user's platform state directory, if present.
4. Configures direct or outbound-SOCKS5-proxied HTTP transport.
5. Enters an OPSEC assessment loop and, when allowed, sends an authenticated
   heartbeat with the stored session or embedded bootstrap.
6. Persists a returned session credential atomically and uses it on all
   lifecycle requests.
7. Polls for one typed task at a time.
8. Retains the task until an exact running acknowledgement is accepted.
9. Dispatches by task type: shell work uses its configured process-group/job-object
   timeout and bounded output capture; a module can execute only if it was
   compiled into the payload's registry.
10. Retains and retries the exact correlated result until the listener accepts
    it, without executing the task again.

Agent state is rooted at `$XDG_STATE_HOME/microc2/agent` on Linux (falling back
to `$HOME/.local/state/microc2/agent`), at
`$HOME/Library/Application Support/microc2/agent` on macOS, and at
`%LOCALAPPDATA%\microc2\agent` on Windows. Listener, payload, and agent IDs are
encoded as separate unpadded-base64url path components. Windows protects the
session bearer with current-user DPAPI; Unix state directories and files use
`0700` and `0600` permissions.

Shell Task v1 remains the active general-purpose format. Module Task v1 now
adds a compile-time registry boundary: the server catalog validates closed
input/output schemas, and the agent advertises only payload-compiled module IDs
in its heartbeat. The shipped `agent.capability_inventory.v1` module is
read-only, self-scoped, and returns bounded OS/architecture/CPU/memory evidence.
File transfer and pivot control must use the same typed-task route instead of
parsing operator-provided raw command strings.

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
SOCKS5/pivot types exist under `agent/src/networking/`. The active agent can use
an existing SOCKS5 proxy for outbound HTTP(S), but does not expose a supported
SOCKS5 listener or typed pivot operation. Issue #88 tracks extending the v1
foundation after #98, and #71 tracks SOCKS5/pivot maturity.

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

- #98: typed shell task/result v1 is complete; deprecated raw-command adapters
  remain only for compatibility.
- #97: durable storage is merged into `dev`.
- #104: authenticated agent enrollment is complete for the `dev` integration
  line; it does not imply a `dev` to `main` promotion.
- #100: structured, durable audit events are complete on the `dev` integration
  line; operator-facing evidence export is still future work.
- #108: cross-platform open-beneath payload artifact handling is complete on
  the `dev` integration line; no `dev` to `main` promotion was performed.
- #88: add file transfer and pivot controls as typed task families after #98.
- #99: the bounded payload validation and manifest contract is implemented.
- #65: finish the agent configuration system and optional OPSEC feature gating.

Until the remaining production-hardening work is complete, MicroC2 should be
treated as a controlled lab research prototype rather than a hardened
multi-user operations platform.
