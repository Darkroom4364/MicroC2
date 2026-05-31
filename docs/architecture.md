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
  |  creates listeners, queues commands, stores files and payload builds
  v
HTTP(S) listener instances
  |  polling endpoints
  v
Rust agents
  |  heartbeat, command poll, result submission
  v
In-memory task/result state on the server
```

The server hosts both operator-facing routes and agent-facing routes in one
process. Listener instances can bind additional ports for agent polling, but
operator UI/API routes, WebSockets, and listener management are still registered
on the same default `net/http` mux. Splitting operator and agent surfaces is
tracked by #75.

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

The current server uses Go's default HTTP mux for most routes. That keeps the
prototype simple, but it also means route ownership and trust boundaries are not
strongly expressed in code yet. Unknown `/api/*` paths currently fall through to
a generic `{"status":"ok"}` response, which can hide unsupported UI calls.

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
| `/api/agents/{id}/command` | `internal/handlers/api` | Queue a raw command string for an agent. |
| `/api/agents/{id}/results` | `internal/handlers/api` | Fetch stored command results. |
| `/api/file_drop/upload` | `internal/handlers/api` | Upload operator files into the server file store. |
| `/api/file_drop/list` | `internal/handlers/api` | List operator file-drop contents. |
| `/api/file_drop/download/{name}` | `internal/handlers/api` | Download a file-drop item. |
| `/api/file_drop/delete/{name}` | `internal/handlers/api` | Delete a file-drop item. |
| `/api/payload/generate` | `internal/handlers/api/payload` | Build an agent payload from a listener and payload config. |
| `/api/payload/download/{id}` | `internal/handlers/api/payload` | Download a generated payload tracked in memory. |
| `/ws/logs` | `internal/handlers/ws` | Stream recent and live server logs. |
| `/ws/terminal` | `internal/handlers/ws` | Browser-accessible shell on the server host. |

The operator APIs and WebSockets currently lack a complete authentication,
authorization, origin, and CSRF boundary. The server terminal can execute shell
commands on the host running MicroC2 and should be treated as a local lab-only
tool until #75 and #78 are complete.

### Agent Listener Routes

HTTP(S) listener instances use `server/internal/behaviour/http_polling.go`.
Each listener exposes routes under `/api/agent/{agent_id}/...` on the listener's
bound host and port.

| Route | Method | Purpose |
| --- | --- | --- |
| `/api/agent/{agent_id}/heartbeat` | `POST` | Agent reports ID, OS, host, IPs, and last-seen data. |
| `/api/agent/{agent_id}/command` | `GET` | Agent polls for the next queued raw command string. |
| `/api/agent/{agent_id}/result` | `POST` | Agent submits one command result. |
| `/api/agent/{agent_id}/tasks` | `GET` | Placeholder currently returning an empty task list. |
| `/api/agent/{agent_id}/results` | `POST` | Alias path handled as result submission in the current dispatcher. |

The active protocol stores agents, command queues, and result history in memory.
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

Current limitation: the payload ID is the listener ID. That couples listener,
payload build, and runtime agent identity. Issue #64 tracks separating listener
ID, payload/build ID, and runtime agent ID.

### Storage

Current storage is intentionally simple:

- Listener configs: JSON files under `static/listeners/`.
- Operator uploads: configured server upload directory, default `uploads`.
- Payload artifacts: `static/payloads/{debug,release}/{payload_id}`.
- Server logs: `server.log`, streamed to `/ws/logs`.
- Agent registry, command queues, results, and generated payload registry:
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
6. Polls for one command at a time.
7. Executes shell commands with a timeout.
8. Obfuscates command output with the agent ID as key material.
9. Submits results back to the HTTP polling listener.

The agent uses raw command strings as the active task format. A typed task/result
model is planned but not implemented yet.

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
SOCKS5/pivot types exist under `agent/src/networking/`. The active command loop
does not yet expose a complete operator command grammar for file transfer or
pivot start/stop. `pivot_start` and `pivot_stop` helper functions exist but are
not wired into the active dispatch path. Issue #88 tracks completing that
integration, and #71 tracks SOCKS5/pivot maturity.

## Static UI

The UI is static HTML/CSS/JavaScript served by the Go server. Current pages
cover:

- Dashboard and agent command submission.
- Listener creation and lifecycle actions.
- Payload generation and download.
- File drop upload, list, download, and delete.
- Server terminal.

The UI talks directly to the REST and WebSocket routes listed above. It does not
currently have a separate frontend build system. A few UI paths are ahead of the
backend:

- dashboard command submission still contains a hard-coded `8080` API base in
  one path, while the default HTTPS UI/API port is `8443`;
- agent removal calls `DELETE /api/agents/{id}`, which has no real handler yet;
- listener and file-drop JavaScript reference EventSource streams that are not
  registered by the server.

## Current Prototype Gaps

The main gaps are tracked as issues:

- #75: separate operator UI/API/WebSocket routes from agent-facing endpoints.
- #78: add lab-safety hardening for auth, origins, TLS defaults, and file paths.
- #64: separate listener, payload/build, and runtime agent identities.
- #88: wire file transfer and pivot controls into active command dispatch.
- #65: finish the agent configuration system and optional OPSEC feature gating.

Until those are complete, MicroC2 should be treated as a controlled lab research
prototype rather than a hardened multi-user operations platform.
