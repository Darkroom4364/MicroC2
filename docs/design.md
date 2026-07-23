# MicroC2 Design Notes

MicroC2 was created as a bachelor's thesis prototype for studying lightweight,
context-aware command and control behavior in controlled lab environments. The
long-term project goal is broader: make it a polished, reproducible research
testbed for C2, payload, agent, and detection engineering without hiding the
prototype-grade parts that still need work.

This document captures the design intent and the current implementation status.
For component and route details, see [architecture.md](architecture.md). For
sequencing, see [roadmap.md](roadmap.md).

## Design Goals

- Keep the core small enough to understand, test, and extend.
- Prefer stable lifecycle behavior over adding more protocols too early.
- Make risky operator actions explicit, scoped, and eventually audited.
- Use asynchronous polling and structured server-side queues as the baseline
  communication model.
- Treat OPSEC as contextual behavior instead of relying only on binary
  obfuscation.
- Keep research features behind documented configuration and tests.
- Preserve a clear lab-safety boundary: authorized, isolated environments only.

## Core Model

MicroC2 has three primary roles:

| Role | Responsibility |
| --- | --- |
| Operator UI | Browser interface for listeners, agents, payload generation, files, logs, and terminal access. |
| Server | Coordination point for operator APIs, listeners, payload builds, file storage, task queues, and results. |
| Agent | Rust runtime that reports status, polls for tasks, executes allowed work, and submits results under OPSEC control. |

The primary command path now uses a versioned typed contract:

1. The operator selects an agent and creates a shell task with
   `POST /api/agents/{agent_id}/tasks`.
2. The server validates the request, assigns the task ID and v1 envelope, and
   queues it with an expiry and execution timeout.
3. The agent polls `GET /api/agent/{agent_id}/tasks`; the server dispatches the
   next task or returns `204 No Content`.
4. The agent acknowledges execution through
   `POST /api/agent/{agent_id}/tasks/{task_id}/status`.
5. The agent submits a correlated terminal result to
   `POST /api/agent/{agent_id}/results`.
6. The UI reads a bounded page of lifecycle summaries through
   `GET /api/agents/{agent_id}/tasks?limit=50&offset=0` and retrieves a full
   Task v1 resource, including output, only when the operator opens
   `GET /api/agents/{agent_id}/tasks/{task_id}`.

Shell is the first task type. File transfer, pivot control, and future modules
should extend this envelope with explicit argument and result schemas rather
than add new string grammars.

### Typed Task Contract v1

The normative contracts are:

- [Create Task Request v1](schemas/task-create-request-v1.schema.json)
- [Task v1](schemas/task-v1.schema.json)
- [Task summary v1](schemas/task-summary-v1.schema.json)
- [Task page v1](schemas/task-page-v1.schema.json)
- [Task status update v1](schemas/task-status-update-v1.schema.json)
- [Task result v1](schemas/task-result-v1.schema.json)
- [Task result summary v1](schemas/task-result-summary-v1.schema.json)

An operator creates a shell task with:

```json
{
  "schema_version": 1,
  "type": "shell",
  "arguments": {
    "command": "whoami"
  },
  "timeout_seconds": 30,
  "expires_in_seconds": 300
}
```

The server responds with `202 Accepted` and the complete Task v1 resource,
including `schema_version`, `id`, `agent_id`, status, and server timestamps.
The terminal Task Result v1 is nested under `result` when present and separates
`stdout` from `stderr`. Operator list responses are newest-first Task Page v1
resources with a maximum of 100 Task Summary v1 items. Summaries retain result
metadata but omit the potentially large output streams; the individual task
resource is the canonical output retrieval path.

The lifecycle is `queued → dispatched → running → completed|failed`. A queued
task may instead become `cancelled`; a queued or dispatched task becomes
`expired` when it has not started by `expires_at`. Delivery uses an internal
lease: a lost poll response causes the same task ID to be offered again, while
exact repeated acknowledgements and results are accepted idempotently. Task
lifecycle timestamps use server receipt time; the nested result preserves the
agent's execution timestamps without making clock synchronization a transition
precondition.

`POST /api/agents/command` and `POST /api/agents/{agent_id}/command` remain
temporary compatibility adapters. They translate legacy raw commands into v1
shell tasks and are deprecated: new UI and API clients must use `/tasks`.

## Server Design

The Go server was chosen for its standard-library networking, simple deployment,
and straightforward concurrency model. The server uses mutex-protected maps for
prototype state and goroutines for listeners, redirects, and WebSocket
connections.

Current strengths:

- Listener lifecycle is centralized in `ListenerManager`.
- HTTP(S) listeners have explicit start, stop, delete, port conflict, and config
  persistence behavior.
- Operator APIs and static UI are small and easy to inspect.
- The payload builder can generate agent builds from selected listener config.
- CI now runs context-aware Go, Rust, static/script, format, and Foxguard checks.

Current constraints:

- Agent registry, task queues, result history, and generated payload registry
  are in memory.
- Operator access uses a lab-oriented shared-token or loopback guard, not
  production multi-user authentication and authorization.
- Agent listener requests are correlated by runtime ID but are not yet bound to
  an authenticated enrollment session (#104).
- Structured audit events and durable task/result history are not implemented.
- The server terminal remains a powerful lab-only capability even with the
  operator guard and origin checks.

The server now keeps the route surfaces explicit so they can be hardened
independently:

```text
Operator UI/API/WebSockets -> auth, origin checks, audit, local-lab defaults
Agent listener endpoints   -> minimal polling API, stable task/result schemas
Payload builder            -> reproducible profiles and build provenance
Storage                    -> durable agents, tasks, results, files, events
```

Operator routes are served by the web/API port. Agent polling routes are served
by listener ports and should not be mounted on the operator mux.

## Agent Design

The Rust agent was chosen for memory safety, static builds, and cross-platform
potential. It is structured around a build-time config, an OPSEC state machine,
HTTP polling, command execution, and optional networking helpers.

The active implementation supports:

- Embedded XOR-obfuscated JSON config generated by `build.rs`.
- Fallback config loading from `.config/config.json`.
- Direct or SOCKS5-proxied HTTP client creation.
- Heartbeats with host, OS, local IP, and egress metadata.
- Versioned shell task polling, running acknowledgement, and correlated result
  submission.
- Lease-safe task redelivery and an in-memory delivery outbox that retries exact
  acknowledgements/results without re-executing completed work.
- Server-defined task expiry and agent-enforced command timeout handling.
- Process-group (Unix) or job-object (Windows) timeouts and bounded
  stdout/stderr capture.
- Explicit UTF-8 stdout/stderr in typed results; XOR output remains limited to
  deprecated legacy result compatibility.
- Adaptive OPSEC scoring and mode transitions.
- In-memory encryption helper for OPSEC state.

Partially wired or prototype areas:

- File upload/download helpers exist but are not reachable through a stable
  typed task yet.
- Pivot frame/server code exists, but command dispatch does not fully expose
  pivot start/stop.
- OPSEC is runtime-configurable in several places, but not fully feature-gated.
- Cross-platform behavior is uneven: Windows has richer user/window checks,
  while non-Windows checks are simpler.

## OPSEC Design

The thesis design emphasized behavioral adaptation: the agent should reduce
activity when the environment looks risky instead of constantly trying to
out-obfuscate analysis. The current OPSEC engine implements that idea with a
score, dynamic thresholds, and three modes.

Signals include:

- Business hours.
- User activity.
- Analysis or security process indicators.
- Suspicious foreground window titles where supported.
- C2 communication instability.
- Recent noisy command execution.
- Correlation bonuses when several signals are active together.

The OPSEC system uses hysteresis and minimum residence times to avoid rapid mode
flapping. `BackgroundOpsec` is the only mode that performs normal command
processing. `ReducedActivity` keeps only limited heartbeat behavior. `FullOpsec`
stops C2 communication and periodically reassesses.

This is a good research foundation, but it should be made more testable before
more advanced behavior is added. The next useful design improvements are
injectable signal providers, deterministic scoring tests, and clearer policy
metadata on task types.

## Payload Design

Payload generation is listener-driven today. The operator selects a listener,
the server derives the agent connection settings, writes a config file, invokes
the Rust build script, and stores the artifact for download.

Listener, payload/build, and runtime agent identities are now distinct:

| Identity | Meaning |
| --- | --- |
| Listener ID | Server-side network endpoint and protocol instance. |
| Payload/build ID | Reproducible build artifact and embedded config. |
| Agent runtime ID | One live or historical runtime agent instance. |

Several payload UI options remain aspirational: indirect syscalls, custom sleep
techniques, DLL sideloading metadata, shellcode output, and an OPSEC checkbox
are passed through parts of the UI/config/build path but are not a complete
implemented payload feature set. Issue #99 is therefore only partially complete:
seed provenance exists, while supported-profile validation, canonical outputs,
and a complete inspectable build manifest remain.

## Transport Design

HTTP(S) polling is the reference transport. It is the only transport that should
be considered active and end-to-end today. The design keeps polling simple:
agents initiate outbound requests, receive at most one command per poll, and
submit results separately.

SOCKS5 and pivot code exists on both server and agent sides, but this area is
not yet a coherent product workflow. In server `socks5` mode, the server starts
a direct SOCKS5 CONNECT proxy with management routes for tunnel listing,
inspection, closing, and runtime config updates. That config update is currently
in-memory only and does not rebind the listener. On the agent side, SOCKS5 config
means the HTTP C2 client uses a SOCKS5 proxy through reqwest. The pivot frame
modules are local/in-memory plumbing today, not a complete multi-hop transport.
This area needs a typed command surface, integration tests, UI state, and clear
ownership of tunnel lifecycle.

New transports should not be added until the transport boundary is explicit.
The desired boundary is:

- Validated profile/config.
- Start/stop lifecycle.
- Agent enrollment and heartbeat behavior.
- Task/result transport semantics.
- Health/error telemetry.
- Tests or a documented manual lab run.

## Safety Design

The project must still be operated as a lab-only prototype. The Phase 0 safety
baseline now guards operator routes with loopback-or-token access, restricts
operator WebSocket origins, makes listener CORS explicit, keeps insecure agent
TLS opt-in, and validates file-store basenames. The remaining design direction
is:

- Evolve the shared-token guard into actor-aware authentication and roles before
  multi-user operation.
- Bind every agent task/status/result request to an authenticated enrollment
  credential or enforced mTLS identity (#104).
- Add audit events for listener, payload, file, terminal, and agent tasking.
- Add target scoping and explicit confirmation metadata for risky future task
  types.
- Add clear docs for isolated lab deployment.

The Phase 0 route split and lab-safety work are complete in #75 and #78;
structured governance continues in #100.

## Documentation And Testing Expectations

Every major feature should have at least one of:

- A unit test for pure logic.
- An integration or smoke test for server/agent lifecycle.
- A documented manual verification path when automation is too heavy.

CI currently gives the project a baseline safety net. Future design work should
keep new behavior within those checks instead of adding unchecked prototype
paths.

## Near-Term Design Priorities

1. Finish the retry-safe typed shell task/result path and retire primary UI use
   of raw command adapters (#98).
2. Bind agent-facing lifecycle requests to authenticated enrollment sessions
   before any promotion beyond an isolated lab (#104).
3. Persist agents, task state, results, payload metadata, and listener events
   across restart (#97).
4. Add causal structured audit events on top of the durable model (#100).
5. Extend the typed task registry with file transfer and pivot operations after
   the v1 shell contract is stable (#88).
6. Complete payload profile validation and full build manifests; current #99
   provenance is partial P1 work.

The data path is #98 → #97 → #100; #104 is a parallel P0 security gate before
promotion beyond the isolated-lab boundary.
