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
- Make risky operator actions explicit, scoped, and auditable.
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

1. The operator selects an agent and creates a typed shell or registered module
   task with `POST /api/agents/{agent_id}/tasks`.
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

Shell and the read-only `agent.capability_inventory.v1` module are the active
task types. File transfer, pivot control, and future modules must extend this
envelope with explicit argument and result schemas rather than add new string
grammars or accept operator-provided code.

### Typed Task Contract v1

The normative contracts are:

- [Create Task Request v1](schemas/task-create-request-v1.schema.json)
- [Task v1](schemas/task-v1.schema.json)
- [Task summary v1](schemas/task-summary-v1.schema.json)
- [Task page v1](schemas/task-page-v1.schema.json)
- [Task status update v1](schemas/task-status-update-v1.schema.json)
- [Task result v1](schemas/task-result-v1.schema.json)
- [Task result summary v1](schemas/task-result-summary-v1.schema.json)
- [Module catalog v1](schemas/module-catalog-v1.schema.json)
- [Capability inventory input v1](schemas/module-capability-inventory-input-v1.schema.json)
- [Capability inventory output v1](schemas/module-capability-inventory-output-v1.schema.json)

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

The module form is selected from `GET /api/modules`; it uses a registered
`module_id` and closed `input`. The selected agent must have advertised that
module ID in its authenticated heartbeat. The server validates module inputs and
completed `output.data` against the registry, and the module's catalog safety
metadata can require `safety_acknowledged: true` before queueing work.

The server responds with `202 Accepted` and the complete Task v1 resource,
including `schema_version`, `id`, `agent_id`, status, and server timestamps.
The terminal Task Result v1 is nested under `result` when present and separates
`stdout` from `stderr`; a completed module result additionally carries
registry-validated structured evidence in `output.data`. Operator list
responses are newest-first Task Page v1 resources with a maximum of 100 Task
Summary v1 items. Summaries retain result metadata but omit potentially large
output streams and module evidence; the individual task resource is the
canonical result retrieval path.

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
and straightforward concurrency model. The production composition uses one
process-wide SQLite database for durable coordination state and goroutines for
listeners, redirects, and WebSocket connections. In-memory stores remain useful
for focused tests, but are not the production task/result authority.

Current strengths:

- Listener lifecycle is centralized in `ListenerManager`.
- HTTP(S) listeners have explicit start, stop, delete, port conflict, and config
  persistence behavior.
- Listener-scoped agents, tasks, results, payload metadata, and listener events
  survive server restart.
- Operator APIs and static UI are small and easy to inspect.
- The payload builder can generate agent builds from selected listener config.
- CI runs context-aware Go (including Windows), Rust, static/script, format, and
  Foxguard checks.

Current constraints:

- Durable storage is local and single-process; file artifacts still require a
  coordinated filesystem backup.
- Operator access uses a lab-oriented shared-token or loopback guard, not
  production multi-user authentication and authorization.
- Authenticated agent enrollment from #104 is part of the `dev` integration
  line; bearer possession remains the trust boundary.
- Structured, actor-aware audit events cover listener, payload, file, terminal,
  and task lifecycles; shared-token attribution still does not identify an
  individual human.
- The server terminal remains a powerful lab-only capability, is disabled by
  default, and is audited without recording commands or output when enabled.

The server now keeps the route surfaces explicit so they can be hardened
independently:

```text
Operator UI/API/WebSockets -> auth, origin checks, audit, local-lab defaults
Agent listener endpoints   -> minimal polling API, stable task/result schemas
Payload builder            -> reproducible profiles and build provenance
Storage                    -> SQLite metadata plus filesystem artifacts
```

Operator routes are served by the web/API port. Agent polling routes are served
by listener ports and should not be mounted on the operator mux.

## Agent Design

The Rust agent was chosen for memory safety, static builds, and cross-platform
potential. It is structured around a build-time config, an OPSEC state machine,
HTTP polling, command execution, and optional networking helpers.

The active implementation supports:

- Embedded XOR-obfuscated JSON config generated by `build.rs`.
- Strict validation of one embedded runtime config; unknown fields, runtime
  sidecars, and command-line C2 overrides are rejected.
- Direct or SOCKS5-proxied HTTP client creation.
- Per-build bootstrap enrollment and a durable session bound to listener,
  payload, and runtime agent IDs.
- Authenticated heartbeats with host, OS, local IP, egress metadata, and the
  compile-time module IDs the payload can execute.
- Bearer authentication on every task, status, result, and legacy lifecycle
  request, with two-phase rotation and explicit revoke/re-enroll actions.
- Versioned shell and module task polling, running acknowledgement, and
  correlated result submission.
- A compile-time module registry; the shipped capability inventory validates
  empty input and returns bounded OS, architecture, CPU, and memory evidence.
- Lease-safe task redelivery and an in-memory delivery outbox that retries exact
  acknowledgements/results without re-executing completed work.
- Server-defined task expiry and agent-enforced command or module timeout
  handling.
- Process-group (Unix) or job-object (Windows) timeouts and bounded
  stdout/stderr capture.
- Explicit UTF-8 stdout/stderr in typed results; structured module evidence is
  JSON, and XOR output remains limited to deprecated legacy result compatibility.
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
the Rust build script, stores the artifact for download, and records its
listener, path, size, SHA-256 digest, state, and provenance in SQLite. Indexed
artifacts are revalidated at startup and immediately before download; missing
or corrupt artifacts retain diagnostic metadata but are not served.

Listener, payload/build, and runtime agent identities are now distinct:

| Identity | Meaning |
| --- | --- |
| Listener ID | Server-side network endpoint and protocol instance. |
| Payload/build ID | Indexed build artifact, embedded config, and bootstrap allowance. |
| Agent runtime ID | One live or historical runtime agent instance. |

Issue #99 defines and implements the bounded payload-build contract. Linux x64
ELF and Windows x64 EXE builds support debug and release modes; unsupported
profiles and aspirational options fail validation before build side effects.
Every successful build has one canonical output and a mandatory, versioned,
inspectable manifest. See [Payload build contract](payload-builds.md).

Reproducibility has an intentional security boundary. Mutation decisions are
derived from the source revision and mutation seed, but every production build
also embeds a fresh random enrollment bootstrap. Only its hash is stored.
Source and seed alone therefore do not reproduce byte-identical production
artifacts, and provenance must not record the raw secret to close that gap.

## Storage Design

The #97 implementation merged into `dev` makes SQLite the production authority
for listener-scoped agents, typed task lifecycles/results, payload-build
metadata, and listener lifecycle events. Issue #104 adds bootstrap hashes and
allowances, the server enrollment key, and durable listener-scoped sessions.
The task store writes directly through SQL transactions rather than serializing
process snapshots.

Restart recovery favors evidence preservation without silently replaying
side effects:

- queued work remains eligible for dispatch;
- dispatched work preserves its initial timestamp and delivery lease before
  redelivery of the same task ID;
- running work remains running and is not automatically executed again;
- exact running/result retries remain idempotent and terminal states remain
  immutable;
- persisted agents remain historical/inactive until a fresh heartbeat; and
- loaded listeners previously recorded active or errored recover stopped with
  one lifecycle event.

SQLite is also authoritative for listener configuration. Restrictive,
secret-redacted filesystem projections support compatibility and are rebuilt
when missing; they never overwrite an existing durable config. Payload builds
record `building` before execution, transition to `completed` or `failed`, and
become `interrupted` after a process restart instead of being resumed.

SQLite uses a full-synchronous rollback journal rather than WAL and one
process-wide connection. The database stores metadata and authoritative
listener configs; payload artifacts, listener uploads, operator uploads, and
logs remain files that must be backed up with it. Redacted listener config
projections are regenerable.
See [storage.md](storage.md) for configuration, migration integrity, permissions,
reconciliation, and backup/restore guidance.

## Transport Design

HTTP(S) polling is the reference transport. It is the only transport that should
be considered active and end-to-end today. The design keeps polling simple:
agents initiate outbound requests, receive at most one command per poll, and
submit results separately.

SOCKS5 and pivot code exists on both server and agent sides, but this area is
not yet a coherent product workflow. The supported setting today is outbound
agent egress: when enabled, the HTTP C2 client uses an existing SOCKS5 proxy
through reqwest. MicroC2 does not expose a supported SOCKS5 listener, server
mode, or multi-hop pivot workflow. The remaining pivot frame modules are
local/in-memory plumbing and need a typed command surface, integration tests,
UI state, and clear ownership of tunnel lifecycle.

New transports should not be added until the transport boundary is explicit.
For HTTP(S), the implemented boundary is:

- Validated profile/config.
- Start/stop lifecycle.
- Authenticated agent enrollment and heartbeat behavior.
- Task/result transport semantics.
- Health/error telemetry.
- Tests or a documented manual lab run.

Production composition rejects plain HTTP unless the explicit isolated-lab
policy is enabled. Generated payloads verify server certificates through the
system trust store and expose no invalid-certificate option. HTTPS listeners
inherit the operator server certificate/key unless explicitly overridden;
all TLS material must remain outside the static root and key pairs are
preflighted before persistence. HTTPS requires TLS 1.2 or newer.
`requireClientCert` is rejected rather than pretending to provide mTLS without
CA-backed client-certificate verification.

## Safety Design

The project must still be operated as a lab-only prototype. The Phase 0 safety
baseline guards operator routes with loopback-or-token access, restricts
operator WebSocket origins, makes listener CORS explicit, keeps insecure agent
transport opt-in, validates file-store basenames, binds agent lifecycle
requests to durable enrollment sessions through #104, and records closed,
redacted audit events through #100. The remaining design direction is:

- Evolve the shared-token guard into actor-aware authentication and roles before
  multi-user operation.
- Build reporting and evidence export on top of the durable audit API.
- Add target scoping and explicit confirmation metadata for risky future task
  types.
- Add clear docs for isolated lab deployment.

The Phase 0 route split and lab-safety work are complete in #75 and #78; #100
adds the first structured governance layer on the `dev` integration line.

## Documentation And Testing Expectations

Every major feature should have at least one of:

- A unit test for pure logic.
- An integration or smoke test for server/agent lifecycle.
- A documented manual verification path when automation is too heavy.

CI currently gives the project a baseline safety net. Future design work should
keep new behavior within those checks instead of adding unchecked prototype
paths.

## Near-Term Design Priorities

1. Extend the typed task registry with file transfer and pivot operations now
   that the v1 shell contract in #98 is stable (#88).
2. Preserve the implemented #99 payload-profile and manifest contract as new
   formats or optional capabilities are researched.
3. Add operator-facing evidence export and reporting on the structured audit
   foundation.

The data path #98 → #97 → #100 is complete on the `dev` integration line.
Issue #104 closes the authenticated-enrollment boundary there as well. This
sequence contains no `dev` to `main` promotion, and the feature work does not
imply that one is ready. Cross-platform payload-path containment in #108 is an
explicit promotion gate.
