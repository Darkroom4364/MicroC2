# Development Workflow

MicroC2 uses a two-branch integration model:

- `main` is the stable branch. It should represent code that is ready for
  regular use in controlled lab environments.
- `dev` is the development integration branch. Issue branches start from
  `dev` and merge back into `dev`.
- Issue branches should be short-lived and named after their work, for example
  `issue/86-listener-lifecycle` or `feature/payload-build-profiles`.

## Normal Issue Flow

```sh
git fetch origin
git switch dev
git pull --ff-only
git switch -c issue/<number>-short-description
```

Open the pull request back into `dev`. The context-aware CI workflow runs only
the relevant suites for the files changed by the branch.

## Stable Promotion Flow

When `dev` reaches a coherent milestone, open a pull request from `dev` into
`main`. Promotion pull requests run the full Linux and Windows server/agent,
static, formatting, and release-package checks.

After the promotion merges, create or update any release notes from the merged
changes. Direct feature work should not target `main`.

## Required Checks

The protected `dev` branch should require:

- `CI Gate`
- `foxguard`

The protected `main` branch should require:

- `CI Gate`
- `Release Package`
- `foxguard`

`CI Gate` is the stable required GitHub Actions status. It depends on the
path-selected suites and fails if any selected blocking suite fails. This keeps
branch protection stable even when a path-specific job is intentionally skipped.
It also enforces that pull requests into `main` come from `dev`.

## Context-Aware Suites

- Server changes run `Go Server`: `go test ./...`, a focused
  `go test -race ./internal/enrollment ./internal/listeners ./internal/tasks ./internal/behaviour`,
  `go vet ./...`, and a server
  build on Linux, plus `Go Server (Windows)` tests and a native Windows build.
- Agent changes run `Rust Agent`: `cargo test --locked`,
  `cargo clippy --locked --all-targets`, and `cargo build --locked` on Linux,
  plus tests and a build in `Rust Agent (Windows)`.
- Static UI or script changes run `Static Assets And Scripts`: shell syntax
  checks and JavaScript syntax checks.
- Server or agent changes run `Format`: `gofmt` validation for `server/` and
  `cargo fmt --check` for `agent/`.
- Pull requests into `main` run every suite regardless of path, because they are
  release-promotion candidates.
- Documentation-only changes to `dev` can pass through `CI Gate` without running
  server or agent builds.

Format checks are blocking whenever they are selected by the path filters.

## Foxguard

Foxguard runs as a GitHub App check and is configured by `.foxguard.yml`.
Existing scanner findings are tracked in `.foxguard/baseline.json` so new
findings can be separated from legacy debt. Secret scanning uses
`.foxguard/secrets-baseline.json`.

## Local Checks

Useful local equivalents before opening a pull request:

```sh
cd server
go test ./...
go test -race ./internal/enrollment ./internal/listeners ./internal/tasks ./internal/behaviour
go vet ./...
go build -o /tmp/microc2-server ./cmd
```

For route and enrollment-boundary changes introduced by #104, use this smoke
path in a controlled local lab. The implementation builds on the #97 durable
storage foundation in `dev`.

1. Start the operator server and confirm
   `https://localhost:8443/api/agents/list` responds.
2. Confirm the operator port does not serve agent polling by checking
   `https://localhost:8443/api/agent/test/heartbeat` returns `404`.
3. Create or start an HTTPS listener on a separate port with a certificate
   trusted by the test agent. Plain HTTP requires
   `security.agentTransport.allowInsecureIsolatedLab=true`; never use that
   override outside a contained lab.
4. Generate a new payload for that listener. Pre-#104 payloads have no
   bootstrap and must be rebuilt.
5. Run the generated agent. Confirm its first heartbeat enrolls, its subsequent
   heartbeat uses a session bearer, and `session.json` is created under the
   per-user MicroC2 state root: `$XDG_STATE_HOME/microc2/agent` (or
   `$HOME/.local/state/microc2/agent`) on Linux,
   `$HOME/Library/Application Support/microc2/agent` on macOS, or
   `%LOCALAPPDATA%\microc2\agent` on Windows. Confirm the listener, payload, and
   agent path components are separately encoded; Unix directories/files use
   `0700`/`0600`, Windows uses current-user DPAPI, and neither credential is
   printed.
6. Create a shell task through `POST /api/agents/{agent_id}/tasks` with typed
   `schema_version: 1`, `arguments`, `timeout_seconds`, and
   `expires_in_seconds`; record the returned task ID and confirm the response
   is `202 Accepted`.
7. Confirm the authenticated agent polls that same Task v1 resource, sends the
   correlated `running` update, and submits the terminal result.
8. Read lifecycle metadata through
   `GET /api/agents/{agent_id}/tasks?limit=50&offset=0`, then read stdout/stderr
   from `GET /api/agents/{agent_id}/tasks/{task_id}`.
9. Restart the server and listener. Confirm historical data remains visible but
   tasking is unavailable until the agent sends a fresh authenticated heartbeat
   using its persisted session.

Run the focused negative-path tests as well:

```sh
cd server
go test ./internal/enrollment ./internal/behaviour ./internal/handlers/api/...
```

They cover missing and malformed bearers, cross-agent/listener/payload use,
bootstrap replay after confirmation, stale generations, rotation promotion,
revocation, explicit re-enrollment, restart gating, duplicate IDs on separate
listeners, and enrollment cardinality.

For delivery-failure coverage, also confirm that a task poll whose response is
lost redelivers the same ID only after its lease, that a dispatched task cannot
start at or after `expires_at`, and that exact repeated running/result payloads
return success without executing shell work twice. Keep a completed result in
the agent outbox until the server acknowledges it.

Agent IDs remain correlation values, not credentials. The session bearer and
its complete listener/payload/runtime binding provide authentication. See
[Authenticated agent enrollment](agent-enrollment.md) for the response-loss
window, operator actions, transport overrides, and backup implications.

The normative fixtures for this smoke path are
[`task-create-request-v1.schema.json`](schemas/task-create-request-v1.schema.json),
[`task-v1.schema.json`](schemas/task-v1.schema.json),
[`task-summary-v1.schema.json`](schemas/task-summary-v1.schema.json),
[`task-page-v1.schema.json`](schemas/task-page-v1.schema.json),
[`task-status-update-v1.schema.json`](schemas/task-status-update-v1.schema.json),
[`task-result-v1.schema.json`](schemas/task-result-v1.schema.json), and
[`task-result-summary-v1.schema.json`](schemas/task-result-summary-v1.schema.json).
Legacy
operator `/command` routes are compatibility adapters only and should not be
used for new smoke tests.

```sh
cd agent
cargo test --locked
cargo clippy --locked --all-targets
cargo build --locked
```
