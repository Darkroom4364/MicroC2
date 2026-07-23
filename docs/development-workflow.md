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
`main`. Promotion pull requests run the full server, agent, static, formatting
advisory, and release package checks.

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

- Server changes run `Go Server`: `go test ./...`, `go vet ./...`, and a server
  build in `server/`.
- Agent changes run `Rust Agent`: `cargo test --locked`,
  `cargo clippy --locked --all-targets`, and `cargo build --locked` in
  `agent/`.
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
go vet ./...
go build -o /tmp/microc2-server ./cmd
```

For route-boundary changes, also use this smoke path in a controlled local lab:

1. Start the operator server and confirm
   `https://localhost:8443/api/agents/list` responds.
2. Confirm the operator port does not serve agent polling by checking
   `https://localhost:8443/api/agent/test/heartbeat` returns `404`.
3. Create or start an HTTP listener on a separate port.
4. POST a heartbeat to the listener at `/api/agent/test/heartbeat`.
5. Create a shell task through `POST /api/agents/test/tasks` with typed
   `schema_version: 1`, `arguments`, `timeout_seconds`, and
   `expires_in_seconds`; record the returned task ID and confirm the response is
   `202 Accepted`.
6. Poll the task from the listener at `/api/agent/test/tasks` and confirm the
   returned Task v1 resource becomes `dispatched`.
7. POST a `running` Task Status Update v1 to
   `/api/agent/test/tasks/{task_id}/status`.
8. POST the terminal Task Result v1 to `/api/agent/test/results`.
9. Read the correlated lifecycle metadata through the bounded
   `GET /api/agents/test/tasks?limit=50&offset=0` Task Page v1 response, then
   read the nested stdout/stderr from
   `GET /api/agents/test/tasks/{task_id}`.

For delivery-failure coverage, also confirm that a task poll whose response is
lost redelivers the same ID only after its lease, that a dispatched task cannot
start at or after `expires_at`, and that exact repeated running/result payloads
return success without executing shell work twice. Keep a completed result in
the agent outbox until the server acknowledges it.

Agent IDs are not credentials in the current listener protocol. Run this smoke
path only on an isolated authorized network until #104 binds the lifecycle
routes to authenticated enrollment sessions.

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
