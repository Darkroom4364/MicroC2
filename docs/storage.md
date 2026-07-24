# Durable Storage

MicroC2's development branch uses one process-wide SQLite database for durable
server state. It stores listener records and lifecycle events, historical agent
metadata, typed task lifecycles and results, legacy result projections,
payload-build metadata, and immutable structured audit events. With #104 it
also stores the enrollment HMAC key, payload bootstrap hashes and allowances,
and durable agent-session state. Payload binaries, listener compatibility
configs, operator uploads, and server logs remain files on disk.

This is a single-process, local-lab persistence design. Issues #97 and #104
provide the durable and authenticated foundations on the `dev` integration
line; #100 adds the separate actor-aware audit layer.

## Configuration

The default setting in `server/config/settings.yaml` is:

```yaml
storage:
  path: "data/microc2.db"
```

Relative paths are resolved from the server process's working directory. When
the server is started from `server/`, the default database is therefore
`server/data/microc2.db`.

Set `MICROC2_STORAGE_PATH` to override the YAML value without modifying the
configuration file:

```sh
MICROC2_STORAGE_PATH=/var/lib/microc2/microc2.db ./server
```

The database must be outside `server.staticDir`. Startup rejects a path inside
the web-served static root so agent, task, result, and listener history cannot
be downloaded as a static asset. Use a local filesystem path; SQLite URI and
in-memory database forms are rejected.

## SQLite Durability Mode

MicroC2 uses the pure-Go SQLite driver pinned in `server/go.mod` and opens one
database connection for the process. It enforces:

- `journal_mode=DELETE` (rollback journal, not WAL);
- `synchronous=FULL`;
- foreign-key enforcement;
- a five-second busy timeout; and
- immediate write transactions.

WAL is deliberately disabled. At the time this storage layer was introduced,
the embedded SQLite version was in a range affected by a documented WAL-reset
failure mode. Do not switch the database to WAL without first updating and
validating the SQLite dependency, crash-recovery tests, and backup procedure.

Only one MicroC2 server process may own a database file. Do not point multiple
server instances at the same file, including through a shared network
filesystem.

## Bootstrap, Migrations, And Permissions

On startup the server creates the database if necessary, opens it, and applies
embedded migrations in one transaction before listeners or API handlers are
initialized. Migration filenames are strictly ordered and contiguous. The
`schema_migrations` ledger records each filename, version, application time,
and SHA-256 checksum.

Startup refuses to continue when:

- an applied migration name or checksum differs from the binary's embedded
  migration;
- the ledger is not an exact prefix of the embedded migration sequence; or
- the database schema is newer than the running binary.

Do not edit an applied migration or the migration ledger. Add a new migration
for every schema change, and back up durable state before running a binary that
contains a new migration.

`0002_agent_enrollment.sql` adds the enrollment key, hash-only payload
bootstraps, immutable per-build session allowances, and listener-scoped agent
sessions. The database does not store raw bootstrap or session bearer strings,
but the HMAC key and session records are security-sensitive and must be
protected as credential material.

`0003_payload_enrollment_allocations.sql` adds immutable allocation history for
each build/listener/agent tuple. Per-build allowances count identities ever
allocated from that bootstrap; revoking a session does not make its slot
available to a different identity.

`0004_structured_audit_events.sql` adds Audit Event v1 storage and causal links
from tasks, payload builds, and listener lifecycle records. Existing records
are backfilled with explicit `system` migration events, so an upgraded database
does not pretend that pre-audit history had an authenticated human actor.

A newly created database directory is restricted to mode `0700` on platforms
that support POSIX permissions. The database file is created or tightened to
mode `0600`. MicroC2 does not change permissions on an existing database parent
directory, so operators remain responsible for securing that directory and its
backups. Listener directories and compatibility configs are tightened to
`0700` and `0600` respectively. Payload roots, build directories, and generated
artifacts are tightened to owner-only mode (`0700` on POSIX platforms);
operators remain responsible for uploads and logs.

## Startup Reconciliation

Startup treats SQLite as the listener authority and reconciles filesystem
artifacts without blindly resuming pre-crash runtime activity:

- Every non-deleted listener is loaded from its checksummed database config,
  even when its compatibility config is missing or stale. The compatibility
  projection is recreated with restrictive permissions and proxy passwords
  redacted; the socket is never auto-started.
- Valid disk-only configs are imported once in deterministic order. They cannot
  overwrite an existing database row. Safe legacy printable-ASCII listener
  names, including internal spaces and punctuation that are portable as
  filenames, remain importable. An unsafe identity or a directory/config-name
  mismatch fails durable startup explicitly instead of silently hiding that
  listener.
- A listener last recorded as `ACTIVE` or `ERROR` is recovered as `STOPPED`.
  Exactly one `recovered_stopped` lifecycle event records that recovery;
  subsequent starts are explicit operator actions.
- A deleted listener remains tombstoned and is not resurrected by a stale
  compatibility config left on disk.
- Historical agents are reloaded, but they remain inactive for the new process
  lifetime until a fresh authenticated heartbeat arrives on their listener.
- Enrollment sessions, credential generations, revocation, re-enrollment
  requirements, and bootstrap-confirmation state survive restart.
- Payload builds left in `building` are changed once to `interrupted`. Builds
  that fail in-process are retained as `failed`; neither state is resumed.
- Indexed payload artifacts are revalidated against their relative path,
  filename, size, provenance JSON, and SHA-256 digest. Their durable state is
  reconciled to `completed`, `missing`, or `corrupt`.

MicroC2 does not scan the payload directory to import files that have no
database record. Preserve both the database and artifact directory when moving
or restoring an installation.

## Restart Semantics

Task recovery preserves server-authorized lifecycle state:

| State before restart | Behavior after restart |
| --- | --- |
| `queued` | Remains queued and is eligible for normal dispatch, subject to expiry. |
| `dispatched` | Keeps its original `dispatched_at` and persisted delivery lease. The same task ID is eligible for redelivery only after the remaining lease expires. |
| `running` | Remains running and is not dispatched for execution again. An exact retry of the running acknowledgement remains idempotent. |
| `completed`, `failed`, `cancelled`, or `expired` | Remains terminal and immutable. An exact terminal-result retry is accepted idempotently; a conflicting retry is rejected. |

Task completion and the deprecated legacy result projection are committed in
one transaction, so a failure cannot leave a terminal task without its required
compatibility history.

Agent history is durable but presence is intentionally process-local. A
persisted agent can still be inspected after restart, yet is not considered an
active dispatch target until it sends a fresh authenticated post-start
heartbeat. A confirmed session can resume from the agent's tuple-bound
per-user state. Linux uses `$XDG_STATE_HOME/microc2/agent` or
`$HOME/.local/state/microc2/agent`; macOS uses
`$HOME/Library/Application Support/microc2/agent`; Windows uses
`%LOCALAPPDATA%\microc2\agent`. The listener, payload, and agent path components
are encoded separately with unpadded base64url. Windows protects the bearer
with current-user DPAPI, while Unix uses `0700` directories and `0600` files.
Losing that state requires an explicit operator re-enrollment because the
embedded bootstrap cannot replay after confirmation.

Listener lifecycle events remain append-only operational history. They cover
creation, import, start, stop, error, delete, compensated creation failure, and
crash recovery. Each new lifecycle record links to its structured audit event;
older records are linked to explicit migration events.

Payload metadata survives restart independently of the artifact bytes. A
metadata row is created in `building` immediately before the build process
starts, then transitions to `completed` or `failed`; startup changes any
leftover `building` row to `interrupted`. Failed or interrupted builds are not
resumed or imported automatically. A payload marked `missing` or `corrupt`
keeps its record for diagnosis, and its download endpoint returns `410 Gone`.
A completed payload is revalidated again at download time and streamed from
the same verified open file handle, so replacing its path after verification
does not substitute different bytes.

The compatibility `/static/` file server denies both `listeners` and `payloads`
trees. Payload downloads must pass through the metadata and digest gate at
`/api/payload/download/{id}`.

## Structured Audit Events

Audit Event v1 records:

- a monotonic sequence and server receipt time;
- an actor kind and identifier;
- a stable action, route, target, and outcome;
- an optional closed reason code and causal event sequence; and
- only the relevant listener, agent, task, payload-build, file-basename, or
  terminal-session identifiers.

The normative contracts are [Audit Event v1](schemas/audit-event-v1.schema.json)
and [Audit Page v1](schemas/audit-page-v1.schema.json). Authenticated operator
requests identify the actor as `operator/loopback` or
`operator/shared-token`. These identify the authentication mechanism, not an
individual person. Agent lifecycle events use the enrolled runtime agent ID,
and recovery or migration events use an explicit system actor.

The application appends audit events transactionally with the durable state
change where a shared SQLite transaction is available. Task and payload rows
retain their root causal sequence; later lifecycle events reference it.
Listener lifecycle rows retain the corresponding event sequence. Exact task
status/result retries remain idempotent instead of manufacturing duplicate
success events. Agent-session rotation, revocation, and required re-enrollment
also share their state transaction with the audit append. Payload artifact
reconciliation emits a root-linked event only when its durable state, detail,
or verified hash changes; failed download attempts and rejected enrollment
revocations receive closed reason codes.
Audit history survives restart and is available newest-first at
`GET /api/audit/events?limit=50&offset=0`; the operator endpoint allows 1–100
events per page, caps requested offsets at 1,000,000, and sends
`Cache-Control: no-store`.

The event input is a closed allowlist. It deliberately has no arbitrary
metadata, details, request-body, or raw-error field. MicroC2 never records:

- task commands, stdout, stderr, or result error text;
- terminal commands, terminal output, or transcripts;
- operator or agent credentials, authorization headers, bootstrap values,
  session bearers, or enrollment keys;
- uploaded/downloaded file contents, multipart bodies, or full filesystem
  paths; or
- payload build output, compiler output, embedded configuration, or secret
  build inputs.

File basenames and object identifiers are still potentially sensitive
metadata, and the SQLite database already contains credential-adjacent
enrollment state. Protect the database and its backups accordingly. Audit
events are application-level append-only: MicroC2 has no event update,
selective-delete, TTL, or automatic-pruning API. The current retention period
is therefore the lifetime of the database and its cold backups. If a lab has a
shorter retention policy, rotate complete, coordinated database/artifact backup
sets outside MicroC2 rather than editing individual audit rows or foreign-key
links.

## Backup, Restore, And Upgrade

Use a cold backup for the current single-process design:

1. Stop the MicroC2 server and confirm the process has exited.
2. Copy the SQLite database file from `storage.path`.
3. Copy `{server.staticDir}/listeners` and
   `{server.staticDir}/payloads`. Listener config projections can be rebuilt
   from SQLite, but listener upload subdirectories and payload artifacts cannot.
4. Copy the configured upload/file-drop directory and any logs needed as
   research evidence.
5. Store the copies together with the server revision and configuration used to
   create them.

Stopping the process matters: copying only the main SQLite file during a write
can produce an inconsistent backup even though rollback journaling is enabled.
Do not omit a transient rollback-journal file from a live filesystem snapshot;
prefer the cold procedure above.

Treat every database copy and backup set as credential material. The stored
enrollment HMAC key plus durable session bindings can be used to derive valid
session credentials even though raw bearers and bootstrap values are absent.

To restore, stop the server, replace the database and companion directories as
one backup set, verify ownership and restrictive permissions, and start the
same MicroC2 revision first. Confirm that listeners load as stopped, historical
agents and task results are present, and payload states reconcile before
upgrading.

Before an upgrade:

1. Create and test a cold backup.
2. Review new migration files and release notes.
3. Convert persisted HTTP listeners to HTTPS, or explicitly enable
   `security.agentTransport.allowInsecureIsolatedLab` only for a contained lab;
   the secure default rejects plaintext listeners during startup.
4. Start the new binary against a disposable copy when the history is
   important.
5. Upgrade the real database only after that check succeeds.

Downgrading a migrated database is not supported: an older binary will refuse a
future schema. Restore the pre-upgrade backup instead of manually editing the
schema or migration ledger.

## Current Limits

- Storage is designed for one local MicroC2 server process, not horizontal
  scaling or a shared database service.
- #104 authenticated enrollment is complete for the `dev` integration line.
- A payload build enrolls one distinct runtime identity by default and may
  declare an immutable allowance from 1 through 64. Allocation is monotonic:
  session revocation does not refund a slot, while explicit same-identity
  re-enrollment reuses the existing allocation. A listener permits at most
  4,096 active enrollment sessions.
- Historical agent listings are bounded with `limit`/`offset` pagination:
  default 100 entries, maximum 500.
- Structured audit history is bounded only at the retrieval API. Storage has no
  automatic retention or pruning policy.
- Operator uploads, payload binaries, listener upload directories, and logs are
  files, not database blobs; backup and restore must include them separately.
  Listener config projections are redacted, regenerable compatibility files.
- Payload reconciliation validates indexed artifacts but does not import
  unindexed files from disk, including artifacts left by an interrupted build.
- SQLite is authoritative for durable listener configuration. Missing or stale
  projections are rebuilt. Unreadable or malformed disk-only configs are
  skipped rather than trusted; unsafe listener identities and directory/name
  mismatches stop durable startup so an existing listener is not hidden.
- Agent IDs remain correlation values, not credentials. Production lifecycle
  routes authenticate the complete listener/payload/runtime tuple through the
  durable enrollment session.
- Payloads built before #104 have no bootstrap credential and must be rebuilt;
  there is no unauthenticated production compatibility path.
- This integration targets `dev` only. It does not promote `dev` to `main` or
  imply that promotion is ready.
