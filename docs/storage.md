# Durable Storage

MicroC2's development branch uses one process-wide SQLite database for durable
server state. It stores listener records and lifecycle events, historical agent
metadata, typed task lifecycles and results, legacy result projections, and
payload-build metadata. Payload binaries, listener compatibility configs,
operator uploads, and server logs remain files on disk.

This is a single-process, local-lab persistence design. It is not a substitute
for the agent enrollment work in #104 or the structured audit trail planned in
#100.

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

A newly created database directory is restricted to mode `0700` on platforms
that support POSIX permissions. The database file is created or tightened to
mode `0600`. MicroC2 does not change permissions on an existing database parent
directory, so operators remain responsible for securing that directory and its
backups. Listener directories and compatibility configs are tightened to
`0700` and `0600` respectively; operators remain responsible for payload
artifacts, uploads, and logs.

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
  lifetime until a fresh heartbeat arrives on their listener.
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
active dispatch target until it sends a fresh post-start heartbeat.

Listener lifecycle events are append-only operational history. They cover
creation, import, start, stop, error, delete, compensated creation failure, and
crash recovery, but they are not actor-aware security audit records. Issue
#100 remains the audit boundary.

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

To restore, stop the server, replace the database and companion directories as
one backup set, verify ownership and restrictive permissions, and start the
same MicroC2 revision first. Confirm that listeners load as stopped, historical
agents and task results are present, and payload states reconcile before
upgrading.

Before an upgrade:

1. Create and test a cold backup.
2. Review new migration files and release notes.
3. Start the new binary against a disposable copy when the history is
   important.
4. Upgrade the real database only after that check succeeds.

Downgrading a migrated database is not supported: an older binary will refuse a
future schema. Restore the pre-upgrade backup instead of manually editing the
schema or migration ledger.

## Current Limits

- Storage is designed for one local MicroC2 server process, not horizontal
  scaling or a shared database service.
- #104 remains the P0 gate for authenticated agent enrollment and for any
  promotion beyond the isolated-lab boundary. Durable correlation does not
  authenticate an agent.
- Listener lifecycle events are not the structured, actor-aware audit trail
  tracked by #100.
- Operator uploads, payload binaries, listener upload directories, and logs are
  files, not database blobs; backup and restore must include them separately.
  Listener config projections are redacted, regenerable compatibility files.
- Payload reconciliation validates indexed artifacts but does not import
  unindexed files from disk, including artifacts left by an interrupted build.
- SQLite is authoritative for durable listener configuration. Missing or stale
  projections are rebuilt. Unreadable or malformed disk-only configs are
  skipped rather than trusted; unsafe listener identities and directory/name
  mismatches stop durable startup so an existing listener is not hidden.
- Until #104 lands, an unauthenticated listener client can invent agent IDs.
  Durable storage therefore remains isolated-lab state and is not an
  authorization boundary.
- This development work does not by itself justify promotion from `dev` to
  `main`.
