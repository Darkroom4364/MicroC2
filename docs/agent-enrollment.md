# Authenticated Agent Enrollment

Issue #104 adds authenticated enrollment to the development line on top of the
#97 durable-storage foundation. Both changes are scoped to `dev`; they do not
promote `dev` to `main` or imply that such a promotion is ready.

## Security Boundary

The enrollment layer prevents a client from receiving tasks or forging
lifecycle updates merely by learning or inventing an agent ID. It binds each
session credential to all of:

- the listener ID;
- the runtime agent ID;
- the payload/build ID;
- an opaque session ID; and
- a credential generation.

Every non-preflight agent route requires a single
`Authorization: Bearer <credential>` header. Heartbeats additionally require
the path agent ID and body agent ID to match, and the body listener and payload
IDs to match the enrolled tuple. Task polls, task-status updates, typed results,
and deprecated command/result adapters reject missing, stale, revoked, or
cross-agent credentials. A duplicate runtime agent ID on another listener is a
separate identity and cannot reuse the first listener's session.

Bootstrap hashes and session MACs are checked with constant-time comparison
primitives. Credential syntax, lookup, binding, and lifecycle failures collapse
to the same agent-visible `401 Unauthorized` response instead of revealing
which check failed.

This is bearer authentication, not proof that the endpoint is uncompromised.
Anyone who extracts a live bootstrap or session credential can act within that
credential's binding. Operator access remains protected by the separate
loopback-or-shared-token guard and is not yet a multi-user authorization
system.

## Bootstrap And Confirmation

Payload generation creates a fresh 32-byte random bootstrap credential. The raw
value is passed only to the Rust build subprocess through
`ENROLLMENT_CREDENTIAL` and embedded in the payload. MicroC2 stores only its
SHA-256 digest and never projects the raw value into SQLite, logs, build output,
operator responses, provenance JSON, or sidecar configuration files.

The first authenticated heartbeat presents the bootstrap and the complete
listener/payload/agent tuple. A successful response returns a signed session
credential with `Cache-Control: no-store`; the agent persists that credential
before using it on later requests.

There is one deliberate response-loss window. Until the server sees the issued
session credential successfully authenticate, the same bootstrap and exact
identity tuple may recover the same session credential. The first successful
session authentication durably confirms the session. After confirmation, the
bootstrap cannot resume or replace it unless an operator explicitly requires
re-enrollment. This avoids both permanent bootstrap replay and an unusable
payload after a lost initial response.

The bootstrap is a deliberate secret build input. Mutation choices remain
reproducible from the source revision and mutation seed, but those inputs alone
cannot recreate a byte-identical production payload because each build embeds a
new random credential. Reusing or recording that secret merely to make artifacts
deterministic would weaken the enrollment boundary.

## Runtime And Restart Behavior

The agent stores runtime identity and session state in the current user's
platform state directory, never beside the executable:

- Linux: `$XDG_STATE_HOME/microc2/agent` when `XDG_STATE_HOME` is absolute,
  otherwise `$HOME/.local/state/microc2/agent`.
- macOS: `$HOME/Library/Application Support/microc2/agent`.
- Windows: `%LOCALAPPDATA%\microc2\agent`, with
  `%USERPROFILE%\AppData\Local\microc2\agent` as the fallback.

Below that root, listener, payload, and runtime-agent IDs are separate
unpadded-base64url path components. The session file is therefore
`<root>/<listener>/<payload>/<agent>/session.json`, using the encoded
components rather than the literal IDs. The generated runtime ID is retained
at the encoded listener/payload scope. Session content repeats the complete
tuple and is accepted only when all three IDs match.

Writes use atomic replacement. Windows protects the bearer with current-user
DPAPI and binds its additional entropy to the complete identity tuple. Unix
relies on owner-only state directories and files (`0700` and `0600`,
respectively). Session files larger than 16 KiB, malformed JSON envelopes, or
tuple/schema mismatches are ignored. Once an envelope selects a supported
protection mode for the matching tuple, however, an unprotect or decryption
failure stops authentication rather than silently falling back to the embedded
bootstrap.

Server restart preserves enrollment state, but historical presence is not proof
of a live runtime. Every agent must send a fresh authenticated heartbeat in the
new server process before it can poll tasks or submit status/results. If a
confirmed agent loses or corrupts its per-user session state, its embedded
bootstrap is no longer sufficient; an operator must explicitly require
re-enrollment.

## Rotation, Revocation, And Re-enrollment

The operator API exposes empty-body `POST` actions:

| Route | Effect |
| --- | --- |
| `/api/listeners/{listener_id}/agents/{agent_id}/session/rotate` | Creates one pending generation and returns generation metadata only. |
| `/api/listeners/{listener_id}/agents/{agent_id}/session/revoke` | Immediately invalidates the session and any pending generation. |
| `/api/listeners/{listener_id}/agents/{agent_id}/session/re-enroll` | Invalidates the current session and explicitly permits the next valid bootstrap enrollment. |
| `/api/payload/{payload_id}/enrollment/revoke` | Idempotently retires the build bootstrap without revoking sessions already issued from it. |

Rotation is two phase. While a replacement is pending, each authenticated
heartbeat using the current credential delivers the same replacement
credential to the agent. The first request using the replacement atomically
promotes it; the previous generation then fails. The operator response never
contains either bearer.

Revocation alone is final: it does not silently reactivate the embedded
bootstrap. Re-enrollment is a distinct operator decision and starts a new
session with the same confirmation rule as initial enrollment.

Build-wide retirement accepts no body or query parameters, returns no
credential material, and sets `Cache-Control: no-store`. Once retired, the
embedded bootstrap cannot create a new session or recover an unconfirmed one;
already-issued session credentials continue to authenticate until their own
session lifecycle action revokes or replaces them.

## Transport Policy

Production listener and payload paths require HTTPS with normal certificate
validation. Listener TLS is configured with a minimum of TLS 1.2.

- Plain HTTP is rejected unless
  `security.agentTransport.allowInsecureIsolatedLab` is explicitly `true`.
- Generated payloads always retain system-trust validation; the payload API
  provides no invalid-certificate switch. Trust the lab CA or certificate on
  the agent machine when testing self-signed HTTPS.
- A manual custom build may set `ALLOW_INVALID_CERTS=true` only together with
  `ALLOW_INSECURE_ISOLATED_LAB=true`. Both are isolated-lab escape hatches, not
  ordinary payload-generation controls.
- `requireClientCert` is rejected. MicroC2 does not claim mTLS support until it
  has CA-backed client-certificate verification.

If installing a lab trust anchor is impractical, explicitly enable the
isolated-lab server policy and use HTTP only inside the contained network. Do
not expose an insecure-lab listener outside an authorized lab.

## Resource Limits

- Heartbeat request bodies are capped at 64 KiB; the single Authorization
  header is capped at 256 bytes.
- Identifiers are capped at 128 bytes and use the restricted identifier
  alphabet. Heartbeat metadata fields and IP-list entries are capped at 512
  characters, with at most 32 IP entries and 64 recent-command entries; each
  recent command is capped at 8,192 characters.
- A payload build enrolls one distinct runtime identity by default.
  `max_sessions` may be set from 1 through 64 and is immutable after
  activation. The allowance is monotonic: revoking a session does not refund a
  build slot, while explicit re-enrollment of the same listener/agent identity
  reuses its existing allocation.
- A listener permits at most 4,096 active enrollment sessions and keeps the
  same bound on its in-memory runtime-agent set. At the runtime-cache bound, an
  authenticated heartbeat from a new runtime evicts the least-recently-seen
  entry (breaking timestamp ties by agent ID) without deleting durable history.
  An evicted runtime must heartbeat again before it is eligible for tasking.
- `GET /api/agents/list` is paginated with `limit` and `offset`. The default
  limit is 100 and the maximum is 500; count and continuation metadata are
  returned in `X-Total-Count`, `X-Limit`, `X-Offset`, and, when applicable,
  `X-Next-Offset`.
- Existing task/status/result transport and content limits continue to apply;
  see [architecture.md](architecture.md#typed-task-contract).

## Migration, Backup, And Upgrade

Migration `0002_agent_enrollment.sql` adds the server HMAC key, payload
bootstrap hashes and allowances, and durable agent-session state. The database
is now security-sensitive credential material even though it does not contain
raw bootstrap or session bearer strings: possession of the HMAC key and session
records can enable credential derivation. Migration
`0003_payload_enrollment_allocations.sql` adds immutable per-build identity
allocation history so session revocation cannot reset `max_sessions`. Keep the
database and cold backups private, preserve them as one set with payload
artifacts, and restore the same server revision before upgrading. See
[storage.md](storage.md) for the complete procedure.

Payloads built before #104 do not contain an enrollment bootstrap and cannot
use authenticated production listeners. Rebuild them after upgrading; do not
add an unauthenticated compatibility path.

Before starting the upgraded server, convert persisted plaintext HTTP listeners
to HTTPS. A plaintext listener now fails the secure-default transport policy
unless `security.agentTransport.allowInsecureIsolatedLab=true` is explicitly
set for a contained lab.
