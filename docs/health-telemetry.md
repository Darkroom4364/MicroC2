# Health, Readiness, and Runtime Telemetry

MicroC2 exposes a small machine-readable health surface on the operator
server so deployments and CI can detect degraded state without tailing logs.
All three endpoints are GET-only JSON routes on the operator mux, so they sit
behind the same operator guard as every other operator route: loopback
clients always pass, and non-loopback clients must present the configured
`X-Operator-Token` header. Local deployment checks and CI smoke tests run
over loopback and need no token.

The endpoints are deterministic and inexpensive by contract. They never spawn
builds, never make network calls, and never scan task payloads or agent
history; readiness is a single `SELECT 1`, and telemetry reads runtime
counters plus two constant-time `COUNT` aggregates per listener.

## Endpoints

### `GET /api/health` — liveness

Answers whenever the process can serve HTTP. Performs no I/O beyond encoding
the response.

```json
{"status": "ok", "uptime_seconds": 42}
```

Always returns `200` with `"status": "ok"`. If the process is wedged, the
request itself fails — that is the liveness signal.

### `GET /api/ready` — readiness

Reports whether the server's configured dependencies answer a trivial check.
Today the only check is durable storage.

```json
{"status": "ready", "checks": {"storage": "ok"}}
```

- `200` with `"status": "ready"` when every check passes.
- `503` with `"status": "not_ready"` when storage is `"unavailable"`.
- Storage is `"disabled"` when the server runs without a configured database;
  that is a valid, ready state for non-durable lab runs.

### `GET /api/telemetry` — runtime summary

Reports operator-server health plus per-listener runtime telemetry.

```json
{
  "status": "degraded",
  "generated_at": "2026-07-25T12:00:00Z",
  "uptime_seconds": 42,
  "storage": "ok",
  "listeners": [
    {
      "id": "…",
      "name": "…",
      "protocol": "https",
      "port": 8443,
      "status": "ACTIVE",
      "health": "degraded",
      "active_agents": 1,
      "queue_depth": 2,
      "recent_task_failures": 1,
      "recent_build_failures": 0
    }
  ],
  "builds": {"recent_failures": 1}
}
```

Always returns `200`; the `status` field carries the verdict. Per listener:

- `status` is the listener lifecycle state (`ACTIVE`, `STOPPED`, `ERROR`).
- `active_agents` counts agents that completed a heartbeat during this server
  process lifetime. Durable agent history loaded at startup does not count
  until the agent heartbeats again.
- `queue_depth` counts tasks `queued` or `dispatched` but not yet completed.
- `recent_task_failures` counts tasks that reached the failed terminal state
  inside the failure window (one hour, trailing).
- `recent_build_failures` counts payload builds in `failed` or `interrupted`
  state created inside the failure window. Completed builds whose artifacts
  later fail reconciliation (`missing`/`corrupt`) are not build failures.
- `last_error_class` appears only when the listener recorded an error and is
  one of `bind_failed`, `tls_config_invalid`, `runtime_error`, or
  `telemetry_unavailable`. Raw error strings are never exposed because they
  can embed certificate paths, bind addresses, and TLS library internals.

Responses never contain agent identifiers, filesystem paths, secrets,
tokens, or raw error internals — only listener identities (already visible on
`/api/listeners/list`), counts, and classified categories.

## Health semantics

Each listener and the server as a whole report one of three states:

- `healthy` — working as configured, no recent failure indicators.
- `degraded` — still serving, but recent task or build failures were recorded
  inside the failure window.
- `failing` — cannot serve its purpose right now.

Listener rules, evaluated in order:

1. Status `ERROR` → `failing`.
2. Listener runtime counters unreadable → `failing` with
   `last_error_class: "telemetry_unavailable"` (counters are not fabricated).
3. Status `ACTIVE` with `recent_task_failures > 0` or
   `recent_build_failures > 0` → `degraded`.
4. Otherwise → `healthy`. A `STOPPED` listener is a deliberate operator
   action and does not degrade the server, though its counters are still
   reported.

Server rules:

1. Storage `unavailable` → `failing`.
2. Otherwise the worst health across all listeners.

Because the failure window is trailing, a resolved incident stops degrading
the server once its failures age out — no operator action is required.

## Local deployment checks

With the server running locally on the default port:

```sh
curl -sk https://127.0.0.1:8443/api/health
curl -sk https://127.0.0.1:8443/api/ready
curl -sk https://127.0.0.1:8443/api/telemetry
```

From a non-loopback host, add the operator token:

```sh
curl -sk -H "X-Operator-Token: $MICROC2_OPERATOR_TOKEN" \
  https://operator-host:8443/api/ready
```

## CI smoke checks

A minimal smoke check starts the server with a test config and polls
readiness until storage answers, then asserts the telemetry contract:

```sh
# Wait for readiness (loopback needs no token).
until curl -skf https://127.0.0.1:8443/api/ready > /dev/null; do sleep 1; done

# Assert the telemetry envelope parses and reports a known state.
curl -skf https://127.0.0.1:8443/api/telemetry \
  | grep -q '"status":"healthy"'
```

Use the HTTP status code of `/api/ready` as the gate (it returns `503` until
ready) and the `status` field of `/api/telemetry` to assert healthy,
degraded, or failing semantics. `/api/health` is the right probe when only
process liveness matters, for example as a container `HEALTHCHECK`.
