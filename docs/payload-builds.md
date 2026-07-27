# Payload Build Contract

MicroC2 payload generation accepts a deliberately small, explicit build
matrix. Requests outside this matrix fail validation before listener lookup,
credential generation, durable build creation, filesystem changes, or build
script execution.

## Supported Profiles

| Target OS | Architecture | Format | Rust target triple | Artifact |
| --- | --- | --- | --- | --- |
| Linux | `x64` | `linux_elf` | `x86_64-unknown-linux-gnu` | `agent` |
| Windows | `x64` | `windows_exe` | `x86_64-pc-windows-gnu` | `agent.exe` |

Both profiles support these build types:

| `agentType` request value | Build type |
| --- | --- |
| `agent` | `release` |
| `debugAgent` | `debug` |

The server returns a specific `400 Bad Request` validation error for an
unsupported or inconsistent profile. In particular, `x86` and `arm64`
architectures and Windows DLL, service, shellcode, Linux ARM, macOS dylib, and
Linux shared-object formats are not supported by the payload API.

The following options remain aspirational and are rejected when requested:

- indirect syscalls;
- custom sleep techniques (`standard` is the only supported technique);
- DLL sideloading, sideload DLL names, and export names;
- a standalone OPSEC enable profile (supported numeric settings remain
  individually configurable); and
- independently configured OPSEC exit thresholds.

Other fields are validated before the build. This includes a positive sleep
interval, a valid SOCKS5 host and port, bounded enrollment sessions,
non-negative duration and counter values, finite non-negative factors, and
OPSEC entry thresholds from 0 through 100 with the Reduced Activity threshold
strictly below the Full OPSEC threshold. An omitted SOCKS5 host and port resolve
to `127.0.0.1:9050`; an omitted sleep technique resolves to `standard`.

## Configuration resolution and fallback boundary

Payload requests are bounded to one JSON value and reject unknown fields. The
decoder preloads the existing OPSEC defaults (scan interval `300`, entry
thresholds `60`/`20`, durations `300`/`120`/`60`, reduced sleep `120`, and C2
values `5`, `1.1`, `0.9`, `3600`, and `2`) before decoding. Consequently,
omitted OPSEC settings receive those defaults, while explicit zero values
overwrite them and remain subject to validation. The resolver separately maps
an empty sleep technique to `standard`, an empty SOCKS5 host or zero port to
`127.0.0.1:9050`, and `max_sessions: 0` to one.

The request must identify a listener, select `agent` or `debugAgent`, select a
supported architecture/format pair, and provide a positive sleep interval. It
rejects unsupported profiles, indirect syscalls, custom sleep techniques, all
DLL-sideload fields, nonzero reserved OPSEC exit thresholds, and invalid
network or numeric ranges. The server, rather than the request, resolves the
authoritative listener endpoint and transport, creates the payload identity and
ephemeral enrollment credential, pins build jitter and transport-safety flags,
and generates a mutation seed when one is not supplied.

`build.rs` treats any nonempty member of `LISTENER_HOST`, `LISTENER_PORT`,
`SERVER_URL`, `LISTENER_ID`, `PAYLOAD_ID`, or `ENROLLMENT_CREDENTIAL` as
production input. That path requires the complete set, a canonical credential,
and a build nonce; it does not fill a partial production configuration from
fallback values. When none is present, the hardcoded development fallback has
blank server URL, listener and payload identities, and enrollment credential,
so it is unusable for a server connection or enrollment.

Resolved request values are embedded at build time. At startup, the agent
deobfuscates and validates that embedded configuration, then rejects any
runtime argument: runtime C2 URL overrides are disabled and require rebuilding
the payload for a different listener.

For a server build, `build.rs` removes `enrollment_credential` before exporting
the expected private per-build effective-config file. The server accepts that
file only when `payload_id`, `listener_id`, and `mutation_seed` match the build
and its `protocol` is independently `http` or `https`; it rejects both an
`enrollment_credential` field and the current credential bytes anywhere in the
JSON. The exact credential-free bytes are then published as `config.json` and
recorded with their digest in provenance. The raw credential is absent from
those files, API responses, and logs; enrollment state retains only its hash
and provenance records `server-generated-ephemeral`.

## Deterministic Output

Each accepted build publishes exactly one artifact beneath the configured
payload root:

```text
<debug|release>/<payload-id>/<agent|agent.exe>
```

This path is stored and returned with forward slashes relative to the payload
root. The build runs in private per-build staging and must produce the exact
expected filename. The server does not walk output directories or fall back to
alternate artifact locations.

The artifact directory also contains the resolved, non-secret `config.json`
and the mandatory `provenance.json` build manifest. A build cannot transition
to `completed` if the artifact or manifest cannot be published.

## Build Manifest

`provenance.json` uses schema
`microc2.payload-build-manifest.v1`. The same JSON document is stored in the
durable payload-build record. It contains:

- `schema_version`;
- `payload_id` and `listener_id`;
- `git_revision` and `source_state` (`clean`, `dirty`, or `unknown`);
- `target_os`, `architecture`, `target_triple`, `format`, and `build_type`;
- the exact embedded `effective_config` object after removal of the ephemeral
  enrollment credential, and its `config_sha256`;
- `artifact.path`, `artifact.filename`, `artifact.size`, and
  `artifact.sha256`;
- `created_at`;
- `mutation_seed`, `seed_generated_by_server`, and `mutation_flags`; and
- `enrollment_credential_source`.

The artifact path is always root-relative. SHA-256 values are lowercase
hexadecimal digests. The Rust build exports the sanitized effective
configuration from the same JSON object it embeds, so SOCKS state, normalized
numeric values, the mutation-selected user agent, and compiled mutation seed
cannot drift from the manifest. Mutation flags remain provenance metadata, not
inactive runtime configuration fields. The server refuses a build if the
effective-config export is missing, malformed, inconsistent with the build
identity, or contains credential material. The manifest decoder verifies its
schema, profile, relative path, effective-config digest, artifact digest shape,
and creation timestamp before the API serves it.

The successful generation response includes both an inline `manifest` and its
root-relative `manifest_url`. A persisted manifest can be inspected later:

```http
GET /api/payload/{payload-id}/manifest
```

The endpoint accepts no query parameters, returns
`Cache-Control: no-store`, and reports the durable state in
`X-MicroC2-Payload-State`. It returns `404` for an unknown build, `409` while a
build is incomplete, and `410` for invalid or inconsistent manifest metadata.

An artifact download includes:

```http
X-MicroC2-Artifact-SHA256: <64 lowercase hexadecimal characters>
Link: </api/payload/{payload-id}/manifest>; rel="describedby"; type="application/json"
```

The `Link` header is present only when the persisted manifest validates
against the durable artifact metadata.

## Reproducibility Boundary

The manifest records the source revision and state, normalized build profile,
effective non-secret configuration, and mutation seed. Those values explain
and reproduce the non-secret build and mutation choices.

They do not recreate a byte-identical production artifact. Every build embeds
a fresh, high-entropy enrollment bootstrap credential. The raw credential is
never written to `provenance.json`, `config.json`, API responses, or logs; only
its hash is retained in enrollment state. The manifest records
`enrollment_credential_source` as `server-generated-ephemeral` so this boundary
is explicit rather than implying byte-for-byte reproducibility.
