# R1: Seeded Source Mutation Engine (Milestone 0)

Status: v0 landed (issues #67 phase 1 scope, #99). Lab use only.

## Threat model

MicroC2 is an academic C2 research testbed for authorized lab environments.
The mutation engine exists to build a **measurement instrument**: N seeded,
functionally identical agent builds whose detection *distributions* can be
measured against EDR products under controlled conditions. It is not an
evasion feature; every artifact carries the provenance needed to reproduce it.

Scope boundaries for v0:

- Mutations are functionality-preserving: the agent protocol, routes, and
  behavior are unchanged. Only build-time surface artifacts vary.
- Builds happen on the operator host; mutated payloads are executed only
  inside the isolated analysis lab.

## The seed

One hex u64, `MUTATION_SEED`, drives every mutation decision via a
hand-rolled splitmix64 PRNG in `agent/build.rs` (no external dependencies).
Resolution order:

1. Server-driven builds: `payload_handler.go` generates a random seed per
   payload (or honors a caller-supplied `mutation_seed` in the generate
   request for reproduction builds) and exports it to `build.sh`.
2. Manual builds: pass `--mutation-seed <hex>` to `agent/build.sh` or export
   `MUTATION_SEED` before invoking cargo.
3. Unset: `build.rs` falls back to a fixed dev seed with a `cargo:warning`,
   so existing fixtures and CI keep working unchanged.

### v0 mutation axes

- **Random config XOR key** — the embedded config is obfuscated with a
  seed-derived random key, replacing the previous payload_id-derived key
  (which was known to the server and reused as key material).
- **Junk-code module** — `build.rs` generates `OUT_DIR/mutation.rs` with
  seed-derived decoy functions, random string constants, and a random-length
  padding blob. The agent references `mutation::mutation_entry()` once via
  `std::hint::black_box` so LLVM cannot strip it. This guarantees a unique
  binary layout/hash per seed and breaks byte-level clustering across builds.
- **Surface strings** — a seed-selected user-agent from a curated pool is
  written into the embedded config (and used by the agent's HTTP client).
  Randomized endpoint path segments are recorded in the embedded config as
  `mutation_endpoint_segments` but are **not consumed by the v0 agent** —
  server routes are fixed, so wiring them belongs to the Phase 2 transport
  profiles. They are recorded now so the provenance story is complete.

The agent reports its own seed at startup (debug log) via
`MUTATION_SEED_USED`, emitted by the build script.

## Provenance

Every server-driven build writes `provenance.json` next to the artifact:

```json
{
  "mutation_seed": "0123456789abcdef",
  "seed_generated_by_server": true,
  "git_revision": "<commit>",
  "target": "x86_64-unknown-linux-gnu",
  "built_at": "<RFC3339>",
  "config_sha256": "<sha256 of resolved agent config>",
  "mutation_flags": ["config-xor-key", "junk-code", "surface-strings"]
}
```

The seed is also returned in the payload API result (`mutation_seed`) and
shown in the payload UI log.

## Reproduction recipe

Any payload is reproducible from (source revision, seed):

```bash
git checkout <git_revision from provenance.json>
cd agent
MUTATION_SEED=<mutation_seed> ./build.sh \
  --target <target> --output out --build-type release \
  --listener-host <host> --listener-port <port> --protocol <proto>
```

Same seed + same revision produces byte-identical generated sources
(`config.rs`, `mutation.rs`) and, on the same host, an identical binary.
Cross-host byte identity is not asserted (linkers differ). Verify locally
with:

```bash
agent/check_mutation_determinism.sh
```

which asserts same-seed source identity and different-seed source/binary
divergence. It runs in CI as part of the agent job.

## Planned measurement protocol (next milestone)

The instrument above exists to run this experiment:

1. Generate **N** payloads with distinct seeds from one source revision
   (functionally identical agents, distinct binaries).
2. Detonate each against **M** EDR products in the isolated lab; capture the
   EDR verdict plus independent ground truth (Sysmon/ETW telemetry).
3. Report detection *distributions*, not single verdicts, and attribute
   signal per telemetry channel (EDR verdict vs. Sysmon ground truth).
4. Cross-layer ablation: static-only (junk code, XOR key) vs.
   behavioral-only vs. transport-only mutation, to attribute which detector
   layer each axis moves.

N, M, and the telemetry collection harness are out of scope for v0; they
land with the EDR lab matrix milestone.

> Update: the measurement harness is now scaffolded. The run protocol lives
> in `docs/research/r1-measurement-protocol.md`; build-matrix tooling, the
> run-manifest schema, and the lab Sysmon config live in `lab/` (see
> `lab/README.md`). No live EDR execution exists yet — the scaffold defines
> formats and procedures only.
