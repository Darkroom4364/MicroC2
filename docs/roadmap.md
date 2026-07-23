# MicroC2 Roadmap

MicroC2 should grow into a serious research testbed for controlled C2, agent,
payload, and detection engineering. The quality target is not to clone any
commercial framework feature-for-feature, but to reach the same level of
coherence: reliable lifecycle behavior, strong operator workflows, documented
architecture, reproducible builds, durable evidence, and clear safety controls.

This roadmap treats MicroC2 as an academic and defensive research platform for
authorized lab environments.

## Product Principles

- Build stable foundations before adding advanced capabilities.
- Prefer typed tasks, structured results, and durable evidence over raw command
  strings and ad hoc logs.
- Keep risky actions explicit, scoped, audited, and disabled by default where
  possible.
- Treat the web UI, API, server, and agent as one product surface.
- Keep extension points narrow and documented before adding more protocols.
- Preserve reproducibility: every important workflow should have a local test,
  scripted check, or documented manual verification path.

## Quality Bar

A mature MicroC2 release should provide:

- Reliable listener, agent, file, task, and pivot lifecycle management.
- Clear operator workflows for setup, tasking, results, payload generation, and
  session review.
- A typed command/task model with stable JSON schemas.
- Transport abstractions that support multiple channels without duplicating
  lifecycle logic.
- Durable storage for agents, tasks, results, files, events, and audit records.
- A test suite and CI baseline that blocks regressions in server and agent code.
- Documentation good enough for a new researcher to build, run, test, and
  safely extend the framework.

## Long-Term North Star

The long-term ambition is for MicroC2 to feel as feature-rich and polished as a
high-end commercial C2 framework, while remaining a transparent academic
research platform. In practice, that means MicroC2 should eventually provide the
same kind of end-to-end completeness:

- A polished multi-user operator console.
- Clear separation between management, C2, redirector, and agent surfaces.
- Rich payload generation with reproducible build profiles.
- Multiple configurable communication channels.
- Peer-to-peer and pivot workflows that are visible as a network graph.
- A typed task/module system instead of raw command strings.
- Automation APIs and event hooks for research workflows.
- Durable audit logs, evidence bundles, and reporting.
- ATT&CK mapping and detection engineering views.
- Strong release hygiene, docs, tests, and upgrade paths.

This is a multi-year target. The first releases should not try to match every
advanced feature. They should build the foundations that make those features
possible without turning the project into another prototype.

Long-term maturity tracks:

- **Operator Console**: dashboards, agent graph, listener health, task queues,
  artifacts, timelines, reporting, dark/light themes, and keyboard-friendly
  workflows.
- **Agent And Tasking**: typed tasks, typed results, cancellation, timeouts,
  retries, permissions, module metadata, and cross-platform test coverage.
- **Payload Lab**: reproducible builds, profile presets, artifact formats,
  signing metadata where applicable, config validation, and build provenance.
- **Transport Lab**: configurable HTTP(S), SOCKS/pivoting, peer-to-peer links,
  profile validation, redirector-aware deployment notes, and transport
  observability.
- **Automation Platform**: stable API, WebSocket events, scripting hooks,
  import/export, and integration points for defensive tooling.
- **Evidence And Detection**: structured session bundles, ATT&CK mapping,
  indicators, telemetry export, and repeatable lab scenario comparison.
- **Safety And Governance**: auth, roles, target scoping, risk metadata,
  explicit confirmations, audit trails, and safe defaults for lab use.
- **Release Engineering**: CI, regression tests, signed releases where
  practical, changelogs, migration notes, and reproducible development setup.

## Phase 0: Stabilize The Prototype

Goal: make the current codebase predictable enough to build on.

Focus areas:

- Fix listener lifecycle, stop/start/delete behavior, and placeholder protocol
  code.
- Add baseline CI for Go server tests/builds and Rust agent checks/builds.
- Separate operator UI/API surfaces from agent-facing endpoints.
- Replace silent failures and fatal process exits with structured errors.
- Add basic auth and local-lab safety defaults before exposing richer operator
  features.
- Populate architecture, design, and roadmap documentation from the thesis and
  current implementation.

Exit criteria:

- `go test ./...` passes in `server/`.
- Rust agent builds reproducibly in the documented local environment.
- Listener create/start/stop/delete is covered by tests.
- The README points to usable architecture, development, and safety docs.

Candidate issues:

- #86 `[Server] Fix listener lifecycle and remove placeholder protocol code` (complete)
- #85 `[CI] Add baseline Go/Rust build and test checks` (complete)
- #89 `[CI] Make format and Foxguard baseline checks blocking` (complete)
- #87 `[Docs] Populate architecture, design, and roadmap docs from thesis/current code` (complete)
- #75 `[Server] Separate UI and agent API endpoints` (complete)
- #78 `[Security] Fix lab-safety and hardening bugs` (complete)

## Phase 1: Make Operations Coherent

Goal: make everyday operator workflows feel like one integrated product.

Focus areas:

- Define a typed task model for shell, file transfer, pivot control, heartbeat,
  and future module tasks.
- Replace raw string-only tasking as the primary API.
- Store agents, tasks, results, files, listener events, and audit records
  durably.
- Build a consistent UI flow for agents, tasking, results, files, listeners,
  payloads, and logs.
- Add task status transitions: queued, dispatched, running, completed, failed,
  cancelled, expired.
- Add result schemas and evidence bundles that can be exported for research
  reporting.

Exit criteria:

- An operator can create a listener, build an agent, receive a heartbeat, run a
  typed task, inspect results, and export session evidence from the UI.
- File transfer and pivot controls are integrated into task dispatch instead of
  living as disconnected code paths.
- Server restart does not erase critical session history.

Candidate issues:

- #98 `[Server/Agent] Replace raw string command dispatch with typed task and
  result schemas` — shell task contract v1, bounded summary pages, and
  on-demand full results are the Phase 1 foundation.
- #104 `[Security] Bind agent tasking to authenticated enrollment sessions` —
  P0 gate before task listeners are exposed beyond an isolated lab.
- #97 `[Server] Add durable storage for agents, tasks, results, payloads, and
  listener events`
- #100 `[Server] Add structured audit events for operator actions and agent
  tasking`
- #88 `[Agent] Wire file transfer and pivot controls into command dispatch` —
  extend the typed contract only after #98.
- #65 `[Agent] Configuration System extension`
- #64 `[ID Parsing and Agent Generation]` (complete)

## Phase 2: Transport And Pivot Maturity

Goal: make communication channels and pivots modular, testable, and observable.

Focus areas:

- Define a shared transport interface for agent C2 channels.
- Make HTTP(S) polling the reference implementation with complete lifecycle
  tests.
- Harden SOCKS5 and reverse tunnel behavior with clear ownership between agent
  and server.
- Add transport profiles for jitter, working hours, host rotation, kill date,
  retry policy, and proxy awareness.
- Add network and listener telemetry suitable for detection engineering.
- Keep new transport work scoped behind explicit configuration and tests.

Exit criteria:

- HTTP(S) polling and SOCKS/pivot flows are covered by integration tests.
- Transport profiles are represented as validated config, not scattered fields.
- The UI can show listener health, connected agents, task latency, and recent
  transport errors.

Candidate issues:

- #71 `[Agent] - SOCKSv5 capability implementation completion`
- #74 `[Agent] - Host Rotation`

## Phase 3: Payload Build And Agent Quality

Goal: make payload generation reliable, reproducible, and research-friendly.

Focus areas:

- Make payload build configuration explicit and versioned.
- Support repeatable local builds for Linux, Windows, and macOS targets where
  practical.
- Add build metadata and provenance to generated payloads.
- Reduce unnecessary dependencies and feature-gate optional capabilities.
- Add agent self-checks for config parsing, task dispatch, and networking.
- Keep advanced OPSEC research behind documented, opt-in lab flags.

Exit criteria:

- Payload builds are reproducible from documented commands.
- Optional agent features can be enabled without bloating the default agent.
- Agent command dispatch is testable without live C2 infrastructure.

Candidate issues:

- #99 `[Payload] Validate build options and record build provenance` — partial,
  P1. Seed provenance landed, but the supported build matrix, fail-fast option
  validation, canonical artifact path, and complete inspectable manifest remain.
- #79 `[Agent] Reduce dependencies as much as possible`
- #67 `[Agent] - Source-Level Mutation Engine (Phase 1)` — v0 landed: seeded
  mutation (`MUTATION_SEED`) covering the config XOR key, a junk-code module,
  and surface strings, with build provenance recorded per payload (see
  `docs/research/r1-mutation-engine.md`). Next axes: behavioral/transport
  mutation via the Phase 2 transport profiles.
- #66 `[Agent] - Selective Encryption routine`

## Phase 4: Extensibility And Research Modules

Goal: let MicroC2 grow without turning the core into a pile of special cases.

Focus areas:

- Define a plugin/module boundary for server-side tools and agent-side tasks.
- Add stable schemas for module inputs, outputs, permissions, and evidence.
- Build a small module SDK or examples before adding many modules.
- Consider read-only integrations with sibling research tools, such as BACillus,
  through structured evidence rather than repo mergers.
- Add ATT&CK mapping and tags at the task/module level for reporting and
  detection work.

Exit criteria:

- A new module can be added without changing the core task/result pipeline.
- Module results are visible in the UI and exportable in reports.
- Risky module classes require explicit safety metadata and operator
  confirmation.

Candidate issues:

- #73 `[Agent] - Beacon Object File (BOF) support`

## Phase 5: Research-Grade Reporting And Detection

Goal: make MicroC2 useful not only for running experiments, but for analyzing
and explaining them.

Focus areas:

- Export session reports with agents, tasks, timelines, files, listener events,
  and evidence.
- Add ATT&CK technique mapping and custom research tags.
- Add detection-oriented telemetry views: network profile, task timing, file
  operations, and operator actions.
- Add reproducible lab scenarios and baseline runs.
- Document known indicators and defensive observations for each transport and
  task family.

Exit criteria:

- A completed lab run can produce a report suitable for thesis, blue-team, or
  detection engineering review.
- Important actions have timestamps, actor identity, target scope, and evidence.
- The project can compare behavior across releases.

## Backlog: Advanced Research

These items are valuable, but should wait until the core is stable and audited:

- Additional transport channels.
- Advanced payload packaging formats.
- BOF-style extensibility.
- OPSEC mutation research beyond the Research Program tracks (see above).
- Cross-platform in-memory execution research.
- Automated scenario orchestration.
- Optional OT/BACnet assessment bridge through BACillus evidence bundles.

## Phase 6: Full-Featured Research Platform

Goal: converge the maturity tracks into a framework that is broad, polished,
and pleasant to operate in real research exercises.

Focus areas:

- Multi-user operations with roles, workspaces, and audit history.
- First-class automation API and event stream.
- A module catalog with stable compatibility metadata.
- Payload profile library with repeatable builds and test fixtures.
- Transport profile library with validation and detection notes.
- Rich reporting and timeline reconstruction.
- Scenario templates for reproducible lab exercises.
- Long-running stability tests for agents, listeners, pivots, and UI sessions.

Exit criteria:

- MicroC2 can support a complete authorized research exercise from setup to
  report without manual database edits, ad hoc scripts, or undocumented steps.
- A new operator can understand the workflow from docs and the UI alone.
- A developer can add a module, transport, or payload profile through documented
  extension points.
- Releases can be compared by test results, scenario outputs, and documented
  behavior changes.

## Research Program: Reproducible Evasion Measurement

Positioning from a literature scan (July 2026, arXiv/USENIX/IEEE S&P/CCS/NDSS):
static evasion against ML classifiers is saturated (Adversarial EXEmples
lineage, GAMMA, MAB-Malware, LLM-driven mutation such as LLMalMorph
2507.09411), and C2 traffic *detection* is big-lab foundation-model territory.
The open gap is measurement infrastructure: nobody has published a seeded,
reproducible, source-level mutation of a *live* agent measured against
behavioral EDR telemetry with detection-engineering output. That gap is
exactly MicroC2's shape.

Differentiation against the closest prior art:

- ShellForge (arXiv:2607.07191, July 2026) benchmarks GA-evolved *shellcode*
  variants against AV/EDR. MicroC2's angle is source-level mutation of a full
  agent, seeded and reproducible, measurement-first, with open artifacts.
- A GOAD-based EDR testbed (arXiv:2606.08168) measures commercial EDR under
  autonomous configuration, but without per-build payload diversity or seeds.
- An MCP-based LLM C2 (arXiv:2511.15998) claims a reduced detection surface
  for agentic C2, but the claim is unmeasured.

Publication posture: this space is moving fast and partially scooped already.
Publish benchmark methodology, seeds, and datasets early; being open and
measurement-first is the moat, not any single evasion trick.

Research tracks:

- **R1: Mutation engine as a measurement instrument** (extends #67, Phase 3).
  Reframe the source-level mutation engine from an evasion feature into a
  benchmark: N seeded builds of functionally identical agents, detection
  *distributions* across EDR products, and per-telemetry-channel attribution
  (Sysmon/ETW ground truth vs. EDR verdict). Includes a cross-layer ablation:
  static-only vs. behavioral-only vs. transport-only mutation, attributing
  which detector layer each axis moves. Every mutation decision derives from
  one per-build seed recorded in build provenance, so any payload is
  reproducible from (source revision, seed) — this resolves the tension
  between Phase 3 reproducibility and mutation.
- **R2: LLMjacking emulation module** (Phase 4 module SDK). No academic
  baseline exists for AI-compute monetization ("LLMjacking"; industry-only
  reporting from Sysdig, Microsoft, Permiso). Build a module that emulates the
  kill chain endpoint-side in the lab: planted honeytoken LLM API keys, model
  enumeration, inference proxied through the C2 to a local model, ORP-style
  traffic under transport profiles. Measure which EDR products detect each
  stage; credential theft is well covered, monetization behavior almost
  certainly is not. Directly answers the "AI-as-a-service botnet" question
  with a citable detection baseline.
- **R3: LLM-in-the-loop transport controller** (Phase 2 transport profiles).
  An LLM policy layer that selects jitter, working hours, host rotation, and
  transport per beacon, evaluated against fixed malleable profiles under real
  EDR/NDR. The contribution is the measurement, not the agent: does adaptive
  tasking actually beat static profiles?
- **R4: Longitudinal EDR drift dataset** (CI byproduct). Freeze a payload
  suite and re-run it against auto-updating EDR versions over months; publish
  the drift dataset. Near-zero marginal cost once R1 exists.

Track dependencies:

- R1 needs Phase 3 build provenance and Phase 5 reporting/telemetry views.
- R2 needs the Phase 4 module SDK and its safety metadata.
- R3 needs Phase 2 transport profiles as validated config.
- R4 needs Phase 0 CI plus R1's frozen build artifacts.

Explicit non-goals (saturated, skip): new byte-level attacks on static ML
classifiers, LLM pentest agents, LLM phishing generation, DoH/DNS tunnel
detection, Internet-scale botnet market measurement.

## Near-Term Order

Recommended next sequence:

1. Finish #98 so shell tasking uses the versioned, retry-safe typed task/result
   contract end to end.
2. Complete #104 before any promotion beyond an isolated lab, binding agent
   tasking to authenticated enrollment sessions.
3. Build #97 on the typed contract so agents, task lifecycles, results, payload
   metadata, and listener events survive restart.
4. Add #100 on the durable model so operator and agent actions have causal,
   reviewable audit events.
5. Tackle #88 after #98, adding file transfer and pivot operations as explicit
   task types instead of new string commands.

The data path is **#98 → #97 → #100**. Issue #104 is a parallel P0 security
gate before promotion, and #99 remains a bounded P1 payload-quality track that
can proceed alongside it.
