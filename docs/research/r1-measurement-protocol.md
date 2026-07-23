# R1 Measurement Protocol: Detection Distributions Across EDR Slots

Status: scaffolded, not yet executed. Companion to `r1-mutation-engine.md`
(which defines the build instrument) and `lab/` (which defines the artifacts
and manifest format). Lab use only.

This protocol measures, for a fixed source revision, the detection
*distribution* of N seeded, functionally identical agent builds against M
EDR products, with per-telemetry-channel attribution (Sysmon/ETW ground
truth vs. EDR verdict). It produces no evasion claims about single builds;
the unit of analysis is the distribution over seeds per EDR slot.

## 1. Lab matrix

The matrix is N seeds × M EDR slots. N and M are study parameters; a
minimum-viable run is N=20, M=2. EDR products are never hard-coded in
tooling — they are configurable **slots**:

| Slot id | Product | Version / engine | Signatures date | VM name | Snapshot |
|---------|---------|------------------|-----------------|---------|----------|
| slot-a  | TBD     | TBD              | TBD             | TBD     | TBD      |
| slot-b  | TBD     | TBD              | TBD             | TBD     | TBD      |

Fill the slot table before the run and record it in the manifest notes.
"Signatures date" matters: EDR verdicts are a function of the content
update level, not just the product version, and R4 (longitudinal drift)
depends on recording it.

### Windows VM baseline (per slot)

- Windows 10/11 22H2 (or later), fully patched at matrix freeze time;
  patch level recorded once per study.
- Sysmon installed with `lab/sysmon/sysmonconfig.xml`
  (`sysmon64.exe -i sysmonconfig.xml`). Same Sysmon binary version across
  slots.
- One EDR product per VM, default/recommended configuration, cloud lookup
  enabled **only if** it does not require internet egress from the
  detonation VM (see §6); otherwise cloud features disabled and this
  recorded in the manifest notes.
- Windows Defender state recorded (enabled/removed/disabled) — it is a
  confound if it varies across slots.
- Agent execution account: standard user, non-admin, unless the study
  explicitly varies privilege.
- Clean snapshot ("baseline") taken after all of the above, before any
  payload touches the disk.

### Snapshot / revert cycle

1. Revert VM to baseline snapshot.
2. Boot, wait for EDR service + Sysmon to report healthy.
3. Execute exactly one cell (one seed, one slot).
4. Collect evidence (§4), power off or pause.
5. Revert to baseline before the next cell.

Never run two cells against the same booted state. Snapshot hygiene is the
only thing standing between a detection distribution and contamination from
prior-run artifacts (quarantine entries, EDR learning caches, USN journal).

## 2. Build side (operator host, outside the lab)

Builds happen on the operator host, never inside the lab:

```bash
lab/build_matrix.sh --count 20 --output-dir lab/runs/<study-id> \
  --target x86_64-pc-windows-gnu --base-seed <hex>
```

This produces one directory per seed containing the payload and (for
server-driven builds) `provenance.json`, plus a `manifest.json` skeleton
with build-side fields filled. Record the git revision once per study; all
cells must build from the same revision.

## 3. Run steps per (seed, EDR) cell

Per cell, in order:

1. Revert the slot's VM to baseline; boot; verify EDR and Sysmon healthy.
2. Note wall-clock start time (UTC). Start ETW capture if the study
   includes it (see §4).
3. Transfer the payload for this seed onto the VM via the lab-internal
   share only. Record transfer time.
4. Execute the payload as the standard user. Do not re-execute if the
   first launch fails — record the failure in notes and mark the verdict
   `unknown` unless the failure was EDR-mediated (then `detected`).
5. Let the agent dwell for the configured dwell time (§5). Issue the fixed
   tasking script from the C2 server (also lab-internal).
6. At dwell end: stop ETW capture, export the Sysmon log, export the EDR
   console alerts, pull the agent network log from the C2 side.
7. Record the EDR verdict and alert names in the manifest cell.
8. Power off; revert to baseline.

One operator action per step, in order, every time — deviations go in
`notes`, not in memory.

## 4. Evidence captured per cell

| Channel | Artifact | Purpose |
|---------|----------|---------|
| EDR verdict | `detected` / `not-detected` / `unknown` in manifest | The measured outcome |
| EDR alerts | Alert names + console export (JSON/CSV/PDF) | Attribution: which engine fired (static, behavioral, reputation, cloud) |
| Sysmon | `.evtx` export of `Microsoft-Windows-Sysmon/Operational` | Ground truth: did the behavior actually happen (process, network, DNS, file, registry) |
| ETW | `.etl` trace (e.g., `logman`/`wpr` with Microsoft-Windows-Kernel-* providers), where the study includes it | Ground truth below Sysmon; catches AMSI/ETW-tamper visibility gaps |
| Agent network log | C2 server log for the payload_id (beacon times, tasks issued, responses) | Confirms functional equivalence: the variant actually beaconed and executed the tasking script |
| Static scan | Pre-run on-demand scan verdict of the payload file (optional per study) | Separates static from behavioral detection |

File references go into the cell's `telemetry` object in the manifest.
Naming convention: `<study-id>/<slot-id>/<seed>/<channel>.<ext>`.

Verdict rules:

- `detected` — the EDR raised any alert, block, or quarantine action
  attributable to the payload or its behavior during the cell window.
- `not-detected` — the full dwell + tasking script completed with no
  EDR action and Sysmon ground truth confirms the behavior occurred.
- `unknown` — the cell is invalid (agent failed to run, Sysmon shows no
  activity, evidence incomplete). Unknown cells are excluded from the
  detection-rate denominator but kept in the manifest.

If the EDR blocks at write/scan time (static) vs. during execution
(behavioral), that distinction goes in `alert_names`/`notes` — the
cross-layer ablation (R1 track) depends on it.

## 5. Timing and tasking

- **Dwell time**: fixed per study, default 10 minutes. Detection latency
  is part of the measurement, so dwell must be identical across cells.
- **Tasking script**: fixed sequence issued from the C2 server, e.g.
  `T+60s: sysinfo; T+120s: ls <dir>; T+180s: download; T+300s: sleep`.
  Same script for every cell; it defines "functionally identical" at the
  behavioral level. The exact script is a study parameter, recorded in
  notes.
- **Beacon profile**: fixed sleep/jitter across all builds (the mutation
  engine varies surface artifacts, not behavior — see
  `r1-mutation-engine.md` v0 scope).
- All timestamps in the manifest are UTC RFC 3339.

## 6. Safety rules

- The lab is an isolated network segment (host-only or dedicated VLAN with
  no route out). No internet egress from detonation VMs — block at the
  hypervisor/virtual-switch level, not just by host firewall.
- EDR cloud lookups either proxied through a controlled, logged relay or
  disabled; never direct egress. Record which per slot.
- Payloads leave the operator host only into the isolated lab. Payloads
  are never executed on the operator host or outside the detonation VMs.
- Snapshots: baseline snapshot is never taken after a payload has touched
  the VM; revert after every cell, including failed/unknown cells.
- The C2 server for lab runs binds only to the lab segment.
- No real third-party data on detonation VMs; any credentials present are
  lab canaries.
- MicroC2 is an academic research testbed; all of the above assumes
  authorization for the lab environment.

## 7. Analysis (future)

Analysis tooling is out of scope for this scaffold. The manifest is the
interface: per slot, the detection rate over seeds with a binomial
confidence interval; per cell, cross-tab of EDR verdict against Sysmon
channel coverage to attribute which telemetry channel carried the signal
that preceded the verdict. Anything beyond that (ablation comparisons,
drift over time for R4) consumes the same manifest format.
