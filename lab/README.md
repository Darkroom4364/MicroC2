# MicroC2 R1 Lab Harness

Tooling and formats for the R1 research track: measuring detection
*distributions* of N seeded, functionally identical agent builds against M
EDR products, with per-telemetry-channel attribution (Sysmon/ETW ground
truth vs. EDR verdict). Authorized lab use only.

This directory contains scaffolding only. No EDR execution happens on the
operator host; payloads are detonated exclusively inside the isolated lab.

## Pieces

- `build_matrix.sh` — builds N seeded variants via `agent/build.sh
  --mutation-seed`, one `seed_<hex>/` directory per variant, and writes a
  `manifest.json` skeleton with build-side fields (seed, git revision,
  artifact path, sha256) already filled.
- `manifest.schema.json` / `manifest.example.json` — the run-manifest
  contract: one JSON array of (seed, EDR slot) cells, each carrying build
  provenance, the EDR verdict, alert names, and references to telemetry
  files. `build_matrix.sh` output conforms to the schema with
  verdict/telemetry fields left as placeholders.
- `sysmon/sysmonconfig.xml` — the Sysmon configuration installed on every
  detonation VM (process creation, network, image loads, file creation,
  registry, DNS), i.e. the ground-truth channel.
- `../docs/research/r1-measurement-protocol.md` — the run protocol: lab
  matrix, VM baseline, snapshot/revert cycle, per-cell run steps, evidence,
  timing, safety rules. **Read it before running any cell.**

## Workflow

1. **Build matrix (operator host).**

   ```bash
   lab/build_matrix.sh --count 20 --output-dir lab/runs/<study-id> \
     --target x86_64-pc-windows-gnu --base-seed <hex> \
     --listener-host <lab-c2-ip> --listener-port 8443 --study-id <study-id>
   ```

   Without `--base-seed` a fixed default is used; without `--count` you can
   pass an explicit `--seeds "h1 h2 ..."` list. Seeds are derived
   deterministically and printed, so the matrix is reproducible.

2. **Copy to lab.** Transfer the whole output directory (payloads +
   `manifest.json`) into the isolated lab over the lab-internal share only.

3. **Prepare VMs.** One VM per EDR slot; install Sysmon with
   `sysmon/sysmonconfig.xml`; install/configure the EDR; take the baseline
   snapshot. Fill the slot table in the protocol doc.

4. **Execute per protocol.** For each (seed, EDR slot) cell: revert to
   baseline, boot, transfer that seed's payload, execute, dwell, run the
   fixed tasking script, collect evidence, revert. One cell per booted
   state.

5. **Collect evidence.** Per cell: Sysmon `.evtx` export, ETW `.etl` (if
   captured), EDR console export, C2-side agent network log. Store under
   `<study-id>/<slot-id>/<seed>/`.

6. **Fill the manifest.** For each cell, set `edr.product`/`version`,
   run timestamps, `verdict` (`detected` / `not-detected` / `unknown`),
   `alert_names`, telemetry paths, and notes. Validate against
   `manifest.schema.json`.

7. **Analysis (future).** Per-slot detection rates over seeds with
   confidence intervals, and verdict-vs-telemetry-channel attribution, all
   consuming the manifest format. Not part of this scaffold.
