# MicroC2 R1 Lab Harness

Tooling and formats for the R1 research track: measuring detection
*distributions* of N seeded, functionally identical agent builds against M
EDR products, with per-telemetry-channel attribution (Sysmon/ETW ground
truth vs. EDR verdict). Authorized lab use only.

This directory contains scaffolding only. No EDR execution happens on the
operator host; payloads are detonated exclusively inside the isolated lab.

## Pieces

- `build_matrix.sh` — builds N standalone seeded variants via
  `agent/build.sh --mutation-seed`, one `seed_<hex>/` directory per variant,
  and writes a `manifest.json` skeleton with build-side fields (seed, git
  revision, artifact path, SHA-256, and enrollment status) already filled.
  Each cell receives a fresh in-memory build credential, but the script does
  not activate its hash in the server database. These artifacts therefore set
  `server_enrolled: false` and cannot perform authenticated beaconing or
  tasking.
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
     --listener-host <lab-c2-ip> --listener-port 8443 --protocol https \
     --study-id <study-id>
   ```

   Without `--base-seed` a fixed default is used; without `--count` you can
   pass an explicit `--seeds "h1 h2 ..."` list. Seeds are derived
   deterministically and printed, so the seed schedule is reproducible.
   Full artifact bytes are not reproducible from source revision and seed
   alone: every cell also receives fresh enrollment material and depends on
   the complete resolved configuration, toolchain, target, and build
   environment.

   HTTPS is the default and requires a certificate trusted by the detonation
   VM. Passing `--protocol http` is an explicit isolated-lab choice; the
   script then enables the agent's `ALLOW_INSECURE_ISOLATED_LAB` build gate.

   The generated credential is embedded only in its payload. It is never
   printed or added to `manifest.json`/`provenance.json`. Use a fresh output
   directory for each build; the script refuses to reuse a non-empty seed
   directory so stale artifacts or provenance cannot be attached to a new
   credential.

   For a study that needs live C2 beaconing or tasking, generate each payload
   through the MicroC2 server with the desired `mutation_seed`, then copy the
   resulting artifact and non-secret provenance into the corresponding cell
   directory and set `artifact.server_enrolled` to `true`. Only the server
   build transaction persists the credential hash and binds it to the payload
   build and listener. Merely pointing a standalone matrix build at a running
   listener does not enroll it.

2. **Copy to lab.** Transfer the whole output directory (payloads +
   `manifest.json`) into the isolated lab over the lab-internal share only.

3. **Prepare VMs.** One VM per EDR slot; install Sysmon with
   `sysmon/sysmonconfig.xml`; install/configure the EDR; take the baseline
   snapshot. Fill the slot table in the protocol doc.

4. **Execute per protocol.** For each (seed, EDR slot) cell: revert to
   baseline, boot, transfer that seed's payload, execute, dwell, collect
   evidence, and revert. Run the fixed C2 tasking script only for artifacts
   marked `server_enrolled: true`. One cell per booted state.

5. **Collect evidence.** Per cell: Sysmon `.evtx` export, ETW `.etl` (if
   captured), and EDR console export. Include a C2-side agent network log only
   for server-enrolled cells. Store under `<study-id>/<slot-id>/<seed>/`.

6. **Fill the manifest.** For each cell, set `edr.product`/`version`,
   run timestamps, `verdict` (`detected` / `not-detected` / `unknown`),
   `alert_names`, telemetry paths, and notes. Validate against
   `manifest.schema.json`.

7. **Analysis (future).** Per-slot detection rates over seeds with
   confidence intervals, and verdict-vs-telemetry-channel attribution, all
   consuming the manifest format. Not part of this scaffold.
