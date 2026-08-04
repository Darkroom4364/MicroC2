# Defensive Research Detection-Measurement Rubric

## Version and Immutability

- **Rubric ID**: `microc2-defensive-research-detection-measurement-rubric`
- **Rubric version**: `1.0.0`
- **Schema version**: `1`

This rubric is **immutable at its published version**. Any semantic change (dimension addition, removal, redefinition, or evidence-class change) requires a new exact version. Consumers pin by `rubric_id` + `rubric_version` and MUST NOT use ranges or implicit upgrades. The `schema_version` tracks the JSON Schema document version independently.

## Scope and Purpose

This rubric defines a versioned, evidence-only framework for interpreting saved or synthetic defensive observations across five dimensions. It is a **static measurement contract**, not an operational tool. It contains no products, executors, payloads, agents, tasking instructions, telemetry-capture mechanics, raw evidence, endpoints, commands, run instructions, ATT&CK mappings, task/module mappings, or evasion guidance.

### Distinction from the R1 Lab Scaffold

The R1 lab scaffold (`docs/research/r1-measurement-protocol.md`, `docs/research/r1-mutation-engine.md`) defines **operational** measurement procedures: how to configure, execute, and collect from measurement trials. This rubric defines the **interpretive** framework that governs how those collected observations are assessed and compared. The R1 scaffold produces observations; this rubric grades them.

### Distinction from the Defensive Research Categories Registry

The [defensive research categories registry](./defensive-research-categories.md) defines **what** evidence can be classified and under which categories. This rubric defines **how** classified evidence is measured and interpreted across dimensions. Each dimension pins a category reference to the registry, inheriting that category's allowed evidence classes and excluded surfaces.

## Five Dimensions

### 1. Provenance

**Category**: `integrity-metadata`

Provenance assesses the tamper-evidence and reproducibility properties of redacted observation artifacts by comparing structural metadata across measurement runs. It establishes whether observation metadata can be independently reconstructed and whether structural tampering would be detectable.

**Admissible evidence**: integrity-metadata (subset of the pinned category's allowed classes).

**Invalid handling**: Evidence with corrupt or unverifiable integrity metadata is rejected (reject-assessment).

**Unknown handling**: Missing provenance metadata is reported as unknown (report-as-unknown).

**Uncertainty**: A level with rationale is required for every provenance assessment.

**Comparability**: Provenance comparisons are valid only between measurement runs that share the same observation-artifact schema version. Cross-schema provenance comparisons require explicit normalisation.

### 2. Collection Coverage

**Category**: `coverage-summary`

Collection coverage summarises the defensive-surface coverage achieved by a set of synthetic control measurements, providing a gap-analysis baseline without enumerating individual collection points.

**Admissible evidence**: synthetic-control-summary (subset of the pinned category's allowed classes).

**Invalid handling**: Evidence with unresolvable surface identifiers is downgraded to unknown (downgrade-to-unknown).

**Unknown handling**: Gaps where data existence cannot be confirmed are reported as unknown (report-as-unknown).

**Uncertainty**: A level with rationale is required.

**Comparability**: Collection-coverage comparisons require the same defensive-surface inventory. Differing inventories demand a normalised coverage metric with explicit inventory mapping.

### 3. Validity

**Category**: `defensive-observation-summary`

Validity aggregates redacted sensor observations to identify whether observed patterns are consistent with the expected defensive-signal model. It determines whether the synthetic observation method produces measurements distinguishable from noise.

**Admissible evidence**: redacted-observation-summary (subset of the pinned category's allowed classes).

**Invalid handling**: Evidence that fails the validity threshold is rejected (reject-assessment).

**Unknown handling**: Dimensions with absent validity evidence are excluded from comparative analysis (exclude-from-comparison).

**Uncertainty**: A discrete level is required (level).

**Comparability**: Validity comparisons are valid only for measurements using identical synthetic-observation parameters.

### 4. Uncertainty

**Category**: `defensive-observation-summary`

Uncertainty characterises the quantification limits and confidence bounds of aggregate measurements, identifying systematic and random error sources that affect reliability without exposing raw collection data.

**Admissible evidence**: aggregate-measurement-summary (subset of the pinned category's allowed classes).

**Invalid handling**: Evidence with unquantifiable error bounds is downgraded to unknown (downgrade-to-unknown).

**Unknown handling**: Absent uncertainty characterisations are reported as unknown (report-as-unknown).

**Uncertainty**: A level with rationale is required for the uncertainty dimension itself (level-with-rationale).

**Comparability**: Uncertainty characterisations are valid for comparison only when the measurement protocol, sensor configuration, and aggregation method are held constant.

### 5. Missing / Unknown Data

**Category**: `coverage-summary`

Missing-unknown-data identifies and classifies observational gaps where expected defensive evidence is absent, incomplete, or cannot be confirmed. It distinguishes between known gaps (data expected but absent) and unknown gaps (data whose existence cannot be confirmed), establishing the completeness boundary of a measurement run.

**Admissible evidence**: aggregate-measurement-summary (subset of the pinned category's allowed classes).

**Invalid handling**: Evidence with indeterminate gap classification is downgraded to unknown (downgrade-to-unknown).

**Unknown handling**: This dimension MUST use `report-as-unknown`. Unknown gaps are the dimension's subject matter and cannot be excluded from analysis.

**Uncertainty**: A level with rationale is required (level-with-rationale).

**Comparability**: Missing-unknown-data comparisons require identical surface inventories and observation expectations. Normalise to a common surface inventory before comparison.

## Admissible Evidence

Evidence is admissible for a dimension only when:

1. It belongs to an evidence class listed in that dimension's `admissible_evidence_classes`.
2. That evidence class is a subset of the pinned category's `allowed_evidence_classes` in the defensive research categories registry.
3. All surfaces enumerated in the pinned category's `excluded_surfaces` are absent from the evidence.

Evidence that does not meet these criteria is invalid and handled according to the dimension's `invalid_handling` policy.

## Invalid vs Unknown Semantics

- **Invalid evidence**: Evidence that is present but known to be corrupt, unverifiable, or out-of-scope for the dimension. Handled by `reject-assessment` (the observation must not contribute) or `downgrade-to-unknown` (reclassified as unknown).
- **Unknown evidence**: Evidence whose existence, completeness, or provenance cannot be confirmed. Handled by `report-as-unknown` (the absence is recorded) or `exclude-from-comparison` (the dimension is omitted from comparative analysis).

Invalid and unknown are distinct: invalid means "present but unusable"; unknown means "cannot confirm presence or absence."

## Uncertainty Disclosure

Every dimension MUST disclose uncertainty:

- `level`: A discrete uncertainty level (e.g., low/medium/high) must be assigned.
- `level-with-rationale`: Both a level and a written rationale describing the dominant error sources are required.

There is no `none` option. Uncertainty cannot be opted out of.

## Reporting Requirements

Each dimension defines a `reporting_requirement` specifying what must be included in assessment reports: the required content, format constraints, and any per-dimension specificity. Reports that omit required content are incomplete.

## Comparability Limits

Each dimension defines a `comparability_limit` specifying what comparisons are valid across measurement runs. Comparisons that violate a dimension's limit are invalid and must not be presented as equivalent. Cross-run comparisons require explicit preconditions to be satisfied.

## Inherited Category Exclusions

Each dimension inherits the excluded surfaces from its pinned category in the defensive research categories registry. All seven surfaces — agent, payload, tasking, transport, evasion, credentials, live_control — are excluded from every dimension. No observation may contain or reference any of these surfaces.

## No-Evasion Rule

This rubric MUST NOT be used to design, evaluate, or grade evasion techniques. Dimensions, evidence classes, and assessment procedures are defined exclusively for defensive research observations. Any use that incorporates evasion analysis or evasion-effectiveness measurement is out of scope and invalid.

## No Single-Verdict Rule

This rubric MUST NOT produce a single composite score, pass/fail verdict, or aggregated safety rating. Each dimension is assessed independently. Combining dimensions into a single verdict conceals the trade-offs and uncertainty that the rubric is designed to expose. Consumers MAY present all five dimension assessments together but MUST NOT reduce them to a single claim.

## Relationship to Issue #124

The [Issue #124 experiment-evidence package manifest](./defensive-research-experiment-evidence-package-manifest.md) pins this rubric by `rubric_id` + `rubric_version` to declare which interpretive framework governs contained observations. Each bounded evidence entry names a rubric dimension; the package validator resolves its category and evidence class through this rubric and the pinned registry. The rubric does not validate or consume packages or evidence records. The dependency is one-way: #124 may point here; this rubric points only to the defensive research categories registry.

## Validation

A JSON Schema (Draft 2020-12) for this rubric is available at:

- Schema: `docs/schemas/defensive-research-detection-measurement-rubric-v1.schema.json`
- Example: `docs/schemas/examples/defensive-research-detection-measurement-rubric-v1.json`

The static validator at `docs/schemas/validate-examples.js` enforces both schema conformance and semantic contracts (dimension ID set completeness, category reference resolution, evidence-class subset validation, and missing-unknown-data handling enforcement).
