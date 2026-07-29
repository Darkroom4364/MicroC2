# Defensive Research Experiment-Evidence Package Manifest

## Identity and Immutability

- **Package ID**: `microc2-defensive-research-experiment-evidence-package`
- **Package version**: `1.0.0`
- **Schema version**: `1`

This is an immutable static-review contract. A semantic change to the package
layout, derivative profile, pins, mapping, or permitted summary shape requires
a new exact version. Consumers MUST use exact versions and MUST NOT use ranges
or implicit upgrades.

## Scope and Layout

A package contains one `manifest.json` descriptor and from one through five
bare JSON evidence files. The manifest inventory has exactly two roles:
`manifest` and `audit-event-v1-evidence`. Each evidence descriptor has a
lowercase SHA-256 digest; the manifest is not self-digested.

File names are fixed bare names, not paths. The manifest has no user-provided,
external, or operational URLs, arbitrary metadata, label, notes, source
identifier, or extension field. Its fixed pinned Audit Event schema identifier
is an allowed static contract identifier, not an external URL. The local validator rejects duplicate JSON member names, undeclared files, directories, symlinks, descriptor/entry mismatches, and digest mismatches.

## Pinned Interpretation

The manifest pins the exact v1 detection-measurement rubric and defensive
research category registry. It intentionally has no user-provided category
reference. Instead, each evidence entry names one of the rubric's closed
five-dimension identifiers and one closed evidence class. The validator derives
the category from the pinned rubric and verifies both the rubric's admissible
class and the resolved registry category's allowed class.

| Rubric dimension | Resolved registry category | Required evidence class |
| --- | --- | --- |
| `provenance` | `integrity-metadata` | `integrity-metadata` |
| `collection-coverage` | `coverage-summary` | `synthetic-control-summary` |
| `validity` | `defensive-observation-summary` | `redacted-observation-summary` |
| `uncertainty` | `defensive-observation-summary` | `aggregate-measurement-summary` |
| `missing-unknown-data` | `coverage-summary` | `aggregate-measurement-summary` |

Each dimension appears at most once. A package may be partial; its absence of
a dimension is not an assessment, a verdict, or a claim that the missing
dimension is satisfied.

## Audit Event v1 Derivative Profile

The closed manifest `provenance` object pins the existing Audit Event v1 schema
identity and schema version, plus derivative profile
`microc2-audit-event-v1-identifier-free-summary` version `1.0.0`. Every entry
identifies whether its count-only derivative is `redacted` or `synthetic`.

An entry contains only its fixed entry ID, schema version, rubric dimension,
evidence class, source mode, and a bounded count-only summary. It is not a raw
Audit Event v1 record. In particular, no actor, action, route, target, outcome,
identifier, body, command, output, credential, endpoint, log, artifact, or
free-text field is permitted.

The profile is an asserted identifier-free derivative relationship, not proof
that underlying source material exists, is retained, or has any particular
origin. SHA-256 protects the local evidence-file bytes named by the manifest;
it does not establish source provenance or a review conclusion.

## Static-Only Boundary

This package has no runtime, network, export, database, payload, listener,
task, or result behavior. It is a local JSON schema, fixture, and deterministic
validator contract only.

It is neither the R1 lab manifest nor R1 input or output. It does not configure,
produce, collect, or reproduce R1 material. It is also not evidence that any
of issue #115's sealed-run gates have been met; it makes no execution,
containment, executor, or reproducibility claim.

## Validation

The static schema validator checks root and entry schema conformance, exact
pins and derivative profile, local package inventory, sidecar SHA-256 values,
and the closed rubric-to-registry mapping. Its safe fixture is synthetic and
contains only an identifier-free count summary.
