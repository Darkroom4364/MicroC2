## Defensive Research Categories

The defensive research category registry (`defensive-research-categories-v1`) is the single source of truth for classifying redacted and synthetic defensive research evidence. Categories classify only redacted or synthetic defensive evidence and never describe operations, tradecraft, or capabilities. Every category encodes a bounded defensive-purpose description, a closed set of permitted evidence classes, and the full seven-item excluded-surface set.

### Purpose

- **Classification, not mapping.** The registry enumerates abstract defensive research categories. It contains no product names, ATT&CK technique identifiers, payload paths, agent identifiers, server endpoints, or raw event data.
- **Evidence-only scope.** Every category exists exclusively to classify redacted or synthetic defensive research evidence—never to enumerate offensive capabilities or operational tradecraft.

### Immutable-Publication Policy

  - Every published `registry_version` is immutable. Semantic changes require a new exact registry version.
  - Consumers **MUST** pin an exact `registry_id` + `registry_version` pair. References that omit or mismatch the published pair are invalid. Consumers never use version ranges or implicit upgrades.
  - Category IDs are never reused or repurposed across any version. Renaming or renumbering requires a new registry version.

### Exact-Version-Pin Compatibility Rule

A consumer reference (`defensive-research-category-reference-v1`) declares:

1. The exact `registry_id` (`microc2-defensive-research-categories`).
2. The exact `registry_version` semantic version string.
3. A syntactically valid `category_id` that the consumer asserts exists in that registry version.

Automated validation can (and should) reject references where the `category_id` is not present in the pinned registry. This is enforced in the schema test suite via a deterministic semantic helper.

### Forbidden-Surface Semantics

Every category includes the full seven-item `excluded_surfaces` set:

- `agent`
- `payload`
- `tasking`
- `transport`
- `evasion`
- `credentials`
- `live_control`

These surfaces are **never** in scope for any defensive research category. The `excluded_surfaces` set is **closed**—no other values are permitted—and **always present** at cardinality 7. This is a structural invariant of the registry schema, not a runtime policy.

### Relationship to Future Work

- **Issue #123 (detection-measurement rubric)** may reference categories from this registry to scope what is measured and how.
- **Issue #124 (redacted experiment-evidence package manifest)** may record a pinned category reference in its package metadata.
- Neither issue requires changes to the registry itself; they consume it as a pinned, immutable reference.

### What This Registry Is Not

- **Not the R1 lab protocol.** The R1 mutation-engine research document (`docs/research/r1-mutation-engine.md`) and measurement protocol (`docs/research/r1-measurement-protocol.md`) are separate, lab-scoped artifacts.
- **Not a manifest.** This file is documentation for a JSON Schema artifact; the authoritative shape lives in `docs/schemas/defensive-research-categories-v1.schema.json`.
- **Contains no mappings.** No C2 capability → category mapping, no ATT&CK mapping, no surface → evidence mapping.
- **Introduces no runtime behavior.** This is a static schema registry; adding, removing, or changing categories has no effect on the MicroC2 server, agent, or transport.
