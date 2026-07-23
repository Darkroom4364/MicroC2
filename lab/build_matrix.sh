#!/usr/bin/env bash
# build_matrix.sh — build N seeded MicroC2 agent variants for one study and
# emit a manifest.json skeleton (lab/manifest.schema.json) with build-side
# fields filled. EDR/verdict fields stay as placeholders; the lab run fills
# them per docs/research/r1-measurement-protocol.md.
#
# Builds happen on the operator host only; payloads are executed exclusively
# inside the isolated lab. Lab use only.

set -euo pipefail

# --- Defaults ---
COUNT=""
OUTPUT_DIR=""
TARGET="x86_64-pc-windows-gnu"
BASE_SEED="5eed"
SEEDS=""
LISTENER_HOST="192.0.2.1"   # TEST-NET-1 placeholder; override with the lab C2 address
LISTENER_PORT="8443"
PROTOCOL="http"
FORMAT="windows_exe"
BUILD_TYPE="release"
STUDY_ID=""

usage() {
  cat >&2 <<'EOF'
Usage: build_matrix.sh --count N --output-dir DIR [options]

Required:
  -n, --count N          Number of variants to build (ignored if --seeds given)
  -o, --output-dir DIR   Output directory; one seed_<hex>/ subdir per variant,
                         manifest.json is written at its top level

Options:
  -t, --target TRIPLE    Rust target (default: x86_64-pc-windows-gnu)
      --base-seed HEX    Base for deterministic seed derivation (default: 5eed).
                         Seed i = sha256("microc2-r1:<base>:<i>")[0..15].
      --seeds "h1 h2 .." Explicit space/comma-separated hex seed list
                         (overrides --count and --base-seed)
      --listener-host H  C2 listener host baked into payloads (default: 192.0.2.1)
      --listener-port P  C2 listener port (default: 8443)
      --protocol P       C2 protocol (default: http)
      --format F         build.sh format (default: windows_exe)
      --build-type T     release|debug (default: release)
      --study-id S       Study identifier recorded in the manifest
  -h, --help             This help
EOF
  exit "${1:-1}"
}

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
  case $1 in
    -n|--count)        COUNT="$2"; shift 2 ;;
    -o|--output-dir)   OUTPUT_DIR="$2"; shift 2 ;;
    -t|--target)       TARGET="$2"; shift 2 ;;
    --base-seed)       BASE_SEED="$2"; shift 2 ;;
    --seeds)           SEEDS="$2"; shift 2 ;;
    --listener-host)   LISTENER_HOST="$2"; shift 2 ;;
    --listener-port)   LISTENER_PORT="$2"; shift 2 ;;
    --protocol)        PROTOCOL="$2"; shift 2 ;;
    --format)          FORMAT="$2"; shift 2 ;;
    --build-type)      BUILD_TYPE="$2"; shift 2 ;;
    --study-id)        STUDY_ID="$2"; shift 2 ;;
    -h|--help)         usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

[[ -z "$OUTPUT_DIR" ]] && { echo "Error: --output-dir is required" >&2; usage; }
if [[ -z "$SEEDS" && -z "$COUNT" ]]; then
  echo "Error: --count is required unless --seeds is given" >&2; usage
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_DIR="$REPO_ROOT/agent"
[[ -x "$AGENT_DIR/build.sh" ]] || { echo "Error: $AGENT_DIR/build.sh not found or not executable" >&2; exit 1; }

# --- Portable helpers ---
sha256_hex() { # stdin -> lowercase hex digest
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1
  else shasum -a 256 | cut -d' ' -f1
  fi
}

file_sha256() { # $1 = path -> lowercase hex digest
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

json_escape() { # $1 = raw string -> JSON-escaped (no surrounding quotes)
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# --- Resolve the seed list ---
declare -a SEED_LIST=()
if [[ -n "$SEEDS" ]]; then
  # shellcheck disable=SC2206
  SEED_LIST=(${SEEDS//,/ })
else
  for ((i = 0; i < COUNT; i++)); do
    SEED_LIST+=("$(printf '%s' "microc2-r1:${BASE_SEED}:${i}" | sha256_hex | cut -c1-16)")
  done
fi

for s in "${SEED_LIST[@]}"; do
  [[ "$s" =~ ^[0-9a-fA-F]{1,16}$ ]] || { echo "Error: invalid seed '$s' (expect hex u64)" >&2; exit 1; }
done

GIT_REVISION="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")"
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

echo "Building ${#SEED_LIST[@]} variant(s) from revision $GIT_REVISION"
echo "Seeds: ${SEED_LIST[*]}"

# --- Artifact name per format (mirrors agent/build.sh) ---
case "$FORMAT" in
  windows_exe)     ARTIFACT_NAME="agent.exe" ;;
  windows_dll)     ARTIFACT_NAME="agent.dll" ;;
  windows_shellcode) ARTIFACT_NAME="shellcode.bin" ;;
  windows_service) ARTIFACT_NAME="agent_service.exe" ;;
  linux_elf)       ARTIFACT_NAME="agent" ;;
  macos_dylib)     ARTIFACT_NAME="libagent.dylib" ;;
  linux_so)        ARTIFACT_NAME="libagent.so" ;;
  *)               ARTIFACT_NAME="agent" ;;
esac

# --- Build loop ---
declare -a CELLS=()
for seed in "${SEED_LIST[@]}"; do
  CELL_DIR="$OUTPUT_DIR/seed_${seed}"
  mkdir -p "$CELL_DIR"
  echo "==> seed $seed"

  ( cd "$AGENT_DIR" && ./build.sh \
      --target "$TARGET" \
      --output "$CELL_DIR" \
      --build-type "$BUILD_TYPE" \
      --format "$FORMAT" \
      --listener-host "$LISTENER_HOST" \
      --listener-port "$LISTENER_PORT" \
      --protocol "$PROTOCOL" \
      --mutation-seed "$seed" )

  ARTIFACT="$CELL_DIR/$ARTIFACT_NAME"
  [[ -f "$ARTIFACT" ]] || { echo "Error: expected artifact $ARTIFACT missing after build" >&2; exit 1; }

  HASH="$(file_sha256 "$ARTIFACT")"
  BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  PROVENANCE="null"
  if [[ -f "$CELL_DIR/provenance.json" ]]; then
    PROVENANCE="\"seed_${seed}/provenance.json\""
  fi

  CELLS+=("$(cat <<EOF
    {
      "cell_id": "${seed}@TODO-edr-slot",
      "seed": "${seed}",
      "git_revision": "${GIT_REVISION}",
      "artifact": {
        "path": "seed_${seed}/${ARTIFACT_NAME}",
        "sha256": "${HASH}",
        "provenance_path": ${PROVENANCE}
      },
      "edr": {
        "slot_id": "TODO",
        "product": null,
        "version": null
      },
      "timestamps": {
        "built_at": "${BUILT_AT}",
        "run_started_at": null,
        "run_finished_at": null
      },
      "verdict": "unknown",
      "alert_names": [],
      "telemetry": {
        "sysmon_evtx": null,
        "etw_etl": null,
        "agent_network_log": null,
        "edr_export": null
      },
      "notes": ""
    }
EOF
)")

  echo "    artifact: seed_${seed}/${ARTIFACT_NAME} sha256=${HASH}"
done

# --- Manifest skeleton ---
CELLS_JSON=""
for cell in "${CELLS[@]}"; do
  if [[ -n "$CELLS_JSON" ]]; then CELLS_JSON+=$',\n'; fi
  CELLS_JSON+="$cell"
done
MANIFEST="$OUTPUT_DIR/manifest.json"
cat > "$MANIFEST" <<EOF
{
  "manifest_version": "1.0",
  "study_id": "$(json_escape "${STUDY_ID:-TODO}")",
  "generated_by": "lab/build_matrix.sh",
  "generated_at": "${GENERATED_AT}",
  "cells": [
${CELLS_JSON}
  ]
}
EOF

echo
echo "Wrote $MANIFEST"
echo "Next: copy $OUTPUT_DIR into the isolated lab and run each cell per"
echo "docs/research/r1-measurement-protocol.md, filling verdict fields."
