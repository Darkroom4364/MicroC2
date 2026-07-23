#!/bin/bash
# Determinism check for the seeded source mutation engine (issue #67).
#
# Asserts on the same host:
#   1. Two builds with the same MUTATION_SEED produce identical generated
#      sources (config.rs / mutation.rs).
#   2. Two builds with different seeds produce different generated sources and
#      different binary hashes.
#
# Cross-host byte identity of binaries is explicitly NOT asserted (linkers
# differ); per-seed binary uniqueness is asserted on one host only.
set -euo pipefail
cd "$(dirname "$0")"

SEED_A="0123456789abcdef"
SEED_B="fedcba9876543210"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# Build once with the given seed and print the generated-source and binary
# hashes. Forces a build-script rerun by clearing its output dirs.
build_with_seed() {
    local seed="$1"
    rm -rf target/debug/build/agent-*
    MUTATION_SEED="$seed" cargo build --locked >/dev/null
    local outs=(target/debug/build/agent-*/out/mutation.rs)
    if [ ! -f "${outs[0]}" ]; then
        echo "ERROR: mutation.rs not generated for seed $seed" >&2
        exit 1
    fi
    hash_file "${outs[0]}"
    hash_file "$(dirname "${outs[0]}")/config.rs"
    hash_file target/debug/agent
}

echo "Building with seed $SEED_A (run 1)..."
build_with_seed "$SEED_A" > "$WORK/a1.hashes"
echo "Building with seed $SEED_A (run 2)..."
build_with_seed "$SEED_A" > "$WORK/a2.hashes"
echo "Building with seed $SEED_B..."
build_with_seed "$SEED_B" > "$WORK/b1.hashes"

A1_MUTATION_HASH="$(sed -n '1p' "$WORK/a1.hashes")"
A1_CONFIG_HASH="$(sed -n '2p' "$WORK/a1.hashes")"
A1_BINARY_HASH="$(sed -n '3p' "$WORK/a1.hashes")"
A2_MUTATION_HASH="$(sed -n '1p' "$WORK/a2.hashes")"
A2_CONFIG_HASH="$(sed -n '2p' "$WORK/a2.hashes")"
B1_MUTATION_HASH="$(sed -n '1p' "$WORK/b1.hashes")"
B1_BINARY_HASH="$(sed -n '3p' "$WORK/b1.hashes")"

if [ "$A1_MUTATION_HASH" != "$A2_MUTATION_HASH" ]; then
    echo "FAIL: same seed produced different mutation.rs hashes" >&2
    exit 1
fi
if [ "$A1_CONFIG_HASH" != "$A2_CONFIG_HASH" ]; then
    echo "FAIL: same seed produced different config.rs hashes" >&2
    exit 1
fi
echo "OK: same seed -> identical generated sources"

if [ "$A1_MUTATION_HASH" = "$B1_MUTATION_HASH" ]; then
    echo "FAIL: different seeds produced identical mutation.rs hashes" >&2
    exit 1
fi
echo "OK: different seeds -> different mutation.rs"

if [ "$A1_BINARY_HASH" = "$B1_BINARY_HASH" ]; then
    echo "FAIL: different seeds produced identical binary hashes on this host" >&2
    exit 1
fi
echo "OK: different seeds -> different binary hashes"

echo "Determinism check passed."
