#!/bin/bash
# Determinism check for the seeded source mutation engine (issue #67).
#
# Asserts on the same host:
#   1. Two builds with the same complete build input produce identical
#      generated sources (config.rs / mutation.rs) and host binary.
#   2. Two builds with different seeds produce different generated sources and
#      different binary hashes.
#
# The fixed enrollment credential below is test-only. Production credentials
# are random build inputs, are never persisted raw, and therefore must be
# supplied separately to reproduce an exact authenticated payload.
#
# Cross-host byte identity of binaries is explicitly NOT asserted (linkers
# differ); per-seed binary uniqueness is asserted on one host only. The debug
# test binary is symbol-stripped because rustc gives temporary object files
# nondeterministic names that otherwise survive in debug metadata; production
# release artifacts are stripped as well.
set -euo pipefail
cd "$(dirname "$0")"

SEED_A="0123456789abcdef"
SEED_B="fedcba9876543210"
TEST_ONLY_ENROLLMENT_CREDENTIAL="QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

required_cross_env=(
    LISTENER_HOST LISTENER_PORT SERVER_URL LISTENER_ID SLEEP_INTERVAL JITTER PAYLOAD_ID PROTOCOL
    SOCKS5_ENABLED SOCKS5_HOST SOCKS5_PORT ALLOW_INVALID_CERTS
    ENROLLMENT_CREDENTIAL MICROC2_BUILD_NONCE ALLOW_INSECURE_ISOLATED_LAB
    BASE_SCORE_THRESHOLD_BG_TO_REDUCED BASE_SCORE_THRESHOLD_REDUCED_TO_FULL
    MIN_FULL_OPSEC_SECS MIN_REDUCED_OPSEC_SECS MIN_BG_OPSEC_SECS
    REDUCED_ACTIVITY_SLEEP_SECS BASE_MAX_C2_FAILS C2_THRESH_INC_FACTOR
    C2_THRESH_DEC_FACTOR C2_THRESH_ADJ_INTERVAL C2_THRESH_MAX_MULT
    PROC_SCAN_INTERVAL_SECS MUTATION_SEED
)
for variable in "${required_cross_env[@]}"; do
    if ! grep -q "\"${variable}\"" Cross.toml; then
        echo "FAIL: Cross.toml does not pass through ${variable}" >&2
        exit 1
    fi
done

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
    LISTENER_HOST="127.0.0.1" \
    LISTENER_PORT="8443" \
    SERVER_URL="https://127.0.0.1:8443" \
    LISTENER_ID="listener-determinism" \
    SLEEP_INTERVAL="60" \
    JITTER="2" \
    PAYLOAD_ID="payload-determinism" \
    PROTOCOL="https" \
    SOCKS5_ENABLED="false" \
    SOCKS5_HOST="127.0.0.1" \
    SOCKS5_PORT="9050" \
    ALLOW_INVALID_CERTS="false" \
    ENROLLMENT_CREDENTIAL="$TEST_ONLY_ENROLLMENT_CREDENTIAL" \
    MICROC2_BUILD_NONCE="determinism-$$-${RANDOM:-0}" \
    ALLOW_INSECURE_ISOLATED_LAB="false" \
    MUTATION_SEED="$seed" \
    RUSTFLAGS="-C strip=symbols" \
    cargo build --locked >/dev/null
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
A2_BINARY_HASH="$(sed -n '3p' "$WORK/a2.hashes")"
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
if [ "$A1_BINARY_HASH" != "$A2_BINARY_HASH" ]; then
    echo "FAIL: same complete build inputs produced different binary hashes on this host" >&2
    exit 1
fi
echo "OK: same complete build inputs -> identical generated sources and host binary"

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
