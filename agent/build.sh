#!/bin/bash

echo "MicroC2 Agent Builder"
echo "============================="

# --- Configuration Defaults ---
# Values set here will be used if not provided by environment variables from the calling process (e.g., payload_handler.go)
# Command-line arguments to build.sh can override these further down.
TARGET="" # Primarily set by --target arg or derived
OUTPUT_DIR="" # Primarily set by --output arg or derived
BUILD_TYPE="release" # Primarily set by --build-type arg
LISTENER_HOST="" # Primarily set by --listener-host arg
LISTENER_PORT="" # Primarily set by --listener-port arg
SERVER_URL=${SERVER_URL:-""}
LISTENER_ID=${LISTENER_ID:-""}
PAYLOAD_ID="" # Primarily set by --payload-id arg or derived
PROTOCOL="" # Primarily set by --protocol arg or derived
MUTATION_SEED=${MUTATION_SEED:-""} # Hex u64; empty means build.rs falls back to the fixed dev seed
ENROLLMENT_CREDENTIAL=${ENROLLMENT_CREDENTIAL:-""}
ALLOW_INSECURE_ISOLATED_LAB=${ALLOW_INSECURE_ISOLATED_LAB:-false}
ALLOW_INVALID_CERTS=${ALLOW_INVALID_CERTS:-false}

SLEEP_INTERVAL=${SLEEP_INTERVAL:-60}
JITTER=${JITTER:-2}
SOCKS5_ENABLED=${SOCKS5_ENABLED:-false}
SOCKS5_HOST=${SOCKS5_HOST:-"127.0.0.1"}
SOCKS5_PORT=${SOCKS5_PORT:-9050}

# OPSEC Defaults
BASE_SCORE_THRESHOLD_BG_TO_REDUCED=${BASE_SCORE_THRESHOLD_BG_TO_REDUCED:-20.0}
BASE_SCORE_THRESHOLD_REDUCED_TO_FULL=${BASE_SCORE_THRESHOLD_REDUCED_TO_FULL:-60.0}
MIN_FULL_OPSEC_SECS=${MIN_FULL_OPSEC_SECS:-300}
MIN_REDUCED_OPSEC_SECS=${MIN_REDUCED_OPSEC_SECS:-120}
MIN_BG_OPSEC_SECS=${MIN_BG_OPSEC_SECS:-60}
REDUCED_ACTIVITY_SLEEP_SECS=${REDUCED_ACTIVITY_SLEEP_SECS:-120}
BASE_MAX_C2_FAILS=${BASE_MAX_C2_FAILS:-5}
C2_THRESH_INC_FACTOR=${C2_THRESH_INC_FACTOR:-1.1}
C2_THRESH_DEC_FACTOR=${C2_THRESH_DEC_FACTOR:-0.9}
C2_THRESH_ADJ_INTERVAL=${C2_THRESH_ADJ_INTERVAL:-3600} # 1 hour
C2_THRESH_MAX_MULT=${C2_THRESH_MAX_MULT:-2.0}
PROC_SCAN_INTERVAL_SECS=${PROC_SCAN_INTERVAL_SECS:-300}

decimal_is_zero() {
    [[ "$1" =~ ^0+([.]0+)?$ ]]
}

decimal_greater_than() {
    local left="$1"
    local right="$2"
    local left_integer="${left%%.*}"
    local right_integer="${right%%.*}"
    local left_fraction=""
    local right_fraction=""

    if [[ "$left" == *.* ]]; then
        left_fraction="${left#*.}"
    fi
    if [[ "$right" == *.* ]]; then
        right_fraction="${right#*.}"
    fi
    while [[ ${#left_integer} -gt 1 && "$left_integer" == 0* ]]; do
        left_integer="${left_integer#0}"
    done
    while [[ ${#right_integer} -gt 1 && "$right_integer" == 0* ]]; do
        right_integer="${right_integer#0}"
    done
    if [[ ${#left_integer} -ne ${#right_integer} ]]; then
        [[ ${#left_integer} -gt ${#right_integer} ]]
        return
    fi
    if [[ "$left_integer" != "$right_integer" ]]; then
        [[ "$left_integer" > "$right_integer" ]]
        return
    fi
    while [[ ${#left_fraction} -lt ${#right_fraction} ]]; do
        left_fraction="${left_fraction}0"
    done
    while [[ ${#right_fraction} -lt ${#left_fraction} ]]; do
        right_fraction="${right_fraction}0"
    done
    [[ "$left_fraction" > "$right_fraction" ]]
}

decimal_less_than() {
    decimal_greater_than "$2" "$1"
}

decimal_add_integers() {
    local left="$1"
    local right="$2"
    local left_index=$((${#left} - 1))
    local right_index=$((${#right} - 1))
    local carry=0
    local result=""
    local left_digit
    local right_digit
    local total

    while [[ $left_index -ge 0 || $right_index -ge 0 || $carry -ne 0 ]]; do
        left_digit=0
        right_digit=0
        if [[ $left_index -ge 0 ]]; then
            left_digit="${left:$left_index:1}"
            left_index=$((left_index - 1))
        fi
        if [[ $right_index -ge 0 ]]; then
            right_digit="${right:$right_index:1}"
            right_index=$((right_index - 1))
        fi
        total=$((10#$left_digit + 10#$right_digit + carry))
        result="$((total % 10))${result}"
        carry=$((total / 10))
    done
    while [[ ${#result} -gt 1 && "$result" == 0* ]]; do
        result="${result#0}"
    done
    printf '%s' "$result"
}

# --- Parse Command Line Arguments ---
# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --output)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --build-type)
      BUILD_TYPE="$2"
      shift 2
      ;;
    --format)
      FORMAT="$2" # FORMAT is specific to build.sh logic, not an env-driven default from Go
      shift 2
      ;;
    --listener-host)
      LISTENER_HOST="$2"
      shift 2
      ;;
    --listener-port)
      LISTENER_PORT="$2"
      shift 2
      ;;
    --sleep)
      SLEEP_INTERVAL="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --jitter)
      JITTER="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --payload-id)
      PAYLOAD_ID="$2"
      shift 2
      ;;
    --protocol)
      PROTOCOL="$2"
      shift 2
      ;;
    --mutation-seed)
      MUTATION_SEED="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --socks5-enabled)
      SOCKS5_ENABLED="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --socks5-host)
      SOCKS5_HOST="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --socks5-port)
      SOCKS5_PORT="$2" # CLI arg overrides env/default
      shift 2
      ;;
    # Add OPSEC related flags if desired, or rely on env vars/defaults
    --base-score-bg-reduced)
      BASE_SCORE_THRESHOLD_BG_TO_REDUCED="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --base-score-reduced-full)
      BASE_SCORE_THRESHOLD_REDUCED_TO_FULL="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --reduced-activity-sleep)
      REDUCED_ACTIVITY_SLEEP_SECS="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --min-full-opsec-secs)
      MIN_FULL_OPSEC_SECS="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --min-reduced-opsec-secs)
      MIN_REDUCED_OPSEC_SECS="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --min-bg-opsec-secs)
      MIN_BG_OPSEC_SECS="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --base-max-c2-fails)
      BASE_MAX_C2_FAILS="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --c2-thresh-inc-factor)
      C2_THRESH_INC_FACTOR="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --c2-thresh-dec-factor)
      C2_THRESH_DEC_FACTOR="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --c2-thresh-adj-interval)
      C2_THRESH_ADJ_INTERVAL="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --c2-thresh-max-mult)
      C2_THRESH_MAX_MULT="$2" # CLI arg overrides env/default
      shift 2
      ;;
    --proc-scan-interval-secs)
      PROC_SCAN_INTERVAL_SECS="$2" # CLI arg overrides env/default
      shift 2
      ;;
    *)
      echo "Error: unknown option: $1" >&2
      exit 2
      ;;
  esac
done

# Validate required flags (these are typically NOT from env, but direct args to build.sh)
if [ -z "$LISTENER_HOST" ] || [ -z "$LISTENER_PORT" ]; then
  echo "Error: --listener-host and --listener-port are required for build.sh" >&2
  # Allow to proceed if PAYLOAD_ID is set, as build.rs might get info from embedded config
  if [ -z "$PAYLOAD_ID" ]; then
  exit 1
  else
    echo "Warning: LISTENER_HOST/PORT not set, but PAYLOAD_ID is. Assuming embedded config or build.rs will handle."
  fi
fi

# Determine protocol: Prioritize --protocol flag.
if [ -n "$PROTOCOL" ]; then
  echo "Using specified PROTOCOL from --protocol flag or environment: $PROTOCOL"
else
  echo "Warning: PROTOCOL not provided. Defaulting to 'http'. The server should specify the protocol for the selected listener if this is part of payload generation." >&2
  PROTOCOL="http"
fi

# Use environment variables for TARGET if arguments not provided and TARGET is still empty
TARGET=${TARGET:-"x86_64-unknown-linux-gnu"}


# IMPORTANT: Properly set server address and port for build.rs if not fully specified
# These are primarily for build.rs if it needs to construct a server_url from components.
# LISTENER_HOST and LISTENER_PORT are the primary source for this.
SERVER_IP=$LISTENER_HOST
SERVER_PORT=$LISTENER_PORT


# Store original output dir (as provided by the server/--output)
ORIGINAL_OUTPUT_DIR="$OUTPUT_DIR"

# Handle relative/absolute paths for OUTPUT_DIR
if [ -n "$OUTPUT_DIR" ] && [[ "$OUTPUT_DIR" != /* ]]; then
    OUTPUT_DIR="$(pwd)/$OUTPUT_DIR"
fi

# Determine payload ID if not provided by arg and still empty
if [ -z "$PAYLOAD_ID" ]; then
    if [ -n "$OUTPUT_DIR" ]; then
    PAYLOAD_ID=$(basename "$OUTPUT_DIR")
        echo "Derived PAYLOAD_ID from OUTPUT_DIR: $PAYLOAD_ID"
    else
        echo "Warning: OUTPUT_DIR is not set, cannot derive PAYLOAD_ID from it." >&2
    fi
fi

# Ensure PAYLOAD_ID is never empty after the above steps
if [ -z "$PAYLOAD_ID" ]; then
    echo "Warning: PAYLOAD_ID is empty after attempting to derive it. Generating a unique ID." >&2
    if command -v uuidgen &> /dev/null; then
        PAYLOAD_ID=$(uuidgen)
    elif command -v powershell &> /dev/null; then
        PAYLOAD_ID=$(powershell -Command "[guid]::NewGuid().ToString()")
    elif [ -n "$SYSTEMROOT" ] && command -v powershell.exe &> /dev/null; then
        PAYLOAD_ID=$(powershell.exe -Command "[guid]::NewGuid().ToString()")
    else
        PAYLOAD_ID="agent_$(date +%s%N)"
    fi
    echo "Generated PAYLOAD_ID: $PAYLOAD_ID"
else
    echo "Using determined PAYLOAD_ID: $PAYLOAD_ID"
fi

if [ -z "$ENROLLMENT_CREDENTIAL" ]; then
    echo "Error: ENROLLMENT_CREDENTIAL is required for an agent payload build." >&2
    exit 1
fi
if [ "${#ENROLLMENT_CREDENTIAL}" -ne 43 ] ||
    [[ ! "$ENROLLMENT_CREDENTIAL" =~ ^[A-Za-z0-9_-]{43}$ ]] ||
    [[ ! "${ENROLLMENT_CREDENTIAL: -1}" =~ ^[AEIMQUYcgkosw048]$ ]]; then
    echo "Error: ENROLLMENT_CREDENTIAL must be a canonical 32-byte unpadded base64url credential." >&2
    exit 1
fi
if [[ ! "$PROTOCOL" =~ ^https?$ ]]; then
    echo "Error: PROTOCOL must be http or https." >&2
    exit 1
fi
if [[ "$LISTENER_HOST" == \[* ]]; then
    LISTENER_HOST_IS_VALID=false
    if [[ "$LISTENER_HOST" =~ ^\[[0-9A-Fa-f:.%]+\]$ ]]; then
        LISTENER_HOST_IS_VALID=true
    fi
elif [[ "$LISTENER_HOST" =~ ^[A-Za-z0-9._:%-]+$ ]]; then
    LISTENER_HOST_IS_VALID=true
else
    LISTENER_HOST_IS_VALID=false
fi
if [ "$LISTENER_HOST_IS_VALID" != "true" ]; then
    echo "Error: LISTENER_HOST must be a hostname or IP address without a scheme, port, path, or control characters." >&2
    exit 1
fi
if [[ ! "$LISTENER_PORT" =~ ^[0-9]+$ ]] ||
    [ "$LISTENER_PORT" -lt 1 ] ||
    [ "$LISTENER_PORT" -gt 65535 ]; then
    echo "Error: LISTENER_PORT must be between 1 and 65535." >&2
    exit 1
fi
if [[ ! "$LISTENER_ID" =~ ^[A-Za-z0-9_.:-]{1,128}$ ]]; then
    echo "Error: LISTENER_ID is required and must satisfy the identifier contract." >&2
    exit 1
fi
if [[ ! "$PAYLOAD_ID" =~ ^[A-Za-z0-9_.:-]{1,128}$ ]]; then
    echo "Error: PAYLOAD_ID must satisfy the identifier contract." >&2
    exit 1
fi
if [[ "$SOCKS5_HOST" == \[* ]]; then
    SOCKS5_HOST_IS_VALID=false
    if [[ "$SOCKS5_HOST" =~ ^\[[0-9A-Fa-f:.%]+\]$ ]]; then
        SOCKS5_HOST_IS_VALID=true
    fi
elif [[ "$SOCKS5_HOST" =~ ^[A-Za-z0-9._:%-]+$ ]]; then
    SOCKS5_HOST_IS_VALID=true
else
    SOCKS5_HOST_IS_VALID=false
fi
if [ "$SOCKS5_HOST_IS_VALID" != "true" ]; then
    echo "Error: SOCKS5_HOST must be a hostname or IP address." >&2
    exit 1
fi
if [[ ! "$SOCKS5_PORT" =~ ^[0-9]+$ ]] ||
    [ "$SOCKS5_PORT" -lt 1 ] ||
    [ "$SOCKS5_PORT" -gt 65535 ]; then
    echo "Error: SOCKS5_PORT must be between 1 and 65535." >&2
    exit 1
fi
for unsigned_value in \
    "$SLEEP_INTERVAL" "$JITTER" "$MIN_FULL_OPSEC_SECS" \
    "$MIN_REDUCED_OPSEC_SECS" "$MIN_BG_OPSEC_SECS" \
    "$REDUCED_ACTIVITY_SLEEP_SECS" "$BASE_MAX_C2_FAILS" \
    "$C2_THRESH_ADJ_INTERVAL" "$PROC_SCAN_INTERVAL_SECS"; do
    if [[ ! "$unsigned_value" =~ ^[0-9]+$ ]]; then
        echo "Error: integer build settings must contain decimal digits only." >&2
        exit 1
    fi
done
for decimal_value in \
    "$BASE_SCORE_THRESHOLD_BG_TO_REDUCED" \
    "$BASE_SCORE_THRESHOLD_REDUCED_TO_FULL" \
    "$C2_THRESH_INC_FACTOR" "$C2_THRESH_DEC_FACTOR" "$C2_THRESH_MAX_MULT"; do
    if [[ ! "$decimal_value" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        echo "Error: decimal build settings must be non-negative decimal numbers." >&2
        exit 1
    fi
done
U64_MAX_DECIMAL="18446744073709551615"
U32_MAX_DECIMAL="4294967295"
F32_MAX_DECIMAL="340282346638528859811704183484516925440"
F32_MIN_NONZERO_DECIMAL="0.000000000000000000000000000000000000000000001"

for unsigned_value in \
    "$SLEEP_INTERVAL" "$JITTER" "$MIN_FULL_OPSEC_SECS" \
    "$MIN_REDUCED_OPSEC_SECS" "$MIN_BG_OPSEC_SECS" \
    "$REDUCED_ACTIVITY_SLEEP_SECS" "$C2_THRESH_ADJ_INTERVAL" \
    "$PROC_SCAN_INTERVAL_SECS"; do
    if decimal_greater_than "$unsigned_value" "$U64_MAX_DECIMAL"; then
        echo "Error: unsigned build settings must fit an unsigned 64-bit integer." >&2
        exit 1
    fi
done
if decimal_is_zero "$SLEEP_INTERVAL"; then
    echo "Error: SLEEP_INTERVAL must be at least one second." >&2
    exit 1
fi
if decimal_greater_than \
    "$(decimal_add_integers "$SLEEP_INTERVAL" "$JITTER")" \
    "$U64_MAX_DECIMAL"; then
    echo "Error: SLEEP_INTERVAL plus JITTER exceeds the supported u64 range." >&2
    exit 1
fi
if decimal_greater_than "$BASE_MAX_C2_FAILS" "$U32_MAX_DECIMAL"; then
    echo "Error: BASE_MAX_C2_FAILS must fit an unsigned 32-bit integer." >&2
    exit 1
fi
for decimal_value in \
    "$BASE_SCORE_THRESHOLD_BG_TO_REDUCED" \
    "$BASE_SCORE_THRESHOLD_REDUCED_TO_FULL" \
    "$C2_THRESH_INC_FACTOR" "$C2_THRESH_DEC_FACTOR" "$C2_THRESH_MAX_MULT"; do
    if decimal_greater_than "$decimal_value" "$F32_MAX_DECIMAL" ||
        { ! decimal_is_zero "$decimal_value" &&
          decimal_less_than "$decimal_value" "$F32_MIN_NONZERO_DECIMAL"; }; then
        echo "Error: decimal build settings must be zero or fit a finite non-zero f32." >&2
        exit 1
    fi
done
if decimal_greater_than "$BASE_SCORE_THRESHOLD_BG_TO_REDUCED" "100" ||
    decimal_greater_than "$BASE_SCORE_THRESHOLD_REDUCED_TO_FULL" "100"; then
    echo "Error: OPSEC score thresholds must each be within 0..=100." >&2
    exit 1
fi
if ! decimal_less_than \
    "$BASE_SCORE_THRESHOLD_BG_TO_REDUCED" \
    "$BASE_SCORE_THRESHOLD_REDUCED_TO_FULL"; then
    echo "Error: BASE_SCORE_THRESHOLD_BG_TO_REDUCED must be lower than BASE_SCORE_THRESHOLD_REDUCED_TO_FULL." >&2
    exit 1
fi
if { ! decimal_is_zero "$C2_THRESH_INC_FACTOR" &&
     decimal_less_than "$C2_THRESH_INC_FACTOR" "1"; }; then
    echo "Error: C2_THRESH_INC_FACTOR must be zero or at least one." >&2
    exit 1
fi
if decimal_greater_than "$C2_THRESH_DEC_FACTOR" "1"; then
    echo "Error: C2_THRESH_DEC_FACTOR must be within 0..=1." >&2
    exit 1
fi
if { ! decimal_is_zero "$C2_THRESH_MAX_MULT" &&
     decimal_less_than "$C2_THRESH_MAX_MULT" "1"; }; then
    echo "Error: C2_THRESH_MAX_MULT must be zero or at least one." >&2
    exit 1
fi
if [ -n "$MUTATION_SEED" ] &&
    [[ ! "$MUTATION_SEED" =~ ^(0x)?[0-9A-Fa-f]{1,16}$ ]]; then
    echo "Error: MUTATION_SEED must be a hexadecimal u64." >&2
    exit 1
fi
case "$ALLOW_INSECURE_ISOLATED_LAB" in
    true|false) ;;
    *)
        echo "Error: ALLOW_INSECURE_ISOLATED_LAB must be true or false." >&2
        exit 1
        ;;
esac
case "$ALLOW_INVALID_CERTS" in
    true|false) ;;
    *)
        echo "Error: ALLOW_INVALID_CERTS must be true or false." >&2
        exit 1
        ;;
esac
if [ "$PROTOCOL" != "https" ] && [ "$ALLOW_INSECURE_ISOLATED_LAB" != "true" ]; then
    echo "Error: non-HTTPS agent payload builds require ALLOW_INSECURE_ISOLATED_LAB=true." >&2
    exit 1
fi
if [ "$ALLOW_INVALID_CERTS" = "true" ] && [ "$ALLOW_INSECURE_ISOLATED_LAB" != "true" ]; then
    echo "Error: ALLOW_INVALID_CERTS=true requires ALLOW_INSECURE_ISOLATED_LAB=true." >&2
    exit 1
fi

# Also figure out the server's full path if OUTPUT_DIR was given
if [ -n "$OUTPUT_DIR" ]; then
SERVER_DIR=$(dirname $(dirname "$OUTPUT_DIR"))
  echo "Server path (derived from OUTPUT_DIR): $SERVER_DIR"
else
  echo "Server path cannot be derived as OUTPUT_DIR is not set."
fi


echo "Configuration for build.sh:"
echo "  Target:       $TARGET"
echo "  Output Dir:   $OUTPUT_DIR"
echo "  Original Dir: $ORIGINAL_OUTPUT_DIR"
if [ -n "$SERVER_DIR" ]; then echo "  Server Dir:   $SERVER_DIR"; fi
echo "  Build Type:   $BUILD_TYPE"
echo "  C2 Server:    ${SERVER_IP}:${SERVER_PORT}" # This is component-wise, actual URL in config.json
echo "  Sleep:        ${SLEEP_INTERVAL} seconds"
echo "  Jitter:       ${JITTER} seconds"
echo "  Format:       ${FORMAT:-<not set, will default>}" # FORMAT is specific to build.sh decision logic

echo "OPSEC Config for build.sh:"
echo "  BASE_SCORE_THRESHOLD_BG_TO_REDUCED: ${BASE_SCORE_THRESHOLD_BG_TO_REDUCED}"
echo "  BASE_SCORE_THRESHOLD_REDUCED_TO_FULL: ${BASE_SCORE_THRESHOLD_REDUCED_TO_FULL}"
echo "  MIN_FULL_OPSEC_SECS: ${MIN_FULL_OPSEC_SECS}"
echo "  MIN_REDUCED_OPSEC_SECS: ${MIN_REDUCED_OPSEC_SECS}"
echo "  MIN_BG_OPSEC_SECS: ${MIN_BG_OPSEC_SECS}"
echo "  REDUCED_ACTIVITY_SLEEP_SECS: ${REDUCED_ACTIVITY_SLEEP_SECS}"
echo "  BASE_MAX_C2_FAILS: ${BASE_MAX_C2_FAILS}"
echo "  C2_THRESH_INC_FACTOR: ${C2_THRESH_INC_FACTOR}"
echo "  C2_THRESH_DEC_FACTOR: ${C2_THRESH_DEC_FACTOR}"
echo "  C2_THRESH_ADJ_INTERVAL: ${C2_THRESH_ADJ_INTERVAL}"
echo "  C2_THRESH_MAX_MULT: ${C2_THRESH_MAX_MULT}"
echo "  PROC_SCAN_INTERVAL_SECS: ${PROC_SCAN_INTERVAL_SECS}"


echo "[DIAGNOSTIC] Protocol value before config generation: [$PROTOCOL]"

# Construct the canonical server URL passed to build.rs. Raw IPv6 literals are
# bracketed; already-bracketed literals stay bracketed.
if [[ "$LISTENER_HOST" == \[*\] ]]; then
    CONFIG_SERVER_AUTHORITY="${LISTENER_HOST}:${LISTENER_PORT}"
elif [[ "$LISTENER_HOST" == *:* ]]; then
    CONFIG_SERVER_AUTHORITY="[${LISTENER_HOST}]:${LISTENER_PORT}"
else
    CONFIG_SERVER_AUTHORITY="${LISTENER_HOST}:${LISTENER_PORT}"
fi
CONFIG_SERVER_URL="${PROTOCOL}://${CONFIG_SERVER_AUTHORITY}"
if [ -n "$SERVER_URL" ] && [ "$SERVER_URL" != "$CONFIG_SERVER_URL" ]; then
    echo "Error: SERVER_URL does not match the validated listener host, port, and protocol." >&2
    exit 1
fi
SERVER_URL="$CONFIG_SERVER_URL"

echo "Building agent..."

# Resolve an omitted format only for one of the two implemented target
# profiles, then reject every unsupported target/format combination before
# invoking Cargo.
if [ -z "${FORMAT:-}" ]; then
    case "$TARGET" in
        x86_64-unknown-linux-gnu)
            FORMAT="linux_elf"
            ;;
        x86_64-pc-windows-gnu)
            FORMAT="windows_exe"
            ;;
        *)
            echo "Error: unsupported target '$TARGET'; supported targets are x86_64-unknown-linux-gnu and x86_64-pc-windows-gnu." >&2
            exit 2
            ;;
    esac
fi
case "$TARGET/$FORMAT" in
    x86_64-unknown-linux-gnu/linux_elf)
        AGENT_OUT="agent"
        ;;
    x86_64-pc-windows-gnu/windows_exe)
        AGENT_OUT="agent.exe"
        ;;
    *)
        echo "Error: unsupported target/format '$TARGET/$FORMAT'; supported profiles are x86_64-unknown-linux-gnu/linux_elf and x86_64-pc-windows-gnu/windows_exe." >&2
        exit 2
        ;;
esac

# Set build flags based on build type
BUILD_FLAGS=""
if [ "$BUILD_TYPE" == "release" ]; then
    BUILD_FLAGS="--release"
elif [ "$BUILD_TYPE" == "debug" ]; then
    BUILD_FLAGS="" # No extra flags for debug
else
    echo "Error: BUILD_TYPE must be debug or release, got '$BUILD_TYPE'." >&2
    exit 2
fi

# Cargo records rerun-if-env-changed values in plaintext fingerprint metadata.
# Rotate a non-secret nonce on every wrapper invocation so build.rs reruns
# without fingerprinting the embedded bootstrap credential itself.
MICROC2_BUILD_NONCE="${PAYLOAD_ID}-$$-${SECONDS:-0}-${RANDOM:-0}-${RANDOM:-0}"

# --- Export Environment Variables for build.rs ---
# These ensure build.rs gets the final, resolved values.
export LISTENER_HOST="$LISTENER_HOST" # Actual host/IP for connection
export LISTENER_PORT="$LISTENER_PORT" # Actual port
export SERVER_URL="$SERVER_URL"
export LISTENER_ID="$LISTENER_ID"
export SLEEP_INTERVAL="$SLEEP_INTERVAL"
export JITTER="$JITTER"
export PAYLOAD_ID="$PAYLOAD_ID"
export PROTOCOL="$PROTOCOL" # Actual protocol
export SOCKS5_ENABLED="$SOCKS5_ENABLED"
export SOCKS5_HOST="$SOCKS5_HOST"
export SOCKS5_PORT="$SOCKS5_PORT"
export ENROLLMENT_CREDENTIAL="$ENROLLMENT_CREDENTIAL"
export MICROC2_BUILD_NONCE="$MICROC2_BUILD_NONCE"
export ALLOW_INSECURE_ISOLATED_LAB="$ALLOW_INSECURE_ISOLATED_LAB"
export ALLOW_INVALID_CERTS="$ALLOW_INVALID_CERTS"

# Only export when set; an unset MUTATION_SEED triggers the build.rs dev-seed fallback with a warning.
if [ -n "$MUTATION_SEED" ]; then
    export MUTATION_SEED="$MUTATION_SEED"
    echo "  Mutation Seed: $MUTATION_SEED"
else
    echo "  Mutation Seed: <not set, build.rs will use the fixed dev seed>"
fi

export BASE_SCORE_THRESHOLD_BG_TO_REDUCED="$BASE_SCORE_THRESHOLD_BG_TO_REDUCED"
export BASE_SCORE_THRESHOLD_REDUCED_TO_FULL="$BASE_SCORE_THRESHOLD_REDUCED_TO_FULL"
export MIN_FULL_OPSEC_SECS="$MIN_FULL_OPSEC_SECS"
export MIN_REDUCED_OPSEC_SECS="$MIN_REDUCED_OPSEC_SECS"
export MIN_BG_OPSEC_SECS="$MIN_BG_OPSEC_SECS"
export REDUCED_ACTIVITY_SLEEP_SECS="$REDUCED_ACTIVITY_SLEEP_SECS"
export BASE_MAX_C2_FAILS="$BASE_MAX_C2_FAILS"
export C2_THRESH_INC_FACTOR="$C2_THRESH_INC_FACTOR"
export C2_THRESH_DEC_FACTOR="$C2_THRESH_DEC_FACTOR"
export C2_THRESH_ADJ_INTERVAL="$C2_THRESH_ADJ_INTERVAL"
export C2_THRESH_MAX_MULT="$C2_THRESH_MAX_MULT"
export PROC_SCAN_INTERVAL_SECS="$PROC_SCAN_INTERVAL_SECS"

echo "[ENV EXPORTS for build.rs] Set:"
echo "  LISTENER_HOST: $LISTENER_HOST, LISTENER_PORT: $LISTENER_PORT, PROTOCOL: $PROTOCOL"
echo "  PAYLOAD_ID: $PAYLOAD_ID, SLEEP_INTERVAL: $SLEEP_INTERVAL"
echo "  ENROLLMENT_CREDENTIAL: <redacted>, ALLOW_INSECURE_ISOLATED_LAB: $ALLOW_INSECURE_ISOLATED_LAB"
echo "  MIN_BG_OPSEC_SECS: $MIN_BG_OPSEC_SECS, REDUCED_ACTIVITY_SLEEP_SECS: $REDUCED_ACTIVITY_SLEEP_SECS"
# Add more echos for other critical env vars if needed for debugging

# Build the agent
echo "Building for $TARGET (Format: $FORMAT) with flags: $BUILD_FLAGS..."
if [[ "$TARGET" == *windows* ]]; then
    if command -v cross &> /dev/null; then
        cross build --locked $BUILD_FLAGS --target "$TARGET"
    else
        echo "Warning: 'cross' command not found. Attempting with 'cargo build'. Make sure Rust target '$TARGET' is installed."
        rustup target add "$TARGET" # Ensure target is installed
        cargo build --locked $BUILD_FLAGS --target "$TARGET"
    fi
else # For Linux, macOS, etc.
    cargo build --locked $BUILD_FLAGS --target "$TARGET"
fi

BUILD_SUCCESS=$?
if [ $BUILD_SUCCESS -ne 0 ]; then
    echo "ERROR: Cargo build failed with exit code $BUILD_SUCCESS" >&2
    exit $BUILD_SUCCESS
fi

# Determine the build directory
CARGO_TARGET_ROOT="${CARGO_TARGET_DIR:-target}"
if [ "$BUILD_TYPE" == "debug" ]; then
    CARGO_BUILD_DIR="$CARGO_TARGET_ROOT/$TARGET/debug"
else
    CARGO_BUILD_DIR="$CARGO_TARGET_ROOT/$TARGET/release" # Default to release
fi

# Print contents of build directory for debugging
if [ -d "$CARGO_BUILD_DIR" ]; then
    echo "Contents of $CARGO_BUILD_DIR before copy:" >&2
    ls -la "$CARGO_BUILD_DIR" >&2
else
    echo "ERROR: Build directory $CARGO_BUILD_DIR does not exist after build!" >&2
    exit 1
fi

# Copy the built artifact to the output directory specified by --output (or ORIGINAL_OUTPUT_DIR)
# OUTPUT_DIR is the absolute path from earlier logic, ORIGINAL_OUTPUT_DIR is what was passed via --output.
# The server expects the file in ORIGINAL_OUTPUT_DIR.
TARGET_ARTIFACT_PATH_IN_CARGO_DIR="$CARGO_BUILD_DIR/$AGENT_OUT"
FINAL_OUTPUT_PATH_FOR_SERVER="$ORIGINAL_OUTPUT_DIR/$AGENT_OUT" # Use the path server expects

if [ -f "$TARGET_ARTIFACT_PATH_IN_CARGO_DIR" ]; then
    if [ -n "$ORIGINAL_OUTPUT_DIR" ]; then
        echo "Copying $AGENT_OUT from $TARGET_ARTIFACT_PATH_IN_CARGO_DIR to specified output for server: $FINAL_OUTPUT_PATH_FOR_SERVER"
        mkdir -p "$ORIGINAL_OUTPUT_DIR" # Ensure server's expected output directory exists
        cp "$TARGET_ARTIFACT_PATH_IN_CARGO_DIR" "$FINAL_OUTPUT_PATH_FOR_SERVER"

        # Optionally, also copy to the absolute OUTPUT_DIR if it's different and set (e.g., for local inspection)
        if [ -n "$OUTPUT_DIR" ] && [ "$OUTPUT_DIR" != "$ORIGINAL_OUTPUT_DIR" ]; then
             echo "Also copying to local inspection path: $OUTPUT_DIR/$AGENT_OUT"
    mkdir -p "$OUTPUT_DIR"
             cp "$TARGET_ARTIFACT_PATH_IN_CARGO_DIR" "$OUTPUT_DIR/$AGENT_OUT"
        fi
        echo "Agent binary copied successfully."
    else
        echo "Warning: --output directory not specified. Agent binary is at $TARGET_ARTIFACT_PATH_IN_CARGO_DIR"
    fi
else
    echo "ERROR: agent binary not found at $TARGET_ARTIFACT_PATH_IN_CARGO_DIR" >&2
    echo "Contents of $CARGO_BUILD_DIR:" >&2
    ls -la "$CARGO_BUILD_DIR" >&2
    exit 1
fi

# Strip and compress if possible (operate on the file in server's expected location)
if [ -n "$ORIGINAL_OUTPUT_DIR" ] && [ -f "$FINAL_OUTPUT_PATH_FOR_SERVER" ]; then
    echo "Stripping binary at $FINAL_OUTPUT_PATH_FOR_SERVER..."
    strip "$FINAL_OUTPUT_PATH_FOR_SERVER" || echo "Warning: strip command failed or not available."
    # if command -v upx &> /dev/null; then
    #     echo "Compressing binary with upx..."
    #     upx --best --lzma "$FINAL_OUTPUT_PATH_FOR_SERVER"
    # fi
fi

# Final output checks
if [ -n "$ORIGINAL_OUTPUT_DIR" ]; then
  echo "Final contents of server's output directory ($ORIGINAL_OUTPUT_DIR):"
ls -la "$ORIGINAL_OUTPUT_DIR"
fi


echo "Build process completed"
