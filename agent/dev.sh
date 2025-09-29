#!/bin/bash
# MicroC2 Agent Development Helper Script
# Provides common development tasks in an easy-to-use interface

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

show_help() {
    cat << EOF
MicroC2 Agent Development Helper

USAGE:
    ./dev.sh <command> [options]

COMMANDS:
    test                Run quick tests
    test-full          Run comprehensive test suite
    test-crypto        Test cryptographic functions only
    test-build         Test build system
    
    build              Build debug version
    build-release      Build release version
    build-windows      Cross-compile for Windows
    
    check              Run cargo check
    lint               Run cargo clippy (if available)
    format             Format code with rustfmt
    
    deps               Install test dependencies
    clean              Clean build artifacts
    size               Show binary size info
    
    help               Show this help

EXAMPLES:
    ./dev.sh test                    # Quick development tests
    ./dev.sh test-full --verbose     # Full test suite with details
    ./dev.sh build-release           # Optimized release build
    ./dev.sh size                    # Check binary sizes

EOF
}

run_tests() {
    echo "🧪 Running quick tests..."
    python3 quick_test.py "$@"
}

run_full_tests() {
    echo "🧪 Running comprehensive test suite..."
    python3 agent_test_suite.py "$@"
}

run_crypto_tests() {
    echo "🔐 Running cryptographic tests..."
    python3 agent_test_suite.py crypto "$@"
}

run_build_tests() {
    echo "🔨 Running build system tests..."
    python3 agent_test_suite.py build "$@"
}

build_debug() {
    echo "🔨 Building debug version..."
    cargo build --features encryption-chacha
    echo "✅ Debug build complete"
}

build_release() {
    echo "🔨 Building release version..."
    cargo build --release --features encryption-chacha
    echo "✅ Release build complete"
    show_binary_size
}

build_windows() {
    echo "🔨 Cross-compiling for Windows..."
    if rustup target list --installed | grep -q "x86_64-pc-windows-gnu"; then
        cargo build --target x86_64-pc-windows-gnu --features encryption-chacha
        echo "✅ Windows build complete"
    else
        echo "❌ Windows target not installed. Run: rustup target add x86_64-pc-windows-gnu"
        exit 1
    fi
}

check_code() {
    echo "🔍 Running cargo check..."
    cargo check --features encryption-chacha
    echo "✅ Check complete"
}

lint_code() {
    echo "🔍 Running cargo clippy..."
    if command -v cargo-clippy &> /dev/null; then
        cargo clippy --features encryption-chacha -- -D warnings
        echo "✅ Lint complete"
    else
        echo "❌ clippy not available. Install with: rustup component add clippy"
        exit 1
    fi
}

format_code() {
    echo "✨ Formatting code..."
    cargo fmt
    echo "✅ Format complete"
}

install_deps() {
    echo "📦 Installing test dependencies..."
    if [ -f "install_test_deps.sh" ]; then
        ./install_test_deps.sh
    else
        echo "❌ install_test_deps.sh not found"
        exit 1
    fi
}

clean_build() {
    echo "🧹 Cleaning build artifacts..."
    cargo clean
    echo "✅ Clean complete"
}

show_binary_size() {
    echo "📊 Binary size information:"
    echo "=========================="
    
    if [ -f "target/debug/agent" ]; then
        debug_size=$(du -h target/debug/agent | cut -f1)
        echo "Debug binary: $debug_size"
    fi
    
    if [ -f "target/release/agent" ]; then
        release_size=$(du -h target/release/agent | cut -f1)
        echo "Release binary: $release_size"
        
        if command -v size &> /dev/null; then
            echo ""
            echo "Release binary sections:"
            size target/release/agent
        fi
    fi
    
    if [ -f "target/x86_64-pc-windows-gnu/debug/agent.exe" ]; then
        windows_size=$(du -h target/x86_64-pc-windows-gnu/debug/agent.exe | cut -f1)
        echo "Windows binary: $windows_size"
    fi
}

# Main command dispatcher
case "$1" in
    "test")
        shift
        run_tests "$@"
        ;;
    "test-full")
        shift
        run_full_tests "$@"
        ;;
    "test-crypto")
        shift
        run_crypto_tests "$@"
        ;;
    "test-build")
        shift
        run_build_tests "$@"
        ;;
    "build")
        build_debug
        ;;
    "build-release")
        build_release
        ;;
    "build-windows")
        build_windows
        ;;
    "check")
        check_code
        ;;
    "lint")
        lint_code
        ;;
    "format")
        format_code
        ;;
    "deps")
        install_deps
        ;;
    "clean")
        clean_build
        ;;
    "size")
        show_binary_size
        ;;
    "help"|"--help"|"-h"|"")
        show_help
        ;;
    *)
        echo "❌ Unknown command: $1"
        echo "Run './dev.sh help' for usage information"
        exit 1
        ;;
esac