# MicroC2 Agent Testing Framework

This directory contains comprehensive testing tools for the MicroC2 agent, designed to help you develop with minimal AI assistance while ensuring security and reliability.

## Quick Start

```bash
# Setup (first time only)
./dev.sh deps

# Daily development testing
./dev.sh test

# Before committing changes  
./dev.sh test-full

# Build and size check
./dev.sh build-release
```

## Test Scripts Overview

### 1. `agent_test_suite.py` - Comprehensive Test Suite

A full-featured testing framework covering all agent capabilities:

**Test Categories:**
- **Crypto**: Cryptographic functions (key derivation, encryption/decryption)
- **Build**: Build system, compilation, cross-compilation  
- **Config**: Configuration handling and validation
- **Network**: HTTP/HTTPS clients, SOCKS5 protocol
- **OPSEC**: Threat detection, process scanning, scoring
- **Files**: Upload/download operations
- **Commands**: Command execution and shell operations
- **Integration**: End-to-end workflows and mock C2 communication

**Usage:**
```bash
# Run all tests
python agent_test_suite.py

# Run specific test category
python agent_test_suite.py crypto --verbose

# Run with performance profiling
python agent_test_suite.py build --profile

# Run integration tests only
python agent_test_suite.py integration
```

### 2. `quick_test.py` - Development Testing

Lightweight testing for rapid development iteration:

```bash
# Quick unit tests only
python quick_test.py

# Include build verification
python quick_test.py --build

# Include crypto validation
python quick_test.py --crypto --verbose
```

## Prerequisites

Install required Python dependencies:

```bash
pip install requests cryptography psutil
```

## Test Categories Explained

### Cryptographic Tests
- **Key Derivation**: Validates the secure ChaCha20-based key derivation
- **Encryption Roundtrip**: Tests AES-256-GCM and ChaCha20-Poly1305 
- **Entropy Analysis**: Ensures keys have proper randomness distribution
- **Performance**: Benchmarks key derivation speed (target: <100μs)

### Build System Tests  
- **Compilation**: Verifies code compiles without errors
- **Unit Tests**: Runs all Rust unit tests
- **Release Build**: Creates optimized binary and checks size
- **Cross-compilation**: Tests Windows target (if available)

### OPSEC Tests
- **Process Detection**: Simulates security tool detection
- **Threat Scoring**: Validates OPSEC scoring algorithm
- **Mode Switching**: Tests background/reduced/full mode logic

### Integration Tests
- **Mock C2**: Starts local HTTP server to test agent communication
- **End-to-end**: Simulates complete agent workflow
- **Network Connectivity**: Tests various network scenarios

## Development Workflow

### Daily Development
```bash
# Quick validation during development
python quick_test.py

# After crypto changes
python quick_test.py --crypto

# Before committing
python quick_test.py --build
```

### Comprehensive Testing
```bash
# Full test suite before releases
python agent_test_suite.py --verbose

# Performance analysis
python agent_test_suite.py --profile

# Specific area testing
python agent_test_suite.py network --verbose
```

### Debugging Failed Tests

1. **Build Failures**: Check compiler errors in verbose output
2. **Crypto Failures**: Verify key derivation consistency
3. **Network Failures**: Check external connectivity requirements
4. **OPSEC Failures**: Validate process detection logic

## Test Output Interpretation

### Success Indicators
- ✅ Green PASS status
- All tests show `X/X passed`
- Binary size within expected range (~2-3MB)
- Key derivation performance <100μs

### Warning Signs  
- ⚠️ Yellow status (partial failures)
- High binary size (>10MB)
- Slow crypto operations (>1000μs)
- Network timeouts

### Critical Issues
- ❌ Red FAIL status
- Compilation errors
- Crypto entropy failures  
- Zero-byte keys or high zero count

## Extending the Test Suite

### Adding New Tests

1. **Choose appropriate test suite class**:
   - `CryptographyTests`: For crypto-related functionality
   - `BuildSystemTests`: For build/compilation features
   - `OPSECTests`: For security and detection logic
   - `NetworkTests`: For communication features
   - `IntegrationTests`: For multi-component scenarios

2. **Create test method**:
   ```python
   def test_your_feature(self) -> Tuple[bool, str, Dict]:
       # Test logic here
       success = your_test_logic()
       return (success, "Test description", {"details": "data"})
   ```

3. **Follow naming convention**: `test_feature_name`

### Test Method Return Format
```python
return (
    success: bool,           # True if test passed
    message: str,            # Human-readable result
    details: Dict           # Additional data for debugging
)
```

## Security Testing Focus

The test suite pays special attention to:

1. **Key Derivation Security**: Ensures no zero-padding vulnerabilities
2. **Entropy Validation**: Confirms cryptographic keys have proper randomness
3. **OPSEC Compliance**: Tests threat detection and evasion capabilities
4. **Memory Safety**: Validates encrypted state handling

## Performance Benchmarks

Target performance metrics:
- Key derivation: <100μs per operation
- Binary size: 2-5MB for release builds  
- Build time: <2 minutes for full release
- Test execution: <30 seconds for quick tests

## Troubleshooting

### Common Issues

**"Missing dependencies"**:
```bash
pip install requests cryptography psutil
```

**"Cargo not found"**:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

**"Cross-compilation failed"**:
```bash
rustup target add x86_64-pc-windows-gnu
# Install mingw-w64 for your system
```

**"Network tests failing"**:
- Check internet connectivity
- Verify firewall settings
- Tests gracefully degrade to offline mode when needed

## Contributing

When adding new agent functionality:

1. Add corresponding tests to appropriate test suite
2. Run full test suite before committing
3. Update performance benchmarks if needed
4. Document any new test dependencies

The goal is to maintain high test coverage while keeping the tests fast and reliable for daily development use.