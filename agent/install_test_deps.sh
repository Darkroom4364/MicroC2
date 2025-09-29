#!/bin/bash
# MicroC2 Agent Test Dependencies Installer

echo "🔧 Installing MicroC2 Agent Test Dependencies"
echo "=============================================="

# Check if pip is available
if ! command -v pip &> /dev/null && ! command -v pip3 &> /dev/null; then
    echo "❌ pip not found. Please install pip first."
    exit 1
fi

# Determine pip command
PIP_CMD="pip"
if command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
fi

echo "📦 Using $PIP_CMD to install dependencies..."

# Core dependencies for comprehensive testing
echo "Installing core dependencies..."
$PIP_CMD install --user requests cryptography psutil

# Check installation
echo ""
echo "🧪 Verifying installation..."

python3 -c "
import sys
missing = []

try:
    import requests
    print('✅ requests - OK')
except ImportError:
    missing.append('requests')
    print('❌ requests - FAILED')

try:
    import cryptography
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    print('✅ cryptography - OK')
except ImportError:
    missing.append('cryptography')
    print('❌ cryptography - FAILED')

try:
    import psutil
    print('✅ psutil - OK')
except ImportError:
    missing.append('psutil')
    print('❌ psutil - FAILED')

if missing:
    print(f'\\n❌ Missing dependencies: {missing}')
    print('Try running: $PIP_CMD install --user --upgrade ' + ' '.join(missing))
    sys.exit(1)
else:
    print('\\n✅ All dependencies installed successfully!')
"

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 Setup complete! You can now run:"
    echo "   python3 agent_test_suite.py"
    echo "   python3 quick_test.py"
else
    echo ""
    echo "❌ Some dependencies failed to install"
    exit 1
fi