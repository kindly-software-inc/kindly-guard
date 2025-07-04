#!/bin/bash

# Test script for local npm package installation

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[i]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check current directory
if [ ! -f "package.json" ]; then
    print_error "Please run this script from the npm-package directory"
    exit 1
fi

# Create temporary test directory
TEST_DIR=$(mktemp -d)
print_info "Created test directory: $TEST_DIR"

# Cleanup on exit
cleanup() {
    print_info "Cleaning up..."
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Build local package for current platform
print_info "Building package for current platform..."
./build-npm-package.sh

# Get current platform
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$PLATFORM" in
    linux) PLATFORM_NAME="linux" ;;
    darwin) PLATFORM_NAME="darwin" ;;
    *) print_error "Unsupported platform: $PLATFORM"; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH_NAME="x64" ;;
    aarch64|arm64) ARCH_NAME="arm64" ;;
    *) print_error "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Copy binaries to bin directory for testing
print_info "Preparing test package..."
mkdir -p bin
cp ../target/release/kindly-guard bin/kindlyguard.bin 2>/dev/null || print_error "Server binary not found"
cp ../target/release/kindly-guard-cli bin/kindlyguard-cli.bin 2>/dev/null || print_error "CLI binary not found"
chmod +x bin/*.bin 2>/dev/null || true

# Pack the main package
print_info "Packing main package..."
PACKAGE_FILE=$(npm pack)
print_status "Package created: $PACKAGE_FILE"

# Test installation
cd "$TEST_DIR"
print_info "Installing package in test directory..."

# Copy and install the package
cp "$OLDPWD/$PACKAGE_FILE" .
npm install --no-save "./$PACKAGE_FILE"

print_status "Package installed successfully"

# Test the binaries
print_info "Testing installed binaries..."

# Test kindlyguard command
if npx kindlyguard --help >/dev/null 2>&1; then
    print_status "kindlyguard command works"
else
    print_error "kindlyguard command failed"
fi

# Test kindlyguard-cli command
if npx kindlyguard-cli --help >/dev/null 2>&1; then
    print_status "kindlyguard-cli command works"
else
    print_error "kindlyguard-cli command failed"
fi

# Test programmatic API
print_info "Testing programmatic API..."

cat > test-api.js <<'EOF'
const kindlyguard = require('kindlyguard');

console.log('Testing KindlyGuard API...');

// Test scan function
kindlyguard.scan('Hello world', { format: 'json' })
  .then(result => {
    console.log('Scan completed:', result);
  })
  .catch(err => {
    console.error('Scan failed:', err.message);
  });

// Test status
const kg = kindlyguard.create();
kg.status()
  .then(result => {
    console.log('Status check completed');
  })
  .catch(err => {
    console.error('Status check failed:', err.message);
  });

console.log('API test completed');
EOF

node test-api.js

print_status "All tests completed!"

# Show installation info
echo
print_info "Package details:"
print_info "  Name: kindlyguard"
print_info "  Version: $(node -p "require('./node_modules/kindlyguard/package.json').version")"
print_info "  Binaries:"
ls -la node_modules/kindlyguard/bin/

echo
print_info "To use in your project:"
print_info "  npm install kindlyguard"
print_info "  npx kindlyguard --stdio"