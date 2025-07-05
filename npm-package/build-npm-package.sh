#!/bin/bash

# KindlyGuard NPM Package Build Script
# This script prepares platform-specific npm packages with pre-built binaries

set -e

# Colors
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

# Check if we're in the right directory
if [ ! -f "../Cargo.toml" ] && [ ! -d "../kindlyguard-server" ]; then
    print_error "Please run this script from the npm-package directory"
    exit 1
fi

# Detect current platform
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$PLATFORM" in
    linux) PLATFORM_NAME="linux" ;;
    darwin) PLATFORM_NAME="darwin" ;;
    mingw*|msys*|cygwin*) PLATFORM_NAME="win32" ;;
    *) print_error "Unsupported platform: $PLATFORM"; exit 1 ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH_NAME="x64" ;;
    aarch64|arm64) ARCH_NAME="arm64" ;;
    *) print_error "Unsupported architecture: $ARCH"; exit 1 ;;
esac

PACKAGE_NAME="@kindlyguard/${PLATFORM_NAME}-${ARCH_NAME}"
PACKAGE_DIR="npm/${PLATFORM_NAME}-${ARCH_NAME}"

print_info "Building package for: ${PLATFORM_NAME}-${ARCH_NAME}"

# Create package directory
mkdir -p "$PACKAGE_DIR"

# Copy binaries from release build
print_info "Copying binaries..."

BINARY_EXT=""
if [ "$PLATFORM_NAME" = "win32" ]; then
    BINARY_EXT=".exe"
fi

# Check if binaries exist
if [ ! -f "../target/release/kindlyguard${BINARY_EXT}" ]; then
    print_error "Binary not found: ../target/release/kindlyguard${BINARY_EXT}"
    print_info "Please run 'cargo build --release' first"
    exit 1
fi

if [ ! -f "../target/release/kindlyguard-cli${BINARY_EXT}" ]; then
    print_error "Binary not found: ../target/release/kindlyguard-cli${BINARY_EXT}"
    print_info "Please run 'cargo build --release' first"
    exit 1
fi

# Copy binaries
cp "../target/release/kindlyguard${BINARY_EXT}" "$PACKAGE_DIR/kindlyguard${BINARY_EXT}"
cp "../target/release/kindlyguard-cli${BINARY_EXT}" "$PACKAGE_DIR/kindlyguard-cli${BINARY_EXT}"

print_status "Binaries copied"

# Create package.json for platform package
cat > "$PACKAGE_DIR/package.json" <<EOF
{
  "name": "$PACKAGE_NAME",
  "version": "0.2.0",
  "description": "KindlyGuard binaries for ${PLATFORM_NAME}-${ARCH_NAME}",
  "author": "samduchaine",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/samduchaine/kindly-guard.git"
  },
  "files": [
    "kindlyguard${BINARY_EXT}",
    "kindlyguard-cli${BINARY_EXT}"
  ],
  "os": ["${PLATFORM_NAME}"],
  "cpu": ["${ARCH_NAME}"]
}
EOF

print_status "Platform package created: $PACKAGE_DIR"

# Create README for platform package
cat > "$PACKAGE_DIR/README.md" <<EOF
# KindlyGuard Binaries for ${PLATFORM_NAME}-${ARCH_NAME}

This package contains pre-built KindlyGuard binaries for ${PLATFORM_NAME} ${ARCH_NAME}.

It is automatically installed as an optional dependency of the main \`kindlyguard\` package.

## Direct Usage

If you need to use the binaries directly:

\`\`\`bash
npm install $PACKAGE_NAME
\`\`\`

The binaries will be in \`node_modules/$PACKAGE_NAME/\`

## Main Package

For normal usage, install the main package instead:

\`\`\`bash
npm install -g kindlyguard
\`\`\`
EOF

# Calculate checksums
print_info "Calculating checksums..."

cd "$PACKAGE_DIR"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum kindlyguard* > checksums.txt
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 kindlyguard* > checksums.txt
else
    print_warning "No checksum tool found, skipping checksums"
fi
cd ../..

print_status "Package ready: $PACKAGE_DIR"

# Display package info
echo
print_info "Package details:"
print_info "  Name: $PACKAGE_NAME"
print_info "  Version: 0.2.0"
print_info "  Platform: ${PLATFORM_NAME}-${ARCH_NAME}"
print_info "  Files:"
ls -lh "$PACKAGE_DIR"/kindlyguard*

echo
print_info "To publish this package:"
print_info "  cd $PACKAGE_DIR"
print_info "  npm publish --access public"

echo
print_info "To test locally:"
print_info "  npm install ./$PACKAGE_DIR"