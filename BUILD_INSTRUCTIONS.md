# KindlyGuard Build Instructions

This document provides detailed instructions for building KindlyGuard binaries across different platforms.

## Prerequisites

### All Platforms
- Rust 1.75 or later
- Git

### Platform-Specific Requirements

#### Linux
- Standard build tools (gcc, make)
- OpenSSL development headers (libssl-dev on Ubuntu/Debian)

#### macOS
- Xcode Command Line Tools
- Homebrew (optional, for dependencies)

#### Cross-Compilation
- For Linux → macOS: cargo-zigbuild or osxcross
- For macOS → Linux: Built-in Rust cross-compilation

## Building Native Binaries

### Linux (x86_64)

```bash
# Clone the repository
git clone https://github.com/yourusername/kindly-guard.git
cd kindly-guard

# Build server
cd kindly-guard-server
cargo build --release --target x86_64-unknown-linux-gnu

# Build CLI
cd ../kindly-guard-cli
cargo build --release --target x86_64-unknown-linux-gnu

# Binaries will be in:
# target/x86_64-unknown-linux-gnu/release/kindlyguard
# target/x86_64-unknown-linux-gnu/release/kindlyguard-cli
```

### macOS (Intel x64)

```bash
# On a macOS machine
cd kindly-guard

# Build server
cd kindly-guard-server
cargo build --release --target x86_64-apple-darwin

# Build CLI
cd ../kindly-guard-cli
cargo build --release --target x86_64-apple-darwin
```

### macOS (Apple Silicon ARM64)

```bash
# On a macOS machine
cd kindly-guard

# Build server
cd kindly-guard-server
cargo build --release --target aarch64-apple-darwin

# Build CLI
cd ../kindly-guard-cli
cargo build --release --target aarch64-apple-darwin
```

## Cross-Compilation

### From Linux to macOS (using cargo-zigbuild)

```bash
# Install cargo-zigbuild
cargo install cargo-zigbuild

# Build for macOS x64
cd kindly-guard-server
cargo zigbuild --release --target x86_64-apple-darwin

cd ../kindly-guard-cli
cargo zigbuild --release --target x86_64-apple-darwin

# Build for macOS ARM64
cd ../kindly-guard-server
cargo zigbuild --release --target aarch64-apple-darwin

cd ../kindly-guard-cli
cargo zigbuild --release --target aarch64-apple-darwin
```

**Note**: If you encounter framework linking errors, you may need to:
1. Use a macOS machine for building macOS binaries
2. Set up osxcross with proper SDK
3. Use GitHub Actions for automated builds

### From macOS to Linux

```bash
# Add Linux target
rustup target add x86_64-unknown-linux-gnu

# Install cross-compilation tools
brew install messense/macos-cross-toolchains/x86_64-unknown-linux-gnu

# Build
cargo build --release --target x86_64-unknown-linux-gnu
```

## Creating Distribution Packages

### Package Structure

Each distribution package should contain:
```
kindlyguard-{platform}/
├── kindlyguard         # Main server binary
├── kindlyguard-cli     # CLI binary
├── README.md           # Quick start guide
└── LICENSE             # License file
```

### Creating Archives

```bash
# Create distribution directory
mkdir -p dist

# Linux x64
mkdir -p dist/kindlyguard-linux-x64
cp target/x86_64-unknown-linux-gnu/release/kindlyguard dist/kindlyguard-linux-x64/
cp target/x86_64-unknown-linux-gnu/release/kindlyguard-cli dist/kindlyguard-linux-x64/
cp README.md LICENSE dist/kindlyguard-linux-x64/
cd dist && tar czf kindlyguard-linux-x64.tar.gz kindlyguard-linux-x64/

# macOS x64
mkdir -p dist/kindlyguard-darwin-x64
cp target/x86_64-apple-darwin/release/kindlyguard dist/kindlyguard-darwin-x64/
cp target/x86_64-apple-darwin/release/kindlyguard-cli dist/kindlyguard-darwin-x64/
cp README.md LICENSE dist/kindlyguard-darwin-x64/
cd dist && tar czf kindlyguard-darwin-x64.tar.gz kindlyguard-darwin-x64/

# macOS ARM64
mkdir -p dist/kindlyguard-darwin-arm64
cp target/aarch64-apple-darwin/release/kindlyguard dist/kindlyguard-darwin-arm64/
cp target/aarch64-apple-darwin/release/kindlyguard-cli dist/kindlyguard-darwin-arm64/
cp README.md LICENSE dist/kindlyguard-darwin-arm64/
cd dist && tar czf kindlyguard-darwin-arm64.tar.gz kindlyguard-darwin-arm64/
```

## Automated Build Script

Create `build-all.sh`:

```bash
#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "Building KindlyGuard for all platforms..."

# Function to build for a target
build_target() {
    local target=$1
    local name=$2
    
    echo "Building for $name ($target)..."
    
    cd kindly-guard-server
    if cargo build --release --target "$target"; then
        echo -e "${GREEN}✓ Server built for $name${NC}"
    else
        echo -e "${RED}✗ Failed to build server for $name${NC}"
        return 1
    fi
    
    cd ../kindly-guard-cli
    if cargo build --release --target "$target"; then
        echo -e "${GREEN}✓ CLI built for $name${NC}"
    else
        echo -e "${RED}✗ Failed to build CLI for $name${NC}"
        return 1
    fi
    
    cd ..
}

# Build all targets
build_target "x86_64-unknown-linux-gnu" "Linux x64"

# Try to build macOS targets (may fail on Linux)
if command -v cargo-zigbuild &> /dev/null; then
    echo "Using cargo-zigbuild for macOS targets..."
    
    cd kindly-guard-server
    cargo zigbuild --release --target x86_64-apple-darwin || echo "macOS x64 build failed"
    cargo zigbuild --release --target aarch64-apple-darwin || echo "macOS ARM64 build failed"
    
    cd ../kindly-guard-cli
    cargo zigbuild --release --target x86_64-apple-darwin || echo "macOS x64 build failed"
    cargo zigbuild --release --target aarch64-apple-darwin || echo "macOS ARM64 build failed"
    
    cd ..
else
    echo "cargo-zigbuild not found, skipping macOS builds"
fi

echo "Build complete! Check target/ directory for binaries."
```

## Build Optimization

### Release Profile

Ensure your `Cargo.toml` has optimized release settings:

```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
panic = "abort"
```

### Binary Size Reduction

```bash
# Install cargo-bloat to analyze binary size
cargo install cargo-bloat

# Analyze what's taking space
cargo bloat --release --target x86_64-unknown-linux-gnu

# Use upx for additional compression (optional)
upx --best target/release/kindlyguard
```

## Troubleshooting Build Issues

### Common Problems

1. **Missing OpenSSL on Linux**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libssl-dev pkg-config
   
   # Fedora/RHEL
   sudo dnf install openssl-devel
   ```

2. **macOS Framework Errors (Cross-compilation)**
   - This is a known issue with cross-compiling to macOS
   - Use GitHub Actions or a real macOS machine for reliable builds

3. **Rust Target Not Installed**
   ```bash
   # List installed targets
   rustup target list --installed
   
   # Add missing target
   rustup target add x86_64-apple-darwin
   ```

4. **Linking Errors**
   - Ensure you have the correct linker for the target platform
   - Check `~/.cargo/config.toml` for linker configuration

### Debug Build Issues

```bash
# Verbose build output
cargo build --release --verbose

# Check dependencies
cargo tree

# Clean and rebuild
cargo clean
cargo build --release
```

## CI/CD Build Setup

For reliable cross-platform builds, use GitHub Actions:

```yaml
# .github/workflows/build.yml
name: Build

on: [push, pull_request]

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
            name: linux-x64
          - os: macos-latest
            target: x86_64-apple-darwin
            name: darwin-x64
          - os: macos-latest
            target: aarch64-apple-darwin
            name: darwin-arm64
    
    runs-on: ${{ matrix.os }}
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      
      - name: Build
        run: |
          cargo build --release --target ${{ matrix.target }}
      
      - name: Package
        run: |
          mkdir -p dist/kindlyguard-${{ matrix.name }}
          cp target/${{ matrix.target }}/release/kindlyguard dist/kindlyguard-${{ matrix.name }}/
          cp target/${{ matrix.target }}/release/kindlyguard-cli dist/kindlyguard-${{ matrix.name }}/
          tar czf kindlyguard-${{ matrix.name }}.tar.gz -C dist kindlyguard-${{ matrix.name }}
      
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: kindlyguard-${{ matrix.name }}
          path: kindlyguard-${{ matrix.name }}.tar.gz
```

## Verifying Builds

After building, verify the binaries:

```bash
# Check binary architecture
file target/release/kindlyguard

# Run basic functionality test
./target/release/kindlyguard --version
./target/release/kindlyguard-cli --help

# Check for dynamic dependencies
ldd target/release/kindlyguard  # Linux
otool -L target/release/kindlyguard  # macOS
```

## Next Steps

1. Set up GitHub Actions for automated builds
2. Create release workflow for publishing binaries
3. Set up code signing for macOS binaries
4. Configure reproducible builds
5. Add build status badges to README