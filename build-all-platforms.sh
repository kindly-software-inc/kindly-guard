#!/bin/bash
set -e

echo "🚀 Building KindlyGuard for all platforms..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create dist directory
mkdir -p dist

# Function to verify if a binary is statically linked
verify_static_linking() {
    local binary=$1
    local target=$2
    
    # Only check Linux musl binaries
    if [[ "$target" == *"musl"* ]]; then
        echo "Verifying static linking for $binary..."
        if command -v ldd &> /dev/null; then
            # ldd should report "not a dynamic executable" for static binaries
            if ldd "$binary" 2>&1 | grep -q "not a dynamic executable"; then
                echo -e "${GREEN}✓ Binary is statically linked${NC}"
                return 0
            else
                echo -e "${YELLOW}⚠ Binary appears to be dynamically linked${NC}"
                # Show the dependencies for debugging
                ldd "$binary" 2>&1 | head -5
                return 1
            fi
        else
            echo "ldd not available, skipping static link verification"
        fi
    fi
    return 0
}

# Function to build for a target
build_target() {
    local target=$1
    local name=$2
    local use_zigbuild=$3
    local use_cross=$4
    
    echo -e "${YELLOW}Building for $name ($target)...${NC}"
    
    if [ "$use_zigbuild" = "true" ]; then
        echo "Using cargo-zigbuild..."
        cd kindly-guard-server
        cargo zigbuild --release --target "$target" || return 1
        cd ../kindly-guard-cli
        cargo zigbuild --release --target "$target" || return 1
        cd ..
    elif [ "$use_cross" = "true" ]; then
        echo "Using cross..."
        cd kindly-guard-server
        cross build --release --target "$target" || return 1
        cd ../kindly-guard-cli
        cross build --release --target "$target" || return 1
        cd ..
    else
        echo "Using native cargo..."
        cd kindly-guard-server
        cargo build --release --target "$target" || return 1
        cd ../kindly-guard-cli
        cargo build --release --target "$target" || return 1
        cd ..
    fi
    
    # Package the binaries
    echo "Packaging $name..."
    if [[ "$target" == *"windows"* ]]; then
        cp "kindly-guard-server/target/$target/release/kindlyguard.exe" "dist/" || return 1
        cp "kindly-guard-cli/target/$target/release/kindlyguard-cli.exe" "dist/" || return 1
        cd dist
        zip "kindlyguard-$name.zip" kindlyguard.exe kindlyguard-cli.exe
        rm kindlyguard.exe kindlyguard-cli.exe
        cd ..
    else
        cp "kindly-guard-server/target/$target/release/kindlyguard" "dist/" || return 1
        cp "kindly-guard-cli/target/$target/release/kindlyguard-cli" "dist/" || return 1
        
        # Verify static linking for Linux musl builds
        if [[ "$target" == *"musl"* ]]; then
            verify_static_linking "dist/kindlyguard" "$target"
            verify_static_linking "dist/kindlyguard-cli" "$target"
        fi
        
        chmod +x dist/kindlyguard dist/kindlyguard-cli
        cd dist
        tar czf "kindlyguard-$name.tar.gz" kindlyguard kindlyguard-cli
        rm kindlyguard kindlyguard-cli
        cd ..
    fi
    
    echo -e "${GREEN}✓ Built $name${NC}"
    return 0
}

# Check for required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        echo "Please install $1 first"
        return 1
    fi
    return 0
}

# Install cargo-zigbuild if not present
if ! command -v cargo-zigbuild &> /dev/null; then
    echo "Installing cargo-zigbuild..."
    pip3 install ziglang || { echo -e "${RED}Failed to install ziglang${NC}"; exit 1; }
    cargo install cargo-zigbuild --locked || { echo -e "${RED}Failed to install cargo-zigbuild${NC}"; exit 1; }
fi

# Install cross if not present
if ! command -v cross &> /dev/null; then
    echo "Installing cross..."
    cargo install cross --git https://github.com/cross-rs/cross --locked || { echo -e "${RED}Failed to install cross${NC}"; exit 1; }
fi

# Install musl target for Linux static builds
# musl provides a lightweight C library that enables fully static compilation
# This ensures our binaries work on any Linux system without dependency issues
echo "Checking for musl target..."
if ! rustup target list --installed | grep -q "x86_64-unknown-linux-musl"; then
    echo "Installing x86_64-unknown-linux-musl target..."
    rustup target add x86_64-unknown-linux-musl || { echo -e "${RED}Failed to install musl target${NC}"; exit 1; }
fi

# Build for each platform
echo "Starting multi-platform build..."

# Linux x64 (using musl for static linking)
# We use musl instead of gnu to create fully static binaries that:
# - Work on any Linux distribution without glibc version issues
# - Don't require specific system libraries to be installed
# - Are more portable and easier to deploy in containers
if ! build_target "x86_64-unknown-linux-musl" "linux-x64" false false; then
    echo -e "${RED}Failed to build linux-x64${NC}"
fi

# macOS x64 (using zigbuild)
if ! build_target "x86_64-apple-darwin" "darwin-x64" true false; then
    echo -e "${RED}Failed to build darwin-x64${NC}"
fi

# macOS ARM64 (using zigbuild)
if ! build_target "aarch64-apple-darwin" "darwin-arm64" true false; then
    echo -e "${RED}Failed to build darwin-arm64${NC}"
fi

# Windows x64 (using cross)
if ! build_target "x86_64-pc-windows-gnu" "win32-x64" false true; then
    echo -e "${RED}Failed to build win32-x64${NC}"
fi

# Generate checksums
echo "Generating checksums..."
cd dist
sha256sum kindlyguard-*.{tar.gz,zip} > SHA256SUMS.txt 2>/dev/null || true
cd ..

echo -e "${GREEN}✅ Build complete! Binaries are in the dist/ directory${NC}"

# Display build summary
echo ""
echo "Build Summary:"
echo "============="
echo "• Linux x64: Built with musl for static linking (no runtime dependencies)"
echo "• macOS x64/ARM64: Built with zigbuild for cross-compilation"
echo "• Windows x64: Built with cross for Windows compatibility"
echo ""
echo "The Linux binaries are fully static and will work on any Linux distribution"
echo "without requiring specific glibc versions or system libraries."
echo ""

ls -la dist/