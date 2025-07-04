#!/bin/bash
# Build KindlyGuard for all supported platforms
# This script handles cross-compilation for Linux, macOS, and Windows

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

echo "🔧 KindlyGuard Cross-Platform Build Script"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Check for required tools
check_requirements() {
    echo "Checking requirements..."
    
    if ! command -v rustup &> /dev/null; then
        print_error "rustup is not installed"
        exit 1
    fi
    
    if ! command -v cargo &> /dev/null; then
        print_error "cargo is not installed"
        exit 1
    fi
    
    print_status "Rust toolchain is available"
    
    # Check if cross is available
    if command -v cross &> /dev/null; then
        print_status "cross is installed"
        USE_CROSS=true
    else
        print_warning "cross is not installed. Some targets may not build correctly."
        print_warning "Install with: cargo install cross --git https://github.com/cross-rs/cross"
        USE_CROSS=false
    fi
}

# Install cross if needed
install_cross() {
    if [ "$USE_CROSS" = false ]; then
        echo ""
        read -p "Would you like to install cross for better cross-compilation support? (y/N) " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Installing cross..."
            cargo install cross --git https://github.com/cross-rs/cross
            USE_CROSS=true
            print_status "cross installed successfully"
        fi
    fi
}

# Build for a specific target
build_target() {
    local target=$1
    local output_name=$2
    local binary_name="kindlyguard"
    
    echo ""
    echo "Building for $target..."
    
    # Determine build command
    if [ "$USE_CROSS" = true ] && [[ "$target" != "$(rustc -vV | sed -n 's/host: //p')" ]]; then
        BUILD_CMD="cross"
    else
        BUILD_CMD="cargo"
    fi
    
    # Build the server binary
    if $BUILD_CMD build --release --target "$target" --package kindly-guard-server; then
        print_status "Server build successful for $target"
        
        # Create output directory
        mkdir -p "release-artifacts/$target"
        
        # Copy binary with platform-specific extension
        case "$target" in
            *-windows-*)
                cp "target/$target/release/kindlyguard.exe" "release-artifacts/$target/" 2>/dev/null || \
                cp "target/$target/release/kindly-guard-server.exe" "release-artifacts/$target/kindlyguard.exe" 2>/dev/null
                ;;
            *)
                cp "target/$target/release/kindlyguard" "release-artifacts/$target/" 2>/dev/null || \
                cp "target/$target/release/kindly-guard-server" "release-artifacts/$target/kindlyguard" 2>/dev/null
                ;;
        esac
    else
        print_error "Server build failed for $target"
        return 1
    fi
    
    # Build the CLI binary
    if $BUILD_CMD build --release --target "$target" --package kindly-guard-cli; then
        print_status "CLI build successful for $target"
        
        # Copy CLI binary
        case "$target" in
            *-windows-*)
                cp "target/$target/release/kindly-guard-cli.exe" "release-artifacts/$target/" 2>/dev/null
                ;;
            *)
                cp "target/$target/release/kindly-guard-cli" "release-artifacts/$target/" 2>/dev/null
                ;;
        esac
    else
        print_error "CLI build failed for $target"
        return 1
    fi
    
    return 0
}

# Main build process
main() {
    check_requirements
    install_cross
    
    echo ""
    echo "Starting multi-platform build..."
    echo "================================"
    
    # Define targets
    TARGETS=(
        "x86_64-unknown-linux-gnu:linux-x64"
        "x86_64-apple-darwin:macos-x64"
        "aarch64-apple-darwin:macos-arm64"
        "x86_64-pc-windows-gnu:windows-x64"
    )
    
    # Track successful builds
    SUCCESSFUL_BUILDS=()
    FAILED_BUILDS=()
    
    # Build each target
    for target_info in "${TARGETS[@]}"; do
        IFS=':' read -r target output_name <<< "$target_info"
        
        if build_target "$target" "$output_name"; then
            SUCCESSFUL_BUILDS+=("$target")
        else
            FAILED_BUILDS+=("$target")
        fi
    done
    
    # Summary
    echo ""
    echo "Build Summary"
    echo "============="
    echo ""
    
    if [ ${#SUCCESSFUL_BUILDS[@]} -gt 0 ]; then
        echo "✅ Successful builds:"
        for target in "${SUCCESSFUL_BUILDS[@]}"; do
            print_status "$target"
        done
    fi
    
    if [ ${#FAILED_BUILDS[@]} -gt 0 ]; then
        echo ""
        echo "❌ Failed builds:"
        for target in "${FAILED_BUILDS[@]}"; do
            print_error "$target"
        done
    fi
    
    echo ""
    echo "Build artifacts are in: release-artifacts/"
    
    # Create checksums
    if [ ${#SUCCESSFUL_BUILDS[@]} -gt 0 ]; then
        echo ""
        echo "Creating checksums..."
        cd release-artifacts
        find . -type f -name "kindlyguard*" -exec sha256sum {} \; > checksums.txt
        print_status "Checksums created in release-artifacts/checksums.txt"
        cd ..
    fi
    
    # Return exit code based on failures
    if [ ${#FAILED_BUILDS[@]} -gt 0 ]; then
        return 1
    else
        return 0
    fi
}

# Run main function
main "$@"