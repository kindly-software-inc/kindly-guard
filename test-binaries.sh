#!/bin/bash

# KindlyGuard Binary Testing Script
# Tests compiled binaries across platforms to ensure they work correctly

set -e

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
DIST_DIR="$PROJECT_ROOT/dist"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_header() {
    echo
    echo -e "${BLUE}==== $1 ====${NC}"
    echo
}

# Detect current platform
detect_platform() {
    local platform=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case "$platform" in
        linux) CURRENT_PLATFORM="linux" ;;
        darwin) CURRENT_PLATFORM="darwin" ;;
        mingw*|msys*|cygwin*) CURRENT_PLATFORM="win32" ;;
        *) print_error "Unsupported platform: $platform"; exit 1 ;;
    esac
    
    case "$arch" in
        x86_64|amd64) CURRENT_ARCH="x64" ;;
        aarch64|arm64) CURRENT_ARCH="arm64" ;;
        *) print_error "Unsupported architecture: $arch"; exit 1 ;;
    esac
}

# Test binary execution
test_binary() {
    local binary_path=$1
    local test_name=$2
    
    print_info "Testing $test_name: $binary_path"
    
    if [ ! -f "$binary_path" ]; then
        print_error "  Binary not found"
        return 1
    fi
    
    # Check if executable
    if [ ! -x "$binary_path" ]; then
        print_warning "  Binary not executable, fixing..."
        chmod +x "$binary_path"
    fi
    
    # Test version command
    if "$binary_path" --version &>/dev/null; then
        local version=$("$binary_path" --version 2>&1 | head -1)
        print_status "  Version: $version"
    else
        print_error "  Failed to get version"
        return 1
    fi
    
    # Test help command
    if "$binary_path" --help &>/dev/null; then
        print_status "  Help command works"
    else
        print_error "  Help command failed"
        return 1
    fi
    
    return 0
}

# Test MCP server functionality
test_mcp_server() {
    local binary_path=$1
    
    print_info "Testing MCP server functionality"
    
    # Create test configuration
    local test_config=$(mktemp)
    cat > "$test_config" <<EOF
{
  "threshold": {
    "unicode": 0.7,
    "injection": 0.8,
    "pattern": 0.75
  }
}
EOF
    
    # Test server startup
    print_info "  Starting server..."
    timeout 5s "$binary_path" --stdio < /dev/null &>/dev/null && {
        print_status "  Server starts successfully"
    } || {
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            print_status "  Server runs (timeout expected)"
        else
            print_error "  Server failed to start (exit code: $exit_code)"
            rm -f "$test_config"
            return 1
        fi
    }
    
    rm -f "$test_config"
    return 0
}

# Test CLI functionality
test_cli() {
    local binary_path=$1
    
    print_info "Testing CLI functionality"
    
    # Create test file
    local test_file=$(mktemp)
    echo "Hello World" > "$test_file"
    
    # Test scan command
    if "$binary_path" scan "$test_file" &>/dev/null; then
        print_status "  Scan command works"
    else
        print_warning "  Scan command not available"
    fi
    
    rm -f "$test_file"
    return 0
}

# Verify checksums
verify_checksums() {
    local platform_dir=$1
    
    print_info "Verifying checksums for $(basename "$platform_dir")"
    
    if [ ! -f "$platform_dir/checksums.txt" ]; then
        print_warning "  No checksums file found"
        return 0
    fi
    
    cd "$platform_dir"
    
    if command -v sha256sum &>/dev/null; then
        if sha256sum -c checksums.txt &>/dev/null; then
            print_status "  All checksums valid"
        else
            print_error "  Checksum verification failed"
            cd - >/dev/null
            return 1
        fi
    elif command -v shasum &>/dev/null; then
        if shasum -a 256 -c checksums.txt &>/dev/null; then
            print_status "  All checksums valid"
        else
            print_error "  Checksum verification failed"
            cd - >/dev/null
            return 1
        fi
    else
        print_warning "  No checksum tool available"
    fi
    
    cd - >/dev/null
    return 0
}

# Test current platform binaries
test_current_platform() {
    print_header "Testing Current Platform Binaries"
    
    detect_platform
    local platform_dir="$DIST_DIR/${CURRENT_PLATFORM}-${CURRENT_ARCH}"
    
    print_info "Current platform: ${CURRENT_PLATFORM}-${CURRENT_ARCH}"
    
    if [ ! -d "$platform_dir" ]; then
        print_error "No binaries found for current platform"
        return 1
    fi
    
    # Verify checksums first
    verify_checksums "$platform_dir"
    
    # Determine binary extension
    local ext=""
    if [ "$CURRENT_PLATFORM" = "win32" ]; then
        ext=".exe"
    fi
    
    # Test main binary
    if [ -f "$platform_dir/kindlyguard${ext}" ]; then
        test_binary "$platform_dir/kindlyguard${ext}" "KindlyGuard Server"
        test_mcp_server "$platform_dir/kindlyguard${ext}"
    fi
    
    # Test CLI
    if [ -f "$platform_dir/kindlyguard-cli${ext}" ]; then
        test_binary "$platform_dir/kindlyguard-cli${ext}" "KindlyGuard CLI"
        test_cli "$platform_dir/kindlyguard-cli${ext}"
    fi
    
    # Test shield if present
    if [ -f "$platform_dir/kindly-guard-shield${ext}" ]; then
        test_binary "$platform_dir/kindly-guard-shield${ext}" "KindlyGuard Shield"
    fi
}

# Test all platforms (basic checks)
test_all_platforms() {
    print_header "Testing All Platform Binaries"
    
    local test_results=()
    
    for platform_dir in "$DIST_DIR"/*; do
        if [ -d "$platform_dir" ]; then
            local platform_name=$(basename "$platform_dir")
            print_info "Checking $platform_name"
            
            # Verify checksums
            if verify_checksums "$platform_dir"; then
                test_results+=("$platform_name: PASS")
            else
                test_results+=("$platform_name: FAIL")
            fi
            
            # Check binary presence
            local has_binaries=false
            for binary in "$platform_dir"/kindlyguard*; do
                if [ -f "$binary" ]; then
                    has_binaries=true
                    print_status "  Found: $(basename "$binary")"
                fi
            done
            
            if [ "$has_binaries" = false ]; then
                print_error "  No binaries found"
            fi
        fi
    done
    
    # Print summary
    print_header "Test Summary"
    for result in "${test_results[@]}"; do
        echo "  $result"
    done
}

# Test npm packages
test_npm_packages() {
    print_header "Testing NPM Packages"
    
    local npm_dir="$PROJECT_ROOT/npm-package/npm"
    
    if [ ! -d "$npm_dir" ]; then
        print_warning "No npm packages found"
        return 0
    fi
    
    for platform_dir in "$npm_dir"/*; do
        if [ -d "$platform_dir" ]; then
            local platform_name=$(basename "$platform_dir")
            print_info "Testing npm package: $platform_name"
            
            # Check package.json
            if [ -f "$platform_dir/package.json" ]; then
                local pkg_name=$(node -p "require('$platform_dir/package.json').name" 2>/dev/null || echo "unknown")
                local pkg_version=$(node -p "require('$platform_dir/package.json').version" 2>/dev/null || echo "unknown")
                print_status "  Package: $pkg_name@$pkg_version"
            else
                print_error "  Missing package.json"
            fi
            
            # Check for binaries
            local binary_count=$(find "$platform_dir" -name "kindlyguard*" -type f | wc -l)
            if [ $binary_count -gt 0 ]; then
                print_status "  Binaries: $binary_count found"
            else
                print_error "  No binaries found"
            fi
            
            # Verify checksums
            verify_checksums "$platform_dir"
        fi
    done
}

# Run integration test
run_integration_test() {
    print_header "Running Integration Test"
    
    detect_platform
    local platform_dir="$DIST_DIR/${CURRENT_PLATFORM}-${CURRENT_ARCH}"
    local ext=""
    if [ "$CURRENT_PLATFORM" = "win32" ]; then
        ext=".exe"
    fi
    
    local server_binary="$platform_dir/kindlyguard${ext}"
    
    if [ ! -f "$server_binary" ]; then
        print_warning "Server binary not found, skipping integration test"
        return 0
    fi
    
    print_info "Starting MCP server..."
    
    # Create test input
    local test_input='{"jsonrpc":"2.0","method":"initialize","params":{"clientInfo":{"name":"test"}},"id":1}'
    
    # Run server with test input
    local response=$(echo "$test_input" | timeout 2s "$server_binary" --stdio 2>/dev/null || true)
    
    if [[ "$response" == *"\"result\""* ]]; then
        print_status "Server responds to MCP protocol"
    else
        print_error "Server did not respond correctly"
    fi
}

# Main execution
main() {
    print_header "KindlyGuard Binary Testing"
    
    # Check if dist directory exists
    if [ ! -d "$DIST_DIR" ]; then
        print_error "Distribution directory not found. Run build-binaries.sh first."
        exit 1
    fi
    
    # Run tests based on arguments
    case "${1:-all}" in
        current)
            test_current_platform
            ;;
        npm)
            test_npm_packages
            ;;
        integration)
            run_integration_test
            ;;
        all)
            test_current_platform
            echo
            test_all_platforms
            echo
            test_npm_packages
            echo
            run_integration_test
            ;;
        *)
            echo "Usage: $0 [current|npm|integration|all]"
            echo "  current     - Test binaries for current platform"
            echo "  npm         - Test npm packages"
            echo "  integration - Run integration tests"
            echo "  all         - Run all tests (default)"
            exit 1
            ;;
    esac
    
    print_header "Testing Complete"
}

# Run main function
main "$@"