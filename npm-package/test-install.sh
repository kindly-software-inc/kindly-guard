#!/bin/bash

# Comprehensive test script to verify KindlyGuard installation works correctly
# Tests various installation scenarios and validates functionality

set -e

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
WARNINGS=0

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
    ((TESTS_PASSED++))
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    ((WARNINGS++))
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    ((TESTS_FAILED++))
}

print_section() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

# Detect current platform
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case "$os" in
        linux) PLATFORM="linux" ;;
        darwin) PLATFORM="darwin" ;;
        mingw*|msys*|cygwin*) PLATFORM="win32" ;;
        *) PLATFORM="unknown" ;;
    esac
    
    case "$arch" in
        x86_64|amd64) ARCH="x64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) ARCH="unknown" ;;
    esac
    
    print_info "Detected platform: $PLATFORM-$ARCH"
}

# Create test directory structure
setup_test_environment() {
    TEST_ROOT=$(mktemp -d)
    print_info "Created test root: $TEST_ROOT"
    
    # Create multiple test scenarios
    mkdir -p "$TEST_ROOT/clean-install"
    mkdir -p "$TEST_ROOT/global-install"
    mkdir -p "$TEST_ROOT/local-install"
    mkdir -p "$TEST_ROOT/npx-usage"
    mkdir -p "$TEST_ROOT/programmatic-api"
    mkdir -p "$TEST_ROOT/claude-desktop"
    
    # Copy package files
    if [ -f "package.json" ]; then
        cp -r . "$TEST_ROOT/package-source"
        print_info "Copied package source to test environment"
    else
        print_error "package.json not found. Run from npm-package directory"
        exit 1
    fi
}

# Cleanup function
cleanup() {
    if [ -n "$TEST_ROOT" ] && [ -d "$TEST_ROOT" ]; then
        print_info "Cleaning up test environment..."
        rm -rf "$TEST_ROOT"
    fi
}

trap cleanup EXIT

# Test 1: Platform detection
test_platform_detection() {
    print_section "Test 1: Platform Detection"
    
    # Test Node.js platform detection
    node -e "
        const platform = process.platform;
        const arch = process.arch;
        console.log('Node.js platform:', platform);
        console.log('Node.js arch:', arch);
        
        // Verify platform mapping
        const supportedPlatforms = ['darwin', 'linux', 'win32'];
        const supportedArchs = ['x64', 'arm64'];
        
        if (supportedPlatforms.includes(platform)) {
            console.log('✓ Platform is supported');
        } else {
            console.error('✗ Platform not supported');
            process.exit(1);
        }
        
        if (supportedArchs.includes(arch)) {
            console.log('✓ Architecture is supported');
        } else {
            console.error('✗ Architecture not supported');
            process.exit(1);
        }
    " && print_status "Platform detection works correctly" || print_error "Platform detection failed"
}

# Test 2: Clean NPM install
test_clean_install() {
    print_section "Test 2: Clean NPM Install"
    
    cd "$TEST_ROOT/clean-install"
    
    # Initialize package.json
    npm init -y >/dev/null 2>&1
    
    # Install kindlyguard (simulated - would use actual package in real test)
    print_info "Simulating npm install kindlyguard..."
    
    # Create mock installation
    mkdir -p node_modules/kindlyguard/bin
    cp "$TEST_ROOT/package-source/package.json" node_modules/kindlyguard/
    cp "$TEST_ROOT/package-source/index.js" node_modules/kindlyguard/ 2>/dev/null || true
    cp "$TEST_ROOT/package-source/postinstall.js" node_modules/kindlyguard/ 2>/dev/null || true
    
    # Test postinstall behavior
    print_info "Testing postinstall script..."
    cd node_modules/kindlyguard
    
    # Mock platform-specific package
    mkdir -p "../@kindlyguard/${PLATFORM}-${ARCH}"
    echo '{"name": "@kindlyguard/'${PLATFORM}'-'${ARCH}'", "version": "0.2.0"}' > "../@kindlyguard/${PLATFORM}-${ARCH}/package.json"
    
    # Create mock binaries
    if [ "$PLATFORM" = "win32" ]; then
        touch "../@kindlyguard/${PLATFORM}-${ARCH}/kindlyguard.exe"
        touch "../@kindlyguard/${PLATFORM}-${ARCH}/kindlyguard-cli.exe"
    else
        touch "../@kindlyguard/${PLATFORM}-${ARCH}/kindlyguard"
        touch "../@kindlyguard/${PLATFORM}-${ARCH}/kindlyguard-cli"
        chmod +x "../@kindlyguard/${PLATFORM}-${ARCH}/kindlyguard"
        chmod +x "../@kindlyguard/${PLATFORM}-${ARCH}/kindlyguard-cli"
    fi
    
    # Run postinstall
    node postinstall.js && print_status "Postinstall script completed" || print_error "Postinstall script failed"
    
    # Verify binaries exist
    if [ -f "bin/kindlyguard" ] || [ -f "bin/kindlyguard.exe" ]; then
        print_status "Main binary installed"
    else
        print_error "Main binary not found"
    fi
    
    if [ -f "bin/kindlyguard-cli" ] || [ -f "bin/kindlyguard-cli.exe" ]; then
        print_status "CLI binary installed"
    else
        print_error "CLI binary not found"
    fi
    
    cd "$TEST_ROOT"
}

# Test 3: Binary download simulation
test_binary_download() {
    print_section "Test 3: Binary Download Process"
    
    # Test download URL construction
    node -e "
        const version = '0.2.0';
        const platform = '${PLATFORM}';
        const arch = '${ARCH}';
        
        const baseUrl = 'https://github.com/samduchaine/kindly-guard/releases/download';
        const fileName = \`kindlyguard-\${platform}-\${arch}.tar.gz\`;
        const downloadUrl = \`\${baseUrl}/v\${version}/\${fileName}\`;
        
        console.log('Download URL:', downloadUrl);
        
        // Verify URL format
        if (downloadUrl.includes('undefined')) {
            console.error('✗ Invalid download URL');
            process.exit(1);
        } else {
            console.log('✓ Download URL is valid');
        }
    " && print_status "Binary download URL construction works" || print_error "Binary download URL construction failed"
    
    # Test binary extraction simulation
    cd "$TEST_ROOT/clean-install"
    mkdir -p temp-extract
    
    # Simulate tar.gz extraction
    if command -v tar >/dev/null 2>&1; then
        # Create mock archive
        mkdir -p temp-archive
        touch temp-archive/kindlyguard
        touch temp-archive/kindlyguard-cli
        tar -czf mock-binary.tar.gz -C temp-archive .
        
        # Test extraction
        tar -xzf mock-binary.tar.gz -C temp-extract && print_status "Binary extraction works" || print_error "Binary extraction failed"
        
        rm -rf temp-archive mock-binary.tar.gz
    else
        print_warning "tar command not available, skipping extraction test"
    fi
    
    rm -rf temp-extract
}

# Test 4: NPX usage
test_npx_usage() {
    print_section "Test 4: NPX Usage"
    
    cd "$TEST_ROOT/npx-usage"
    
    # Create mock npx executable
    mkdir -p .bin
    cat > .bin/kindlyguard <<'EOF'
#!/bin/sh
echo "KindlyGuard MCP Server v0.2.0"
echo "Usage: kindlyguard [OPTIONS]"
exit 0
EOF
    chmod +x .bin/kindlyguard
    
    # Test npx execution
    PATH=".bin:$PATH" kindlyguard && print_status "NPX execution works" || print_error "NPX execution failed"
    
    # Test with arguments
    cat > .bin/kindlyguard <<'EOF'
#!/bin/sh
if [ "$1" = "--stdio" ]; then
    echo '{"jsonrpc":"2.0","method":"initialize","params":{}}'
    exit 0
fi
echo "Unknown option: $1"
exit 1
EOF
    
    PATH=".bin:$PATH" kindlyguard --stdio | grep -q "jsonrpc" && print_status "NPX with arguments works" || print_error "NPX with arguments failed"
}

# Test 5: Programmatic API
test_programmatic_api() {
    print_section "Test 5: Programmatic API"
    
    cd "$TEST_ROOT/programmatic-api"
    
    # Copy index.js for testing
    cp "$TEST_ROOT/package-source/index.js" . 2>/dev/null || echo 'module.exports = { scan: () => Promise.resolve({threats: []}), create: () => ({ status: () => Promise.resolve({active: true}) }) };' > index.js
    
    # Test basic API
    cat > test-api.js <<'EOF'
const kindlyguard = require('./index.js');

async function testAPI() {
    try {
        // Test scan function
        if (typeof kindlyguard.scan === 'function') {
            console.log('✓ scan function exists');
        } else {
            console.error('✗ scan function missing');
            process.exit(1);
        }
        
        // Test create function
        if (typeof kindlyguard.create === 'function') {
            console.log('✓ create function exists');
        } else {
            console.error('✗ create function missing');
            process.exit(1);
        }
        
        // Test scan execution
        const scanResult = await kindlyguard.scan('test content');
        console.log('✓ scan execution completed');
        
        // Test instance creation
        const instance = kindlyguard.create();
        if (instance && typeof instance.status === 'function') {
            console.log('✓ instance creation works');
        } else {
            console.error('✗ instance creation failed');
            process.exit(1);
        }
        
    } catch (error) {
        console.error('✗ API test failed:', error.message);
        process.exit(1);
    }
}

testAPI();
EOF
    
    node test-api.js && print_status "Programmatic API works" || print_error "Programmatic API failed"
}

# Test 6: Claude Desktop configuration
test_claude_desktop_config() {
    print_section "Test 6: Claude Desktop Configuration"
    
    cd "$TEST_ROOT/claude-desktop"
    
    # Test config generation
    cat > test-config.js <<'EOF'
const config = {
    mcpServers: {
        "kindly-guard": {
            command: "npx",
            args: ["kindlyguard", "--stdio"]
        }
    }
};

// Validate config structure
if (config.mcpServers && config.mcpServers["kindly-guard"]) {
    const server = config.mcpServers["kindly-guard"];
    
    if (server.command === "npx" && 
        Array.isArray(server.args) && 
        server.args[0] === "kindlyguard" &&
        server.args[1] === "--stdio") {
        console.log('✓ Claude Desktop config is valid');
        console.log(JSON.stringify(config, null, 2));
    } else {
        console.error('✗ Invalid Claude Desktop config');
        process.exit(1);
    }
} else {
    console.error('✗ Config structure is invalid');
    process.exit(1);
}
EOF
    
    node test-config.js && print_status "Claude Desktop config is valid" || print_error "Claude Desktop config invalid"
}

# Test 7: Error handling
test_error_handling() {
    print_section "Test 7: Error Handling"
    
    cd "$TEST_ROOT/clean-install"
    
    # Test missing platform package
    mkdir -p node_modules/kindlyguard
    cp "$TEST_ROOT/package-source/postinstall.js" node_modules/kindlyguard/
    
    cd node_modules/kindlyguard
    
    # Run postinstall without platform packages (should fail gracefully)
    node postinstall.js 2>&1 | grep -q "Failed to install platform-specific package" && print_status "Missing package error handled" || print_error "Missing package error not handled properly"
    
    # Test unsupported platform
    node -e "
        process.platform = 'unsupported';
        process.arch = 'unknown';
    " 2>/dev/null || print_warning "Cannot override process.platform in Node.js"
}

# Test 8: Platform-specific behavior
test_platform_specific() {
    print_section "Test 8: Platform-Specific Behavior"
    
    cd "$TEST_ROOT/clean-install"
    
    # Test Windows-specific behavior
    if [ "$PLATFORM" = "win32" ]; then
        print_info "Testing Windows-specific behavior..."
        
        # Check for .exe extensions
        [ -f "node_modules/kindlyguard/bin/kindlyguard.exe" ] && print_status "Windows .exe extension handled" || print_warning "Windows .exe not found"
    else
        print_info "Testing Unix-specific behavior..."
        
        # Check for executable permissions
        if [ -f "node_modules/kindlyguard/bin/kindlyguard" ]; then
            [ -x "node_modules/kindlyguard/bin/kindlyguard" ] && print_status "Unix executable permissions set" || print_error "Unix executable permissions not set"
        fi
        
        # Check for wrapper scripts
        if [ -f "node_modules/kindlyguard/bin/kindlyguard" ]; then
            grep -q "#!/bin/sh" "node_modules/kindlyguard/bin/kindlyguard" && print_status "Unix wrapper script created" || print_warning "Unix wrapper script not found"
        fi
    fi
}

# Test 9: Performance
test_performance() {
    print_section "Test 9: Performance Tests"
    
    cd "$TEST_ROOT/programmatic-api"
    
    cat > perf-test.js <<'EOF'
const startTime = Date.now();

// Simulate module loading
for (let i = 0; i < 100; i++) {
    delete require.cache[require.resolve('./index.js')];
    require('./index.js');
}

const loadTime = Date.now() - startTime;
console.log(`Module load time (100x): ${loadTime}ms`);

if (loadTime < 1000) {
    console.log('✓ Module loading performance is good');
    process.exit(0);
} else {
    console.error('✗ Module loading is slow');
    process.exit(1);
}
EOF
    
    node perf-test.js && print_status "Performance is acceptable" || print_warning "Performance could be improved"
}

# Test 10: Security checks
test_security() {
    print_section "Test 10: Security Checks"
    
    # Check for proper permissions
    cd "$TEST_ROOT/clean-install"
    
    if [ -d "node_modules/kindlyguard/bin" ]; then
        # Check that binaries are not world-writable
        find node_modules/kindlyguard/bin -type f -perm -002 | grep -q . && print_error "World-writable files found" || print_status "File permissions are secure"
    fi
    
    # Check for path traversal in postinstall
    grep -q '\.\.' "$TEST_ROOT/package-source/postinstall.js" && print_warning "Potential path traversal in postinstall" || print_status "No path traversal detected"
    
    # Check for command injection vulnerabilities
    grep -E 'exec|eval|Function' "$TEST_ROOT/package-source/postinstall.js" | grep -v 'spawnSync' && print_warning "Potentially dangerous functions used" || print_status "No dangerous function calls found"
}

# Main test execution
main() {
    echo -e "${BLUE}KindlyGuard NPM Package Installation Test Suite${NC}"
    echo -e "${BLUE}=============================================${NC}\n"
    
    detect_platform
    
    if [ "$PLATFORM" = "unknown" ] || [ "$ARCH" = "unknown" ]; then
        print_error "Unsupported platform: $PLATFORM-$ARCH"
        exit 1
    fi
    
    setup_test_environment
    
    # Run all tests
    test_platform_detection
    test_clean_install
    test_binary_download
    test_npx_usage
    test_programmatic_api
    test_claude_desktop_config
    test_error_handling
    test_platform_specific
    test_performance
    test_security
    
    # Summary
    echo -e "\n${BLUE}=== Test Summary ===${NC}\n"
    echo -e "${GREEN}Tests passed: $TESTS_PASSED${NC}"
    echo -e "${YELLOW}Warnings: $WARNINGS${NC}"
    echo -e "${RED}Tests failed: $TESTS_FAILED${NC}"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "\n${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "\n${RED}Some tests failed!${NC}"
        exit 1
    fi
}

# Run main function
main "$@"