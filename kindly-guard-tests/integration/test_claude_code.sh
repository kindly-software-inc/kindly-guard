#!/bin/bash
# Test script for KindlyGuard Claude Code MCP Integration

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MCP_DIR="$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

# Function to run a test
run_test() {
    local test_name=$1
    local test_command=$2
    
    log_test "$test_name"
    if eval "$test_command"; then
        log_info "✓ $test_name passed"
        ((TESTS_PASSED++))
    else
        log_error "✗ $test_name failed"
        ((TESTS_FAILED++))
    fi
}

# Test 1: Build MCP Server
test_build_mcp() {
    log_info "Building MCP server..."
    cd "$MCP_DIR"
    
    # Build in release mode
    cargo build --release
    
    # Check if binary exists
    [ -f "$MCP_DIR/target/release/kindly-guard" ]
}

# Test 2: Test MCP Protocol Compliance
test_mcp_protocol() {
    log_info "Testing MCP protocol compliance..."
    cd "$MCP_DIR"
    
    # Create test input for MCP initialize request
    cat > /tmp/mcp-test-init.json << 'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{"roots":{"listChanged":true},"sampling":{}},"clientInfo":{"name":"test-client","version":"1.0.0"}}}
EOF
    
    # Send initialize request
    local RESPONSE=$(echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | \
        timeout 5s "$MCP_DIR/target/release/kindly-guard" --stdio 2>/dev/null | head -n1)
    
    # Check if response contains required fields
    echo "$RESPONSE" | grep -q '"jsonrpc":"2.0"' && \
    echo "$RESPONSE" | grep -q '"id":1' && \
    echo "$RESPONSE" | grep -q '"result"'
}

# Test 3: Test Tool Registration
test_tool_registration() {
    log_info "Testing tool registration..."
    
    # Create a test session
    cat > /tmp/mcp-test-tools.sh << 'EOF'
#!/bin/bash
# Send initialize
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
sleep 0.5
# Send initialized notification
echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
sleep 0.5
# List tools
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
sleep 0.5
EOF
    
    chmod +x /tmp/mcp-test-tools.sh
    
    # Run the test
    local OUTPUT=$(/tmp/mcp-test-tools.sh | "$MCP_DIR/target/release/kindly-guard" --stdio 2>/dev/null)
    
    # Check if tools are listed
    echo "$OUTPUT" | grep -q '"scan_text"' && \
    echo "$OUTPUT" | grep -q '"scan_json"' && \
    echo "$OUTPUT" | grep -q '"monitor_threats"'
}

# Test 4: Test Threat Detection
test_threat_detection() {
    log_info "Testing threat detection..."
    
    # Create test script with malicious content
    cat > /tmp/mcp-test-threat.sh << 'EOF'
#!/bin/bash
# Initialize
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
sleep 0.5
echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
sleep 0.5
# Scan text with Unicode threat
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_text","arguments":{"text":"Hello\u202EWorld"}}}'
sleep 0.5
EOF
    
    chmod +x /tmp/mcp-test-threat.sh
    
    # Run the test
    local OUTPUT=$(/tmp/mcp-test-threat.sh | "$MCP_DIR/target/release/kindly-guard" --stdio 2>/dev/null)
    
    # Check if threat was detected
    echo "$OUTPUT" | grep -q '"threat_type"' || echo "$OUTPUT" | grep -q '"threats"'
}

# Test 5: Test JSON Scanning
test_json_scanning() {
    log_info "Testing JSON scanning..."
    
    # Create test with SQL injection in JSON
    cat > /tmp/mcp-test-json.sh << 'EOF'
#!/bin/bash
# Initialize
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
sleep 0.5
echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
sleep 0.5
# Scan JSON with SQL injection
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_json","arguments":{"json":{"query":"SELECT * FROM users WHERE id = 1 OR 1=1--"}}}}'
sleep 0.5
EOF
    
    chmod +x /tmp/mcp-test-json.sh
    
    # Run the test
    local OUTPUT=$(/tmp/mcp-test-json.sh | "$MCP_DIR/target/release/kindly-guard" --stdio 2>/dev/null)
    
    # Check if SQL injection was detected
    echo "$OUTPUT" | grep -q '"sql_injection"' || echo "$OUTPUT" | grep -q '"injection"' || echo "$OUTPUT" | grep -q '"threat"'
}

# Test 6: Test Performance Mode
test_performance_mode() {
    log_info "Testing performance mode..."
    
    # Run with enhanced mode if available
    local ENV_OUTPUT=$(KINDLY_GUARD_ENHANCED=true "$MCP_DIR/target/release/kindly-guard" --stdio < /tmp/mcp-test-init.json 2>&1 | head -n5)
    
    # Just check that it runs without errors
    echo "$ENV_OUTPUT" | grep -q '"jsonrpc"'
}

# Test 7: Test Error Handling
test_error_handling() {
    log_info "Testing error handling..."
    
    # Send invalid request
    local ERROR_OUTPUT=$(echo '{"jsonrpc":"2.0","id":1,"method":"invalid_method"}' | \
        timeout 5s "$MCP_DIR/target/release/kindly-guard" --stdio 2>/dev/null | head -n1)
    
    # Check for proper error response
    echo "$ERROR_OUTPUT" | grep -q '"error"' && \
    echo "$ERROR_OUTPUT" | grep -q '"code"'
}

# Test 8: Test Concurrent Requests
test_concurrent_requests() {
    log_info "Testing concurrent request handling..."
    
    # Create script with multiple rapid requests
    cat > /tmp/mcp-test-concurrent.sh << 'EOF'
#!/bin/bash
# Initialize
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
sleep 0.2
echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
sleep 0.2
# Send multiple requests quickly
for i in {2..10}; do
    echo "{\"jsonrpc\":\"2.0\",\"id\":$i,\"method\":\"tools/call\",\"params\":{\"name\":\"scan_text\",\"arguments\":{\"text\":\"Test $i\"}}}"
done
sleep 1
EOF
    
    chmod +x /tmp/mcp-test-concurrent.sh
    
    # Run the test
    local OUTPUT=$(/tmp/mcp-test-concurrent.sh | timeout 10s "$MCP_DIR/target/release/kindly-guard" --stdio 2>/dev/null)
    
    # Count responses
    local RESPONSE_COUNT=$(echo "$OUTPUT" | grep -c '"id":[0-9]' || echo "0")
    
    # Should have at least 5 responses
    [ $RESPONSE_COUNT -ge 5 ]
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    
    # Remove test files
    rm -f /tmp/mcp-test-*.json
    rm -f /tmp/mcp-test-*.sh
}

# Main test execution
main() {
    log_info "Starting Claude Code MCP Integration Tests"
    log_info "==========================================="
    
    # Set up cleanup on exit
    trap cleanup EXIT
    
    # Run tests
    run_test "Build MCP Server" test_build_mcp
    run_test "MCP Protocol Compliance" test_mcp_protocol
    run_test "Tool Registration" test_tool_registration
    run_test "Threat Detection" test_threat_detection
    run_test "JSON Scanning" test_json_scanning
    run_test "Performance Mode" test_performance_mode
    run_test "Error Handling" test_error_handling
    run_test "Concurrent Requests" test_concurrent_requests
    
    # Summary
    echo
    log_info "Test Summary"
    log_info "============"
    log_info "Tests passed: $TESTS_PASSED"
    log_error "Tests failed: $TESTS_FAILED"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        log_info "All tests passed! ✓"
        exit 0
    else
        log_error "Some tests failed! ✗"
        exit 1
    fi
}

# Run main function
main "$@"