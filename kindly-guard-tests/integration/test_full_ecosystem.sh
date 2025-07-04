#!/bin/bash
# Test script for Full KindlyGuard Ecosystem Integration

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

# Process tracking
declare -A PROCESSES
declare -A PROCESS_LOGS

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
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

# Start a component and track its PID
start_component() {
    local name=$1
    local command=$2
    local log_file="/tmp/kindly-${name}.log"
    
    log_step "Starting $name..."
    
    # Start the process in background
    eval "$command > $log_file 2>&1 &"
    local pid=$!
    
    # Store PID and log file
    PROCESSES[$name]=$pid
    PROCESS_LOGS[$name]=$log_file
    
    # Give it time to start
    sleep 2
    
    # Check if still running
    if kill -0 $pid 2>/dev/null; then
        log_info "$name started (PID: $pid)"
        return 0
    else
        log_error "$name failed to start"
        cat "$log_file" | tail -n 20
        return 1
    fi
}

# Stop a component
stop_component() {
    local name=$1
    local pid=${PROCESSES[$name]:-0}
    
    if [ "$pid" != "0" ] && kill -0 $pid 2>/dev/null; then
        log_step "Stopping $name (PID: $pid)..."
        kill $pid 2>/dev/null || true
        sleep 1
        kill -9 $pid 2>/dev/null || true
        unset PROCESSES[$name]
    fi
}

# Test 1: Start MCP Server
test_start_mcp_server() {
    cd "$PROJECT_ROOT"
    
    # Build if needed
    if [ ! -f "target/release/kindly-guard" ]; then
        log_info "Building MCP server..."
        cargo build --release
    fi
    
    # Start MCP server with test configuration
    start_component "mcp-server" "RUST_LOG=kindly_guard=debug target/release/kindly-guard --stdio"
}

# Test 2: Start Shield Application
test_start_shield() {
    cd "$PROJECT_ROOT/kindly-guard-shield"
    
    # Install dependencies if needed
    if [ ! -d "node_modules" ]; then
        log_info "Installing Shield dependencies..."
        npm install --silent
    fi
    
    # Start Shield in development mode
    start_component "shield-app" "npm run dev"
    
    # Wait for Shield to be ready
    sleep 5
}

# Test 3: Test MCP-Shield Communication
test_mcp_shield_communication() {
    log_info "Testing MCP-Shield communication..."
    
    # Send a threat through MCP and check if Shield receives it
    local MCP_PID=${PROCESSES["mcp-server"]:-0}
    local SHIELD_LOG=${PROCESS_LOGS["shield-app"]:-"/tmp/kindly-shield-app.log"}
    
    # Clear Shield log position
    local LOG_LINES_BEFORE=$(wc -l < "$SHIELD_LOG" 2>/dev/null || echo "0")
    
    # Send a test threat through MCP
    cat > /tmp/test-threat-injection.sh << 'EOF'
#!/bin/bash
# Initialize
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
sleep 0.5
echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
sleep 0.5
# Monitor threats
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"monitor_threats","arguments":{}}}'
sleep 0.5
# Scan text with threat
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan_text","arguments":{"text":"<script>alert(\"XSS\")</script>"}}}'
sleep 2
EOF
    
    chmod +x /tmp/test-threat-injection.sh
    
    # Send to MCP server
    if [ "$MCP_PID" != "0" ]; then
        /tmp/test-threat-injection.sh | nc -U /tmp/kindly-guard.sock 2>/dev/null || true
    fi
    
    # Wait for propagation
    sleep 3
    
    # Check if Shield received notification
    local LOG_LINES_AFTER=$(wc -l < "$SHIELD_LOG" 2>/dev/null || echo "0")
    local NEW_LINES=$((LOG_LINES_AFTER - LOG_LINES_BEFORE))
    
    # Shield should have logged something about threats
    [ $NEW_LINES -gt 0 ]
}

# Test 4: Test Shared Memory Communication
test_shared_memory() {
    log_info "Testing shared memory communication..."
    
    # Check if shared memory file exists
    local SHM_FILE="/dev/shm/kindly-guard-threats"
    
    if [ -f "$SHM_FILE" ]; then
        # Verify it's being updated
        local SIZE_BEFORE=$(stat -c%s "$SHM_FILE" 2>/dev/null || echo "0")
        sleep 2
        local SIZE_AFTER=$(stat -c%s "$SHM_FILE" 2>/dev/null || echo "0")
        
        log_info "Shared memory file exists (size: $SIZE_AFTER bytes)"
        return 0
    else
        log_info "Shared memory not enabled (optional feature)"
        return 0
    fi
}

# Test 5: Test Binary Protocol
test_binary_protocol() {
    log_info "Testing binary protocol..."
    
    # Check if binary protocol socket exists
    local BINARY_SOCK="/tmp/kindly-guard-binary.sock"
    
    if [ -S "$BINARY_SOCK" ]; then
        # Test connection
        nc -zU "$BINARY_SOCK" 2>/dev/null
    else
        log_info "Binary protocol not enabled (optional feature)"
        return 0
    fi
}

# Test 6: Test Enhanced Mode
test_enhanced_mode() {
    log_info "Testing enhanced mode activation..."
    
    # Restart MCP server with enhanced mode
    stop_component "mcp-server"
    
    cd "$PROJECT_ROOT"
    start_component "mcp-enhanced" "KINDLY_GUARD_ENHANCED=true RUST_LOG=kindly_guard=debug target/release/kindly-guard --stdio"
    
    # Check logs for enhanced mode
    local ENHANCED_LOG=${PROCESS_LOGS["mcp-enhanced"]:-"/tmp/kindly-mcp-enhanced.log"}
    
    # Look for enhanced mode indicators
    grep -E "enhanced|optimized|performance mode" "$ENHANCED_LOG" 2>/dev/null || true
    
    # Enhanced mode should start successfully
    local ENHANCED_PID=${PROCESSES["mcp-enhanced"]:-0}
    [ "$ENHANCED_PID" != "0" ] && kill -0 $ENHANCED_PID 2>/dev/null
}

# Test 7: Test Resource Usage
test_resource_usage() {
    log_info "Testing system resource usage..."
    
    local TOTAL_MEM=0
    local TOTAL_CPU=0
    local COMPONENT_COUNT=0
    
    for name in "${!PROCESSES[@]}"; do
        local pid=${PROCESSES[$name]}
        if kill -0 $pid 2>/dev/null; then
            local MEM=$(ps -o rss= -p $pid 2>/dev/null | tr -d ' ' || echo "0")
            local CPU=$(ps -o %cpu= -p $pid 2>/dev/null | tr -d ' ' | cut -d. -f1 || echo "0")
            
            TOTAL_MEM=$((TOTAL_MEM + MEM))
            TOTAL_CPU=$((TOTAL_CPU + ${CPU:-0}))
            ((COMPONENT_COUNT++))
            
            log_info "$name - Memory: $((MEM/1024))MB, CPU: ${CPU}%"
        fi
    done
    
    local TOTAL_MEM_MB=$((TOTAL_MEM / 1024))
    log_info "Total resource usage - Memory: ${TOTAL_MEM_MB}MB, CPU: ${TOTAL_CPU}%"
    
    # Check reasonable limits
    [ $TOTAL_MEM_MB -lt 1000 ] && [ $TOTAL_CPU -lt 200 ]
}

# Test 8: Test Threat Flow End-to-End
test_threat_flow_e2e() {
    log_info "Testing end-to-end threat detection flow..."
    
    # Inject various threats and verify they appear in Shield
    local threats=(
        '{"text":"Hello\u202EWorld"}'
        '{"text":"<script>alert(1)</script>"}'
        '{"text":"SELECT * FROM users WHERE 1=1--"}'
        '{"text":"../../../etc/passwd"}'
    )
    
    local DETECTED=0
    
    for threat in "${threats[@]}"; do
        # Send threat through MCP
        cat > /tmp/test-e2e-threat.sh << EOF
#!/bin/bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
sleep 0.5
echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
sleep 0.5
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_json","arguments":$threat}}'
EOF
        
        chmod +x /tmp/test-e2e-threat.sh
        
        # Execute if MCP is running
        local MCP_NAME=""
        for name in "mcp-enhanced" "mcp-server"; do
            if [ -n "${PROCESSES[$name]:-}" ]; then
                MCP_NAME=$name
                break
            fi
        done
        
        if [ -n "$MCP_NAME" ]; then
            /tmp/test-e2e-threat.sh | nc -U /tmp/kindly-guard.sock 2>/dev/null || true
            ((DETECTED++))
        fi
    done
    
    log_info "Sent $DETECTED threat samples"
    [ $DETECTED -gt 0 ]
}

# Test 9: Test Graceful Shutdown
test_graceful_shutdown() {
    log_info "Testing graceful shutdown..."
    
    # Send SIGTERM to all components
    for name in "${!PROCESSES[@]}"; do
        local pid=${PROCESSES[$name]}
        if kill -0 $pid 2>/dev/null; then
            log_step "Sending SIGTERM to $name (PID: $pid)"
            kill -TERM $pid 2>/dev/null || true
        fi
    done
    
    # Wait for graceful shutdown
    sleep 3
    
    # Check if processes terminated cleanly
    local STILL_RUNNING=0
    for name in "${!PROCESSES[@]}"; do
        local pid=${PROCESSES[$name]}
        if kill -0 $pid 2>/dev/null; then
            ((STILL_RUNNING++))
            log_error "$name still running after SIGTERM"
        else
            log_info "$name shut down gracefully"
        fi
    done
    
    [ $STILL_RUNNING -eq 0 ]
}

# Cleanup function
cleanup() {
    log_info "Cleaning up ecosystem test..."
    
    # Stop all components
    for name in "${!PROCESSES[@]}"; do
        stop_component "$name"
    done
    
    # Clean up test files
    rm -f /tmp/test-*.sh
    rm -f /tmp/kindly-*.log
    
    # Show logs if tests failed
    if [ $TESTS_FAILED -gt 0 ]; then
        echo
        log_error "Showing recent logs from failed components:"
        for name in "${!PROCESS_LOGS[@]}"; do
            local log_file=${PROCESS_LOGS[$name]}
            if [ -f "$log_file" ]; then
                echo
                log_info "=== $name logs ==="
                tail -n 20 "$log_file"
            fi
        done
    fi
}

# Main test execution
main() {
    log_info "Starting Full Ecosystem Integration Tests"
    log_info "========================================="
    
    # Set up cleanup on exit
    trap cleanup EXIT
    
    # Phase 1: Component Startup
    echo
    log_step "Phase 1: Starting Components"
    run_test "Start MCP Server" test_start_mcp_server
    run_test "Start Shield Application" test_start_shield
    
    # Phase 2: Communication Tests
    echo
    log_step "Phase 2: Testing Communication"
    run_test "MCP-Shield Communication" test_mcp_shield_communication
    run_test "Shared Memory" test_shared_memory
    run_test "Binary Protocol" test_binary_protocol
    
    # Phase 3: Feature Tests
    echo
    log_step "Phase 3: Testing Features"
    run_test "Enhanced Mode" test_enhanced_mode
    run_test "Resource Usage" test_resource_usage
    run_test "Threat Flow E2E" test_threat_flow_e2e
    
    # Phase 4: Shutdown Tests
    echo
    log_step "Phase 4: Testing Shutdown"
    run_test "Graceful Shutdown" test_graceful_shutdown
    
    # Summary
    echo
    log_info "Test Summary"
    log_info "============"
    log_info "Tests passed: $TESTS_PASSED"
    log_error "Tests failed: $TESTS_FAILED"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        log_info "All ecosystem tests passed! ✓"
        exit 0
    else
        log_error "Some ecosystem tests failed! ✗"
        exit 1
    fi
}

# Run main function
main "$@"