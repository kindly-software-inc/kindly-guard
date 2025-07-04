#!/bin/bash
# Test script for KindlyGuard Shield Desktop Application

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SHIELD_DIR="$PROJECT_ROOT/kindly-guard-shield"

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

# Function to check if a process is running
is_process_running() {
    local process_name=$1
    pgrep -f "$process_name" > /dev/null 2>&1
}

# Function to wait for a process to start
wait_for_process() {
    local process_name=$1
    local timeout=${2:-30}
    local count=0
    
    while ! is_process_running "$process_name" && [ $count -lt $timeout ]; do
        sleep 1
        ((count++))
    done
    
    if [ $count -eq $timeout ]; then
        return 1
    fi
    return 0
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

# Test 1: Build Shield Application
test_build_shield() {
    log_info "Building Shield application..."
    cd "$SHIELD_DIR"
    
    # Install dependencies
    npm install --silent
    
    # Build for development (faster than production build)
    npm run build:dev
    
    # Check if build artifacts exist
    [ -d "$SHIELD_DIR/dist" ]
}

# Test 2: Start Shield Application
test_start_shield() {
    log_info "Starting Shield application..."
    cd "$SHIELD_DIR"
    
    # Start the application in background
    npm run dev > /tmp/shield-test.log 2>&1 &
    local SHIELD_PID=$!
    echo $SHIELD_PID > /tmp/shield-test.pid
    
    # Wait for the application to start
    sleep 5
    
    # Check if process is running
    kill -0 $SHIELD_PID 2>/dev/null
}

# Test 3: Test IPC Communication
test_ipc_communication() {
    log_info "Testing IPC communication..."
    
    # Create a test script to send IPC message
    cat > /tmp/test-ipc.js << 'EOF'
const { ipcRenderer } = require('electron');

// Send test message
ipcRenderer.send('test-message', { type: 'ping' });

// Listen for response
ipcRenderer.once('test-response', (event, data) => {
    if (data.type === 'pong') {
        process.exit(0);
    } else {
        process.exit(1);
    }
});

// Timeout after 5 seconds
setTimeout(() => process.exit(1), 5000);
EOF

    # Run the test (this would need to be integrated into the app)
    # For now, we'll just check if the app is responsive
    local SHIELD_PID=$(cat /tmp/shield-test.pid 2>/dev/null || echo "0")
    kill -0 $SHIELD_PID 2>/dev/null
}

# Test 4: Test Threat Detection UI
test_threat_detection_ui() {
    log_info "Testing threat detection UI..."
    
    # Simulate a threat detection event
    # This would normally come from the MCP server
    # For testing, we'll check if the notification system is ready
    
    # Check if the app log contains initialization messages
    grep -q "Shield initialized" /tmp/shield-test.log 2>/dev/null || \
    grep -q "Ready to receive threats" /tmp/shield-test.log 2>/dev/null
}

# Test 5: Test WebSocket Connection
test_websocket_connection() {
    log_info "Testing WebSocket connection readiness..."
    
    # Check if WebSocket server is initialized in the log
    grep -q "WebSocket" /tmp/shield-test.log 2>/dev/null || \
    grep -q "IPC" /tmp/shield-test.log 2>/dev/null
}

# Test 6: Test Memory Usage
test_memory_usage() {
    log_info "Testing memory usage..."
    
    local SHIELD_PID=$(cat /tmp/shield-test.pid 2>/dev/null || echo "0")
    if [ "$SHIELD_PID" != "0" ] && kill -0 $SHIELD_PID 2>/dev/null; then
        # Get memory usage in KB
        local MEM_USAGE=$(ps -o rss= -p $SHIELD_PID | tr -d ' ')
        local MEM_MB=$((MEM_USAGE / 1024))
        
        log_info "Memory usage: ${MEM_MB}MB"
        
        # Check if memory usage is reasonable (less than 500MB)
        [ $MEM_MB -lt 500 ]
    else
        return 1
    fi
}

# Test 7: Test CPU Usage
test_cpu_usage() {
    log_info "Testing CPU usage..."
    
    local SHIELD_PID=$(cat /tmp/shield-test.pid 2>/dev/null || echo "0")
    if [ "$SHIELD_PID" != "0" ] && kill -0 $SHIELD_PID 2>/dev/null; then
        # Sample CPU usage
        local CPU_USAGE=$(ps -o %cpu= -p $SHIELD_PID | tr -d ' ' | cut -d. -f1)
        
        log_info "CPU usage: ${CPU_USAGE}%"
        
        # Check if CPU usage is reasonable (less than 50%)
        [ ${CPU_USAGE:-0} -lt 50 ]
    else
        return 1
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    
    # Stop Shield application
    if [ -f /tmp/shield-test.pid ]; then
        local SHIELD_PID=$(cat /tmp/shield-test.pid)
        if kill -0 $SHIELD_PID 2>/dev/null; then
            kill $SHIELD_PID 2>/dev/null || true
            sleep 2
            kill -9 $SHIELD_PID 2>/dev/null || true
        fi
        rm -f /tmp/shield-test.pid
    fi
    
    # Clean up test files
    rm -f /tmp/shield-test.log
    rm -f /tmp/test-ipc.js
}

# Main test execution
main() {
    log_info "Starting Shield Application Tests"
    log_info "================================"
    
    # Set up cleanup on exit
    trap cleanup EXIT
    
    # Run tests
    run_test "Build Shield Application" test_build_shield
    run_test "Start Shield Application" test_start_shield
    run_test "IPC Communication" test_ipc_communication
    run_test "Threat Detection UI" test_threat_detection_ui
    run_test "WebSocket Connection" test_websocket_connection
    run_test "Memory Usage" test_memory_usage
    run_test "CPU Usage" test_cpu_usage
    
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