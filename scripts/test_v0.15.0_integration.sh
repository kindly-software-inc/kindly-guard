#!/bin/bash
# Integration test script for KindlyGuard v0.15.0
# Tests enhanced threat system with quarantine, user-friendly messages, and MCP integration

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test environment setup
TEST_DIR="/tmp/kindlyguard_v0.15.0_test_$$"
CONFIG_DIR="$TEST_DIR/config"
QUARANTINE_DIR="$TEST_DIR/quarantine"
LOG_FILE="$TEST_DIR/test.log"
BINARY="${KINDLYGUARD_BINARY:-kindly-guard}"

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
log() {
    echo -e "${BLUE}[TEST]${NC} $*" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[PASS]${NC} $*" | tee -a "$LOG_FILE"
    ((TESTS_PASSED++))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $*" | tee -a "$LOG_FILE"
    ((TESTS_FAILED++))
}

run_test() {
    local test_name="$1"
    echo -e "\n${YELLOW}Running test: $test_name${NC}" | tee -a "$LOG_FILE"
    ((TESTS_RUN++))
}

cleanup() {
    log "Cleaning up test environment..."
    rm -rf "$TEST_DIR"
}

trap cleanup EXIT

# Setup test environment
setup_test_env() {
    mkdir -p "$TEST_DIR" "$CONFIG_DIR" "$QUARANTINE_DIR"
    touch "$LOG_FILE"
    log "Setting up test environment..."
    
    # Create v0.11.x style config for upgrade test
    cat > "$CONFIG_DIR/kindlyguard_v0.11.toml" <<'EOF'
[server]
address = "127.0.0.1"
port = 8080
workers = 4

[security]
scan_depth = "deep"
unicode_normalization = true
max_scan_size = "10MB"
threat_reporting = "verbose"

[scanner]
enabled_checks = ["unicode", "injection", "xss", "patterns"]
pattern_update_interval = "24h"

[storage]
type = "sqlite"
path = "./kindlyguard.db"
max_connections = 10

[monitoring]
enabled = true
metrics_port = 9090
export_interval = "30s"
EOF

    # Create v0.15.0 config with new features
    cat > "$CONFIG_DIR/kindlyguard_v0.15.toml" <<'EOF'
[server]
address = "127.0.0.1"
port = 8080
workers = 4

[security]
scan_depth = "deep"
unicode_normalization = true
max_scan_size = "10MB"
threat_reporting = "verbose"

[protection]
mode = "interactive"
auto_clean = true
quarantine_threats = true
notify_user = true

[quarantine]
path = "./quarantine"
max_size = "1GB"
retention_days = 30
compression = true

[user_experience]
friendly_messages = true
show_suggestions = true
educational_mode = true
confidence_threshold = 0.7

[scanner]
enabled_checks = ["unicode", "injection", "xss", "patterns"]
pattern_update_interval = "24h"

[storage]
type = "sqlite"
path = "./kindlyguard.db"
max_connections = 10

[monitoring]
enabled = true
metrics_port = 9090
export_interval = "30s"

[resilience]
circuit_breaker.failure_threshold = 5
circuit_breaker.recovery_timeout = "30s"
retry.max_attempts = 3
retry.initial_delay = "100ms"
EOF

    # Create threat samples
    mkdir -p "$TEST_DIR/samples"
    
    # Unicode threats
    echo 'Paypal' > "$TEST_DIR/samples/unicode_homograph.txt"  # Using Cyrillic 'a'
    echo -e 'Normal\u202Eevil' > "$TEST_DIR/samples/unicode_bidi.txt"
    echo -e 'Hidden\u200B\u200Ctext' > "$TEST_DIR/samples/unicode_zerowidth.txt"
    
    # Injection threats
    cat > "$TEST_DIR/samples/sql_injection.json" <<'EOF'
{
    "query": "SELECT * FROM users WHERE id = '1' OR '1'='1'",
    "input": "'; DROP TABLE users; --"
}
EOF

    cat > "$TEST_DIR/samples/xss_attempt.html" <<'EOF'
<div>
    <script>alert('XSS')</script>
    <img src="x" onerror="alert('XSS')">
    <a href="javascript:alert('XSS')">Click me</a>
</div>
EOF

    # Safe content
    echo "This is completely safe content" > "$TEST_DIR/samples/safe_content.txt"
    
    # MCP request samples
    cat > "$TEST_DIR/samples/mcp_scan_request.json" <<'EOF'
{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "scan_content",
        "arguments": {
            "content": "Check this: Paypal.com",
            "options": {
                "deep_scan": true,
                "return_suggestions": true
            }
        }
    },
    "id": 1
}
EOF

    cat > "$TEST_DIR/samples/mcp_quarantine_list.json" <<'EOF'
{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "quarantine_list",
        "arguments": {
            "limit": 10,
            "include_metadata": true
        }
    },
    "id": 2
}
EOF
}

# Test 1: Configuration upgrade from v0.11.x to v0.15.0
test_config_upgrade() {
    run_test "Configuration upgrade (v0.11.x -> v0.15.0)"
    
    # Test upgrade command
    if $BINARY config upgrade --input "$CONFIG_DIR/kindlyguard_v0.11.toml" --output "$CONFIG_DIR/upgraded.toml" 2>&1 | tee -a "$LOG_FILE"; then
        # Verify new sections were added
        if grep -q "\[protection\]" "$CONFIG_DIR/upgraded.toml" && \
           grep -q "\[quarantine\]" "$CONFIG_DIR/upgraded.toml" && \
           grep -q "\[user_experience\]" "$CONFIG_DIR/upgraded.toml"; then
            success "Configuration upgraded successfully with new sections"
        else
            fail "Configuration upgrade missing new sections"
        fi
        
        # Verify backward compatibility
        if grep -q "scan_depth = \"deep\"" "$CONFIG_DIR/upgraded.toml"; then
            success "Backward compatibility maintained"
        else
            fail "Backward compatibility broken"
        fi
    else
        fail "Configuration upgrade command failed"
    fi
}

# Test 2: Protection modes
test_protection_modes() {
    run_test "Protection modes (auto, interactive, report-only)"
    
    # Test auto mode
    export KINDLYGUARD_CONFIG="$CONFIG_DIR/kindlyguard_v0.15.toml"
    
    # Modify config for auto mode
    sed -i 's/mode = "interactive"/mode = "auto"/' "$CONFIG_DIR/kindlyguard_v0.15.toml"
    
    log "Testing auto mode with SQL injection..."
    if $BINARY scan "$TEST_DIR/samples/sql_injection.json" 2>&1 | tee -a "$LOG_FILE" | grep -q "automatically cleaned"; then
        success "Auto mode: threat cleaned automatically"
    else
        fail "Auto mode: failed to clean threat"
    fi
    
    # Test interactive mode
    sed -i 's/mode = "auto"/mode = "interactive"/' "$CONFIG_DIR/kindlyguard_v0.15.toml"
    
    log "Testing interactive mode with XSS..."
    # Simulate user choosing to clean
    echo "c" | $BINARY scan "$TEST_DIR/samples/xss_attempt.html" 2>&1 | tee -a "$LOG_FILE"
    if grep -q "What would you like to do?" "$LOG_FILE"; then
        success "Interactive mode: user prompt displayed"
    else
        fail "Interactive mode: no user prompt"
    fi
    
    # Test report-only mode
    sed -i 's/mode = "interactive"/mode = "report-only"/' "$CONFIG_DIR/kindlyguard_v0.15.toml"
    
    log "Testing report-only mode..."
    if $BINARY scan "$TEST_DIR/samples/unicode_homograph.txt" 2>&1 | tee -a "$LOG_FILE" | grep -q "Report Only"; then
        success "Report-only mode: threats reported but not cleaned"
    else
        fail "Report-only mode: incorrect behavior"
    fi
}

# Test 3: Quarantine operations
test_quarantine_operations() {
    run_test "Quarantine operations"
    
    # Set quarantine directory
    export KINDLYGUARD_QUARANTINE_DIR="$QUARANTINE_DIR"
    
    # Test quarantine creation
    log "Testing threat quarantine..."
    $BINARY scan --quarantine "$TEST_DIR/samples/unicode_bidi.txt" 2>&1 | tee -a "$LOG_FILE"
    
    # Check if file was quarantined
    if ls "$QUARANTINE_DIR"/*.quarantine 2>/dev/null | grep -q quarantine; then
        success "Threat successfully quarantined"
        QUARANTINE_ID=$(ls "$QUARANTINE_DIR"/*.quarantine | head -1 | xargs basename | cut -d. -f1)
    else
        fail "Threat quarantine failed"
        return
    fi
    
    # Test quarantine list
    log "Testing quarantine list..."
    if $BINARY quarantine list 2>&1 | tee -a "$LOG_FILE" | grep -q "$QUARANTINE_ID"; then
        success "Quarantine list shows quarantined item"
    else
        fail "Quarantine list failed"
    fi
    
    # Test quarantine retrieve
    log "Testing quarantine retrieve..."
    if $BINARY quarantine retrieve "$QUARANTINE_ID" --output "$TEST_DIR/retrieved.txt" 2>&1 | tee -a "$LOG_FILE"; then
        if [ -f "$TEST_DIR/retrieved.txt" ]; then
            success "Quarantined item retrieved successfully"
        else
            fail "Retrieved file not found"
        fi
    else
        fail "Quarantine retrieve failed"
    fi
    
    # Test quarantine delete
    log "Testing quarantine delete..."
    if $BINARY quarantine delete "$QUARANTINE_ID" 2>&1 | tee -a "$LOG_FILE"; then
        if ! ls "$QUARANTINE_DIR/$QUARANTINE_ID.quarantine" 2>/dev/null; then
            success "Quarantined item deleted successfully"
        else
            fail "Quarantine file still exists after delete"
        fi
    else
        fail "Quarantine delete failed"
    fi
}

# Test 4: User-friendly messages
test_friendly_messages() {
    run_test "User-friendly message generation"
    
    # Test various threat types for friendly messages
    threats=("unicode_homograph.txt" "unicode_bidi.txt" "sql_injection.json" "xss_attempt.html")
    
    for threat_file in "${threats[@]}"; do
        log "Testing friendly message for $threat_file..."
        output=$($BINARY scan --explain "$TEST_DIR/samples/$threat_file" 2>&1)
        
        # Check for user-friendly elements
        if echo "$output" | grep -qE "(What we found|Why this matters|What you can do|Learn more)"; then
            success "Friendly message generated for $threat_file"
            
            # Verify educational content
            if echo "$output" | grep -q "Learn more"; then
                success "Educational content included"
            fi
        else
            fail "No friendly message for $threat_file"
        fi
    done
}

# Test 5: MCP tool functionality
test_mcp_tools() {
    run_test "MCP tool functionality"
    
    # Start MCP server in background
    log "Starting MCP server..."
    $BINARY server --config "$CONFIG_DIR/kindlyguard_v0.15.toml" --stdio > "$TEST_DIR/mcp_server.log" 2>&1 &
    MCP_PID=$!
    sleep 2
    
    # Test scan_content tool
    log "Testing scan_content MCP tool..."
    if echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"scan_content","arguments":{"content":"Check this: Paypal.com"}},"id":1}' | \
       nc -w 2 localhost 8080 2>/dev/null | grep -q "threat_detected"; then
        success "MCP scan_content tool working"
    else
        fail "MCP scan_content tool failed"
    fi
    
    # Test quarantine_list tool
    log "Testing quarantine_list MCP tool..."
    if echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"quarantine_list","arguments":{}},"id":2}' | \
       nc -w 2 localhost 8080 2>/dev/null | grep -q "items"; then
        success "MCP quarantine_list tool working"
    else
        fail "MCP quarantine_list tool failed"
    fi
    
    # Test get_protection_stats tool
    log "Testing get_protection_stats MCP tool..."
    if echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_protection_stats","arguments":{}},"id":3}' | \
       nc -w 2 localhost 8080 2>/dev/null | grep -q "total_scans"; then
        success "MCP get_protection_stats tool working"
    else
        fail "MCP get_protection_stats tool failed"
    fi
    
    # Clean up MCP server
    kill $MCP_PID 2>/dev/null || true
}

# Test 6: Real-world scenarios
test_real_world_scenarios() {
    run_test "Real-world threat scenarios"
    
    # Scenario 1: Email with homograph domain
    cat > "$TEST_DIR/samples/phishing_email.txt" <<'EOF'
Dear Customer,

Your account at Paypal.com needs verification.
Please click here to verify: https://paypal.com/verify

Best regards,
Security Team
EOF
    
    log "Testing phishing email detection..."
    if $BINARY scan "$TEST_DIR/samples/phishing_email.txt" 2>&1 | tee -a "$LOG_FILE" | grep -q "homograph"; then
        success "Phishing email with homograph detected"
    else
        fail "Failed to detect phishing email"
    fi
    
    # Scenario 2: Code submission with injection
    cat > "$TEST_DIR/samples/user_code.py" <<'EOF'
import os
user_input = input("Enter filename: ")
# Dangerous: user input not validated
os.system(f"cat {user_input}")
EOF
    
    log "Testing code injection detection..."
    if $BINARY scan "$TEST_DIR/samples/user_code.py" 2>&1 | tee -a "$LOG_FILE" | grep -q "injection"; then
        success "Code injection vulnerability detected"
    else
        fail "Failed to detect code injection"
    fi
    
    # Scenario 3: Mixed content with multiple threats
    cat > "$TEST_DIR/samples/mixed_threats.json" <<'EOF'
{
    "comment": "Visit Amazοn.com for deals",
    "code": "<script>alert('test')</script>",
    "query": "SELECT * FROM users WHERE name = 'admin' --",
    "hidden": "Visible\u200Binvisible"
}
EOF
    
    log "Testing multiple threat detection..."
    threat_count=$($BINARY scan "$TEST_DIR/samples/mixed_threats.json" 2>&1 | grep -c "Threat detected")
    if [ "$threat_count" -ge 3 ]; then
        success "Multiple threats detected in single scan"
    else
        fail "Not all threats detected (found: $threat_count)"
    fi
}

# Test 7: Performance and resilience
test_performance_resilience() {
    run_test "Performance and resilience"
    
    # Test large file handling
    log "Creating large test file..."
    dd if=/dev/urandom of="$TEST_DIR/samples/large_file.bin" bs=1M count=5 2>/dev/null
    
    log "Testing large file scan..."
    start_time=$(date +%s.%N)
    if timeout 10 $BINARY scan "$TEST_DIR/samples/large_file.bin" 2>&1 | tee -a "$LOG_FILE"; then
        end_time=$(date +%s.%N)
        duration=$(echo "$end_time - $start_time" | bc)
        log "Scan completed in $duration seconds"
        success "Large file handled successfully"
    else
        fail "Large file scan failed or timed out"
    fi
    
    # Test concurrent scans
    log "Testing concurrent scans..."
    for i in {1..5}; do
        $BINARY scan "$TEST_DIR/samples/safe_content.txt" > "$TEST_DIR/concurrent_$i.log" 2>&1 &
    done
    
    wait
    
    success_count=$(grep -l "No threats found" "$TEST_DIR"/concurrent_*.log | wc -l)
    if [ "$success_count" -eq 5 ]; then
        success "All concurrent scans completed successfully"
    else
        fail "Some concurrent scans failed ($success_count/5 succeeded)"
    fi
}

# Test 8: Backward compatibility
test_backward_compatibility() {
    run_test "Backward compatibility"
    
    # Test old API endpoints still work
    log "Testing legacy scan API..."
    if $BINARY scan --format json "$TEST_DIR/samples/safe_content.txt" 2>&1 | tee -a "$LOG_FILE" | grep -q '"threats":\[\]'; then
        success "Legacy JSON output format maintained"
    else
        fail "Legacy JSON format broken"
    fi
    
    # Test old config options still work
    cat > "$CONFIG_DIR/minimal_config.toml" <<'EOF'
[server]
port = 8081

[scanner]
enabled_checks = ["unicode"]
EOF
    
    if $BINARY --config "$CONFIG_DIR/minimal_config.toml" scan "$TEST_DIR/samples/unicode_homograph.txt" 2>&1 | tee -a "$LOG_FILE"; then
        success "Minimal legacy config still works"
    else
        fail "Legacy config compatibility broken"
    fi
}

# Main test execution
main() {
    echo -e "${BLUE}KindlyGuard v0.15.0 Integration Test Suite${NC}"
    echo "=========================================="
    
    # Check if binary exists
    if ! command -v "$BINARY" &> /dev/null; then
        echo -e "${RED}Error: KindlyGuard binary not found at '$BINARY'${NC}"
        echo "Set KINDLYGUARD_BINARY environment variable to specify location"
        exit 1
    fi
    
    # Setup test environment
    setup_test_env
    
    # Run all tests
    test_config_upgrade
    test_protection_modes
    test_quarantine_operations
    test_friendly_messages
    test_mcp_tools
    test_real_world_scenarios
    test_performance_resilience
    test_backward_compatibility
    
    # Summary
    echo -e "\n${BLUE}Test Summary${NC}"
    echo "============="
    echo "Tests run:    $TESTS_RUN"
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    
    if [ "$TESTS_FAILED" -eq 0 ]; then
        echo -e "\n${GREEN}All tests passed! ✓${NC}"
        exit 0
    else
        echo -e "\n${RED}Some tests failed ✗${NC}"
        echo "Check $LOG_FILE for details"
        exit 1
    fi
}

# Run main if not sourced
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi