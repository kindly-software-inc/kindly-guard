#!/bin/bash
# Comprehensive Security Test Suite Runner for KindlyGuard
# Runs all security tests created based on OWASP 2024 best practices

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Print header
print_header() {
    echo -e "${BLUE}==== $1 ====${NC}"
    echo
}

# Run test and track results
run_test() {
    local test_name=$1
    local test_command=$2
    
    echo -e "${YELLOW}Running: ${test_name}${NC}"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if eval "$test_command"; then
        echo -e "${GREEN}✓ ${test_name} passed${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ ${test_name} failed${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    echo
}

# Check if running in CI
if [ -n "$CI" ]; then
    echo "Running in CI mode"
    export RUST_BACKTRACE=1
fi

# Main execution
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║          KindlyGuard Comprehensive Security Test Suite        ║${NC}"
echo -e "${PURPLE}║                    Based on OWASP 2024                        ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo

# Build the project first
print_header "Building KindlyGuard"
echo "Building with all features..."
cargo build --all-features 2>&1 | grep -E "(Compiling|Finished)" || true
echo

# 1. Unicode Tag Injection Tests (CVE-2024-5184)
print_header "Unicode Tag Injection Tests"
run_test "Unicode Tag Detection" \
    "cargo test --test unicode_tag_injection_tests -- --test-threads=1"

# 2. Enhanced Prompt Injection Tests
print_header "Enhanced Prompt Injection Tests"
run_test "Neural Exec Patterns" \
    "cargo test --test enhanced_prompt_injection_tests test_neural_exec -- --nocapture"
run_test "Multi-turn Attacks" \
    "cargo test --test enhanced_prompt_injection_tests test_multi_turn -- --nocapture"
run_test "Context Window Manipulation" \
    "cargo test --test enhanced_prompt_injection_tests test_context_window -- --nocapture"

# 3. Multi-Protocol Security Tests
print_header "Multi-Protocol Security Tests"
run_test "HTTP API Security" \
    "cargo test --test multi_protocol_security_tests test_http_api -- --nocapture"
run_test "HTTPS Proxy Security" \
    "cargo test --test multi_protocol_security_tests test_proxy -- --nocapture"
run_test "WebSocket Security" \
    "cargo test --test multi_protocol_security_tests test_websocket -- --nocapture"
run_test "Cross-Protocol Attacks" \
    "cargo test --test multi_protocol_security_tests test_cross_protocol -- --nocapture"

# 4. AI Service Integration Tests
print_header "AI Service Integration Tests"
run_test "API Key Security" \
    "cargo test --test ai_service_integration_tests test_api_key -- --nocapture"
run_test "Service-Specific Attacks" \
    "cargo test --test ai_service_integration_tests test_service_specific -- --nocapture"
run_test "Rate Limiting" \
    "cargo test --test ai_service_integration_tests test_rate_limiting -- --nocapture"

# 5. CLI Wrapper Security Tests
print_header "CLI Wrapper Security Tests"
cd kindly-guard-cli
run_test "Command Injection Prevention" \
    "cargo test --test cli_wrapper_security_tests test_command_injection -- --nocapture"
run_test "Environment Security" \
    "cargo test --test cli_wrapper_security_tests test_environment -- --nocapture"
run_test "Blocking Mode" \
    "cargo test --test cli_wrapper_security_tests test_blocking_mode -- --nocapture"
cd ..

# 6. OWASP ASVS Compliance Tests
print_header "OWASP ASVS Compliance Tests"
run_test "V2: Authentication" \
    "cargo test --test owasp_asvs_compliance_tests test_v2 -- --nocapture"
run_test "V3: Session Management" \
    "cargo test --test owasp_asvs_compliance_tests test_v3 -- --nocapture"
run_test "V4: Access Control" \
    "cargo test --test owasp_asvs_compliance_tests test_v4 -- --nocapture"
run_test "V5: Input Validation" \
    "cargo test --test owasp_asvs_compliance_tests test_v5 -- --nocapture"
run_test "V6: Cryptography" \
    "cargo test --test owasp_asvs_compliance_tests test_v6 -- --nocapture"
run_test "V7: Logging" \
    "cargo test --test owasp_asvs_compliance_tests test_v7 -- --nocapture"

# 7. Chaos Engineering Tests (Quick versions)
print_header "Chaos Engineering Tests"
run_test "Random Failure Injection" \
    "cargo test --test chaos_engineering_tests test_random_failure -- --nocapture"
run_test "Recovery Time" \
    "cargo test --test chaos_engineering_tests test_recovery_time -- --nocapture"
run_test "Data Consistency" \
    "cargo test --test chaos_engineering_tests test_data_consistency -- --nocapture"

# 8. Existing Security Tests
print_header "Core Security Tests"
run_test "Scanner Security" \
    "cargo test --test security_tests -- --test-threads=1"
run_test "MCP Protocol Security" \
    "cargo test --test mcp_protocol_tests -- --nocapture"

# Performance Benchmarks (Quick run)
if [ "$1" == "--with-benchmarks" ]; then
    print_header "Performance Benchmarks"
    echo "Running quick performance benchmarks..."
    cargo bench --bench comprehensive_benchmarks -- --warm-up-time 1 --measurement-time 3
fi

# Summary
echo
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║                        Test Summary                           ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "Total Tests Run: ${TOTAL_TESTS}"
echo -e "${GREEN}Passed: ${PASSED_TESTS}${NC}"
echo -e "${RED}Failed: ${FAILED_TESTS}${NC}"
echo -e "${YELLOW}Skipped: ${SKIPPED_TESTS}${NC}"
echo

# Calculate pass rate
if [ $TOTAL_TESTS -gt 0 ]; then
    PASS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    echo -e "Pass Rate: ${PASS_RATE}%"
    
    if [ $PASS_RATE -ge 95 ]; then
        echo -e "${GREEN}✓ Excellent security test coverage!${NC}"
    elif [ $PASS_RATE -ge 80 ]; then
        echo -e "${YELLOW}⚠ Good coverage, but some tests need attention${NC}"
    else
        echo -e "${RED}✗ Security test coverage needs improvement${NC}"
    fi
fi

# Exit with appropriate code
if [ $FAILED_TESTS -gt 0 ]; then
    exit 1
else
    exit 0
fi