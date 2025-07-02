#!/bin/bash
# Run integration tests (tests that require full async runtime and server setup)

set -e

echo "KindlyGuard Integration Test Runner"
echo "==================================="
echo

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test results
declare -A TEST_RESULTS

# Run a specific test file
run_test_file() {
    local test_name=$1
    local description=$2
    
    echo -e "${YELLOW}Running ${description}...${NC}"
    
    if cargo test --test ${test_name} -- --test-threads=1 --nocapture 2>&1 | grep -q "test result: ok"; then
        echo -e "${GREEN}✓ ${description} passed${NC}"
        TEST_RESULTS["${test_name}"]="PASSED"
    else
        echo -e "${RED}✗ ${description} failed${NC}"
        TEST_RESULTS["${test_name}"]="FAILED"
        # Show last few lines of output
        cargo test --test ${test_name} 2>&1 | grep -E "(test .* ... FAILED|error\[|thread.*panicked)" | head -10
    fi
    echo
}

# Core security tests
echo -e "${BLUE}=== Core Security Tests ===${NC}"
run_test_file "security_tests" "Security Tests"
run_test_file "unicode_tag_injection_tests" "Unicode Tag Injection Tests"
run_test_file "enhanced_prompt_injection_tests" "Enhanced Prompt Injection Tests"

# Protocol tests
echo -e "${BLUE}=== Protocol Tests ===${NC}"
run_test_file "mcp_protocol_tests" "MCP Protocol Tests"
run_test_file "multi_protocol_security_tests" "Multi-Protocol Security Tests"

# Service integration tests
echo -e "${BLUE}=== Service Integration Tests ===${NC}"
run_test_file "ai_service_integration_tests" "AI Service Integration Tests"

# Advanced tests
echo -e "${BLUE}=== Advanced Tests ===${NC}"
run_test_file "chaos_engineering_tests" "Chaos Engineering Tests"
run_test_file "owasp_asvs_compliance_tests" "OWASP ASVS Compliance Tests"

# CLI tests
echo -e "${BLUE}=== CLI Tests ===${NC}"
cd kindly-guard-cli
if cargo test --test cli_wrapper_security_tests 2>&1 | grep -q "test result: ok"; then
    echo -e "${GREEN}✓ CLI Wrapper Security Tests passed${NC}"
    TEST_RESULTS["cli_wrapper_security_tests"]="PASSED"
else
    echo -e "${RED}✗ CLI Wrapper Security Tests failed${NC}"
    TEST_RESULTS["cli_wrapper_security_tests"]="FAILED"
fi
cd ..

# Summary
echo
echo -e "${BLUE}Test Summary${NC}"
echo "============"

TOTAL=0
PASSED=0
FAILED=0

for test in "${!TEST_RESULTS[@]}"; do
    TOTAL=$((TOTAL + 1))
    if [ "${TEST_RESULTS[$test]}" = "PASSED" ]; then
        echo -e "${GREEN}✓${NC} $test"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗${NC} $test"
        FAILED=$((FAILED + 1))
    fi
done

echo
echo "Total: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

# Calculate pass rate
if [ $TOTAL -gt 0 ]; then
    PASS_RATE=$((PASSED * 100 / TOTAL))
    echo "Pass Rate: ${PASS_RATE}%"
fi

echo

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All integration tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some integration tests failed.${NC}"
    echo "Run individual tests with more output:"
    echo "  cargo test --test <test_name> -- --nocapture"
    exit 1
fi