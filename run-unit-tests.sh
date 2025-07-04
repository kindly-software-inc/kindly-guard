#!/bin/bash
# Run unit tests (library tests that don't require full integration setup)

set -e

echo "KindlyGuard Unit Test Runner"
echo "============================"
echo

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Test counters
TOTAL=0
PASSED=0
FAILED=0

# Run tests for a specific module
run_module_tests() {
    local module=$1
    local description=$2
    
    echo -e "${YELLOW}Testing ${description}...${NC}"
    TOTAL=$((TOTAL + 1))
    
    if cargo test --lib ${module}:: --quiet 2>&1 | grep -q "test result: ok"; then
        echo -e "${GREEN}✓ ${description} tests passed${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗ ${description} tests failed${NC}"
        FAILED=$((FAILED + 1))
        # Show the actual output on failure
        cargo test --lib ${module}:: 2>&1 | tail -20
    fi
    echo
}

# Run unit tests for each module
run_module_tests "scanner::unicode" "Unicode Scanner"
run_module_tests "scanner::injection" "Injection Scanner"
run_module_tests "scanner::patterns" "Pattern Scanner"
run_module_tests "scanner::sync_wrapper" "Sync Scanner Wrapper"
run_module_tests "config" "Configuration"
run_module_tests "shield" "Shield Display"
run_module_tests "auth" "Authentication"
run_module_tests "protocol" "Protocol"

# Run CLI unit tests
echo -e "${YELLOW}Testing CLI unit tests...${NC}"
cd kindly-guard-cli
if cargo test --lib --quiet 2>&1 | grep -q "test result: ok"; then
    echo -e "${GREEN}✓ CLI unit tests passed${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗ CLI unit tests failed${NC}"
    FAILED=$((FAILED + 1))
fi
cd ..
TOTAL=$((TOTAL + 1))

echo
echo "Summary"
echo "======="
echo -e "Total modules tested: ${TOTAL}"
echo -e "${GREEN}Passed: ${PASSED}${NC}"
echo -e "${RED}Failed: ${FAILED}${NC}"
echo

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All unit tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some unit tests failed.${NC}"
    exit 1
fi