#!/bin/bash
# Comprehensive test runner for KindlyGuard
# Runs all test suites with proper reporting

set -e

echo "🧪 KindlyGuard Comprehensive Test Suite"
echo "======================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test suite
run_test_suite() {
    local name=$1
    local command=$2
    echo -e "${YELLOW}Running $name...${NC}"
    
    if $command; then
        echo -e "${GREEN}✓ $name passed${NC}"
        ((PASSED_TESTS++))
    else
        echo -e "${RED}✗ $name failed${NC}"
        ((FAILED_TESTS++))
    fi
    ((TOTAL_TESTS++))
    echo ""
}

# Check for required tools
echo "📋 Checking prerequisites..."
command -v cargo >/dev/null 2>&1 || { echo "cargo is required but not installed."; exit 1; }
command -v cargo-nextest >/dev/null 2>&1 || { 
    echo "Installing cargo-nextest..."
    curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C ${CARGO_HOME:-~/.cargo}/bin
}

# Clean previous test artifacts
echo "🧹 Cleaning test artifacts..."
rm -rf target/nextest coverage/ lcov.info

# 1. Run unit tests with nextest
run_test_suite "Unit Tests" "cargo nextest run --lib --bins"

# 2. Run integration tests
run_test_suite "Integration Tests" "cargo nextest run --test '*' --exclude e2e_tests"

# 3. Run E2E tests (serial execution)
run_test_suite "E2E Tests" "cargo nextest run --test e2e_tests"

# 4. Run property-based tests
run_test_suite "Property Tests" "cargo test --test property_tests -- --nocapture"

# 5. Run doc tests
run_test_suite "Documentation Tests" "cargo test --doc"

# 6. Run examples as tests
echo -e "${YELLOW}Testing examples...${NC}"
for example in kindly-guard-server/examples/*.rs; do
    if [ -f "$example" ]; then
        example_name=$(basename "$example" .rs)
        run_test_suite "Example: $example_name" "cargo run --example $example_name"
    fi
done

# 7. Run security-specific tests
run_test_suite "Security Tests" "cargo nextest run test_security test_unicode test_injection test_auth"

# 8. Check for common security issues
echo -e "${YELLOW}Running security checks...${NC}"
run_test_suite "Clippy Security Lints" "cargo clippy --all-features -- -D warnings -W clippy::all"

# 9. Generate coverage report
if command -v cargo-llvm-cov >/dev/null 2>&1; then
    echo -e "${YELLOW}Generating coverage report...${NC}"
    cargo llvm-cov test --all-features --workspace \
        --exclude-private \
        --lcov --output-path lcov.info \
        --summary-only
    echo ""
fi

# Summary
echo "======================================"
echo "📊 Test Summary"
echo "======================================"
echo -e "Total test suites: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "\n${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some tests failed${NC}"
    exit 1
fi