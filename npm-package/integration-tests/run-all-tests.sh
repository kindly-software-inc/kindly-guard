#!/bin/bash

# Master test runner for KindlyGuard NPM package
# Runs all test suites and generates a comprehensive report

set -e

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

print_header() {
    echo -e "\n${BLUE}=================================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=================================================================================${NC}\n"
}

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Function to run a test suite
run_test_suite() {
    local test_name=$1
    local test_file=$2
    local test_type=$3
    
    print_header "Running $test_name"
    ((TOTAL_TESTS++))
    
    if [ ! -f "$test_file" ]; then
        print_error "Test file not found: $test_file"
        ((FAILED_TESTS++))
        return 1
    fi
    
    # Make sure test file is executable
    chmod +x "$test_file"
    
    # Run the test
    if [ "$test_type" = "node" ]; then
        if node "$test_file"; then
            print_status "$test_name completed successfully"
            ((PASSED_TESTS++))
        else
            print_error "$test_name failed"
            ((FAILED_TESTS++))
        fi
    else
        if bash "$test_file"; then
            print_status "$test_name completed successfully"
            ((PASSED_TESTS++))
        else
            print_error "$test_name failed"
            ((FAILED_TESTS++))
        fi
    fi
}

# Start time
START_TIME=$(date +%s)

print_header "KindlyGuard NPM Package Comprehensive Test Suite"
echo "Date: $(date)"
echo "Platform: $(uname -s)"
echo "Architecture: $(uname -m)"
echo "Node.js: $(node --version)"
echo "NPM: $(npm --version)"

# Check current directory
if [ ! -f "../package.json" ]; then
    print_error "Please run this script from the integration-tests directory"
    exit 1
fi

# Create test results directory
RESULTS_DIR="test-results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"
print_info "Test results will be saved to: $RESULTS_DIR"

# Test 1: Installation test
print_info "Checking for installation test script..."
if [ -f "../test-install.sh" ]; then
    run_test_suite "Installation Test" "../test-install.sh" "bash" 2>&1 | tee "$RESULTS_DIR/installation-test.log"
else
    print_warning "Installation test script not found, skipping"
    ((SKIPPED_TESTS++))
fi

# Test 2: Platform test harness
print_info "Running platform-specific tests..."
if [ -f "../test-harness/run-tests.js" ]; then
    run_test_suite "Platform Test Harness" "../test-harness/run-tests.js" "node" 2>&1 | tee "$RESULTS_DIR/platform-tests.log"
else
    print_warning "Platform test harness not found, skipping"
    ((SKIPPED_TESTS++))
fi

# Test 3: Claude Desktop integration
run_test_suite "Claude Desktop Integration" "test-claude-desktop.js" "node" 2>&1 | tee "$RESULTS_DIR/claude-desktop-test.log"

# Test 4: NPX usage
run_test_suite "NPX Usage Tests" "test-npx-usage.js" "node" 2>&1 | tee "$RESULTS_DIR/npx-usage-test.log"

# Test 5: Programmatic API
run_test_suite "Programmatic API Tests" "test-programmatic-api.js" "node" 2>&1 | tee "$RESULTS_DIR/programmatic-api-test.log"

# Test 6: CLI commands
run_test_suite "CLI Commands Tests" "test-cli-commands.js" "node" 2>&1 | tee "$RESULTS_DIR/cli-commands-test.log"

# Additional checks
print_header "Additional Validation Checks"

# Check package.json validity
print_info "Validating package.json..."
if node -e "JSON.parse(require('fs').readFileSync('../package.json'))" 2>/dev/null; then
    print_status "package.json is valid JSON"
else
    print_error "package.json is invalid"
fi

# Check for required files
print_info "Checking required files..."
REQUIRED_FILES=(
    "../package.json"
    "../index.js"
    "../postinstall.js"
    "../README.md"
    "../LICENSE"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        print_status "Found: $file"
    else
        print_error "Missing: $file"
    fi
done

# Check npm audit (if package-lock.json exists)
if [ -f "../package-lock.json" ]; then
    print_info "Running npm audit..."
    cd ..
    if npm audit --audit-level=high 2>&1 | tee "$RESULTS_DIR/npm-audit.log"; then
        print_status "No high severity vulnerabilities found"
    else
        print_warning "Security vulnerabilities detected"
    fi
    cd integration-tests
fi

# End time
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Generate summary report
print_header "Test Summary Report"

REPORT_FILE="$RESULTS_DIR/summary-report.txt"
{
    echo "KindlyGuard NPM Package Test Summary"
    echo "==================================="
    echo ""
    echo "Test Date: $(date)"
    echo "Duration: ${DURATION} seconds"
    echo ""
    echo "Test Results:"
    echo "  Total Tests: $TOTAL_TESTS"
    echo "  Passed: $PASSED_TESTS"
    echo "  Failed: $FAILED_TESTS"
    echo "  Skipped: $SKIPPED_TESTS"
    echo ""
    echo "Success Rate: $(( TOTAL_TESTS > 0 ? PASSED_TESTS * 100 / TOTAL_TESTS : 0 ))%"
    echo ""
    
    if [ $FAILED_TESTS -gt 0 ]; then
        echo "Failed Tests:"
        grep -h "✗" "$RESULTS_DIR"/*.log 2>/dev/null || true
    fi
    
    echo ""
    echo "Test Logs:"
    ls -la "$RESULTS_DIR"/*.log 2>/dev/null || echo "No log files generated"
} | tee "$REPORT_FILE"

# Display summary
echo ""
if [ $FAILED_TESTS -eq 0 ] && [ $TOTAL_TESTS -gt 0 ]; then
    print_status "All tests passed! 🎉"
    EXIT_CODE=0
else
    print_error "Some tests failed. Please check the logs in $RESULTS_DIR"
    EXIT_CODE=1
fi

print_info "Full test results saved to: $RESULTS_DIR"
print_info "Summary report: $REPORT_FILE"

exit $EXIT_CODE