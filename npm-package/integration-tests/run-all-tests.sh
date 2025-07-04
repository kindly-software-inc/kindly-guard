#!/bin/bash

# Master test runner for KindlyGuard NPM package
# Fixed version that properly handles test execution and result tracking

set -e

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test tracking - using a temp file to track across subshells
TEST_RESULTS_FILE=$(mktemp)
echo "0 0 0 0" > "$TEST_RESULTS_FILE"  # total passed failed skipped

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

update_test_counts() {
    local delta_total=$1
    local delta_passed=$2
    local delta_failed=$3
    local delta_skipped=$4
    
    local counts=$(cat "$TEST_RESULTS_FILE")
    local total=$(echo $counts | cut -d' ' -f1)
    local passed=$(echo $counts | cut -d' ' -f2)
    local failed=$(echo $counts | cut -d' ' -f3)
    local skipped=$(echo $counts | cut -d' ' -f4)
    
    total=$((total + delta_total))
    passed=$((passed + delta_passed))
    failed=$((failed + delta_failed))
    skipped=$((skipped + delta_skipped))
    
    echo "$total $passed $failed $skipped" > "$TEST_RESULTS_FILE"
}

# Function to run a test suite
run_test_suite() {
    local test_name=$1
    local test_file=$2
    local test_type=$3
    local log_file=$4
    
    print_header "Running $test_name"
    update_test_counts 1 0 0 0
    
    if [ ! -f "$test_file" ]; then
        print_error "Test file not found: $test_file"
        update_test_counts 0 0 1 0
        return 1
    fi
    
    # Make sure test file is executable
    chmod +x "$test_file"
    
    # Run the test and capture output
    local test_output=$(mktemp)
    local test_exit_code=0
    
    if [ "$test_type" = "node" ]; then
        node "$test_file" > "$test_output" 2>&1 || test_exit_code=$?
    else
        bash "$test_file" > "$test_output" 2>&1 || test_exit_code=$?
    fi
    
    # Display and save output
    cat "$test_output" | tee "$log_file"
    
    # Update counts based on exit code
    if [ $test_exit_code -eq 0 ]; then
        print_status "$test_name completed successfully"
        update_test_counts 0 1 0 0
    else
        print_error "$test_name failed"
        update_test_counts 0 0 1 0
    fi
    
    rm -f "$test_output"
    return $test_exit_code
}

# Start time
START_TIME=$(date +%s)

# Display header
print_header "KindlyGuard NPM Package Comprehensive Test Suite"

echo "Date: $(date)"
echo "Platform: $(uname)"
echo "Architecture: $(uname -m)"
echo "Node.js: $(node -v)"
echo "NPM: $(npm -v)"

# Create test results directory
RESULTS_DIR="test-results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$RESULTS_DIR"
print_info "Test results will be saved to: $RESULTS_DIR"

# Test 1: Installation test
print_info "Checking for installation test script..."
if [ -f "../test-install.sh" ]; then
    # test-install.sh needs to be run from npm-package directory
    (cd .. && bash test-install.sh > "integration-tests/$RESULTS_DIR/installation-test.log" 2>&1) || test_exit_code=$?
    if [ "${test_exit_code:-0}" -eq 0 ]; then
        print_status "Installation Test completed successfully"
        update_test_counts 1 1 0 0
    else
        print_error "Installation Test failed"
        update_test_counts 1 0 1 0
    fi
    cat "$RESULTS_DIR/installation-test.log"
else
    print_warning "Installation test script not found, skipping"
    update_test_counts 0 0 0 1
fi

# Test 2: Platform test harness
print_info "Running platform-specific tests..."
if [ -f "../test-harness/run-tests.js" ]; then
    run_test_suite "Platform Test Harness" "../test-harness/run-tests.js" "node" "$RESULTS_DIR/platform-tests.log"
else
    print_warning "Platform test harness not found, skipping"
    update_test_counts 0 0 0 1
fi

# Test 3: Integration tests
for test_file in test-claude-desktop.js test-npx-usage.js test-programmatic-api.js test-cli-commands.js; do
    if [ -f "$test_file" ]; then
        test_name=$(echo "$test_file" | sed 's/test-//; s/\.js//; s/-/ /g' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)} 1')
        log_name=$(echo "$test_file" | sed 's/\.js/.log/')
        run_test_suite "$test_name" "$test_file" "node" "$RESULTS_DIR/$log_name"
    fi
done

# Additional validation checks
print_header "Additional Validation Checks"

# Validate package.json
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
    "../lib/main.js"
    "../lib/postinstall.js"
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
    if npm audit --audit-level=high 2>&1 | tee "integration-tests/$RESULTS_DIR/npm-audit.log"; then
        print_status "No high severity vulnerabilities found"
    else
        print_warning "Security vulnerabilities detected"
    fi
    cd integration-tests
fi

# Calculate duration
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Read final test counts
counts=$(cat "$TEST_RESULTS_FILE")
TOTAL_TESTS=$(echo $counts | cut -d' ' -f1)
PASSED_TESTS=$(echo $counts | cut -d' ' -f2)
FAILED_TESTS=$(echo $counts | cut -d' ' -f3)
SKIPPED_TESTS=$(echo $counts | cut -d' ' -f4)

# Generate summary report
REPORT_FILE="$RESULTS_DIR/summary-report.txt"
{
    print_header "Test Summary Report"
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

# Cleanup
rm -f "$TEST_RESULTS_FILE"

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