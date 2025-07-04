#!/bin/bash
# Load Testing Runner for KindlyGuard
# Tests system behavior under various load patterns

set -e

echo "=== KindlyGuard Load Testing Suite ==="
echo "Testing system behavior under various load patterns"
echo

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to run a test with nice output
run_test() {
    local test_name=$1
    echo -e "${YELLOW}Running: $test_name${NC}"
    
    if cargo test --test load_testing $test_name -- --nocapture 2>/dev/null; then
        echo -e "${GREEN}✓ $test_name passed${NC}"
    else
        echo -e "${RED}✗ $test_name failed${NC}"
    fi
    echo
}

cd kindly-guard-server

# Quick tests (run by default)
echo "=== Quick Load Tests ==="
run_test test_steady_load
run_test test_burst_load
run_test test_gradual_ramp
run_test test_mixed_workload
run_test test_rate_limiting_under_load
run_test test_performance_degradation

# Long-running tests (optional)
if [ "$1" == "--all" ]; then
    echo
    echo "=== Extended Load Tests ==="
    echo "Warning: These tests take several minutes to complete"
    run_test test_sustained_load
fi

echo
echo "=== Load Testing Complete ==="
echo "To run all tests including long-running ones, use: ./run-load-tests.sh --all"