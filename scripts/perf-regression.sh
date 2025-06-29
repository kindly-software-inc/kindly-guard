#!/bin/bash
# Performance regression testing script
# Runs benchmarks and compares against baseline

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BENCH_DIR="target/criterion"
BASELINE_FILE=".perf-baseline.json"
THRESHOLD=5 # 5% regression threshold

echo "🚀 Running KindlyGuard Performance Regression Tests"
echo "=================================================="

# Function to check for regressions
check_regression() {
    local bench_name=$1
    local current_time=$2
    local baseline_time=$3
    
    if [[ -z "$baseline_time" ]]; then
        echo -e "${YELLOW}⚠️  No baseline for $bench_name${NC}"
        return 0
    fi
    
    # Calculate percentage change
    local change=$(echo "scale=2; (($current_time - $baseline_time) / $baseline_time) * 100" | bc)
    local abs_change=${change#-}
    
    if (( $(echo "$change > $THRESHOLD" | bc -l) )); then
        echo -e "${RED}❌ REGRESSION: $bench_name - ${change}% slower${NC}"
        return 1
    elif (( $(echo "$change < -$THRESHOLD" | bc -l) )); then
        echo -e "${GREEN}✅ IMPROVEMENT: $bench_name - ${abs_change}% faster${NC}"
    else
        echo -e "${GREEN}✓ OK: $bench_name - within threshold (${change}%)${NC}"
    fi
    return 0
}

# Run benchmarks
echo "Running benchmarks..."
if [ "${1:-}" = "--baseline" ]; then
    echo "Creating new baseline..."
    cargo bench --bench regression_benchmarks -- --save-baseline baseline
    echo -e "${GREEN}✅ Baseline created${NC}"
    exit 0
fi

# Run current benchmarks
cargo bench --bench regression_benchmarks

# Compare against baseline if it exists
if [ -f "$BENCH_DIR/baseline/estimates.json" ]; then
    echo ""
    echo "Comparing against baseline..."
    echo "============================"
    
    # Use critcmp if available
    if command -v critcmp &> /dev/null; then
        echo "Using critcmp for detailed comparison:"
        critcmp baseline -g '.*regression.*'
    else
        echo -e "${YELLOW}Install critcmp for detailed comparisons: cargo install critcmp${NC}"
    fi
fi

# Run additional checks
echo ""
echo "Additional Performance Checks"
echo "============================"

# Check binary size
echo -n "Binary size: "
if [ -f "target/release/kindly-guard" ]; then
    size=$(ls -lh target/release/kindly-guard | awk '{print $5}')
    echo "$size"
else
    echo "Release binary not found. Run 'cargo build --release' first."
fi

# Check memory usage during tests
if command -v /usr/bin/time &> /dev/null; then
    echo ""
    echo "Memory usage test (scanning large file):"
    echo "echo 'Test data' | /usr/bin/time -v cargo run --release -- scan -"
fi

echo ""
echo "Performance Regression Test Complete!"
echo ""
echo "Tips:"
echo "- Run with --baseline to create a new performance baseline"
echo "- Install critcmp for better benchmark comparisons: cargo install critcmp"
echo "- Use 'cargo bench -- --save-baseline <name>' to save named baselines"
echo "- View detailed results in target/criterion/report/index.html"