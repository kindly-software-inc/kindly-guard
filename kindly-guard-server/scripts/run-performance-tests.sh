#!/bin/bash
# Performance regression testing script for KindlyGuard

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== KindlyGuard Performance Regression Tests ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "$PROJECT_ROOT/Cargo.toml" ]; then
    echo -e "${RED}Error: Not in the kindly-guard-server directory${NC}"
    exit 1
fi

cd "$PROJECT_ROOT"

# Parse command line arguments
RUN_ENHANCED=false
UPDATE_BASELINES=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --enhanced)
            RUN_ENHANCED=true
            shift
            ;;
        --update-baselines)
            UPDATE_BASELINES=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --enhanced         Run enhanced implementation tests (requires feature flag)"
            echo "  --update-baselines Update performance baselines"
            echo "  --verbose          Show detailed output"
            echo "  --help             Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Backup existing baselines if updating
if [ "$UPDATE_BASELINES" = true ] && [ -f "tests/performance_baselines.json" ]; then
    BACKUP_FILE="tests/performance_baselines.backup.$(date +%Y%m%d_%H%M%S).json"
    echo -e "${YELLOW}Backing up existing baselines to: $BACKUP_FILE${NC}"
    cp "tests/performance_baselines.json" "$BACKUP_FILE"
fi

# Function to run tests
run_performance_tests() {
    local features=$1
    local label=$2
    
    echo -e "${GREEN}Running $label performance tests...${NC}"
    
    if [ "$VERBOSE" = true ]; then
        cargo test --test performance_regression $features -- --nocapture --test-threads=1
    else
        cargo test --test performance_regression $features -- --test-threads=1
    fi
}

# Run standard implementation tests
run_performance_tests "" "standard"

# Run enhanced implementation tests if requested
if [ "$RUN_ENHANCED" = true ]; then
    echo
    run_performance_tests "--features enhanced" "enhanced"
fi

# Generate performance comparison report
echo
echo -e "${GREEN}Generating performance report...${NC}"

if [ -f "tests/performance_baselines.json" ]; then
    # Extract and display key metrics
    echo
    echo "=== Performance Summary ==="
    
    if command -v jq &> /dev/null; then
        # Use jq to parse JSON if available
        jq -r '
            to_entries | 
            map(select(.key | contains("standard"))) |
            .[] | 
            "\(.value.operation) (\(.value.implementation)): \(.value.mean_duration_ns / 1000000 | floor)ms ± \(.value.std_deviation_ns / 1000000 | floor)ms"
        ' tests/performance_baselines.json 2>/dev/null || echo "Could not parse baselines"
        
        if [ "$RUN_ENHANCED" = true ]; then
            echo
            echo "Enhanced vs Standard Comparison:"
            # Would show comparison here if both implementations are tested
        fi
    else
        echo "Install 'jq' for detailed performance summaries"
    fi
fi

# Check for regressions
if [ -f "tests/performance_regression_report.log" ]; then
    if grep -q "Performance regression detected" "tests/performance_regression_report.log"; then
        echo
        echo -e "${RED}⚠️  Performance regressions detected!${NC}"
        echo "See tests/performance_regression_report.log for details"
        exit 1
    fi
fi

echo
echo -e "${GREEN}✅ Performance tests completed successfully${NC}"

# Provide next steps
if [ "$UPDATE_BASELINES" = false ]; then
    echo
    echo "To update performance baselines, run:"
    echo "  $0 --update-baselines"
fi