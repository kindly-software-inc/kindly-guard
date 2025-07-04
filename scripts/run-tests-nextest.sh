#!/bin/bash
# KindlyGuard Test Runner using cargo-nextest
# This script provides various test execution modes optimized for security testing

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROFILE="default"
FILTER=""
SHOW_OUTPUT=false
LIST_ONLY=false

# Helper functions
echo_header() {
    echo -e "\n${BLUE}==== $1 ====${NC}"
}

echo_success() {
    echo -e "${GREEN}✓${NC} $1"
}

echo_error() {
    echo -e "${RED}✗${NC} $1"
}

echo_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Show usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Run KindlyGuard tests using cargo-nextest with various profiles

OPTIONS:
    -p, --profile PROFILE    Use specific nextest profile (default: default)
                            Available: default, ci, security, perf, quick, release
    -f, --filter FILTER     Filter tests by name pattern
    -s, --show-output       Show test output even for passing tests
    -l, --list              List tests without running them
    -h, --help              Show this help message

EXAMPLES:
    # Run all tests with default profile
    $0

    # Run security tests with maximum isolation
    $0 -p security

    # Run only unicode-related tests
    $0 -f unicode

    # Quick test run for development
    $0 -p quick

    # CI-style test run with JUnit output
    $0 -p ci

    # List all security tests
    $0 -l -f security

PROFILES:
    default   - Balanced settings for local development
    ci        - Conservative settings for CI with JUnit output
    security  - Sequential execution with full isolation for security tests
    perf      - Maximum parallelism for performance testing
    quick     - Fast feedback, skips slow tests
    release   - Thorough testing for release validation
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--profile)
            PROFILE="$2"
            shift 2
            ;;
        -f|--filter)
            FILTER="$2"
            shift 2
            ;;
        -s|--show-output)
            SHOW_OUTPUT=true
            shift
            ;;
        -l|--list)
            LIST_ONLY=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Check if nextest is installed
if ! command -v cargo-nextest &> /dev/null && ! cargo nextest --version &> /dev/null 2>&1; then
    echo_error "cargo-nextest is not installed"
    echo_info "Install with: cargo install cargo-nextest"
    echo_info "Or use: curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C \${CARGO_HOME:-~/.cargo}/bin"
    exit 1
fi

# Change to project root
cd "$PROJECT_ROOT"

# Build command
CMD="cargo nextest"

if [[ "$LIST_ONLY" == true ]]; then
    CMD="$CMD list"
else
    CMD="$CMD run"
fi

CMD="$CMD --workspace --profile=$PROFILE"

if [[ -n "$FILTER" ]]; then
    CMD="$CMD -E 'test(/$FILTER/)'"
fi

if [[ "$SHOW_OUTPUT" == true ]] && [[ "$LIST_ONLY" == false ]]; then
    CMD="$CMD --no-capture"
fi

# Display test configuration
echo_header "KindlyGuard Test Runner (nextest)"
echo_info "Profile: ${MAGENTA}$PROFILE${NC}"
if [[ -n "$FILTER" ]]; then
    echo_info "Filter: ${MAGENTA}$FILTER${NC}"
fi
echo_info "Command: $CMD"

# Profile-specific messages
case "$PROFILE" in
    security)
        echo -e "\n${YELLOW}🔒 Security Profile:${NC}"
        echo "  • Tests run sequentially for maximum isolation"
        echo "  • No retries - tests must be deterministic"
        echo "  • Extended timeouts for thorough checks"
        echo "  • Full output capture for audit trail"
        ;;
    quick)
        echo -e "\n${YELLOW}⚡ Quick Profile:${NC}"
        echo "  • Maximum parallelism for speed"
        echo "  • Fail fast on first error"
        echo "  • Skips slow tests"
        ;;
    ci)
        echo -e "\n${YELLOW}🤖 CI Profile:${NC}"
        echo "  • Fixed thread count for reproducibility"
        echo "  • JUnit output to target/nextest/junit.xml"
        echo "  • Test output captured for debugging"
        ;;
    release)
        echo -e "\n${YELLOW}📦 Release Profile:${NC}"
        echo "  • Conservative parallelism"
        echo "  • Extended timeouts"
        echo "  • Full archival of results"
        ;;
esac

# Run tests
echo_header "Running Tests"

if eval "$CMD"; then
    echo_success "All tests passed!"
    
    # Show additional information for CI profile
    if [[ "$PROFILE" == "ci" ]] && [[ "$LIST_ONLY" == false ]]; then
        if [[ -f "target/nextest/junit.xml" ]]; then
            echo_info "JUnit report generated: target/nextest/junit.xml"
        fi
    fi
    
    # Show security recommendations
    if [[ "$PROFILE" == "default" ]] || [[ "$PROFILE" == "quick" ]]; then
        echo -e "\n${YELLOW}💡 Tip:${NC} Run with '-p security' for thorough security testing"
    fi
else
    echo_error "Some tests failed!"
    exit_code=$?
    
    # Provide helpful information on failure
    echo -e "\n${YELLOW}Debug tips:${NC}"
    echo "  • Run with -s/--show-output to see test output"
    echo "  • Check target/nextest/ for detailed logs"
    echo "  • Use -f/--filter to run specific tests"
    
    if [[ "$PROFILE" != "security" ]]; then
        echo "  • Try '-p security' for isolated test execution"
    fi
    
    exit $exit_code
fi

# Run doc tests separately (nextest doesn't support them)
if [[ "$LIST_ONLY" == false ]] && [[ -z "$FILTER" ]]; then
    echo_header "Running Doc Tests"
    echo_info "Doc tests still use standard cargo test"
    
    if cargo test --workspace --doc; then
        echo_success "All doc tests passed!"
    else
        echo_error "Some doc tests failed!"
        exit 1
    fi
fi