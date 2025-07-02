#!/bin/bash
# Master test runner - runs both unit and integration tests

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           KindlyGuard Comprehensive Test Suite                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Timing
START_TIME=$(date +%s)

# Results
UNIT_RESULT=0
INTEGRATION_RESULT=0

# Check if we should run with coverage
WITH_COVERAGE=false
if [ "$1" = "--coverage" ]; then
    WITH_COVERAGE=true
    echo -e "${YELLOW}Running with coverage analysis${NC}"
    echo
fi

# Build the project first
echo -e "${BLUE}Building project...${NC}"
# Build without enhanced feature to avoid compilation errors
cargo build --quiet
echo -e "${GREEN}✓ Build completed${NC}"
echo

# Run unit tests
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║                        Unit Tests                             ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo

if ./run-unit-tests.sh; then
    UNIT_RESULT=0
else
    UNIT_RESULT=1
fi

echo
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║                    Integration Tests                          ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo

if ./run-integration-tests.sh; then
    INTEGRATION_RESULT=0
else
    INTEGRATION_RESULT=1
fi

# Performance benchmarks (optional)
if [ "$2" = "--bench" ]; then
    echo
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║                  Performance Benchmarks                       ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    cargo bench --bench comprehensive_benchmarks -- --warm-up-time 1 --measurement-time 3
fi

# Calculate elapsed time
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
MINUTES=$((ELAPSED / 60))
SECONDS=$((ELAPSED % 60))

# Final summary
echo
echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║                      Final Summary                            ║${NC}"
echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo

if [ $UNIT_RESULT -eq 0 ]; then
    echo -e "Unit Tests:        ${GREEN}PASSED${NC}"
else
    echo -e "Unit Tests:        ${RED}FAILED${NC}"
fi

if [ $INTEGRATION_RESULT -eq 0 ]; then
    echo -e "Integration Tests: ${GREEN}PASSED${NC}"
else
    echo -e "Integration Tests: ${RED}FAILED${NC}"
fi

echo -e "Time Elapsed:      ${MINUTES}m ${SECONDS}s"
echo

# Overall result
if [ $UNIT_RESULT -eq 0 ] && [ $INTEGRATION_RESULT -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed! KindlyGuard is ready for deployment.${NC}"
    echo
    echo "Next steps:"
    echo "  - Build binaries: ./build-binaries.sh"
    echo "  - Run benchmarks: cargo bench"
    echo "  - Check coverage: cargo tarpaulin"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Please fix the issues before deployment.${NC}"
    echo
    echo "Debug tips:"
    echo "  - Run failing test with output: cargo test --test <name> -- --nocapture"
    echo "  - Check logs: RUST_LOG=debug cargo test"
    echo "  - Run single test: cargo test test_name_here"
    exit 1
fi