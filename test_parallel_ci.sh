#!/bin/bash
# Test script for parallel CI - demonstrates the power of parallel execution

echo "Testing KindlyGuard Parallel CI System"
echo "======================================"
echo ""
echo "This will run a quick smoke test of the parallel CI"
echo ""

# Test with smoke tests only
echo "Running smoke tests in parallel..."
cargo xtask parallel-ci --smoke-tests --config .ci/parallel/config.toml

echo ""
echo "To run full parallel CI with all pipelines:"
echo "cargo xtask parallel-ci --dashboard"
echo ""
echo "To run with specific targets:"
echo "cargo xtask parallel-ci --targets linux-x64,macos --full-suite"