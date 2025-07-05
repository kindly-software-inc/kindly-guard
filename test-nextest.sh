#!/usr/bin/env bash
# Test script to demonstrate cargo-nextest integration

set -euo pipefail

echo "=== Testing cargo-nextest integration ==="
echo

# Build xtask first
echo "Building xtask..."
cargo build -p xtask

# Run tests with nextest using default profile
echo "Running tests with nextest (default profile)..."
cargo xtask test --nextest

echo
echo "Running tests with nextest (quick profile)..."
cargo xtask test --nextest --nextest-profile quick

echo
echo "Running only unit tests with nextest..."
cargo xtask test --nextest --unit

echo
echo "Running tests with custom thread count..."
cargo xtask test --nextest --test-threads 4

echo
echo "=== Nextest integration test complete ==="