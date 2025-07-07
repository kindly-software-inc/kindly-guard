#!/bin/bash
# Test script for event buffer benchmarks

set -e

echo "Testing event buffer benchmarks..."
cd kindly-guard/kindly-guard-server

# First, check if the benchmark compiles
echo "Checking benchmark compilation..."
cargo check --benches --all-features

# Run a quick benchmark test (just 1 iteration to verify it works)
echo "Running quick benchmark test..."
cargo bench --bench event_buffer_benchmarks -- --test

echo "Event buffer benchmarks are ready!"
echo ""
echo "To run the full benchmarks:"
echo "  cd kindly-guard/kindly-guard-server"
echo "  cargo bench --bench event_buffer_benchmarks"
echo ""
echo "To run with enhanced features:"
echo "  cargo bench --bench event_buffer_benchmarks --features enhanced"