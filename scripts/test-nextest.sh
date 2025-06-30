#!/bin/bash
# Script to run tests using cargo-nextest for better performance and output

set -e

echo "🚀 Running tests with cargo-nextest..."

# Check if cargo-nextest is installed
if ! command -v cargo-nextest &> /dev/null; then
    echo "📦 Installing cargo-nextest..."
    curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C ${CARGO_HOME:-~/.cargo}/bin
fi

# Run tests with nextest
echo "🧪 Running all tests..."
cargo nextest run --all-features --workspace \
    --exclude private-deps \
    --status-level all \
    --failure-output immediate \
    --success-output never

# Run tests with enhanced output for CI
if [ "$CI" == "true" ]; then
    echo "📊 Running tests with JUnit output for CI..."
    cargo nextest run --all-features --workspace \
        --exclude private-deps \
        --profile ci \
        --message-format libtest-json-plus \
        --output-path test-results.xml
fi

# Show test summary
echo ""
echo "✅ All tests passed!"