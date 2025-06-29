#!/bin/bash
# Script to run tests with coverage reporting using cargo-llvm-cov

set -e

echo "🔍 Running tests with coverage..."

# Check if cargo-llvm-cov is installed
if ! command -v cargo-llvm-cov &> /dev/null; then
    echo "📦 Installing cargo-llvm-cov..."
    cargo install cargo-llvm-cov
fi

# Clean previous coverage data
echo "🧹 Cleaning previous coverage data..."
cargo llvm-cov clean --workspace

# Run tests with coverage
echo "🧪 Running tests with coverage collection..."
cargo llvm-cov test --all-features --workspace \
    --exclude kindly-guard-core \
    --lcov --output-path lcov.info

# Generate HTML report
echo "📊 Generating HTML coverage report..."
cargo llvm-cov report --html --output-dir coverage

# Generate summary
echo "📈 Coverage Summary:"
cargo llvm-cov report --summary-only

# Run security-specific tests separately for visibility
echo "🔒 Running security tests..."
cargo llvm-cov test --all-features security_tests

# Check if we meet minimum coverage threshold
COVERAGE=$(cargo llvm-cov report --summary-only | grep TOTAL | awk '{print $10}' | sed 's/%//')
THRESHOLD=70

echo ""
if (( $(echo "$COVERAGE >= $THRESHOLD" | bc -l) )); then
    echo "✅ Coverage ${COVERAGE}% meets minimum threshold of ${THRESHOLD}%"
else
    echo "❌ Coverage ${COVERAGE}% is below minimum threshold of ${THRESHOLD}%"
    exit 1
fi

echo ""
echo "📂 Coverage report available at: coverage/html/index.html"
echo "📄 LCOV report available at: lcov.info"