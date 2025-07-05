#!/bin/bash
# Test script for xtask interactive mode

set -e

echo "Building xtask..."
cd "$(dirname "$0")"
cargo build --quiet

echo ""
echo "Testing interactive mode..."
echo ""

# Run in interactive mode
cargo run -- --interactive

# Or just run without any commands to trigger interactive mode
# cargo run