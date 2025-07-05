#!/bin/bash
# Test script for the new release checklist functionality

set -e

echo "Building xtask..."
cd xtask
cargo build --quiet

echo -e "\nTesting release checklist without version:"
cargo run -- release --checklist

echo -e "\nTesting release checklist with version:"
cargo run -- release --checklist 1.0.0

echo -e "\nNote: Some checks may fail if development tools are not installed."
echo "This is expected behavior and demonstrates the warning system."