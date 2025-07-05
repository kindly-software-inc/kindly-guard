#!/bin/bash
set -e

echo "Testing validate-dist command..."

cd /home/samuel/kindly-guard

# Build xtask first
echo "Building xtask..."
cargo build -p xtask

# Test the validate-dist command
echo -e "\n1. Testing basic validation:"
cargo xtask validate-dist

echo -e "\n2. Testing detailed output:"
cargo xtask validate-dist --detailed

echo -e "\n3. Testing specific package validation:"
cargo xtask validate-dist --package kindly-guard-server

echo -e "\n4. Testing help output:"
cargo xtask validate-dist --help

echo -e "\nAll tests completed!"