#!/bin/bash

echo "Testing KindlyGuard Universal Display and Commands..."
echo "===================================================="

# Build the project first
echo "Building KindlyGuard..."
cd /home/samuel/kindly-guard/kindly-guard-server
cargo build --release 2>/dev/null

# Test 1: Basic status command
echo -e "\n1. Testing /kindlyguard status (minimal format):"
../kindlyguard status --format minimal

echo -e "\n2. Testing /kindlyguard status (compact format):"
../kindlyguard status --format text

echo -e "\n3. Testing /kindlyguard status (JSON format):"
../kindlyguard status --format json | jq '.' 2>/dev/null || ../kindlyguard status --format json

echo -e "\n4. Testing /kindlyguard scan with text:"
../kindlyguard scan "Hello \u202e World" --text

echo -e "\n5. Testing /kindlyguard info:"
../kindlyguard info

echo -e "\n6. Testing /kindlyguard advancedsecurity status:"
../kindlyguard advancedsecurity status

echo -e "\n7. Testing /kindlyguard telemetry:"
../kindlyguard telemetry

echo -e "\n8. Testing color output (enhanced mode):"
../kindlyguard advancedsecurity enable
../kindlyguard status

echo -e "\n9. Testing no-color mode:"
../kindlyguard status --no-color

echo -e "\n10. Writing status to file:"
# This would happen automatically if status_file is configured
echo "Status file would be written to: /tmp/kindlyguard-status.json"

echo -e "\nAll tests completed!"