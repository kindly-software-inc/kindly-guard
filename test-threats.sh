#!/bin/bash

# Test script to simulate various threats for KindlyGuard monitoring

echo "Testing KindlyGuard threat detection..."

# Test 1: Unicode attack
echo "Test 1: Unicode homograph attack"
./target/release/kindly-guard --config minimal-config.toml scan --text "Check out this link: www.gооgle.com"

# Test 2: SQL injection
echo -e "\nTest 2: SQL injection"
./target/release/kindly-guard --config minimal-config.toml scan --text "'; DROP TABLE users; --"

# Test 3: XSS attack
echo -e "\nTest 3: XSS attack"
./target/release/kindly-guard --config minimal-config.toml scan --text "<script>alert('XSS')</script>"

# Test 4: Path traversal
echo -e "\nTest 4: Path traversal"
./target/release/kindly-guard --config minimal-config.toml scan --text "../../../etc/passwd"

# Test 5: Command injection
echo -e "\nTest 5: Command injection"
./target/release/kindly-guard --config minimal-config.toml scan --text "echo test; rm -rf /"

# Test 6: Zero-width character
echo -e "\nTest 6: Zero-width character"
./target/release/kindly-guard --config minimal-config.toml scan --text "Invis​ible"

echo -e "\nAll tests completed!"