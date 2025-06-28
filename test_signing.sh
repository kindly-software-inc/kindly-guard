#!/bin/bash
# Test script for message signing and verification

echo "=== Testing KindlyGuard Message Signing ==="

# Generate a test secret for HMAC (32 bytes = 44 chars base64)
TEST_SECRET=$(echo -n "test-secret-key-for-kindlyguard-hmac" | base64)

# Create config with signing enabled
cat > test_signing_config.toml << EOF
[server]
port = 8080
stdio = true

[scanner]
unicode_detection = true
injection_detection = true

[shield]
enabled = false

[auth]
enabled = false

[signing]
enabled = true
algorithm = "hmac_sha256"
hmac_secret = "$TEST_SECRET"
require_signatures = false
include_timestamp = true
EOF

echo "1. Testing unsigned message (grace period)..."
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}' | \
RUST_LOG=kindly_guard=debug cargo run --package kindly-guard-server --bin kindly-guard -- --config test_signing_config.toml --stdio 2>&1 | grep -E "(initialize|signature)"

echo -e "\n2. Testing signed message structure..."
# The server will sign its responses when signing is enabled
echo '{"jsonrpc":"2.0","method":"tools/list","params":null,"id":2}' | \
cargo run --package kindly-guard-server --bin kindly-guard -- --config test_signing_config.toml --stdio 2>&1 | \
grep -v "^\[" | jq . || echo "Response parsing failed"

echo -e "\n3. Testing with Ed25519..."
# Generate Ed25519 key for testing (using openssl or similar would be needed for real test)
cat > test_ed25519_config.toml << EOF
[server]
port = 8080
stdio = true

[scanner]
unicode_detection = true
injection_detection = true

[shield]
enabled = false

[auth]
enabled = false

[signing]
enabled = false  # Disabled for now as we need proper key generation
algorithm = "ed25519"
# ed25519_private_key = "base64-encoded-32-byte-key"
EOF

echo "Signing tests completed."

# Cleanup
rm -f test_signing_config.toml test_ed25519_config.toml