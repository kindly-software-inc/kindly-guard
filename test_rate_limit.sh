#!/bin/bash
# Test script for rate limiting functionality

echo "=== Testing KindlyGuard Rate Limiting ==="

# Create config with rate limiting enabled
cat > test_rate_limit_config.toml << EOF
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
enabled = false

[rate_limit]
enabled = true
default_rpm = 12  # 12 per minute = 1 every 5 seconds for easy testing
burst_capacity = 3  # Allow 3 immediate requests
cleanup_interval_secs = 60

[rate_limit.method_limits."tools/list"]
rpm = 6  # Even more restrictive for testing
burst = 2
EOF

echo "1. Testing burst capacity (should allow 3 quick requests)..."
for i in {1..5}; do
    echo "Request $i:"
    echo '{"jsonrpc":"2.0","method":"tools/list","params":null,"id":'$i'}' | \
    timeout 2 cargo run --quiet --package kindly-guard-server --bin kindly-guard -- --config test_rate_limit_config.toml --stdio 2>/dev/null | \
    grep -o '"method":"tools/list"' && echo "✓ Allowed" || echo "✗ Rate limited"
    sleep 0.1
done

echo -e "\n2. Testing rate limit status endpoint..."
echo '{"jsonrpc":"2.0","method":"security/rate_limit_status","params":null,"id":10}' | \
cargo run --quiet --package kindly-guard-server --bin kindly-guard -- --config test_rate_limit_config.toml --stdio 2>/dev/null | \
grep -v "^\[" | jq '.result' || echo "Failed to get rate limit status"

echo -e "\n3. Testing threat penalty..."
# Send a request with unicode threat
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"scan_text","arguments":{"text":"Hello\u202EWorld"}},"id":20}' | \
cargo run --quiet --package kindly-guard-server --bin kindly-guard -- --config test_rate_limit_config.toml --stdio 2>/dev/null | \
grep -o '"code":-32000' && echo "✓ Threat detected (penalty should be applied)" || echo "✗ Threat not detected"

echo -e "\nRate limiting tests completed."

# Cleanup
rm -f test_rate_limit_config.toml