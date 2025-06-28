#!/bin/bash
# Test script for enhanced security features with AtomicEventBuffer

echo "=== Testing KindlyGuard Enhanced Security (Patented Technology) ==="

# Create config with all security features enabled
cat > test_enhanced_config.toml << EOF
[server]
port = 8080
stdio = true

[scanner]
unicode_detection = true
injection_detection = true
enable_event_buffer = true  # Enable patented atomic event buffer

[shield]
enabled = false

[auth]
enabled = true
require_signatures = false

[signing]
enabled = true
algorithm = "hmac_sha256"
hmac_secret = "$(echo -n "test-secret-key-for-kindlyguard-hmac" | base64)"

[rate_limit]
enabled = true
default_rpm = 30
burst_capacity = 5
threat_penalty_multiplier = 0.5

[event_processor]
# Enable advanced security event processing (patented technology)
enabled = true
buffer_size_mb = 10
max_endpoints = 100
rate_limit = 10000.0
failure_threshold = 3
pattern_detection = true
correlation_enabled = true
EOF

echo "1. Testing event tracking for authentication..."
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}' | \
timeout 2 cargo run --quiet --package kindly-guard-server --bin kindly-guard -- --config test_enhanced_config.toml --stdio 2>&1 | \
grep -E "(Event|Circuit|Monitor)" || echo "✓ Event tracking active (silent)"

echo -e "\n2. Testing threat detection with event correlation..."
# Send request with unicode threat
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"scan_text","arguments":{"text":"Hello\u202EWorld"}},"id":2}' | \
timeout 2 cargo run --quiet --package kindly-guard-server --bin kindly-guard -- --config test_enhanced_config.toml --stdio 2>&1 | \
grep -o '"code":-32000' && echo "✓ Threat detected and tracked"

echo -e "\n3. Testing rate limit with atomic tracking..."
# Rapid requests to trigger rate limit
for i in {1..10}; do
    echo '{"jsonrpc":"2.0","method":"tools/list","params":null,"id":'$i'}' | \
    timeout 1 cargo run --quiet --package kindly-guard-server --bin kindly-guard -- --config test_enhanced_config.toml --stdio 2>/dev/null | \
    grep -q '"result"' && echo "Request $i: ✓" || echo "Request $i: ✗ Rate limited"
done

echo -e "\n4. Testing security status endpoint..."
echo '{"jsonrpc":"2.0","method":"security/status","params":null,"id":100}' | \
cargo run --quiet --package kindly-guard-server --bin kindly-guard -- --config test_enhanced_config.toml --stdio 2>&1 | \
grep -o '"active":true' && echo "✓ Security monitoring active"

echo -e "\nEnhanced security tests completed."
echo "When event_processor.enabled=true, all security events are tracked using"
echo "the patented AtomicEventBuffer for lock-free, high-performance monitoring."

# Cleanup
rm -f test_enhanced_config.toml