#!/bin/bash
# Demo script showing Purple Shield with enhanced security

echo "=== KindlyGuard Purple Shield Demo ==="
echo "When event_processor.enabled=true, the shield display turns PURPLE"
echo "and shows enhanced protection indicators."
echo ""

# Create config with all security features and event processor enabled
cat > purple_shield_config.toml << EOF
[server]
port = 8080
stdio = true

[scanner]
unicode_detection = true
injection_detection = true
enable_event_buffer = true  # Enables optimized event processing in scanner

[shield]
enabled = true  # Must use --shield flag to see display
update_interval_ms = 500
detailed_stats = true
color = true

[auth]
enabled = true

[signing]
enabled = true
algorithm = "hmac_sha256"
hmac_secret = "$(echo -n "demo-secret-key-for-purple-shield-demo" | base64)"

[rate_limit]
enabled = true
default_rpm = 60
burst_capacity = 10

[event_processor]
# ENABLE THIS FOR PURPLE SHIELD MODE
enabled = true  # <-- When true, shield turns purple!
buffer_size_mb = 20
max_endpoints = 1000
rate_limit = 10000.0
pattern_detection = true
correlation_enabled = true
EOF

echo "Configuration created with event_processor.enabled=true"
echo ""
echo "To see the Purple Shield in action, run:"
echo "  cargo run --package kindly-guard-server --bin kindly-guard -- --config purple_shield_config.toml --shield --stdio"
echo ""
echo "The shield will display:"
echo "  - Purple borders and title"
echo "  - '⚡ Enhanced Protection Active' indicator"
echo "  - 'Pattern Recognition: Active' in purple"
echo "  - 'Advanced Analytics: Enabled' in purple"
echo ""
echo "Behind the scenes:"
echo "  - Optimized event processing handles 10,000 events/second"
echo "  - High-performance threat correlation across all security layers"
echo "  - Efficient pattern matching in scanners"
echo "  - Automatic circuit breakers for attack mitigation"

# Also create a config with it disabled for comparison
cat > normal_shield_config.toml << EOF
[server]
port = 8080
stdio = true

[scanner]
unicode_detection = true
injection_detection = true
enable_event_buffer = false  # Normal mode

[shield]
enabled = true
update_interval_ms = 500
detailed_stats = true
color = true

[auth]
enabled = true

[signing]
enabled = true
algorithm = "hmac_sha256"
hmac_secret = "$(echo -n "demo-secret-key-for-purple-shield-demo" | base64)"

[rate_limit]
enabled = true

[event_processor]
enabled = false  # Normal green/red shield
EOF

echo ""
echo "Also created normal_shield_config.toml for comparison."
echo "Run with that config to see the standard green/red shield."