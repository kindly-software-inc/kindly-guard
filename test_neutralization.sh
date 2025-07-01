#!/bin/bash

echo "Building KindlyGuard with enhanced features..."
cd /home/samuel/kindly-guard/kindly-guard-server
cargo build --release --features enhanced

echo -e "\n=== Testing Unicode Neutralization ==="

# Test with BiDi character
cat <<EOF | KINDLY_GUARD_CONFIG=/home/samuel/kindly-guard/test-neutralization-config.toml cargo run --release --features enhanced -- --stdio 2>/dev/null
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocol_version":"2024-11-05","client_info":{"name":"test","version":"1.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_text","arguments":{"text":"Hello\u202EWorld"}}}
{"jsonrpc":"2.0","id":3,"method":"shutdown"}
EOF

echo -e "\n=== Testing SQL Injection Neutralization ==="

# Test with SQL injection
cat <<EOF | KINDLY_GUARD_CONFIG=/home/samuel/kindly-guard/test-neutralization-config.toml cargo run --release --features enhanced -- --stdio 2>/dev/null
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocol_version":"2024-11-05","client_info":{"name":"test","version":"1.0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_text","arguments":{"text":"SELECT * FROM users WHERE name = 'admin' OR '1'='1'"}}}
{"jsonrpc":"2.0","id":3,"method":"shutdown"}
EOF