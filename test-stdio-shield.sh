#!/bin/bash

# Test script to interact with KindlyGuard in stdio mode with shield display

echo "Starting KindlyGuard with shield display..."

# Create a named pipe for bidirectional communication
mkfifo /tmp/kindly-in /tmp/kindly-out 2>/dev/null || true

# Start KindlyGuard in background with shield
./target/release/kindly-guard --config minimal-config.toml --shield --stdio < /tmp/kindly-in > /tmp/kindly-out 2>&1 &
KINDLY_PID=$!

# Give it a moment to start
sleep 1

# Send initialize request
echo '{"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {"roots": {"listChanged": true}, "sampling": {}}, "clientInfo": {"name": "test-client", "version": "1.0.0"}}, "id": 1}' > /tmp/kindly-in

# Read response
timeout 2 cat /tmp/kindly-out

# Send a scan request with a threat
echo '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "scan_text", "arguments": {"text": "<script>alert(XSS)</script>"}}, "id": 2}' > /tmp/kindly-in

# Read response
timeout 2 cat /tmp/kindly-out

# Cleanup
kill $KINDLY_PID 2>/dev/null
rm -f /tmp/kindly-in /tmp/kindly-out