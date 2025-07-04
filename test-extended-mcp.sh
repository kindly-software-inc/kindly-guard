#!/bin/bash
# Extended MCP test with threat monitoring

# Initialize
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
sleep 0.5

# Send initialized notification
echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
sleep 0.5

# Get shield status
echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_shield_status","arguments":{}}}'
sleep 0.5

# Scan various threats
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan_text","arguments":{"text":"Hello\u202EWorld"}}}'
sleep 0.5

echo '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"scan_text","arguments":{"text":"admin@example.com OR 1=1--"}}}'
sleep 0.5

echo '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"scan_text","arguments":{"text":"<img src=x onerror=alert(1)>"}}}'
sleep 0.5

# Get security info after threats
echo '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_security_info","arguments":{}}}'
sleep 0.5

# Keep alive for monitoring
sleep 10