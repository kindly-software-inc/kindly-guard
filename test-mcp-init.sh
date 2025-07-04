#!/bin/bash
# Test MCP initialization sequence

# Initialize
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
sleep 0.5

# Send initialized notification
echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
sleep 0.5

# List tools
echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
sleep 0.5

# Scan text with threat
echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan_text","arguments":{"text":"<script>alert(1)</script>"}}}'
sleep 2

# Keep connection alive for a bit
sleep 5