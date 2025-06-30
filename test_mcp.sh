#!/bin/bash

echo "Testing KindlyGuard MCP Server"
echo "=============================="

# Function to send JSON-RPC request
send_request() {
    local request="$1"
    echo -e "\n>>> Request: $request"
    echo "$request" | ./target/release/kindly-guard --stdio 2>&1 | grep -E '"result"|"error"|INFO' | tail -5
}

# Test 1: Initialize
echo -e "\n1. Initialize"
send_request '{"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test", "version": "1.0"}}, "id": 1}'

# Test 2: List tools
echo -e "\n2. List Available Tools"
send_request '{"jsonrpc": "2.0", "method": "tools/list", "id": 2}'

# Test 3: Get security status
echo -e "\n3. Get Security Status"
send_request '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "security_status", "arguments": {}}, "id": 3}'

# Test 4: Scan for Unicode attacks
echo -e "\n4. Scan for Unicode Attacks (with malicious text)"
send_request '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "scan_text", "arguments": {"text": "Hello\\u202eWorld", "scan_type": "unicode"}}, "id": 4}'

# Test 5: Scan for SQL injection
echo -e "\n5. Scan for SQL Injection"
send_request '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "scan_text", "arguments": {"text": "SELECT * FROM users WHERE id = '\''1'\'' OR '\''1'\''='\''1'\''", "scan_type": "injection"}}, "id": 5}'

# Test 6: Path traversal detection
echo -e "\n6. Path Traversal Detection"
send_request '{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "scan_text", "arguments": {"text": "../../etc/passwd", "scan_type": "all"}}, "id": 6}'

echo -e "\n\nTest Complete!"