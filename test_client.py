#!/usr/bin/env python3
"""Test client for KindlyGuard MCP server"""

import json
import subprocess
import sys

def send_request(request):
    """Send a JSON-RPC request to the server via stdin"""
    print(f"\n>>> Sending: {json.dumps(request, indent=2)}")
    print(json.dumps(request))
    sys.stdout.flush()

# Test 1: Initialize
print("=== Test 1: Initialize ===")
send_request({
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {},
            "sampling": {}
        },
        "clientInfo": {
            "name": "test-client",
            "version": "1.0.0"
        }
    },
    "id": 1
})

# Test 2: List tools
print("\n=== Test 2: List Available Tools ===")
send_request({
    "jsonrpc": "2.0",
    "method": "tools/list",
    "id": 2
})

# Test 3: Get security status
print("\n=== Test 3: Get Security Status ===")
send_request({
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "security_status",
        "arguments": {}
    },
    "id": 3
})

# Test 4: Scan for Unicode attacks
print("\n=== Test 4: Scan for Unicode Attacks ===")
send_request({
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "scan_text",
        "arguments": {
            "text": "Hello\u202eWorld",
            "scan_type": "unicode"
        }
    },
    "id": 4
})

# Test 5: Scan for injection attempts
print("\n=== Test 5: Scan for SQL Injection ===")
send_request({
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "scan_text",
        "arguments": {
            "text": "SELECT * FROM users WHERE id = '1' OR '1'='1'",
            "scan_type": "injection"
        }
    },
    "id": 5
})

# Test 6: Test path traversal detection
print("\n=== Test 6: Path Traversal Detection ===")
send_request({
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "scan_text",
        "arguments": {
            "text": "../../etc/passwd",
            "scan_type": "all"
        }
    },
    "id": 6
})

print("\n=== All tests sent! ===")
print("Check server output for responses and security shield display")