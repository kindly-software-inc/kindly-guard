#!/usr/bin/env python3
"""
Test client for KindlyGuard MCP server
Tests the JSON-RPC 2.0 protocol implementation
"""

import json
import subprocess
import sys
import time

def send_request(proc, request):
    """Send a JSON-RPC request and get response"""
    request_str = json.dumps(request)
    print(f"→ Sending: {request_str}")
    
    proc.stdin.write(request_str + "\n")
    proc.stdin.flush()
    
    response_line = proc.stdout.readline().strip()
    if response_line:
        response = json.loads(response_line)
        print(f"← Received: {json.dumps(response, indent=2)}")
        return response
    return None

def test_mcp_protocol():
    """Test the MCP protocol implementation"""
    print("Starting KindlyGuard MCP server test...")
    
    # Start the server
    proc = subprocess.Popen(
        ["cargo", "run", "--bin", "kindly-guard", "--", "--stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=0
    )
    
    try:
        # Give server time to start
        time.sleep(1)
        
        # Test 1: Initialize
        print("\n=== Test 1: Initialize ===")
        response = send_request(proc, {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {}
                },
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            },
            "id": 1
        })
        
        if response and "result" in response:
            print("✓ Initialize successful")
        else:
            print("✗ Initialize failed")
            
        # Test 2: Send initialized notification
        print("\n=== Test 2: Initialized notification ===")
        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0",
            "method": "initialized"
        }) + "\n")
        proc.stdin.flush()
        print("✓ Notification sent (no response expected)")
        
        # Test 3: List tools
        print("\n=== Test 3: List tools ===")
        response = send_request(proc, {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 2
        })
        
        if response and "result" in response and "tools" in response["result"]:
            print(f"✓ Found {len(response['result']['tools'])} tools")
            for tool in response["result"]["tools"]:
                print(f"  - {tool['name']}: {tool['description']}")
        
        # Test 4: Call scan_text tool
        print("\n=== Test 4: Call scan_text tool ===")
        response = send_request(proc, {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "scan_text",
                "arguments": {
                    "text": "Normal text with \u202Ehidden\u202C unicode attack"
                }
            },
            "id": 3
        })
        
        if response and "result" in response:
            result = response["result"]
            print(f"✓ Scan complete: safe={result.get('safe', 'unknown')}")
            if "threats" in result and result["threats"]:
                print(f"  Found {len(result['threats'])} threats:")
                for threat in result["threats"]:
                    print(f"    - {threat.get('threat_type', 'unknown')}: {threat.get('description', '')}")
        
        # Test 5: List resources
        print("\n=== Test 5: List resources ===")
        response = send_request(proc, {
            "jsonrpc": "2.0",
            "method": "resources/list",
            "params": {},
            "id": 4
        })
        
        if response and "result" in response and "resources" in response["result"]:
            print(f"✓ Found {len(response['result']['resources'])} resources")
            for resource in response["result"]["resources"]:
                print(f"  - {resource['uri']}: {resource['name']}")
        
        # Test 6: Read security report
        print("\n=== Test 6: Read security report ===")
        response = send_request(proc, {
            "jsonrpc": "2.0",
            "method": "resources/read",
            "params": {
                "uri": "security-report://latest"
            },
            "id": 5
        })
        
        if response and "result" in response:
            print("✓ Retrieved security report")
        
        # Test 7: Test threat detection
        print("\n=== Test 7: Test threat detection ===")
        response = send_request(proc, {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "scan_text",
                "arguments": {
                    "text": "Injection test: '; DROP TABLE users; --"
                }
            },
            "id": 6
        })
        
        if response and "result" in response:
            result = response["result"]
            if not result.get("safe", True):
                print("✓ Correctly detected injection threat")
            else:
                print("✗ Failed to detect injection threat")
        
        # Test 8: Batch request
        print("\n=== Test 8: Batch request ===")
        batch_request = [
            {
                "jsonrpc": "2.0",
                "method": "security/status",
                "params": {},
                "id": 7
            },
            {
                "jsonrpc": "2.0",
                "method": "security/threats",
                "params": {"limit": 5},
                "id": 8
            }
        ]
        
        print(f"→ Sending batch: {json.dumps(batch_request)}")
        proc.stdin.write(json.dumps(batch_request) + "\n")
        proc.stdin.flush()
        
        # Note: Current implementation might not support batch requests
        # This is testing for future implementation
        
        # Test 9: Shutdown
        print("\n=== Test 9: Shutdown ===")
        response = send_request(proc, {
            "jsonrpc": "2.0",
            "method": "shutdown",
            "params": {},
            "id": 9
        })
        
        if response:
            print("✓ Shutdown command sent")
        
    except Exception as e:
        print(f"\n✗ Error during testing: {e}")
        
    finally:
        # Cleanup
        proc.terminate()
        proc.wait()
        print("\n=== Test complete ===")

if __name__ == "__main__":
    test_mcp_protocol()