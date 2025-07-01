#!/usr/bin/env python3
"""Test the neutralization feature of KindlyGuard"""

import json
import subprocess
import sys

def send_request(method, params=None):
    """Send a JSON-RPC request to the server"""
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or {}
    }
    
    proc = subprocess.Popen(
        ['cargo', 'run', '--release', '--features', 'enhanced', '--', '--stdio'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd='/home/samuel/kindly-guard/kindly-guard-server'
    )
    
    # Send initialize first
    init_request = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocol_version": "2024-11-05",
            "client_info": {
                "name": "test_client",
                "version": "1.0.0"
            },
            "capabilities": {}
        }
    }
    
    proc.stdin.write(json.dumps(init_request) + '\n')
    proc.stdin.flush()
    init_response = proc.stdout.readline()
    print(f"Initialize response: {init_response}")
    
    # Send our actual request
    proc.stdin.write(json.dumps(request) + '\n')
    proc.stdin.flush()
    
    response = proc.stdout.readline()
    proc.terminate()
    
    return json.loads(response)

def test_unicode_neutralization():
    """Test Unicode threat neutralization"""
    print("\n=== Testing Unicode Neutralization ===")
    
    # Text with BiDi override character
    dangerous_text = "Hello\u202EWorld"
    
    response = send_request("tools/call", {
        "name": "scan_text",
        "arguments": {
            "text": dangerous_text
        }
    })
    
    print(f"Request: scan_text with BiDi character")
    print(f"Response: {json.dumps(response, indent=2)}")
    
    if "result" in response:
        result_text = response["result"]["content"][0]["text"]
        result_data = json.loads(result_text)
        
        print(f"\nThreats found: {result_data['threats_found']}")
        if "neutralization" in result_data:
            print(f"Neutralization mode: {result_data['neutralization']['mode']}")
            print(f"Neutralized: {result_data['neutralization']['neutralized']}")
            if "sanitized_text" in result_data:
                print(f"Sanitized text: {result_data['sanitized_text']}")

def test_sql_injection_neutralization():
    """Test SQL injection neutralization"""
    print("\n=== Testing SQL Injection Neutralization ===")
    
    # SQL injection attempt
    dangerous_sql = "SELECT * FROM users WHERE name = 'admin' OR '1'='1'"
    
    response = send_request("tools/call", {
        "name": "scan_text",
        "arguments": {
            "text": dangerous_sql
        }
    })
    
    print(f"Request: scan_text with SQL injection")
    print(f"Response: {json.dumps(response, indent=2)}")

if __name__ == "__main__":
    try:
        test_unicode_neutralization()
        test_sql_injection_neutralization()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)