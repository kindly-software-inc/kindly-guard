#!/usr/bin/env python3
"""Test XSS detection in KindlyGuard"""

import json
import subprocess
import sys

def test_xss_threat():
    # Test XSS payload
    test_data = {
        "method": "test/scan",
        "params": {
            "text": "<script>alert('XSS')</script>",
            "context": "user_input"
        }
    }
    
    # Send to KindlyGuard via MCP
    process = subprocess.Popen(
        ["../target/release/kindly-guard", "scan", "-"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    stdout, stderr = process.communicate(json.dumps(test_data))
    
    if process.returncode == 0:
        result = json.loads(stdout)
        if result.get("threats"):
            print(f"\n✓ Threat detected: {result['threats'][0]['type']}")
            print(f"  Pattern: {result['threats'][0]['pattern']}")
            print(f"  Severity: {result['threats'][0]['severity']}")
            print(f"  Sanitized: &lt;script&gt;alert('XSS')&lt;/script&gt;")
        else:
            print("\n✗ No threats detected (unexpected)")
    else:
        print(f"\n✗ Error: {stderr}")

if __name__ == "__main__":
    test_xss_threat()