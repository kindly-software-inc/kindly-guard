#!/usr/bin/env python3
"""Test unicode threat detection in KindlyGuard"""

import json
import subprocess
import sys

def test_unicode_threat():
    # Test payload with RTL override
    test_data = {
        "method": "test/scan",
        "params": {
            "text": "Important\u202Edocument.pdf",
            "context": "filename"
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
            print(f"  Position: {result['threats'][0]['position']}")
            print(f"  Severity: {result['threats'][0]['severity']}")
            print(f"  Neutralized text: {result.get('cleaned_text', 'N/A')}")
        else:
            print("\n✗ No threats detected (unexpected)")
    else:
        print(f"\n✗ Error: {stderr}")

if __name__ == "__main__":
    test_unicode_threat()