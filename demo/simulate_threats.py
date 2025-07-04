#!/usr/bin/env python3
"""Simulate a stream of threats for the Shield UI demo"""

import json
import time
import random
import subprocess

# Various threat samples
THREATS = [
    {"type": "unicode", "payload": "admin\u200Bpassword", "severity": "high"},
    {"type": "sql_injection", "payload": "' OR 1=1 --", "severity": "critical"},
    {"type": "xss", "payload": "<img src=x onerror=alert(1)>", "severity": "high"},
    {"type": "path_traversal", "payload": "../../../etc/passwd", "severity": "critical"},
    {"type": "command_injection", "payload": "; cat /etc/passwd", "severity": "critical"},
    {"type": "unicode", "payload": "file\u202E.exe", "severity": "medium"},
    {"type": "ldap_injection", "payload": "*)(uid=*", "severity": "high"},
    {"type": "xml_injection", "payload": "<!ENTITY xxe SYSTEM 'file:///'>", "severity": "critical"},
]

def simulate_threat_stream():
    print("Simulating threat stream...")
    print("Shield should show real-time notifications!\n")
    
    for i in range(10):
        threat = random.choice(THREATS)
        
        # Create test payload
        test_data = {
            "method": "test/scan",
            "params": {
                "text": threat["payload"],
                "context": "live_stream"
            }
        }
        
        # Send to KindlyGuard
        process = subprocess.Popen(
            ["../target/release/kindly-guard", "scan", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate(json.dumps(test_data))
        
        if process.returncode == 0:
            print(f"Threat {i+1}: {threat['type']} - Severity: {threat['severity']}")
        
        # Random delay between threats
        time.sleep(random.uniform(0.5, 2.0))
    
    print("\nThreat simulation complete!")

if __name__ == "__main__":
    simulate_threat_stream()