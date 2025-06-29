#\!/usr/bin/env python3
import json
import subprocess
import sys

def send_request(request):
    """Send a request to the server and get response"""
    proc = subprocess.Popen(
        ['./target/release/kindly-guard', '--stdio'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    response, stderr = proc.communicate(json.dumps(request) + '\n')
    
    # Print stderr to see server logs
    if stderr:
        print("Server logs:", file=sys.stderr)
        print(stderr, file=sys.stderr)
    
    # Extract JSON response from stdout
    for line in response.split('\n'):
        if line.strip() and line.startswith('{'):
            return json.loads(line)
    return None

print("🧪 Testing KindlyGuard Server...\n")

# Test 1: Initialize
print("📍 Test 1: Initialize")
init_request = {
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {
            "name": "test-client",
            "version": "1.0.0"
        }
    },
    "id": 1
}
response = send_request(init_request)
print(json.dumps(response, indent=2))

# Test 2: List tools  
print("\n📍 Test 2: List tools")
tools_request = {
    "jsonrpc": "2.0",
    "method": "tools/list",
    "params": {},
    "id": 2
}
response = send_request(tools_request)
if response:
    print(f"Available tools: {len(response.get('result', {}).get('tools', []))}")
    for tool in response.get('result', {}).get('tools', []):
        print(f"  - {tool['name']}: {tool['description']}")

# Test 3: Scan text with threat
print("\n📍 Test 3: Scan text with Unicode threat")
scan_request = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "scan_text",
        "arguments": {
            "text": "Hello\u202EWorld"
        }
    },
    "id": 3
}
response = send_request(scan_request)
if response and 'result' in response:
    threats = response['result'].get('threats', [])
    print(f"Threats found: {len(threats)}")
    for threat in threats:
        print(f"  - {threat.get('threat_type')}: {threat.get('description')}")

# Test 4: Get security status
print("\n📍 Test 4: Get security status")
status_request = {
    "jsonrpc": "2.0",
    "method": "security/status",
    "params": {},
    "id": 4
}
response = send_request(status_request)
if response and 'result' in response:
    result = response['result']
    print(f"Security Status:")
    print(f"  - Active: {result.get('active')}")
    print(f"  - Threats blocked: {result.get('threats_blocked')}")
    print(f"  - Uptime: {result.get('uptime_seconds')}s")

print("\n✅ Testing complete\!")
EOF < /dev/null
