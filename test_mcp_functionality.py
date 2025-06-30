#!/usr/bin/env python3
"""Test script to verify KindlyGuard MCP functionality."""

import json
import subprocess
import sys
import time
from typing import Dict, Any, Optional

class MCPTester:
    """Test the MCP server functionality."""
    
    def __init__(self):
        self.request_id = 0
        
    def create_request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create a JSON-RPC request."""
        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "method": method,
            "id": self.request_id
        }
        if params:
            request["params"] = params
        return request
    
    def test_initialize(self) -> bool:
        """Test the initialize method."""
        print("\n=== Testing initialize ===")
        request = self.create_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        })
        
        response = self.send_request(request)
        if response and "result" in response:
            result = response["result"]
            print(f"✓ Protocol version: {result.get('protocolVersion')}")
            print(f"✓ Server info: {result.get('serverInfo')}")
            print(f"✓ Capabilities: {result.get('capabilities')}")
            return True
        return False
    
    def test_tools_list(self) -> bool:
        """Test the tools/list method."""
        print("\n=== Testing tools/list ===")
        request = self.create_request("tools/list")
        
        response = self.send_request(request)
        if response and "result" in response:
            tools = response["result"].get("tools", [])
            print(f"✓ Found {len(tools)} tools:")
            for tool in tools:
                print(f"  - {tool['name']}: {tool['description']}")
            return len(tools) > 0
        return False
    
    def test_scan_text(self) -> bool:
        """Test the scan_text tool."""
        print("\n=== Testing scan_text tool ===")
        
        # Test with safe text
        request = self.create_request("tools/call", {
            "name": "scan_text",
            "arguments": {
                "text": "Hello, this is a safe text message."
            }
        })
        
        response = self.send_request(request)
        if response and "result" in response:
            content = response["result"].get("content", [])
            if content and len(content) > 0:
                result_text = content[0].get("text", "")
                result_data = json.loads(result_text)
                print(f"✓ Safe text scan: {result_data.get('safe')}")
                print(f"  Threats found: {len(result_data.get('threats', []))}")
            
            # Test with unicode threat
            request = self.create_request("tools/call", {
                "name": "scan_text",
                "arguments": {
                    "text": "Hello\u202EWorld"  # Unicode BiDi override
                }
            })
            
            response = self.send_request(request)
            if response and "result" in response:
                content = response["result"].get("content", [])
                if content and len(content) > 0:
                    result_text = content[0].get("text", "")
                    result_data = json.loads(result_text)
                    print(f"✓ Unicode threat scan: {not result_data.get('safe')}")
                    threats = result_data.get('threats', [])
                    if threats:
                        print(f"  Detected threat: {threats[0]['type']}")
                    return True
        return False
    
    def test_get_security_info(self) -> bool:
        """Test the get_security_info tool."""
        print("\n=== Testing get_security_info tool ===")
        request = self.create_request("tools/call", {
            "name": "get_security_info",
            "arguments": {}
        })
        
        response = self.send_request(request)
        if response and "result" in response:
            content = response["result"].get("content", [])
            if content and len(content) > 0:
                result_text = content[0].get("text", "")
                result_data = json.loads(result_text)
                print(f"✓ Security status: {result_data.get('status')}")
                print(f"✓ Shield active: {result_data.get('shield', {}).get('active')}")
                print(f"✓ Threats blocked: {result_data.get('shield', {}).get('threats_blocked')}")
                return True
        return False
    
    def test_error_handling(self) -> bool:
        """Test error handling."""
        print("\n=== Testing error handling ===")
        
        # Test invalid method
        request = self.create_request("invalid/method")
        response = self.send_request(request)
        if response and "error" in response:
            error = response["error"]
            print(f"✓ Invalid method error: {error['message']}")
            
        # Test invalid params
        request = self.create_request("tools/call", {
            "name": "scan_text"
            # Missing required 'arguments' field
        })
        response = self.send_request(request)
        if response and "error" in response:
            error = response["error"]
            print(f"✓ Invalid params error: {error['message']}")
            return True
        return False
    
    def test_batch_requests(self) -> bool:
        """Test batch request handling."""
        print("\n=== Testing batch requests ===")
        
        batch = [
            self.create_request("tools/list"),
            self.create_request("tools/call", {
                "name": "get_security_info",
                "arguments": {}
            })
        ]
        
        # Send batch request directly as JSON string
        response = self.send_raw_json(json.dumps(batch))
        if response:
            try:
                batch_response = json.loads(response)
                if isinstance(batch_response, list) and len(batch_response) == 2:
                    print(f"✓ Received {len(batch_response)} responses")
                    return all("result" in r for r in batch_response)
            except json.JSONDecodeError:
                pass
        return False
    
    def send_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Send a request to the MCP server."""
        json_str = json.dumps(request)
        response_str = self.send_raw_json(json_str)
        if response_str:
            try:
                return json.loads(response_str)
            except json.JSONDecodeError as e:
                print(f"Failed to parse response: {e}")
                print(f"Response: {response_str}")
        return None
    
    def send_raw_json(self, json_str: str) -> Optional[str]:
        """Send raw JSON to the server via stdio."""
        try:
            # Start the server process
            process = subprocess.Popen(
                ["cargo", "run", "--release", "--bin", "kindly-guard", "--", "--stdio"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd="/home/samuel/kindly-guard"
            )
            
            # Send request and get response
            stdout, stderr = process.communicate(input=json_str + "\n", timeout=5)
            
            if stderr:
                print(f"Server stderr: {stderr}")
            
            # Extract the last line as response (skip log messages)
            lines = stdout.strip().split('\n')
            for line in reversed(lines):
                if line.strip().startswith('{'):
                    return line.strip()
            
            return None
            
        except subprocess.TimeoutExpired:
            print("Request timed out")
            process.kill()
        except Exception as e:
            print(f"Error: {e}")
        
        return None

def main():
    """Run all MCP tests."""
    print("🛡️ KindlyGuard MCP Functionality Test")
    print("=" * 40)
    
    tester = MCPTester()
    
    tests = [
        ("Initialize", tester.test_initialize),
        ("Tools List", tester.test_tools_list),
        ("Scan Text", tester.test_scan_text),
        ("Get Security Info", tester.test_get_security_info),
        ("Error Handling", tester.test_error_handling),
        ("Batch Requests", tester.test_batch_requests),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"\n✅ {test_name}: PASSED")
            else:
                failed += 1
                print(f"\n❌ {test_name}: FAILED")
        except Exception as e:
            failed += 1
            print(f"\n❌ {test_name}: FAILED with error: {e}")
    
    print("\n" + "=" * 40)
    print(f"Total tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())