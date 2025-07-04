#!/usr/bin/env python3
"""
WebSocket test client for KindlyGuard Shield
Tests the WebSocket server functionality without requiring the full Tauri app
"""

import asyncio
import json
import time
import websockets
from datetime import datetime

async def test_websocket_server():
    uri = "ws://localhost:9955"
    
    print(f"🔗 Connecting to KindlyGuard Shield WebSocket server at {uri}...")
    
    try:
        async with websockets.connect(uri) as websocket:
            print("✅ Connected successfully!\n")
            
            # Test 1: Subscribe
            subscribe_cmd = {"type": "subscribe"}
            print(f"📤 Sending: {json.dumps(subscribe_cmd)}")
            await websocket.send(json.dumps(subscribe_cmd))
            
            # Listen for initial response
            response = await websocket.recv()
            print(f"📥 Received: {response}")
            parse_message(response)
            
            # Test 2: Get Status
            await asyncio.sleep(1)
            status_cmd = {"type": "get_status"}
            print(f"\n📤 Sending: {json.dumps(status_cmd)}")
            await websocket.send(json.dumps(status_cmd))
            
            # Test 3: Toggle Protection
            await asyncio.sleep(1)
            toggle_cmd = {"type": "toggle_protection"}
            print(f"\n📤 Sending: {json.dumps(toggle_cmd)}")
            await websocket.send(json.dumps(toggle_cmd))
            
            # Test 4: Invalid command (to test error handling)
            await asyncio.sleep(1)
            invalid_cmd = {"type": "invalid_command"}
            print(f"\n📤 Sending invalid command: {json.dumps(invalid_cmd)}")
            await websocket.send(json.dumps(invalid_cmd))
            
            # Test 5: Rate limiting test
            print("\n🏃 Testing rate limiting (sending 10 rapid requests)...")
            for i in range(10):
                await websocket.send(json.dumps({"type": "get_status"}))
                await asyncio.sleep(0.1)  # 100ms between requests
            
            # Listen for more messages
            print("\n👂 Listening for messages for 5 seconds...")
            end_time = time.time() + 5
            
            while time.time() < end_time:
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    print(f"\n📥 Received: {response}")
                    parse_message(response)
                except asyncio.TimeoutError:
                    print(".", end="", flush=True)
            
            print("\n\n🔌 Closing connection...")
            
    except websockets.exceptions.ConnectionRefused:
        print("❌ Connection refused! Is the KindlyGuard Shield running?")
        print("   The WebSocket server should be running on port 9955")
    except Exception as e:
        print(f"❌ Error: {type(e).__name__}: {e}")

def parse_message(message):
    """Parse and display WebSocket message in a readable format"""
    try:
        data = json.loads(message)
        msg_type = data.get('type', 'unknown')
        
        if msg_type == 'status':
            protection = "🛡️ ENABLED" if data.get('protection_enabled') else "⚠️ DISABLED"
            threats = data.get('threats_blocked', 0)
            print(f"   Status: Protection {protection}, Threats blocked: {threats}")
        
        elif msg_type == 'threat':
            threats = data.get('threats', [])
            print(f"   ⚠️ {len(threats)} threat(s) detected:")
            for i, threat in enumerate(threats):
                print(f"      {i+1}. {threat.get('threat_type')} - {threat.get('description')}")
        
        elif msg_type == 'error':
            print(f"   ❌ Error: {data.get('message')}")
        
        elif msg_type == 'heartbeat':
            print("   💓 Heartbeat received")
        
        else:
            print(f"   📦 {msg_type}: {json.dumps(data, indent=2)}")
            
    except json.JSONDecodeError:
        print(f"   📝 Raw message: {message}")

async def test_binary_protocol():
    """Test binary protocol support (if implemented)"""
    uri = "ws://localhost:9955"
    
    print("\n🔧 Testing binary protocol support...")
    
    try:
        async with websockets.connect(uri) as websocket:
            # Send a binary message
            binary_data = b'\x00\x01\x02\x03\x04\x05'
            print(f"📤 Sending binary data: {binary_data.hex()}")
            await websocket.send(binary_data)
            
            # Wait for response
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                if isinstance(response, bytes):
                    print(f"📥 Received binary: {response.hex()}")
                else:
                    print(f"📥 Received text: {response}")
            except asyncio.TimeoutError:
                print("⏱️ No response to binary message (server may not support binary protocol)")
                
    except Exception as e:
        print(f"❌ Binary test error: {type(e).__name__}: {e}")

if __name__ == "__main__":
    print("🛡️ KindlyGuard Shield WebSocket Test Client")
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # Run main test
    asyncio.run(test_websocket_server())
    
    # Optionally test binary protocol
    # asyncio.run(test_binary_protocol())
    
    print("\n✅ Test completed!")