#!/usr/bin/env node

// Simple WebSocket client to test KindlyGuard Shield WebSocket server
const WebSocket = require('ws');

const ws = new WebSocket('ws://localhost:9955');

console.log('Attempting to connect to KindlyGuard Shield WebSocket server...');

ws.on('open', function open() {
    console.log('✅ Connected to WebSocket server');
    
    // Test 1: Subscribe to updates
    console.log('\n📤 Sending: Subscribe command');
    ws.send(JSON.stringify({ type: 'subscribe' }));
    
    // Test 2: Get status after 1 second
    setTimeout(() => {
        console.log('\n📤 Sending: Get status command');
        ws.send(JSON.stringify({ type: 'get_status' }));
    }, 1000);
    
    // Test 3: Toggle protection after 2 seconds
    setTimeout(() => {
        console.log('\n📤 Sending: Toggle protection command');
        ws.send(JSON.stringify({ type: 'toggle_protection' }));
    }, 2000);
    
    // Test 4: Send heartbeat after 3 seconds
    setTimeout(() => {
        console.log('\n📤 Sending: Heartbeat');
        ws.send(JSON.stringify({ type: 'heartbeat' }));
    }, 3000);
    
    // Close connection after 5 seconds
    setTimeout(() => {
        console.log('\n🔌 Closing connection...');
        ws.close();
    }, 5000);
});

ws.on('message', function message(data) {
    try {
        const msg = JSON.parse(data.toString());
        console.log('\n📥 Received:', JSON.stringify(msg, null, 2));
        
        // Analyze message type
        switch(msg.type) {
            case 'status':
                console.log(`   Protection: ${msg.protection_enabled ? '🛡️ ENABLED' : '⚠️ DISABLED'}`);
                console.log(`   Threats blocked: ${msg.threats_blocked}`);
                break;
            case 'threat':
                console.log(`   ⚠️ Threats detected: ${msg.threats.length}`);
                msg.threats.forEach((threat, i) => {
                    console.log(`   ${i+1}. ${threat.threat_type} - ${threat.description}`);
                });
                break;
            case 'error':
                console.log(`   ❌ Error: ${msg.message}`);
                break;
            case 'heartbeat':
                console.log('   💓 Heartbeat acknowledged');
                break;
        }
    } catch (e) {
        console.log('📥 Received raw:', data.toString());
    }
});

ws.on('error', function error(err) {
    console.error('❌ WebSocket error:', err.message);
    console.log('\nMake sure the KindlyGuard Shield is running and the WebSocket server is active on port 9955');
});

ws.on('close', function close() {
    console.log('\n👋 Disconnected from WebSocket server');
    process.exit(0);
});

// Handle Ctrl+C gracefully
process.on('SIGINT', function() {
    console.log('\n\nReceived SIGINT, closing connection...');
    ws.close();
});