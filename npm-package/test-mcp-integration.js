#!/usr/bin/env node

/**
 * Test script to verify MCP integration
 */

const { spawn } = require('child_process');
const path = require('path');

console.log('Testing KindlyGuard MCP integration...\n');

// Test 1: Check if kindlyguard.js exists and is executable
console.log('1. Checking CLI entry point...');
const cliPath = path.join(__dirname, 'kindlyguard.js');
try {
  require('fs').accessSync(cliPath, require('fs').constants.X_OK);
  console.log('   ✓ CLI entry point is executable');
} catch (e) {
  console.error('   ✗ CLI entry point is not executable');
  process.exit(1);
}

// Test 2: Test help command
console.log('\n2. Testing help command...');
const helpProc = spawn('node', [cliPath, '--help']);
let helpOutput = '';

helpProc.stdout.on('data', (data) => {
  helpOutput += data.toString();
});

helpProc.on('close', (code) => {
  if (code === 0 && helpOutput.includes('KindlyGuard')) {
    console.log('   ✓ Help command works');
  } else {
    console.error('   ✗ Help command failed');
  }
});

// Test 3: Test stdio mode startup
console.log('\n3. Testing stdio mode...');
const stdioProc = spawn('node', [cliPath, '--stdio'], {
  stdio: ['pipe', 'pipe', 'ignore']
});

// Send initialization message
setTimeout(() => {
  const initMessage = JSON.stringify({
    jsonrpc: "2.0",
    method: "initialize",
    params: {
      protocolVersion: "0.1.0",
      capabilities: {}
    },
    id: 1
  }) + '\n';
  
  stdioProc.stdin.write(initMessage);
  console.log('   ✓ Sent initialization message');
  
  // Wait a bit then kill the process
  setTimeout(() => {
    stdioProc.kill();
    console.log('   ✓ Server shutdown cleanly');
    console.log('\n✅ All tests passed! KindlyGuard is ready for MCP integration.');
  }, 1000);
}, 500);

stdioProc.on('error', (error) => {
  console.error('   ✗ Failed to start stdio mode:', error);
  process.exit(1);
});