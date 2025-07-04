#!/usr/bin/env node

/**
 * Test script for KindlyGuard npm package
 * Verifies the package is correctly installed and functional
 */

const kindlyguard = require('./lib/main.js');
const platform = require('./lib/platform.js');
const assert = require('assert');
const path = require('path');
const fs = require('fs');

console.log('Testing KindlyGuard npm package...\n');

// Test 1: Platform detection
console.log('1. Testing platform detection:');
try {
  const platformKey = platform.getPlatformKey();
  console.log(`   ✓ Platform: ${platformKey}`);
  console.log(`   ✓ Package name: ${platform.getPackageName()}`);
  console.log(`   ✓ Binary name: ${platform.getBinaryName('kindlyguard')}`);
} catch (error) {
  console.error(`   ✗ Platform detection failed: ${error.message}`);
  process.exit(1);
}

// Test 2: Binary validation
console.log('\n2. Testing binary validation:');
try {
  const binaryPath = platform.getBinaryPath('kindlyguard');
  const validation = platform.validateBinary(binaryPath);
  
  if (validation.valid) {
    console.log(`   ✓ Binary found at: ${binaryPath}`);
  } else {
    console.log(`   ✗ Binary validation failed: ${validation.error}`);
    console.log('   Note: Run npm install to download the binary');
  }
} catch (error) {
  console.error(`   ✗ Binary validation error: ${error.message}`);
}

// Test 3: API interface
console.log('\n3. Testing API interface:');
try {
  // Test factory function
  const instance = kindlyguard({ logLevel: 'info' });
  assert(instance instanceof kindlyguard.KindlyGuard);
  console.log('   ✓ Factory function works');
  
  // Test exports
  assert(typeof kindlyguard.scan === 'function');
  assert(typeof kindlyguard.startServer === 'function');
  assert(typeof kindlyguard.platform === 'object');
  console.log('   ✓ All exports present');
  
} catch (error) {
  console.error(`   ✗ API test failed: ${error.message}`);
  process.exit(1);
}

// Test 4: Scan functionality (if binary is available)
console.log('\n4. Testing scan functionality:');
async function testScan() {
  try {
    const testText = 'Hello World! This is a test.';
    const result = await kindlyguard.scan(testText, { format: 'json' });
    
    if (result && typeof result === 'object') {
      console.log('   ✓ Scan completed successfully');
      console.log(`   ✓ Threats found: ${result.threatsFound || false}`);
    }
  } catch (error) {
    if (error.message.includes('not found')) {
      console.log('   ⚠ Skipping scan test (binary not installed)');
    } else {
      console.error(`   ✗ Scan test failed: ${error.message}`);
    }
  }
}

// Test 5: TypeScript definitions
console.log('\n5. Testing TypeScript definitions:');
const dtsPath = path.join(__dirname, 'lib', 'main.d.ts');
if (fs.existsSync(dtsPath)) {
  console.log('   ✓ TypeScript definitions found');
} else {
  console.log('   ✗ TypeScript definitions missing');
}

// Run async tests
testScan().then(() => {
  console.log('\n✅ All tests completed!');
  console.log('\nTo use KindlyGuard:');
  console.log('  const kindlyguard = require(\'@kindlyguard/kindlyguard\');');
  console.log('  kindlyguard.startServer({ stdio: true });');
}).catch(error => {
  console.error('\n❌ Test failed:', error);
  process.exit(1);
});