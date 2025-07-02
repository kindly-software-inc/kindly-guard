// Quick test to verify the package works
const kindlyguard = require('./index.js');

console.log('Testing kindlyguard package...\n');

// Test basic properties
console.log('Package info:');
console.log('- Name:', kindlyguard.name);
console.log('- Version:', kindlyguard.version);
console.log('- Status:', kindlyguard.status);
console.log('- Repository:', kindlyguard.repository);

console.log('\nTesting init function:');
const result = kindlyguard.init();
console.log('Result:', result);

console.log('\n✅ Package test completed successfully!');