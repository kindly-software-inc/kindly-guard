#!/usr/bin/env node

const { exec } = require('child_process');
const path = require('path');

console.log('🚀 Auto-publishing KindlyGuard placeholder package...\n');

// Change to the npm-package directory
process.chdir(__dirname);

// Run npm publish
const publishProcess = exec('npm publish', (error, stdout, stderr) => {
    if (error) {
        console.error('❌ Error publishing package:', error.message);
        if (stderr) {
            console.error('Error details:', stderr);
        }
        process.exit(1);
    }
    
    console.log('✅ Package published successfully!\n');
    console.log(stdout);
    console.log('\n🎉 The "kindlyguard" package name is now reserved!');
    console.log('📦 View it at: https://www.npmjs.com/package/kindlyguard');
    console.log('\n📝 Next steps:');
    console.log('   1. When ready to publish the real package, update to version 1.0.0');
    console.log('   2. Replace the placeholder content with the actual implementation');
    console.log('   3. Run npm publish again to update the package');
});

// Show output as it comes
publishProcess.stdout.on('data', (data) => {
    process.stdout.write(data);
});

publishProcess.stderr.on('data', (data) => {
    process.stderr.write(data);
});