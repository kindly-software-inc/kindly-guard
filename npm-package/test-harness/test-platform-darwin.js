#!/usr/bin/env node

/**
 * Platform-specific test harness for macOS (Darwin)
 * Tests macOS-specific functionality and edge cases
 */

const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const assert = require('assert');

// Test results
let passed = 0;
let failed = 0;

// Color codes
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

function test(name, fn) {
    try {
        fn();
        console.log(`${GREEN}✓${RESET} ${name}`);
        passed++;
    } catch (error) {
        console.log(`${RED}✗${RESET} ${name}`);
        console.error(`  ${error.message}`);
        failed++;
    }
}

async function testAsync(name, fn) {
    try {
        await fn();
        console.log(`${GREEN}✓${RESET} ${name}`);
        passed++;
    } catch (error) {
        console.log(`${RED}✗${RESET} ${name}`);
        console.error(`  ${error.message}`);
        failed++;
    }
}

console.log('macOS (Darwin) Platform Test Harness\n');

// Test 1: Platform detection
test('Platform detection returns darwin', () => {
    assert.strictEqual(process.platform, 'darwin');
});

// Test 2: Architecture detection
test('Architecture detection (x64 or arm64)', () => {
    const validArchs = ['x64', 'arm64'];
    assert(validArchs.includes(process.arch), `Invalid architecture: ${process.arch}`);
    
    // Additional check for Apple Silicon
    if (process.arch === 'arm64') {
        console.log('  Detected Apple Silicon (M1/M2)');
    } else {
        console.log('  Detected Intel Mac');
    }
});

// Test 3: Binary path construction
test('Binary path construction for macOS', () => {
    const platform = 'darwin';
    const arch = process.arch;
    const binaryName = `kindlyguard-${platform}-${arch}`;
    
    assert(!binaryName.includes('.exe'), 'macOS binary should not have .exe extension');
    assert(binaryName.includes('darwin'), 'Binary name should include darwin');
});

// Test 4: File permissions
test('File permission handling', () => {
    const testFile = path.join(__dirname, 'test-binary');
    
    try {
        // Create test file
        fs.writeFileSync(testFile, '#!/bin/sh\necho "test"');
        
        // Set executable permissions
        fs.chmodSync(testFile, 0o755);
        
        // Check permissions
        const stats = fs.statSync(testFile);
        const mode = (stats.mode & parseInt('777', 8)).toString(8);
        assert.strictEqual(mode, '755', 'Permissions should be 755');
        
        // Cleanup
        fs.unlinkSync(testFile);
    } catch (error) {
        // Cleanup on error
        if (fs.existsSync(testFile)) {
            fs.unlinkSync(testFile);
        }
        throw error;
    }
});

// Test 5: Code signing check
test('Code signing availability', () => {
    const result = spawnSync('which', ['codesign'], { encoding: 'utf8' });
    
    if (result.status === 0) {
        console.log('  codesign tool is available');
        
        // Check if binary would need signing
        console.log('  Note: Downloaded binaries may require security approval');
    } else {
        console.log(`  ${YELLOW}Warning: codesign tool not found${RESET}`);
    }
});

// Test 6: Gatekeeper implications
test('Gatekeeper security check', () => {
    // Check for spctl tool
    const result = spawnSync('which', ['spctl'], { encoding: 'utf8' });
    
    if (result.status === 0) {
        console.log('  spctl (Gatekeeper) tool is available');
        console.log('  Downloaded binaries may trigger security warnings');
    } else {
        console.log(`  ${YELLOW}Warning: spctl tool not found${RESET}`);
    }
});

// Test 7: Quarantine attribute handling
test('Quarantine attribute awareness', () => {
    const testFile = path.join(__dirname, 'test-quarantine');
    
    try {
        fs.writeFileSync(testFile, 'test content');
        
        // Check xattr command availability
        const result = spawnSync('which', ['xattr'], { encoding: 'utf8' });
        
        if (result.status === 0) {
            console.log('  xattr command available for quarantine handling');
            
            // Command to remove quarantine would be: xattr -d com.apple.quarantine file
            console.log('  Can handle quarantine attributes on downloaded files');
        }
        
        fs.unlinkSync(testFile);
    } catch (error) {
        if (fs.existsSync(testFile)) fs.unlinkSync(testFile);
        throw error;
    }
});

// Test 8: Universal binary support
test('Universal binary considerations', () => {
    const arch = process.arch;
    
    if (arch === 'arm64') {
        console.log('  Running on Apple Silicon - may need arm64 binary');
    } else if (arch === 'x64') {
        console.log('  Running on Intel - needs x64 binary');
    }
    
    console.log('  Note: Universal binaries would work on both architectures');
});

// Test 9: Home directory detection
test('Home directory detection', () => {
    const home = process.env.HOME;
    assert(home, 'HOME environment variable should be set');
    assert(home.startsWith('/'), 'Home directory should start with /');
    assert(home.includes('/Users/'), 'macOS home should be under /Users');
});

// Test 10: Application Support directory
test('Application Support directory', () => {
    const home = process.env.HOME;
    const appSupport = path.join(home, 'Library', 'Application Support');
    
    assert(fs.existsSync(path.join(home, 'Library')), 'Library directory should exist');
    console.log(`  App Support path: ${appSupport}`);
});

// Test 11: Binary download simulation
test('Binary download URL for macOS', () => {
    const version = '0.2.0';
    const platform = 'darwin';
    const arch = process.arch;
    
    const fileName = `kindlyguard-${platform}-${arch}.tar.gz`;
    const downloadUrl = `https://github.com/samduchaine/kindly-guard/releases/download/v${version}/${fileName}`;
    
    assert(downloadUrl.includes('darwin'), 'Download URL should include darwin');
    assert(downloadUrl.endsWith('.tar.gz'), 'macOS binary should be tar.gz');
});

// Test 12: Rosetta 2 compatibility
test('Rosetta 2 compatibility check', () => {
    if (process.arch === 'arm64') {
        // Check if Rosetta 2 is installed
        const result = spawnSync('pgrep', ['oahd'], { encoding: 'utf8' });
        
        if (result.stdout) {
            console.log('  Rosetta 2 is active (can run x64 binaries)');
        } else {
            console.log('  Rosetta 2 status unknown');
        }
    } else {
        console.log('  Not applicable (Intel Mac)');
    }
});

// Test 13: File system case sensitivity
test('File system case sensitivity check', () => {
    const testDir = path.join(__dirname, 'CaseSensitiveTest');
    const testDir2 = path.join(__dirname, 'casesensitivetest');
    
    try {
        // Create directory with mixed case
        fs.mkdirSync(testDir);
        
        // Try to create with different case
        let caseSensitive = true;
        try {
            fs.mkdirSync(testDir2);
            // If we can create both, file system is case sensitive
            fs.rmdirSync(testDir2);
        } catch (error) {
            // If we can't create the second one, might be case insensitive
            caseSensitive = !fs.existsSync(testDir2);
        }
        
        // Cleanup
        fs.rmdirSync(testDir);
        
        console.log(`  File system is ${caseSensitive ? 'case sensitive' : 'case insensitive (default)'}`);
    } catch (error) {
        // Cleanup on error
        if (fs.existsSync(testDir)) fs.rmdirSync(testDir);
        if (fs.existsSync(testDir2)) fs.rmdirSync(testDir2);
        throw error;
    }
});

// Test 14: NPM global directory
test('NPM global directory detection', () => {
    const result = spawnSync('npm', ['config', 'get', 'prefix'], { encoding: 'utf8' });
    
    if (result.status === 0) {
        const prefix = result.stdout.trim();
        assert(prefix, 'NPM prefix should be set');
        assert(path.isAbsolute(prefix), 'NPM prefix should be absolute path');
        console.log(`  NPM prefix: ${prefix}`);
    } else {
        console.log(`  ${YELLOW}Warning: Could not detect npm prefix${RESET}`);
    }
});

// Test 15: Dynamic library paths
test('Dynamic library loading paths', () => {
    const dylibPath = process.env.DYLD_LIBRARY_PATH;
    const dylibFallbackPath = process.env.DYLD_FALLBACK_LIBRARY_PATH;
    
    console.log(`  DYLD_LIBRARY_PATH: ${dylibPath || '(not set)'}`);
    console.log(`  DYLD_FALLBACK_LIBRARY_PATH: ${dylibFallbackPath || '(not set)'}`);
});

// Summary
console.log('\n=== macOS Test Summary ===');
console.log(`${GREEN}Passed: ${passed}${RESET}`);
console.log(`${RED}Failed: ${failed}${RESET}`);

process.exit(failed > 0 ? 1 : 0);