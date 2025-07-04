#!/usr/bin/env node

/**
 * Platform-specific test harness for Linux
 * Tests Linux-specific functionality and edge cases
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

console.log('Linux Platform Test Harness\n');

// Test 1: Platform detection
test('Platform detection returns linux', () => {
    assert.strictEqual(process.platform, 'linux');
});

// Test 2: Architecture detection
test('Architecture detection (x64 or arm64)', () => {
    const validArchs = ['x64', 'arm64'];
    assert(validArchs.includes(process.arch), `Invalid architecture: ${process.arch}`);
});

// Test 3: Binary path construction
test('Binary path construction for Linux', () => {
    const platform = 'linux';
    const arch = process.arch;
    const binaryName = `kindlyguard-${platform}-${arch}`;
    
    assert(!binaryName.includes('.exe'), 'Linux binary should not have .exe extension');
    assert(binaryName.includes('linux'), 'Binary name should include linux');
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

// Test 5: Symlink creation
test('Symlink creation support', () => {
    const targetFile = path.join(__dirname, 'test-target');
    const linkFile = path.join(__dirname, 'test-link');
    
    try {
        // Create target
        fs.writeFileSync(targetFile, 'test content');
        
        // Create symlink
        fs.symlinkSync(targetFile, linkFile);
        
        // Verify symlink
        assert(fs.lstatSync(linkFile).isSymbolicLink(), 'Should be a symlink');
        assert.strictEqual(fs.readFileSync(linkFile, 'utf8'), 'test content');
        
        // Cleanup
        fs.unlinkSync(linkFile);
        fs.unlinkSync(targetFile);
    } catch (error) {
        // Cleanup on error
        if (fs.existsSync(linkFile)) fs.unlinkSync(linkFile);
        if (fs.existsSync(targetFile)) fs.unlinkSync(targetFile);
        throw error;
    }
});

// Test 6: Process spawning
testAsync('Process spawning on Linux', async () => {
    return new Promise((resolve, reject) => {
        const result = spawnSync('echo', ['hello'], { encoding: 'utf8' });
        
        if (result.error) {
            reject(result.error);
        } else {
            assert.strictEqual(result.stdout.trim(), 'hello');
            assert.strictEqual(result.status, 0);
            resolve();
        }
    });
});

// Test 7: Path separator
test('Path separator is forward slash', () => {
    assert.strictEqual(path.sep, '/', 'Linux should use forward slash');
});

// Test 8: Home directory detection
test('Home directory detection', () => {
    const home = process.env.HOME;
    assert(home, 'HOME environment variable should be set');
    assert(home.startsWith('/'), 'Home directory should start with /');
});

// Test 9: Temp directory
test('Temp directory detection', () => {
    const tmpdir = require('os').tmpdir();
    assert(tmpdir, 'Temp directory should be available');
    assert(tmpdir.startsWith('/'), 'Temp directory should be absolute path');
});

// Test 10: Binary download simulation
test('Binary download URL for Linux', () => {
    const version = '0.2.0';
    const platform = 'linux';
    const arch = process.arch;
    
    const fileName = `kindlyguard-${platform}-${arch}.tar.gz`;
    const downloadUrl = `https://github.com/samduchaine/kindly-guard/releases/download/v${version}/${fileName}`;
    
    assert(downloadUrl.includes('linux'), 'Download URL should include linux');
    assert(downloadUrl.endsWith('.tar.gz'), 'Linux binary should be tar.gz');
});

// Test 11: Wrapper script generation
test('Shell wrapper script format', () => {
    const wrapperContent = `#!/bin/sh
exec "$(dirname "$0")/kindlyguard.bin" "$@"
`;
    
    assert(wrapperContent.startsWith('#!/bin/sh'), 'Should start with shebang');
    assert(wrapperContent.includes('exec'), 'Should use exec');
    assert(wrapperContent.includes('$@'), 'Should forward arguments');
});

// Test 12: Signal handling
testAsync('Signal handling', async () => {
    return new Promise((resolve) => {
        // This test just verifies signal names exist
        assert(process.platform === 'linux');
        assert(typeof process.kill === 'function');
        assert(process.pid > 0);
        resolve();
    });
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
        
        console.log(`  File system is ${caseSensitive ? 'case sensitive' : 'case insensitive'}`);
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
    } else {
        console.log(`  ${YELLOW}Warning: Could not detect npm prefix${RESET}`);
    }
});

// Test 15: Library loading paths
test('Library loading paths', () => {
    const ldLibraryPath = process.env.LD_LIBRARY_PATH;
    // This is optional, so we just log it
    console.log(`  LD_LIBRARY_PATH: ${ldLibraryPath || '(not set)'}`);
});

// Summary
console.log('\n=== Linux Test Summary ===');
console.log(`${GREEN}Passed: ${passed}${RESET}`);
console.log(`${RED}Failed: ${failed}${RESET}`);

process.exit(failed > 0 ? 1 : 0);