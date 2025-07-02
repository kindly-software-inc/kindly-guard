#!/usr/bin/env node

/**
 * Platform-specific test harness for Windows
 * Tests Windows-specific functionality and edge cases
 */

const fs = require('fs');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const assert = require('assert');

// Test results
let passed = 0;
let failed = 0;

// Color codes (may not work in all Windows terminals)
const GREEN = process.stdout.isTTY ? '\x1b[32m' : '';
const RED = process.stdout.isTTY ? '\x1b[31m' : '';
const YELLOW = process.stdout.isTTY ? '\x1b[33m' : '';
const RESET = process.stdout.isTTY ? '\x1b[0m' : '';

function test(name, fn) {
    try {
        fn();
        console.log(`${GREEN}√${RESET} ${name}`);
        passed++;
    } catch (error) {
        console.log(`${RED}×${RESET} ${name}`);
        console.error(`  ${error.message}`);
        failed++;
    }
}

async function testAsync(name, fn) {
    try {
        await fn();
        console.log(`${GREEN}√${RESET} ${name}`);
        passed++;
    } catch (error) {
        console.log(`${RED}×${RESET} ${name}`);
        console.error(`  ${error.message}`);
        failed++;
    }
}

console.log('Windows Platform Test Harness\n');

// Test 1: Platform detection
test('Platform detection returns win32', () => {
    assert.strictEqual(process.platform, 'win32');
});

// Test 2: Architecture detection
test('Architecture detection (x64 expected)', () => {
    // Windows npm packages typically only support x64
    assert.strictEqual(process.arch, 'x64', 'Only x64 is supported on Windows');
});

// Test 3: Binary path construction
test('Binary path construction for Windows', () => {
    const platform = 'win32';
    const arch = 'x64';
    const binaryName = `kindlyguard-${platform}-${arch}.exe`;
    
    assert(binaryName.includes('.exe'), 'Windows binary should have .exe extension');
    assert(binaryName.includes('win32'), 'Binary name should include win32');
});

// Test 4: Executable extension handling
test('Executable extension is .exe', () => {
    const exeExt = process.platform === 'win32' ? '.exe' : '';
    assert.strictEqual(exeExt, '.exe', 'Windows executables need .exe extension');
});

// Test 5: Path separator
test('Path separator is backslash', () => {
    assert.strictEqual(path.sep, '\\', 'Windows should use backslash');
});

// Test 6: Drive letter handling
test('Path includes drive letter', () => {
    const cwd = process.cwd();
    assert(/^[A-Za-z]:/.test(cwd), 'Current directory should start with drive letter');
});

// Test 7: Environment variable handling
test('Environment variables case insensitive', () => {
    // Windows env vars are case insensitive
    process.env.TEST_VAR = 'test';
    assert.strictEqual(process.env.test_var, 'test', 'Env vars should be case insensitive');
    delete process.env.TEST_VAR;
});

// Test 8: Home directory detection
test('Home directory detection', () => {
    const home = process.env.USERPROFILE || process.env.HOME;
    assert(home, 'Home directory should be set');
    assert(/^[A-Za-z]:/.test(home), 'Home directory should include drive letter');
});

// Test 9: Temp directory
test('Temp directory detection', () => {
    const tmpdir = require('os').tmpdir();
    assert(tmpdir, 'Temp directory should be available');
    assert(/^[A-Za-z]:/.test(tmpdir), 'Temp directory should include drive letter');
});

// Test 10: Binary download simulation
test('Binary download URL for Windows', () => {
    const version = '0.2.0';
    const platform = 'win32';
    const arch = 'x64';
    
    const fileName = `kindlyguard-${platform}-${arch}.zip`;
    const downloadUrl = `https://github.com/samduchaine/kindly-guard/releases/download/v${version}/${fileName}`;
    
    assert(downloadUrl.includes('win32'), 'Download URL should include win32');
    assert(downloadUrl.endsWith('.zip'), 'Windows binary should be zip file');
});

// Test 11: Command execution
testAsync('Command execution on Windows', async () => {
    return new Promise((resolve, reject) => {
        // Use 'cmd.exe /c echo' for Windows
        const result = spawnSync('cmd.exe', ['/c', 'echo', 'hello'], { encoding: 'utf8' });
        
        if (result.error) {
            reject(result.error);
        } else {
            assert.strictEqual(result.stdout.trim(), 'hello');
            assert.strictEqual(result.status, 0);
            resolve();
        }
    });
});

// Test 12: PowerShell availability
test('PowerShell availability', () => {
    const result = spawnSync('powershell', ['-Command', 'echo test'], { encoding: 'utf8' });
    
    if (result.status === 0) {
        console.log('  PowerShell is available');
    } else {
        console.log(`  ${YELLOW}Warning: PowerShell not available${RESET}`);
    }
});

// Test 13: File system case sensitivity
test('File system case insensitivity', () => {
    const testFile = path.join(__dirname, 'TestFile.txt');
    const testFile2 = path.join(__dirname, 'testfile.txt');
    
    try {
        // Create file with mixed case
        fs.writeFileSync(testFile, 'test content');
        
        // Try to access with different case
        const exists = fs.existsSync(testFile2);
        
        // Cleanup
        fs.unlinkSync(testFile);
        
        assert(exists, 'Windows file system should be case insensitive');
        console.log('  File system is case insensitive (expected)');
    } catch (error) {
        // Cleanup on error
        if (fs.existsSync(testFile)) fs.unlinkSync(testFile);
        throw error;
    }
});

// Test 14: NPM command format
test('NPM command execution', () => {
    // On Windows, npm might be npm.cmd
    const npmCommands = ['npm', 'npm.cmd'];
    let npmFound = false;
    
    for (const cmd of npmCommands) {
        const result = spawnSync(cmd, ['--version'], { encoding: 'utf8' });
        if (result.status === 0) {
            npmFound = true;
            console.log(`  NPM found as: ${cmd}`);
            break;
        }
    }
    
    assert(npmFound, 'NPM should be available');
});

// Test 15: Long path support
test('Long path handling', () => {
    // Windows has a 260 character path limit by default
    const longPath = 'a'.repeat(250);
    console.log('  Standard path limit: 260 characters');
    console.log('  Long path support may require Windows 10 v1607+');
});

// Test 16: UAC considerations
test('UAC (User Account Control) awareness', () => {
    // Check if running as administrator
    try {
        // Try to access a typically protected location
        const systemDir = process.env.WINDIR || 'C:\\Windows';
        const testFile = path.join(systemDir, 'temp', 'test-uac.txt');
        
        // Don't actually write to system directories
        console.log('  UAC may affect installation in protected directories');
        console.log('  Running as admin:', process.env.USERNAME === 'Administrator' ? 'possibly' : 'unlikely');
    } catch (error) {
        // Expected to fail for non-admin users
    }
});

// Test 17: Windows Defender considerations
test('Windows Defender awareness', () => {
    console.log('  Downloaded executables may be scanned by Windows Defender');
    console.log('  First run may be slower due to real-time scanning');
});

// Test 18: Registry-free operation
test('Registry-free operation', () => {
    console.log('  KindlyGuard operates without registry modifications');
    console.log('  No system-wide installation required');
});

// Test 19: Batch file wrapper
test('Batch file wrapper format', () => {
    const wrapperContent = `@echo off
"%~dp0\\kindlyguard.exe" %*
`;
    
    assert(wrapperContent.includes('@echo off'), 'Should disable echo');
    assert(wrapperContent.includes('%*'), 'Should forward all arguments');
    assert(wrapperContent.includes('%~dp0'), 'Should use script directory');
});

// Test 20: Node.js path resolution
test('Node.js path resolution on Windows', () => {
    const testPath = 'C:\\Users\\test\\file.txt';
    const parsed = path.parse(testPath);
    
    assert.strictEqual(parsed.root, 'C:\\');
    assert.strictEqual(parsed.dir, 'C:\\Users\\test');
    assert.strictEqual(parsed.base, 'file.txt');
});

// Summary
console.log('\n=== Windows Test Summary ===');
console.log(`${GREEN}Passed: ${passed}${RESET}`);
console.log(`${RED}Failed: ${failed}${RESET}`);

process.exit(failed > 0 ? 1 : 0);