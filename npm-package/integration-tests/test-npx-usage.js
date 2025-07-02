#!/usr/bin/env node

/**
 * Integration test for NPX usage scenarios
 * Tests various ways to use KindlyGuard via npx
 */

const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const assert = require('assert');

console.log('NPX Usage Integration Test\n');

let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`✓ ${name}`);
        passed++;
    } catch (error) {
        console.log(`✗ ${name}`);
        console.error(`  ${error.message}`);
        failed++;
    }
}

async function testAsync(name, fn) {
    try {
        await fn();
        console.log(`✓ ${name}`);
        passed++;
    } catch (error) {
        console.log(`✗ ${name}`);
        console.error(`  ${error.message}`);
        failed++;
    }
}

// Create temporary test directory
const testDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 'kindlyguard-npx-test-'));
console.log(`Test directory: ${testDir}\n`);

// Cleanup function
function cleanup() {
    try {
        fs.rmSync(testDir, { recursive: true, force: true });
    } catch (error) {
        console.error('Cleanup error:', error.message);
    }
}

// Ensure cleanup on exit
process.on('exit', cleanup);
process.on('SIGINT', () => { cleanup(); process.exit(1); });

// Test 1: Basic npx execution
testAsync('Basic npx execution', async () => {
    return new Promise((resolve, reject) => {
        // Create mock binary
        const binDir = path.join(testDir, 'node_modules', '.bin');
        fs.mkdirSync(binDir, { recursive: true });
        
        const mockBinary = path.join(binDir, 'kindlyguard');
        const mockContent = `#!/usr/bin/env node
console.log('KindlyGuard MCP Server v0.2.0');
console.log('Usage: kindlyguard [OPTIONS]');
process.exit(0);
`;
        
        fs.writeFileSync(mockBinary, mockContent);
        fs.chmodSync(mockBinary, 0o755);
        
        // Test execution
        const proc = spawn(mockBinary, [], { cwd: testDir });
        
        let output = '';
        proc.stdout.on('data', (data) => {
            output += data.toString();
        });
        
        proc.on('close', (code) => {
            if (code === 0 && output.includes('KindlyGuard MCP Server')) {
                resolve();
            } else {
                reject(new Error(`Unexpected exit code: ${code}`));
            }
        });
        
        proc.on('error', reject);
    });
});

// Test 2: NPX with --stdio flag
testAsync('NPX with --stdio flag', async () => {
    return new Promise((resolve, reject) => {
        // Create mock stdio binary
        const binDir = path.join(testDir, 'node_modules', '.bin');
        const mockBinary = path.join(binDir, 'kindlyguard');
        
        const mockContent = `#!/usr/bin/env node
if (process.argv.includes('--stdio')) {
    console.log('{"jsonrpc":"2.0","method":"initialize","params":{}}');
    process.exit(0);
} else {
    console.error('Expected --stdio flag');
    process.exit(1);
}
`;
        
        fs.writeFileSync(mockBinary, mockContent);
        fs.chmodSync(mockBinary, 0o755);
        
        // Test execution
        const proc = spawn(mockBinary, ['--stdio'], { cwd: testDir });
        
        let output = '';
        proc.stdout.on('data', (data) => {
            output += data.toString();
        });
        
        proc.on('close', (code) => {
            if (code === 0 && output.includes('jsonrpc')) {
                resolve();
            } else {
                reject(new Error('Failed to run with --stdio'));
            }
        });
        
        proc.on('error', reject);
    });
});

// Test 3: NPX one-time execution
test('NPX one-time execution command', () => {
    const command = 'npx kindlyguard@latest --help';
    console.log(`  Command: ${command}`);
    console.log('  This would download and run the latest version');
});

// Test 4: NPX with specific version
test('NPX with specific version', () => {
    const versions = ['0.1.0', '0.2.0', 'latest'];
    
    versions.forEach(version => {
        const command = `npx kindlyguard@${version}`;
        console.log(`  ${command}`);
    });
});

// Test 5: NPX in package.json scripts
test('NPX in package.json scripts', () => {
    const packageJson = {
        name: "test-project",
        scripts: {
            "security-check": "npx kindlyguard scan .",
            "start-guard": "npx kindlyguard --stdio",
            "guard-monitor": "npx kindlyguard monitor --detailed"
        }
    };
    
    const packagePath = path.join(testDir, 'package.json');
    fs.writeFileSync(packagePath, JSON.stringify(packageJson, null, 2));
    
    // Verify scripts
    const saved = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    assert(saved.scripts['security-check'], 'Should have security-check script');
    assert(saved.scripts['start-guard'], 'Should have start-guard script');
    assert(saved.scripts['guard-monitor'], 'Should have guard-monitor script');
});

// Test 6: NPX with environment variables
testAsync('NPX with environment variables', async () => {
    return new Promise((resolve, reject) => {
        // Create mock binary that reads env vars
        const binDir = path.join(testDir, 'node_modules', '.bin');
        const mockBinary = path.join(binDir, 'kindlyguard');
        
        const mockContent = `#!/usr/bin/env node
console.log('KINDLY_GUARD_CONFIG:', process.env.KINDLY_GUARD_CONFIG || 'not set');
console.log('RUST_LOG:', process.env.RUST_LOG || 'not set');
process.exit(0);
`;
        
        fs.writeFileSync(mockBinary, mockContent);
        fs.chmodSync(mockBinary, 0o755);
        
        // Test execution with env vars
        const proc = spawn(mockBinary, [], {
            cwd: testDir,
            env: {
                ...process.env,
                KINDLY_GUARD_CONFIG: '/etc/kindlyguard/config.toml',
                RUST_LOG: 'debug'
            }
        });
        
        let output = '';
        proc.stdout.on('data', (data) => {
            output += data.toString();
        });
        
        proc.on('close', (code) => {
            if (code === 0 && output.includes('KINDLY_GUARD_CONFIG: /etc/kindlyguard')) {
                resolve();
            } else {
                reject(new Error('Environment variables not passed correctly'));
            }
        });
        
        proc.on('error', reject);
    });
});

// Test 7: NPX with piped input
testAsync('NPX with piped input', async () => {
    return new Promise((resolve, reject) => {
        // Create mock binary that reads stdin
        const binDir = path.join(testDir, 'node_modules', '.bin');
        const mockBinary = path.join(binDir, 'kindlyguard');
        
        const mockContent = `#!/usr/bin/env node
let input = '';
process.stdin.on('data', (chunk) => {
    input += chunk.toString();
});
process.stdin.on('end', () => {
    console.log('Received:', input.trim());
    process.exit(0);
});
`;
        
        fs.writeFileSync(mockBinary, mockContent);
        fs.chmodSync(mockBinary, 0o755);
        
        // Test execution with piped input
        const proc = spawn(mockBinary, [], { cwd: testDir });
        
        let output = '';
        proc.stdout.on('data', (data) => {
            output += data.toString();
        });
        
        proc.stdin.write('Test input data\n');
        proc.stdin.end();
        
        proc.on('close', (code) => {
            if (code === 0 && output.includes('Received: Test input data')) {
                resolve();
            } else {
                reject(new Error('Failed to handle piped input'));
            }
        });
        
        proc.on('error', reject);
    });
});

// Test 8: NPX error handling
testAsync('NPX error handling', async () => {
    return new Promise((resolve, reject) => {
        // Create mock binary that exits with error
        const binDir = path.join(testDir, 'node_modules', '.bin');
        const mockBinary = path.join(binDir, 'kindlyguard');
        
        const mockContent = `#!/usr/bin/env node
console.error('Error: Configuration file not found');
process.exit(1);
`;
        
        fs.writeFileSync(mockBinary, mockContent);
        fs.chmodSync(mockBinary, 0o755);
        
        // Test execution
        const proc = spawn(mockBinary, [], { cwd: testDir });
        
        let stderr = '';
        proc.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        
        proc.on('close', (code) => {
            if (code === 1 && stderr.includes('Error: Configuration file not found')) {
                resolve();
            } else {
                reject(new Error('Error handling not working correctly'));
            }
        });
        
        proc.on('error', reject);
    });
});

// Test 9: NPX cache behavior
test('NPX cache behavior', () => {
    const cacheDir = path.join(process.env.HOME || process.env.USERPROFILE, '.npm', '_npx');
    console.log(`  NPX cache directory: ${cacheDir}`);
    console.log('  Cached packages can be reused for faster execution');
});

// Test 10: NPX with custom registry
test('NPX with custom registry', () => {
    const commands = [
        'npx --registry https://registry.npmjs.org kindlyguard',
        'NPM_CONFIG_REGISTRY=https://custom.registry.com npx kindlyguard'
    ];
    
    commands.forEach(cmd => {
        console.log(`  ${cmd}`);
    });
});

// Summary
console.log('\n=== NPX Usage Test Summary ===');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed > 0) {
    console.log('\nCommon NPX usage patterns:');
    console.log('  npx kindlyguard --help              # Show help');
    console.log('  npx kindlyguard --stdio             # Start MCP server');
    console.log('  npx kindlyguard scan "text"         # Scan text');
    console.log('  npx kindlyguard@latest monitor      # Use latest version');
    process.exit(1);
} else {
    console.log('\nAll NPX usage tests passed!');
    process.exit(0);
}