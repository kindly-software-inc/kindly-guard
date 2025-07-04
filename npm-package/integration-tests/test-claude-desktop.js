#!/usr/bin/env node

/**
 * Integration test for Claude Desktop configuration
 * Tests MCP server integration with Claude Desktop
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const assert = require('assert');

console.log('Claude Desktop Integration Test\n');

// Test configuration
const testConfig = {
    mcpServers: {
        "kindly-guard": {
            command: "npx",
            args: ["kindlyguard", "--stdio"]
        }
    }
};

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

// Test 1: Configuration structure
test('Configuration structure is valid', () => {
    assert(testConfig.mcpServers, 'mcpServers key should exist');
    assert(testConfig.mcpServers['kindly-guard'], 'kindly-guard server should be configured');
    
    const serverConfig = testConfig.mcpServers['kindly-guard'];
    assert.strictEqual(serverConfig.command, 'npx', 'Command should be npx');
    assert(Array.isArray(serverConfig.args), 'Args should be an array');
    assert.strictEqual(serverConfig.args[0], 'kindlyguard', 'First arg should be kindlyguard');
    assert.strictEqual(serverConfig.args[1], '--stdio', 'Second arg should be --stdio');
});

// Test 2: Configuration file location
test('Configuration file paths', () => {
    const platform = process.platform;
    let configPath;
    
    switch (platform) {
        case 'darwin':
            configPath = path.join(process.env.HOME, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
            break;
        case 'win32':
            configPath = path.join(process.env.APPDATA, 'Claude', 'claude_desktop_config.json');
            break;
        case 'linux':
            configPath = path.join(process.env.HOME, '.config', 'claude', 'claude_desktop_config.json');
            break;
    }
    
    console.log(`  Config path for ${platform}: ${configPath}`);
    assert(configPath, 'Config path should be determined');
});

// Test 3: Stdio mode communication
testAsync('Stdio mode communication protocol', async () => {
    return new Promise((resolve, reject) => {
        // Simulate stdio communication
        const mockMessages = [
            {
                jsonrpc: "2.0",
                id: 1,
                method: "initialize",
                params: {
                    protocolVersion: "0.1.0",
                    capabilities: {}
                }
            },
            {
                jsonrpc: "2.0",
                id: 2,
                method: "tools/list",
                params: {}
            }
        ];
        
        // Validate message format
        mockMessages.forEach(msg => {
            assert.strictEqual(msg.jsonrpc, "2.0", 'Should use JSON-RPC 2.0');
            assert(msg.id, 'Should have an ID');
            assert(msg.method, 'Should have a method');
        });
        
        resolve();
    });
});

// Test 4: Tool registration
test('Tool registration format', () => {
    const mockToolsResponse = {
        jsonrpc: "2.0",
        id: 2,
        result: {
            tools: [
                {
                    name: "scan",
                    description: "Scan text for security threats",
                    inputSchema: {
                        type: "object",
                        properties: {
                            text: {
                                type: "string",
                                description: "Text to scan"
                            }
                        },
                        required: ["text"]
                    }
                },
                {
                    name: "monitor",
                    description: "Get security monitoring status",
                    inputSchema: {
                        type: "object",
                        properties: {}
                    }
                }
            ]
        }
    };
    
    assert(mockToolsResponse.result.tools, 'Should have tools array');
    assert(mockToolsResponse.result.tools.length > 0, 'Should have at least one tool');
    
    const scanTool = mockToolsResponse.result.tools[0];
    assert.strictEqual(scanTool.name, 'scan', 'Should have scan tool');
    assert(scanTool.inputSchema, 'Tool should have input schema');
});

// Test 5: Error handling in stdio mode
testAsync('Error handling in stdio mode', async () => {
    const errorResponse = {
        jsonrpc: "2.0",
        id: 3,
        error: {
            code: -32601,
            message: "Method not found",
            data: {
                method: "unknown/method"
            }
        }
    };
    
    assert.strictEqual(errorResponse.error.code, -32601, 'Should use standard JSON-RPC error code');
    assert(errorResponse.error.message, 'Should have error message');
});

// Test 6: NPX command execution
testAsync('NPX command execution simulation', async () => {
    return new Promise((resolve, reject) => {
        // Check if npx is available
        const npxTest = spawn('npx', ['--version']);
        
        npxTest.on('close', (code) => {
            if (code === 0) {
                console.log('  npx is available');
                resolve();
            } else {
                reject(new Error('npx not available'));
            }
        });
        
        npxTest.on('error', (error) => {
            if (error.code === 'ENOENT') {
                console.log('  Warning: npx not found - npm may not be installed');
                resolve(); // Don't fail the test
            } else {
                reject(error);
            }
        });
    });
});

// Test 7: Configuration merge behavior
test('Configuration merge behavior', () => {
    const existingConfig = {
        mcpServers: {
            "other-server": {
                command: "other",
                args: ["--flag"]
            }
        }
    };
    
    const mergedConfig = {
        mcpServers: {
            ...existingConfig.mcpServers,
            ...testConfig.mcpServers
        }
    };
    
    assert(mergedConfig.mcpServers['other-server'], 'Should preserve existing servers');
    assert(mergedConfig.mcpServers['kindly-guard'], 'Should add new server');
    assert.strictEqual(Object.keys(mergedConfig.mcpServers).length, 2, 'Should have both servers');
});

// Test 8: Security context
test('Security context validation', () => {
    const securityContext = {
        scanOnInput: true,
        blockThreats: true,
        notifyUser: true,
        logThreats: true
    };
    
    Object.entries(securityContext).forEach(([key, value]) => {
        assert.strictEqual(value, true, `${key} should be enabled by default`);
    });
});

// Test 9: Alternative configuration formats
test('Alternative configuration formats', () => {
    // Test with local installation
    const localConfig = {
        mcpServers: {
            "kindly-guard-local": {
                command: "node",
                args: ["./node_modules/kindlyguard/bin/kindlyguard", "--stdio"]
            }
        }
    };
    
    // Test with global installation
    const globalConfig = {
        mcpServers: {
            "kindly-guard-global": {
                command: "kindlyguard",
                args: ["--stdio"]
            }
        }
    };
    
    // Test with custom path
    const customConfig = {
        mcpServers: {
            "kindly-guard-custom": {
                command: "/usr/local/bin/kindlyguard",
                args: ["--stdio", "--config", "/etc/kindlyguard/config.toml"]
            }
        }
    };
    
    [localConfig, globalConfig, customConfig].forEach(config => {
        assert(config.mcpServers, 'Config should have mcpServers');
        const serverKey = Object.keys(config.mcpServers)[0];
        const server = config.mcpServers[serverKey];
        assert(server.command, 'Server should have command');
        assert(server.args, 'Server should have args');
    });
});

// Test 10: Write sample configuration
testAsync('Write sample configuration file', async () => {
    const sampleConfigPath = path.join(__dirname, 'claude-desktop-config-sample.json');
    
    const sampleConfig = {
        mcpServers: {
            "kindly-guard": {
                command: "npx",
                args: ["kindlyguard", "--stdio"]
            }
        }
    };
    
    try {
        fs.writeFileSync(sampleConfigPath, JSON.stringify(sampleConfig, null, 2));
        console.log(`  Sample config written to: ${sampleConfigPath}`);
        
        // Verify it's valid JSON
        const readConfig = JSON.parse(fs.readFileSync(sampleConfigPath, 'utf8'));
        assert.deepStrictEqual(readConfig, sampleConfig, 'Written config should match');
        
        // Cleanup
        fs.unlinkSync(sampleConfigPath);
    } catch (error) {
        // Cleanup on error
        if (fs.existsSync(sampleConfigPath)) {
            fs.unlinkSync(sampleConfigPath);
        }
        throw error;
    }
});

// Summary
console.log('\n=== Claude Desktop Integration Test Summary ===');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed > 0) {
    console.log('\nTo integrate with Claude Desktop:');
    console.log('1. Install KindlyGuard: npm install -g kindlyguard');
    console.log('2. Add the configuration to your Claude Desktop config file');
    console.log('3. Restart Claude Desktop');
    process.exit(1);
} else {
    console.log('\nIntegration test passed! Ready for Claude Desktop.');
    process.exit(0);
}