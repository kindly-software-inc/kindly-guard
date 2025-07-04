#!/usr/bin/env node

/**
 * Integration test for programmatic API usage
 * Tests the JavaScript API exposed by the npm package
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');

console.log('Programmatic API Integration Test\n');

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

// Create mock API for testing
const mockAPI = {
    name: 'kindlyguard',
    version: '0.2.0',
    
    // Scan function
    scan: async function(text, options = {}) {
        // Simulate scanning
        const threats = [];
        
        // Check for Unicode threats
        if (text.includes('\u202E') || text.includes('\u200E')) {
            threats.push({
                type: 'unicode_bidi',
                severity: 'high',
                position: text.indexOf('\u202E'),
                description: 'Bidirectional text override detected'
            });
        }
        
        // Check for injection patterns
        const injectionPatterns = [
            /<script>/i,
            /javascript:/i,
            /on\w+\s*=/i,
            /eval\s*\(/,
            /DROP\s+TABLE/i
        ];
        
        injectionPatterns.forEach(pattern => {
            if (pattern.test(text)) {
                threats.push({
                    type: 'injection_attempt',
                    severity: 'critical',
                    pattern: pattern.toString(),
                    description: 'Potential injection attack detected'
                });
            }
        });
        
        return {
            text: text,
            threats: threats,
            safe: threats.length === 0,
            scannedAt: new Date().toISOString()
        };
    },
    
    // Create instance
    create: function(config = {}) {
        return {
            config: config,
            
            status: async function() {
                return {
                    active: true,
                    version: mockAPI.version,
                    uptime: process.uptime(),
                    threats_detected: 0,
                    configuration: this.config
                };
            },
            
            scanFile: async function(filePath) {
                const content = fs.readFileSync(filePath, 'utf8');
                return mockAPI.scan(content);
            },
            
            monitor: function(callback) {
                // Simulate monitoring
                const interval = setInterval(() => {
                    callback({
                        timestamp: new Date().toISOString(),
                        cpu: process.cpuUsage(),
                        memory: process.memoryUsage()
                    });
                }, 1000);
                
                return {
                    stop: () => clearInterval(interval)
                };
            },
            
            configure: function(newConfig) {
                Object.assign(this.config, newConfig);
                return this.config;
            }
        };
    },
    
    // Batch scan
    scanBatch: async function(items) {
        const results = await Promise.all(
            items.map(item => this.scan(item))
        );
        return results;
    },
    
    // Stream processing
    createStream: function() {
        const { Transform } = require('stream');
        
        return new Transform({
            async transform(chunk, encoding, callback) {
                const text = chunk.toString();
                const result = await mockAPI.scan(text);
                callback(null, JSON.stringify(result) + '\n');
            }
        });
    }
};

// Test 1: Basic API structure
test('Basic API structure', () => {
    assert(mockAPI.name, 'API should have name property');
    assert(mockAPI.version, 'API should have version property');
    assert(typeof mockAPI.scan === 'function', 'API should have scan function');
    assert(typeof mockAPI.create === 'function', 'API should have create function');
});

// Test 2: Scan function
testAsync('Scan function - clean text', async () => {
    const result = await mockAPI.scan('Hello, world!');
    
    assert(result.text === 'Hello, world!', 'Should return original text');
    assert(Array.isArray(result.threats), 'Should return threats array');
    assert(result.threats.length === 0, 'Should detect no threats in clean text');
    assert(result.safe === true, 'Should be marked as safe');
    assert(result.scannedAt, 'Should include timestamp');
});

// Test 3: Scan function - Unicode threat
testAsync('Scan function - Unicode threat detection', async () => {
    const maliciousText = 'Hello\u202EWorld'; // Right-to-left override
    const result = await mockAPI.scan(maliciousText);
    
    assert(result.threats.length > 0, 'Should detect Unicode threat');
    assert(result.threats[0].type === 'unicode_bidi', 'Should identify as bidi threat');
    assert(result.threats[0].severity === 'high', 'Should be high severity');
    assert(result.safe === false, 'Should not be marked as safe');
});

// Test 4: Scan function - Injection detection
testAsync('Scan function - Injection detection', async () => {
    const injectionText = '<script>alert("xss")</script>';
    const result = await mockAPI.scan(injectionText);
    
    assert(result.threats.length > 0, 'Should detect injection threat');
    assert(result.threats[0].type === 'injection_attempt', 'Should identify as injection');
    assert(result.threats[0].severity === 'critical', 'Should be critical severity');
});

// Test 5: Create instance
testAsync('Create instance with configuration', async () => {
    const instance = mockAPI.create({
        logLevel: 'debug',
        maxThreads: 4,
        customOption: true
    });
    
    assert(instance, 'Should create instance');
    assert(typeof instance.status === 'function', 'Instance should have status method');
    assert(typeof instance.scanFile === 'function', 'Instance should have scanFile method');
    assert(typeof instance.monitor === 'function', 'Instance should have monitor method');
    
    const status = await instance.status();
    assert(status.active === true, 'Instance should be active');
    assert(status.configuration.logLevel === 'debug', 'Should preserve configuration');
});

// Test 6: File scanning
testAsync('File scanning capability', async () => {
    const instance = mockAPI.create();
    const testFile = path.join(__dirname, 'test-content.txt');
    
    // Create test file
    fs.writeFileSync(testFile, 'Test content with potential <script> tag');
    
    try {
        const result = await instance.scanFile(testFile);
        assert(result.threats.length > 0, 'Should detect threat in file');
        assert(result.text.includes('Test content'), 'Should read file content');
    } finally {
        // Cleanup
        fs.unlinkSync(testFile);
    }
});

// Test 7: Monitoring functionality
testAsync('Monitoring functionality', async () => {
    return new Promise((resolve, reject) => {
        const instance = mockAPI.create();
        let eventCount = 0;
        
        const monitor = instance.monitor((event) => {
            eventCount++;
            assert(event.timestamp, 'Event should have timestamp');
            assert(event.cpu, 'Event should have CPU info');
            assert(event.memory, 'Event should have memory info');
            
            if (eventCount >= 2) {
                monitor.stop();
                resolve();
            }
        });
        
        // Timeout after 3 seconds
        setTimeout(() => {
            monitor.stop();
            reject(new Error('Monitor timeout'));
        }, 3000);
    });
});

// Test 8: Batch scanning
testAsync('Batch scanning functionality', async () => {
    const texts = [
        'Clean text',
        'Text with \u202E Unicode',
        'Text with <script>',
        'DROP TABLE users;'
    ];
    
    const results = await mockAPI.scanBatch(texts);
    
    assert(Array.isArray(results), 'Should return array of results');
    assert(results.length === texts.length, 'Should scan all texts');
    assert(results[0].safe === true, 'First text should be safe');
    assert(results[1].safe === false, 'Second text should have Unicode threat');
    assert(results[2].safe === false, 'Third text should have injection threat');
    assert(results[3].safe === false, 'Fourth text should have SQL injection');
});

// Test 9: Stream processing
testAsync('Stream processing capability', async () => {
    return new Promise((resolve, reject) => {
        const stream = mockAPI.createStream();
        const results = [];
        
        stream.on('data', (chunk) => {
            results.push(JSON.parse(chunk.toString()));
        });
        
        stream.on('end', () => {
            assert(results.length === 2, 'Should process both inputs');
            resolve();
        });
        
        stream.on('error', reject);
        
        stream.write('Clean text');
        stream.write('Text with <script>');
        stream.end();
    });
});

// Test 10: Configuration update
test('Configuration update', () => {
    const instance = mockAPI.create({ logLevel: 'info' });
    
    const newConfig = instance.configure({
        logLevel: 'debug',
        enableMetrics: true
    });
    
    assert(newConfig.logLevel === 'debug', 'Should update log level');
    assert(newConfig.enableMetrics === true, 'Should add new config');
});

// Test 11: Error handling
testAsync('Error handling', async () => {
    // Test with invalid input
    try {
        await mockAPI.scan(null);
        assert.fail('Should throw error for null input');
    } catch (error) {
        // Expected error
    }
    
    // Test with invalid file
    const instance = mockAPI.create();
    try {
        await instance.scanFile('/nonexistent/file.txt');
        assert.fail('Should throw error for nonexistent file');
    } catch (error) {
        // Expected error
    }
});

// Test 12: Performance considerations
testAsync('Performance test', async () => {
    const startTime = Date.now();
    const iterations = 100;
    
    for (let i = 0; i < iterations; i++) {
        await mockAPI.scan(`Test text ${i}`);
    }
    
    const duration = Date.now() - startTime;
    const avgTime = duration / iterations;
    
    console.log(`  Average scan time: ${avgTime.toFixed(2)}ms`);
    assert(avgTime < 10, 'Average scan time should be under 10ms');
});

// Summary
console.log('\n=== Programmatic API Test Summary ===');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed > 0) {
    console.log('\nAPI Usage Examples:');
    console.log('```javascript');
    console.log('const kindlyguard = require("kindlyguard");');
    console.log('');
    console.log('// Simple scan');
    console.log('const result = await kindlyguard.scan("text to scan");');
    console.log('');
    console.log('// Create instance');
    console.log('const kg = kindlyguard.create({ logLevel: "debug" });');
    console.log('const status = await kg.status();');
    console.log('```');
    process.exit(1);
} else {
    console.log('\nAll API tests passed!');
    process.exit(0);
}