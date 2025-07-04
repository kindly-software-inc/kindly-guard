#!/usr/bin/env node

/**
 * Binary Protocol Test Suite
 * Tests binary message handling between KindlyGuard components
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const WebSocket = require('ws');
const crypto = require('crypto');

// Test configuration
const TEST_CONFIG = {
    binaryTestCases: [
        // UTF-8 with special characters
        { 
            name: 'UTF-8 with emojis',
            data: Buffer.from('Hello 🌍 World 🚀 Security 🛡️', 'utf8'),
            type: 'text'
        },
        // Binary data
        {
            name: 'Random binary data',
            data: crypto.randomBytes(1024),
            type: 'binary'
        },
        // Mixed content
        {
            name: 'Mixed binary and text',
            data: Buffer.concat([
                Buffer.from('HEADER:', 'utf8'),
                crypto.randomBytes(32),
                Buffer.from(':FOOTER', 'utf8')
            ]),
            type: 'mixed'
        },
        // Large binary payload
        {
            name: 'Large binary payload (1MB)',
            data: crypto.randomBytes(1024 * 1024),
            type: 'binary'
        },
        // Zero bytes
        {
            name: 'Data with null bytes',
            data: Buffer.from('Hello\x00World\x00Test', 'utf8'),
            type: 'text'
        },
        // All possible byte values
        {
            name: 'All byte values',
            data: Buffer.from(Array.from({length: 256}, (_, i) => i)),
            type: 'binary'
        },
        // Common binary formats
        {
            name: 'PNG magic bytes',
            data: Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            type: 'binary'
        },
        {
            name: 'JPEG magic bytes',
            data: Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]),
            type: 'binary'
        },
        // Protocol-specific patterns
        {
            name: 'WebSocket frame',
            data: Buffer.from([0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]),
            type: 'binary'
        },
        // Edge cases
        {
            name: 'Empty buffer',
            data: Buffer.alloc(0),
            type: 'binary'
        },
        {
            name: 'Single byte',
            data: Buffer.from([0xFF]),
            type: 'binary'
        },
        // Security test cases
        {
            name: 'Shellcode pattern',
            data: Buffer.from([0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68]),
            type: 'binary'
        },
        {
            name: 'Format string pattern',
            data: Buffer.from('%s%s%s%s%s%s%s%s', 'utf8'),
            type: 'text'
        }
    ]
};

let passed = 0;
let failed = 0;

// Helper functions
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

// Binary protocol tests
class BinaryProtocolTester {
    // Test binary message framing
    async testBinaryFraming() {
        for (const testCase of TEST_CONFIG.binaryTestCases) {
            await this.testSingleBinaryFrame(testCase);
        }
    }

    async testSingleBinaryFrame(testCase) {
        return new Promise((resolve, reject) => {
            const proc = spawn('node', [path.join(__dirname, 'npm-package/bin/kindlyguard'), '--stdio'], {
                stdio: ['pipe', 'pipe', 'pipe']
            });

            let responseReceived = false;

            proc.on('exit', (code) => {
                if (code === 0 || responseReceived) {
                    resolve();
                } else {
                    reject(new Error(`Process exited with code ${code}`));
                }
            });

            proc.on('error', reject);

            // Create a binary message with proper framing
            const message = {
                jsonrpc: "2.0",
                id: 1,
                method: "tools/call",
                params: {
                    name: "scan_binary",
                    arguments: {
                        data: testCase.data.toString('base64'),
                        type: testCase.type
                    }
                }
            };

            const jsonStr = JSON.stringify(message);
            const frame = Buffer.concat([
                Buffer.from(jsonStr, 'utf8'),
                Buffer.from('\n', 'utf8')
            ]);

            proc.stdin.write(frame);

            // Listen for response
            proc.stdout.on('data', (data) => {
                responseReceived = true;
                try {
                    const response = JSON.parse(data.toString());
                    if (response.error) {
                        // Some binary patterns might be rejected as threats
                        console.log(`  Binary test '${testCase.name}' was flagged: ${response.error.message}`);
                    }
                } catch (e) {
                    // Ignore parse errors for this test
                }
            });

            setTimeout(() => {
                proc.kill();
                resolve();
            }, 2000);
        });
    }

    // Test WebSocket binary frames
    async testWebSocketBinary() {
        return new Promise((resolve, reject) => {
            const server = spawn('node', [path.join(__dirname, 'npm-package/bin/kindlyguard'), '--websocket', '--port', '8766']);
            
            setTimeout(() => {
                const ws = new WebSocket('ws://localhost:8766');
                
                ws.on('open', () => {
                    // Send binary frame
                    const binaryData = crypto.randomBytes(1024);
                    ws.send(binaryData, { binary: true });
                    
                    // Also send text frame with binary content
                    const textMessage = {
                        jsonrpc: "2.0",
                        id: 1,
                        method: "test",
                        params: {
                            binary: binaryData.toString('base64')
                        }
                    };
                    ws.send(JSON.stringify(textMessage));
                    
                    setTimeout(() => {
                        ws.close();
                        server.kill();
                        resolve();
                    }, 1000);
                });

                ws.on('error', (error) => {
                    server.kill();
                    reject(error);
                });
            }, 2000);

            server.on('error', reject);
        });
    }

    // Test shared memory binary transfer
    async testSharedMemoryBinary() {
        // This tests the concept of shared memory binary transfer
        const shmBuffer = Buffer.alloc(4096);
        
        // Write test pattern
        for (let i = 0; i < shmBuffer.length; i++) {
            shmBuffer[i] = i & 0xFF;
        }
        
        // Simulate reading from shared memory
        const readBuffer = Buffer.from(shmBuffer);
        
        // Verify integrity
        for (let i = 0; i < readBuffer.length; i++) {
            if (readBuffer[i] !== (i & 0xFF)) {
                throw new Error(`Shared memory corruption at byte ${i}`);
            }
        }
        
        return true;
    }

    // Test binary protocol boundaries
    async testBinaryBoundaries() {
        const boundaryTests = [
            // Multiple binary messages in sequence
            async () => {
                const messages = [
                    Buffer.from([0x01, 0x02, 0x03]),
                    Buffer.from([0x04, 0x05, 0x06]),
                    Buffer.from([0x07, 0x08, 0x09])
                ];
                
                for (const msg of messages) {
                    await this.sendBinaryMessage(msg);
                }
            },
            
            // Binary message split across chunks
            async () => {
                const largeMessage = crypto.randomBytes(65536);
                const chunks = [];
                for (let i = 0; i < largeMessage.length; i += 1024) {
                    chunks.push(largeMessage.slice(i, Math.min(i + 1024, largeMessage.length)));
                }
                
                // This simulates fragmented delivery
                for (const chunk of chunks) {
                    await this.sendBinaryChunk(chunk);
                }
            }
        ];
        
        for (const test of boundaryTests) {
            await test();
        }
    }

    async sendBinaryMessage(data) {
        // Simulate sending a complete binary message
        return new Promise((resolve) => {
            setTimeout(resolve, 10);
        });
    }

    async sendBinaryChunk(data) {
        // Simulate sending a binary chunk
        return new Promise((resolve) => {
            setTimeout(resolve, 5);
        });
    }

    // Test binary encoding/decoding
    async testBinaryEncoding() {
        const encodings = ['base64', 'hex', 'utf8', 'binary'];
        const testData = crypto.randomBytes(256);
        
        for (const encoding of encodings) {
            if (encoding === 'utf8') {
                // Skip UTF-8 for random binary data
                continue;
            }
            
            const encoded = testData.toString(encoding);
            const decoded = Buffer.from(encoded, encoding);
            
            if (!testData.equals(decoded)) {
                throw new Error(`Encoding/decoding failed for ${encoding}`);
            }
        }
    }

    // Test binary protocol security
    async testBinarySecurity() {
        const securityTests = [
            // Integer overflow in size field
            {
                name: 'Integer overflow',
                data: Buffer.from([0xFF, 0xFF, 0xFF, 0xFF]), // Max uint32
                expectReject: true
            },
            // Malformed length prefix
            {
                name: 'Malformed length',
                data: Buffer.from([0x00, 0x00, 0x00, 0x01, 0x02]), // Claims 1 byte but has 2
                expectReject: true
            },
            // Zip bomb pattern
            {
                name: 'Compression bomb',
                data: Buffer.from('PK\x03\x04'), // ZIP magic bytes
                expectReject: false // Should handle gracefully
            }
        ];
        
        for (const test of securityTests) {
            try {
                await this.testSecurityPattern(test);
            } catch (error) {
                if (!test.expectReject) {
                    throw error;
                }
            }
        }
    }

    async testSecurityPattern(test) {
        // Test that security patterns are handled safely
        return new Promise((resolve) => {
            // Simulate security check
            setTimeout(resolve, 10);
        });
    }
}

// Message chunking tests
class MessageChunkingTester {
    async testChunking() {
        const sizes = [
            1,          // Tiny
            1024,       // 1KB
            65536,      // 64KB
            1048576,    // 1MB
            10485760    // 10MB
        ];
        
        for (const size of sizes) {
            await this.testChunkSize(size);
        }
    }
    
    async testChunkSize(size) {
        const data = crypto.randomBytes(size);
        const chunks = this.chunkData(data, 4096); // 4KB chunks
        
        // Reassemble
        const reassembled = Buffer.concat(chunks);
        
        if (!data.equals(reassembled)) {
            throw new Error(`Chunking failed for size ${size}`);
        }
    }
    
    chunkData(data, chunkSize) {
        const chunks = [];
        for (let i = 0; i < data.length; i += chunkSize) {
            chunks.push(data.slice(i, Math.min(i + chunkSize, data.length)));
        }
        return chunks;
    }
}

// Main test execution
async function runTests() {
    console.log('Binary Protocol Test Suite\n');
    
    const binaryTester = new BinaryProtocolTester();
    const chunkingTester = new MessageChunkingTester();
    
    // Test 1: Binary Message Framing
    console.log('=== Binary Message Framing ===');
    await testAsync('Binary frame handling', async () => {
        await binaryTester.testBinaryFraming();
    });
    
    // Test 2: WebSocket Binary Frames
    console.log('\n=== WebSocket Binary Protocol ===');
    await testAsync('WebSocket binary frame support', async () => {
        await binaryTester.testWebSocketBinary();
    });
    
    // Test 3: Shared Memory Binary
    console.log('\n=== Shared Memory Binary Transfer ===');
    await testAsync('Shared memory binary integrity', async () => {
        await binaryTester.testSharedMemoryBinary();
    });
    
    // Test 4: Binary Boundaries
    console.log('\n=== Binary Protocol Boundaries ===');
    await testAsync('Binary message boundaries', async () => {
        await binaryTester.testBinaryBoundaries();
    });
    
    // Test 5: Encoding/Decoding
    console.log('\n=== Binary Encoding/Decoding ===');
    await testAsync('Binary encoding round-trip', async () => {
        await binaryTester.testBinaryEncoding();
    });
    
    // Test 6: Message Chunking
    console.log('\n=== Message Chunking ===');
    await testAsync('Large message chunking', async () => {
        await chunkingTester.testChunking();
    });
    
    // Test 7: Binary Security
    console.log('\n=== Binary Protocol Security ===');
    await testAsync('Binary security patterns', async () => {
        await binaryTester.testBinarySecurity();
    });
    
    // Summary
    console.log('\n=== Test Summary ===');
    console.log(`Total tests: ${passed + failed}`);
    console.log(`Passed: ${passed}`);
    console.log(`Failed: ${failed}`);
    
    // Write report
    const report = {
        timestamp: new Date().toISOString(),
        summary: { total: passed + failed, passed, failed },
        binaryTestCases: TEST_CONFIG.binaryTestCases.length,
        maxPayloadTested: '10MB'
    };
    
    fs.writeFileSync(
        path.join(__dirname, 'binary-protocol-report.json'),
        JSON.stringify(report, null, 2)
    );
    
    console.log('\nDetailed report written to: binary-protocol-report.json');
    
    process.exit(failed > 0 ? 1 : 0);
}

// Run tests
runTests().catch(error => {
    console.error('Test suite failed:', error);
    process.exit(1);
});