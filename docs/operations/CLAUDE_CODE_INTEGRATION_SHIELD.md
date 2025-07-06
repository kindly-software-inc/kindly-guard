# Claude Code Extension - Shared Memory Integration Guide

This guide explains how to integrate the KindlyGuard Shield's shared memory IPC into the Claude Code extension for ultra-low latency threat notifications.

## Overview

The shared memory IPC provides <100μs latency for local communication between KindlyGuard Shield and the Claude Code extension, replacing the higher-latency WebSocket connection when both components are running on the same machine.

## Architecture

```
┌─────────────────────┐     ┌──────────────────┐
│  KindlyGuard Shield │     │ Claude Code Ext  │
│                     │     │                  │
│  ┌───────────────┐  │     │  ┌────────────┐ │
│  │ Threat Scanner│  │     │  │ SHM Client │ │
│  └───────┬───────┘  │     │  └──────┬─────┘ │
│          │          │     │         │       │
│  ┌───────▼───────┐  │     │         │       │
│  │ SHM Writer    │  │     │         │       │
│  └───────┬───────┘  │     │         │       │
└──────────┼──────────┘     └─────────┼───────┘
           │                          │
           └──────────┬───────────────┘
                      │
            ┌─────────▼──────────┐
            │  Shared Memory     │
            │  /dev/shm/kindly-  │
            │  guard/kindly-     │
            │  guard.shm         │
            └────────────────────┘
```

## Integration Steps

### 1. Detection Logic

Add shared memory detection to the Claude Code extension:

```typescript
// In extension activation
async function activate(context: vscode.ExtensionContext) {
    // Try shared memory first
    const shmAvailable = await checkSharedMemoryAvailable();
    
    if (shmAvailable) {
        console.log("Using shared memory IPC (<100μs latency)");
        await initSharedMemoryClient();
    } else {
        console.log("Falling back to WebSocket IPC");
        await initWebSocketClient();
    }
}

async function checkSharedMemoryAvailable(): Promise<boolean> {
    try {
        // Check if shared memory file exists and is accessible
        const shmPath = getSharedMemoryPath();
        await fs.access(shmPath, fs.constants.R_OK);
        return true;
    } catch {
        return false;
    }
}

function getSharedMemoryPath(): string {
    if (process.platform === 'linux') {
        return '/dev/shm/kindly-guard/kindly-guard.shm';
    } else if (process.platform === 'darwin') {
        return '/tmp/kindly-guard-shm/kindly-guard.shm';
    } else if (process.platform === 'win32') {
        return path.join(process.env.LOCALAPPDATA, 'KindlyGuard', 'shm', 'kindly-guard.shm');
    }
    throw new Error('Unsupported platform');
}
```

### 2. Native Node.js Module

Create a native Node.js module for shared memory access:

```javascript
// shm-client.node (native module)
const { SharedMemoryClient } = require('./build/Release/shm-client');

class KindlyGuardShmClient {
    constructor() {
        this.client = new SharedMemoryClient();
    }
    
    async connect() {
        return this.client.connect();
    }
    
    async readThreat() {
        // Returns null if no threats available
        return this.client.readThreat();
    }
    
    async getStats() {
        return this.client.getStats();
    }
    
    async startPolling(callback) {
        // Poll every 100μs
        this.pollInterval = setInterval(async () => {
            const threat = await this.readThreat();
            if (threat) {
                callback(threat);
            }
        }, 0.1); // 100μs
    }
    
    stopPolling() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
        }
    }
}

module.exports = { KindlyGuardShmClient };
```

### 3. Extension Integration

Integrate the shared memory client into the extension:

```typescript
import { KindlyGuardShmClient } from './native/shm-client';

let shmClient: KindlyGuardShmClient | null = null;

async function initSharedMemoryClient() {
    try {
        shmClient = new KindlyGuardShmClient();
        await shmClient.connect();
        
        // Start polling for threats
        await shmClient.startPolling((threat) => {
            handleThreatEvent(threat);
        });
        
        // Show connection status
        vscode.window.showInformationMessage(
            'KindlyGuard: Connected via shared memory (ultra-low latency)'
        );
    } catch (error) {
        console.error('Failed to init shared memory:', error);
        // Fall back to WebSocket
        await initWebSocketClient();
    }
}

function handleThreatEvent(threat: ThreatEvent) {
    // Update UI
    updateThreatCount(threat);
    
    // Show notification for high severity
    if (threat.severity >= Severity.High) {
        vscode.window.showWarningMessage(
            `Security Threat: ${threat.details}`
        );
    }
    
    // Update status bar
    updateStatusBar(threat);
}
```

### 4. Performance Monitoring

Add performance monitoring to track latency:

```typescript
class LatencyMonitor {
    private latencies: number[] = [];
    private readonly maxSamples = 1000;
    
    recordLatency(microseconds: number) {
        this.latencies.push(microseconds);
        if (this.latencies.length > this.maxSamples) {
            this.latencies.shift();
        }
    }
    
    getStats() {
        if (this.latencies.length === 0) return null;
        
        const sorted = [...this.latencies].sort((a, b) => a - b);
        return {
            avg: sorted.reduce((a, b) => a + b) / sorted.length,
            min: sorted[0],
            max: sorted[sorted.length - 1],
            p99: sorted[Math.floor(sorted.length * 0.99)],
            count: sorted.length
        };
    }
}

// Usage
const latencyMonitor = new LatencyMonitor();

// In threat handler
const start = performance.now();
handleThreatEvent(threat);
const latency = (performance.now() - start) * 1000; // to microseconds
latencyMonitor.recordLatency(latency);

// Show stats in status bar
setInterval(() => {
    const stats = latencyMonitor.getStats();
    if (stats && stats.avg < 100) {
        statusBar.text = `$(shield) KindlyGuard (SHM ${stats.avg.toFixed(0)}μs)`;
        statusBar.color = 'green';
    }
}, 1000);
```

### 5. Graceful Degradation

Implement automatic fallback to WebSocket:

```typescript
class HybridIpcClient {
    private shmClient?: KindlyGuardShmClient;
    private wsClient?: WebSocketClient;
    private usingSHM = false;
    
    async connect() {
        // Try SHM first
        try {
            if (await this.trySharedMemory()) {
                this.usingSHM = true;
                return;
            }
        } catch (error) {
            console.warn('SHM not available:', error);
        }
        
        // Fall back to WebSocket
        await this.connectWebSocket();
    }
    
    private async trySharedMemory(): Promise<boolean> {
        if (!KindlyGuardShmClient.isAvailable()) {
            return false;
        }
        
        this.shmClient = new KindlyGuardShmClient();
        await this.shmClient.connect();
        
        // Verify it's working
        const stats = await this.shmClient.getStats();
        return stats.isHealthy;
    }
    
    private async connectWebSocket() {
        this.wsClient = new WebSocketClient('ws://localhost:9955');
        await this.wsClient.connect();
    }
    
    getConnectionType(): string {
        return this.usingSHM ? 'SharedMemory' : 'WebSocket';
    }
    
    getExpectedLatency(): string {
        return this.usingSHM ? '<100μs' : '1-5ms';
    }
}
```

## Testing

### Unit Tests

```typescript
describe('SharedMemoryClient', () => {
    it('should connect to shared memory', async () => {
        const client = new KindlyGuardShmClient();
        await expect(client.connect()).resolves.not.toThrow();
    });
    
    it('should read threats with low latency', async () => {
        const client = new KindlyGuardShmClient();
        await client.connect();
        
        const start = performance.now();
        const threat = await client.readThreat();
        const latency = performance.now() - start;
        
        expect(latency).toBeLessThan(0.1); // <100μs
    });
});
```

### Integration Tests

```bash
# Run shared memory demo
cd kindly-guard-shield/src-tauri
cargo run --example shm_demo

# In another terminal, run extension tests
cd claude-code-extension
npm test -- --grep "shared memory"
```

## Deployment Considerations

1. **Permissions**: Ensure the extension has read access to shared memory files
2. **Platform Support**: Test on Linux, macOS, and Windows
3. **Fallback**: Always implement WebSocket fallback
4. **Monitoring**: Track SHM vs WebSocket usage in telemetry
5. **Updates**: Handle Shield updates that might change SHM format

## Performance Targets

- **Latency**: <100μs (shared memory) vs 1-5ms (WebSocket)
- **Throughput**: >100,000 events/sec (SHM) vs ~10,000 events/sec (WS)
- **CPU Usage**: <1% for polling
- **Memory Usage**: <10MB for ring buffer

## Troubleshooting

### "Cannot connect to shared memory"
- Check if KindlyGuard Shield is running
- Verify file permissions on SHM file
- Ensure same user is running both processes

### "High latency despite SHM"
- Check CPU frequency scaling
- Disable power saving modes
- Use process affinity to pin to same CPU core

### "Missing threats"
- Increase polling frequency
- Check ring buffer size
- Monitor for buffer overflows