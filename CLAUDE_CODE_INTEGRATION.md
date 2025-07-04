# Claude Code Integration Design

## Overview

This document outlines the integration design for KindlyGuard with Claude Code, implementing a local WebSocket server with MCP protocol extensions for real-time security shield status updates.

## Architecture

### 1. WebSocket Server Module

Location: `src/transport/claude_code.rs`

```rust
// Claude Code specific WebSocket transport
pub struct ClaudeCodeTransport {
    config: ClaudeCodeConfig,
    shield: Arc<Shield>,
    scanner: Arc<SecurityScanner>,
    event_buffer: Arc<dyn EventProcessor>, // Trait-based for enhanced mode
}

pub struct ClaudeCodeConfig {
    pub port: u16,              // Default: 9955
    pub bind_addr: String,      // Default: "127.0.0.1"
    pub enhanced_mode: bool,    // Enable binary protocol
    pub batch_delay_ms: u64,    // Max 50ms for notifications
    pub shared_memory: bool,    // Enable SHM optimization
}
```

### 2. MCP Protocol Extensions

#### Shield Status Notification

```typescript
interface ShieldStatusNotification {
  jsonrpc: "2.0";
  method: "shield/status";
  params: {
    active: boolean;
    enhanced: boolean;
    threats: number;
    threatRate: number;  // per minute
    lastThreat?: {
      type: string;
      severity: "low" | "medium" | "high" | "critical";
      timestamp: number;
      description: string;
    };
    performance: {
      scanTimeUs: number;  // microseconds
      queueDepth: number;
      memoryMb: number;
    };
  };
}
```

#### Shield Control Methods

```typescript
interface ShieldControlRequest {
  jsonrpc: "2.0";
  method: "shield/control";
  params: {
    action: "pause" | "resume" | "reset" | "enhance";
    duration?: number; // milliseconds
  };
  id: string | number;
}

interface ShieldInfoRequest {
  jsonrpc: "2.0";
  method: "shield/info";
  params?: {
    detailed: boolean;
  };
  id: string | number;
}
```

### 3. Performance Optimization Traits

```rust
// Event processing trait for zero-allocation updates
pub trait EventProcessor: Send + Sync {
    async fn process_batch(&self, events: &[SecurityEvent]) -> Result<ShieldStatus>;
    fn supports_binary(&self) -> bool;
    fn supports_shared_memory(&self) -> bool;
}

// Standard implementation
pub struct StandardEventProcessor {
    stats: Arc<Mutex<ShieldStats>>,
}

// Enhanced implementation (feature-gated)
#[cfg(feature = "enhanced")]
struct AtomicEventProcessor {
    buffer: Arc<AtomicEventBuffer>, // Proprietary zero-allocation buffer
    stats: AtomicShieldStats,        // Lock-free statistics
}

// Factory selection
pub fn create_event_processor(config: &Config) -> Arc<dyn EventProcessor> {
    if config.claude_code.enhanced_mode {
        #[cfg(feature = "enhanced")]
        return Arc::new(AtomicEventProcessor::new(config));
        
        Arc::new(StandardEventProcessor::new(config))
    } else {
        Arc::new(StandardEventProcessor::new(config))
    }
}
```

### 4. Binary Protocol (Enhanced Mode)

```rust
// Binary message format for minimal latency
#[repr(C, packed)]
struct BinaryShieldStatus {
    header: u32,           // Magic number + version
    timestamp: u64,        // Nanoseconds since epoch
    active: u8,            // Boolean flag
    enhanced: u8,          // Boolean flag
    threat_count: u32,     // Total threats
    threat_rate: f32,      // Per minute
    scan_time_ns: u64,     // Last scan duration
    queue_depth: u16,      // Current queue size
    memory_kb: u32,        // Memory usage
    last_threat_type: u16, // Enum value
    last_threat_time: u64, // Timestamp
}

// Shared memory structure
#[cfg(feature = "enhanced")]
struct SharedMemoryStatus {
    shm_key: String,
    layout: SharedMemoryLayout,
    update_counter: AtomicU64, // For change detection
}
```

## Implementation Phases

### Phase 1: Basic WebSocket Server (Week 1)
- [ ] Create `claude_code.rs` transport module
- [ ] Implement basic WebSocket server on port 9955
- [ ] Add MCP shield/status notification
- [ ] Integrate with existing Shield component
- [ ] Basic JSON protocol support

### Phase 2: Real-time Notifications (Week 2)
- [ ] Implement event batching (50ms max delay)
- [ ] Add threat severity classification
- [ ] Create notification queue with backpressure
- [ ] Add connection management and reconnection
- [ ] Performance metrics in notifications

### Phase 3: Enhanced Binary Protocol (Week 3)
- [ ] Design binary message format
- [ ] Implement AtomicEventProcessor trait
- [ ] Add feature-gated enhanced mode
- [ ] Zero-copy serialization
- [ ] Benchmark standard vs enhanced

### Phase 4: Shared Memory Optimization (Week 4)
- [ ] Design shared memory layout
- [ ] Implement SHM transport option
- [ ] Add change detection mechanism
- [ ] Claude Code client library updates
- [ ] Performance testing and tuning

## Configuration

```toml
[claude_code]
enabled = true
port = 9955
bind_address = "127.0.0.1"
enhanced_mode = false
batch_delay_ms = 50
max_connections = 10

[claude_code.notifications]
threat_alerts = true
performance_metrics = true
detailed_threats = false

[claude_code.security]
require_auth = true
auth_token_env = "CLAUDE_CODE_TOKEN"
allowed_origins = ["claude://localhost"]

[claude_code.performance]
shared_memory = false
binary_protocol = false
compression = true
```

## Integration Points

### 1. Server Module (`src/server.rs`)
- Add ClaudeCodeTransport to TransportManager
- Route shield/* methods to handler
- Integrate with authentication system

### 2. Shield Module (`src/shield/mod.rs`)
- Add notification hooks for status changes
- Expose detailed metrics for Claude Code
- Support pause/resume operations

### 3. Scanner Module (`src/scanner/mod.rs`)
- Add performance timing for scans
- Threat classification for notifications
- Queue depth monitoring

### 4. Main Entry (`src/main.rs`)
- Initialize Claude Code transport
- Configuration loading
- Graceful shutdown handling

## Security Considerations

1. **Local-only binding**: Default to 127.0.0.1, no external access
2. **Authentication**: Required auth token for connections
3. **Rate limiting**: Prevent notification flooding
4. **Input validation**: All control commands validated
5. **Threat isolation**: Claude Code cannot modify security policies

## Performance Targets

- **Latency**: < 1ms for status updates (enhanced mode)
- **Throughput**: 10,000 notifications/second
- **Memory**: < 10MB overhead for transport
- **CPU**: < 1% baseline, < 5% under load

## Testing Strategy

1. **Unit tests**: Each component in isolation
2. **Integration tests**: Full WebSocket flow
3. **Performance tests**: Benchmark both modes
4. **Security tests**: Auth, rate limiting, fuzzing
5. **Claude Code client**: Mock client for e2e tests

## Future Enhancements

1. **Multi-client support**: Allow multiple Claude Code instances
2. **Historical data**: Time-series threat data
3. **Custom notifications**: User-defined alert rules
4. **Remote monitoring**: Secure remote access option
5. **Plugin integration**: Shield status in Claude Code UI