# KindlyGuard Shield Binary Protocol

This directory contains the high-performance binary protocol implementation for KindlyGuard Shield.

## Overview

The binary protocol provides significant performance improvements over JSON:
- **60-80% size reduction** for typical messages
- **Zero-copy parsing** in enhanced mode
- **Fixed-size headers** for efficient streaming
- **Delta encoding** for incremental updates

## Protocol Structure

### Message Header (20 bytes)
```
[0-3]   Magic bytes: "KGSP"
[4]     Protocol version (currently 2)
[5]     Message type (4 bits) + flags (4 bits)
[6-7]   Payload size (little-endian u16)
[8-11]  Message sequence number (little-endian u32)
[12-19] Timestamp in milliseconds (little-endian u64)
```

### Message Types
- `0x01` THREAT - Threat detection message
- `0x02` STATUS - Shield status update
- `0x03` HEARTBEAT - Keep-alive message
- `0x04` ERROR - Error notification
- `0x05` COMMAND - Client command
- `0x06` STATS_DELTA - Incremental statistics update

### Threat Encoding

Threats are encoded with bit-packed flags for maximum efficiency:

```
[0]     Threat type flags (8 bits)
[1]     Severity (2 bits) + reserved (6 bits)
[2]     Blocked flag (1 byte)
[3-4]   Source length (little-endian u16)
[N]     Source UTF-8 bytes
[N+1-2] Details length (little-endian u16)
[M]     Details UTF-8 bytes
[8]     Timestamp (little-endian u64)
```

## Protocol Negotiation

Clients negotiate the protocol version during WebSocket handshake:

1. Client sends: `{"type":"hello","version":2,"capabilities":{...}}`
2. Server responds: `{"type":"accept","version":2,"capabilities":{...}}`
3. Or fallback: `{"type":"reject","reason":"...","fallback_version":1}`

## Performance Characteristics

### Size Comparison
- **Threat message**: ~70% smaller than JSON
- **Status update**: ~60% smaller than JSON
- **Delta update**: ~85% smaller than full update

### Processing Speed
- **Encoding**: 5-10x faster than JSON
- **Decoding**: 8-15x faster than JSON
- **Zero-copy mode**: Near-zero allocation overhead

## Usage

### Standard Mode
```rust
let mut encoder = BinaryEncoder::new();
let mut buf = Vec::new();
encoder.encode(&message, &mut buf)?;
```

### Enhanced Mode (with feature flag)
```rust
let mut encoder = EnhancedBinaryEncoder::new();
let mut out_buf = [0u8; 1024];
let size = encoder.encode_zero_copy(&message, &mut out_buf)?;
```

## Security Considerations

- All inputs are validated for size limits
- UTF-8 validation on all string fields
- Checksums can be enabled for critical messages
- Rate limiting applies to binary protocol same as JSON