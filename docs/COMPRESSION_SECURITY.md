# Compression Security in KindlyGuard

## Overview

KindlyGuard's enhanced event buffer includes comprehensive security measures to handle compressed data safely, preventing compression-based attacks while maintaining performance.

## Threat Model

### 1. Compression Bombs (Zip Bombs)

**Attack Vector**: Malicious actors submit highly compressed data that expands to enormous sizes when decompressed, causing:
- Memory exhaustion
- CPU starvation
- Denial of Service

**Example**: A 1KB compressed payload claiming to expand to 1GB

### 2. Compression Ratio Attacks

**Attack Vector**: Exploiting compression algorithms to:
- Leak information through compression ratios
- Perform timing attacks based on compression time
- Bypass size limits through clever compression

### 3. Decompression Vulnerabilities

**Attack Vector**: Malformed compressed data triggering:
- Buffer overflows in decompression routines
- Integer overflows in size calculations
- Infinite loops in decompression algorithms

## Security Measures

### 1. Compression Detection

The atomic state machine tracks compression state at the bit level:

```rust
// Magic byte detection for common compression formats
let is_compressed = data.len() > 4 && (
    (data[0] == 0x1F && data[1] == 0x8B) ||  // gzip
    (data[0] == 0x50 && data[1] == 0x4B) ||  // zip
    (data[0] == 0xFD && data[1] == 0x37)     // xz
);
```

### 2. Ratio Validation

Strict limits on compression ratios prevent bombs:

```rust
const MAX_COMPRESSION_RATIO: u8 = 10;  // Maximum 10:1 compression

if is_compressed && compression_ratio > MAX_COMPRESSION_RATIO {
    tracing::warn!(
        target: "security.compression",
        "Suspicious compression ratio: {}",
        compression_ratio
    );
    return Err(anyhow::anyhow!("Compression ratio exceeds security limits"));
}
```

### 3. Size Limits

Multiple layers of size validation:

```rust
const MAX_DECOMPRESSED_SIZE: usize = 1024 * 1024;  // 1MB max

fn decompress_with_bounds_check(
    compressed_data: &[u8],
    expected_size: usize,
    max_expansion_ratio: f32,
) -> Result<Vec<u8>> {
    // Validate compression header
    if compressed_data.len() < 4 {
        anyhow::bail!("Invalid compressed data");
    }
    
    // Check claimed size against limits
    let uncompressed_size = u32::from_le_bytes([
        compressed_data[0],
        compressed_data[1],
        compressed_data[2],
        compressed_data[3],
    ]) as usize;
    
    if uncompressed_size > MAX_DECOMPRESSED_SIZE {
        anyhow::bail!("Decompressed size exceeds maximum");
    }
    
    if uncompressed_size > expected_size * max_expansion_ratio as usize {
        anyhow::bail!("Compression ratio exceeds security limits");
    }
    
    // Allocate with limits
    let mut output = Vec::with_capacity(uncompressed_size.min(MAX_DECOMPRESSED_SIZE));
    
    // Decompress with timeout
    tokio::time::timeout(
        Duration::from_millis(100),
        async { decompress_internal(&compressed_data[4..], &mut output) }
    ).await??;
    
    Ok(output)
}
```

### 4. Constant-Time Operations

Security-critical compression checks use constant-time operations:

```rust
// Constant-time compression flag check
fn is_compressed_constant_time(flags: u8) -> bool {
    // No branching - prevents timing attacks
    let compressed_bit = flags & FLAG_COMPRESSED;
    compressed_bit != 0
}

// Constant-time flag update
flags = (flags & !FLAG_COMPRESSED) | if is_compressed { FLAG_COMPRESSED } else { 0 };
```

### 5. Audit Trail

All compression events are logged for security monitoring:

```rust
tracing::info!(
    target: "security.audit.compression",
    endpoint_id = endpoint_id,
    compressed = is_compressed,
    ratio = compression_ratio,
    size_before = data.len(),
    size_claimed = uncompressed_size,
    "Compression event processed"
);
```

## Implementation Guidelines

### DO's

1. **Always validate compression headers** before processing
2. **Set strict size and ratio limits** appropriate for your use case
3. **Use timeouts** for all decompression operations
4. **Log compression events** for security monitoring
5. **Isolate decompression** in separate processes when possible
6. **Update compression libraries** regularly for security patches

### DON'Ts

1. **Never trust claimed sizes** without validation
2. **Don't decompress directly into production memory**
3. **Avoid synchronous decompression** in request handlers
4. **Don't ignore compression ratio anomalies**
5. **Never disable compression security checks** for performance

## Configuration

```toml
[security.compression]
enabled = true                    # Enable compression handling
max_ratio = 10                    # Maximum compression ratio (10:1)
max_decompressed_size = 1048576   # 1MB maximum decompressed size
timeout_ms = 100                  # Decompression timeout
allowed_formats = ["gzip", "zlib"] # Allowed compression formats
audit_log = true                  # Enable compression audit logging
```

## Monitoring

Key metrics to monitor:

1. **Compression ratio distribution** - Detect anomalies
2. **Decompression time** - Identify potential attacks
3. **Rejection rate** - Track blocked compression attempts
4. **Memory usage during decompression** - Prevent exhaustion

## Testing

### Security Tests

```rust
#[test]
fn test_compression_bomb_detection() {
    // Create a compression bomb (small compressed, huge claimed size)
    let mut bomb = vec![0x1F, 0x8B, 0xFF, 0xFF, 0xFF, 0xFF]; // Claims 4GB
    bomb.extend_from_slice(b"small data");
    
    let buffer = create_enhanced_buffer();
    let result = buffer.enqueue_event(0, &bomb, Priority::Normal);
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("compression bomb"));
}

#[test]
fn test_compression_ratio_limits() {
    // Test various compression ratios
    for ratio in [5, 10, 15, 20] {
        let data = create_compressed_data_with_ratio(ratio);
        let buffer = create_enhanced_buffer();
        let result = buffer.enqueue_event(0, &data, Priority::Normal);
        
        if ratio <= MAX_COMPRESSION_RATIO {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }
}
```

## Incident Response

If a compression-based attack is detected:

1. **Immediate**: Block the endpoint (circuit breaker opens)
2. **Log**: Capture full details for forensics
3. **Alert**: Notify security team
4. **Analyze**: Review compression patterns
5. **Update**: Adjust limits if needed

## References

- [CVE-2019-20907](https://nvd.nist.gov/vuln/detail/CVE-2019-20907) - Python Zip Bomb
- [Compression Bomb Vulnerabilities](https://en.wikipedia.org/wiki/Zip_bomb)
- [OWASP Compression Attacks](https://owasp.org/www-community/attacks/Denial_of_Service)