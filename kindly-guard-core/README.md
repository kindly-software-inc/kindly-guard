# KindlyGuard Core - Private Enhanced Library

This is the private core library for KindlyGuard that provides patented lock-free data structures and advanced security algorithms.

## ⚠️ Private Repository

This library contains proprietary technology and should not be distributed publicly.

## Overview

This crate contains the proprietary enhanced implementations for KindlyGuard's high-performance security features. The architecture follows a trait-based design pattern that separates public interfaces from private implementations, allowing for clean API boundaries while protecting intellectual property.

## Architecture

### Trait-Based Interface

The library exposes public traits that define the API contract, while keeping the actual implementations private:

```rust
// Public trait (exposed in kindly-guard-shield)
pub trait EventBufferTrait<T>: Send + Sync {
    fn push(&self, event: T) -> Result<(), BufferError>;
    fn pop(&self) -> Option<T>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
}

// Private implementation (in this crate)
struct AtomicBitPackedEventBuffer<T, const N: usize> {
    // Proprietary bit-packed atomic state machine
    // Implementation details are hidden
}
```

### Core Components

- **AtomicBitPackedEventBuffer**: Patented lock-free ring buffer with bit-packed atomic state machine
- **BinaryProtocol**: Custom binary encoding with compression
- **PatternMatcher**: SIMD-accelerated pattern matching with ML models
- **ThreatClassifier**: Machine learning-based threat classification
- **UnicodeNormalizer**: Advanced unicode threat detection

## Usage Examples

### Creating an Event Buffer

The library provides factory functions that return trait objects, hiding the implementation details:

```rust
use kindly_guard_core::create_event_buffer;
use kindly_guard_shield::EventBufferTrait;

// Create a high-performance event buffer
let buffer: Box<dyn EventBufferTrait<SecurityEvent>> = 
    create_event_buffer::<SecurityEvent>(8192)?;

// Use it through the trait interface
buffer.push(SecurityEvent::new("login_attempt"))?;
if let Some(event) = buffer.pop() {
    // Process event
}
```

### Integration with Shield

```rust
use kindly_guard_shield::{Shield, ShieldConfig};

let config = ShieldConfig::enhanced()
    .with_event_buffer_size(16384)
    .with_correlation_enabled(true);

let shield = Shield::new(config)?;
// The shield internally uses the enhanced event buffer
// when the enhanced feature is enabled
```

## Benefits of Trait-Based Architecture

1. **API Stability**: Public traits provide a stable API that won't break with implementation changes
2. **IP Protection**: Implementation details remain private and protected
3. **Flexibility**: Easy to swap implementations for testing or different deployment scenarios
4. **Type Safety**: Rust's trait system ensures compile-time correctness
5. **Performance**: Zero-cost abstractions - trait calls are inlined

## Building

```bash
cargo build --release
```

For development builds with debug symbols:
```bash
cargo build
```

## Integration

The enhanced features in other KindlyGuard components use this library when the `enhanced` feature is enabled:

```toml
[dependencies]
kindly-guard-core = { path = "../kindly-guard-core", optional = true }

[features]
enhanced = ["kindly-guard-core"]
```

## Components Using This Library

- `kindly-guard-shield`: Uses AtomicBitPackedEventBuffer, BinaryProtocol, and PatternMatcher
- `kindly-guard-server`: Would use the full suite of enhanced features
- `kindly-guard-gateway`: Leverages the event correlation engine

## License

Proprietary - All rights reserved