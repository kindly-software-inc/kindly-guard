# KindlyGuard Rust Development Guide

This guide documents Rust-specific patterns, idioms, and conventions used in the KindlyGuard project.

## Core Rust Principles

### Error Handling
```rust
// CLAUDE-note-pattern: Always use Result<T, E> for fallible operations
// Location: Throughout codebase, especially src/scanner/*.rs
pub fn analyze_input(input: &str) -> Result<SecurityAnalysis, KindlyError> {
    // Never use unwrap() or expect() in production code
    let normalized = normalize_unicode(input)?;
    // Chain errors with context
    validate_input(&normalized).context("Input validation failed")?;
    Ok(SecurityAnalysis::new(normalized))
}
```

### Trait-Based Architecture
```rust
// CLAUDE-note-implemented: Core traits in src/protocol/traits.rs
pub trait SecurityScanner: Send + Sync {
    type Config;
    type Result;
    
    async fn scan(&self, input: &str) -> Result<Self::Result, Error>;
    fn configure(&mut self, config: Self::Config) -> Result<(), Error>;
}

// CLAUDE-note-pattern: All components implement standard traits
impl Default for Scanner {
    fn default() -> Self {
        Self::new(Config::default())
    }
}
```

### Async/Await Patterns
```rust
// CLAUDE-note-pattern: Tokio runtime for all async operations
// Location: src/server/main.rs, src/transport/*.rs
#[tokio::main]
async fn main() -> Result<()> {
    // Use select! for concurrent operations
    tokio::select! {
        result = server.run() => result?,
        _ = signal::ctrl_c() => {
            info!("Shutting down gracefully");
        }
    }
    Ok(())
}
```

### Memory Safety Patterns
```rust
// CLAUDE-note-pattern: Zero-copy operations where possible
// Location: src/scanner/unicode.rs
pub fn analyze_bytes(input: &[u8]) -> SecurityResult {
    // Avoid allocations in hot paths
    let mut scanner = ByteScanner::new_const();
    scanner.scan_in_place(input)
}

// CLAUDE-note-pattern: Use Arc for shared ownership
// Location: src/storage/cache.rs
type SharedCache = Arc<RwLock<HashMap<String, CachedResult>>>;
```

## Project-Specific Conventions

### Module Organization
```
src/
├── scanner/        # CLAUDE-note-feature: Threat detection modules
│   ├── unicode.rs  # Unicode security analysis
│   ├── injection.rs # SQL/Command injection detection
│   └── xss.rs      # XSS prevention
├── neutralizer/    # CLAUDE-note-feature: Threat neutralization
├── shield/         # CLAUDE-note-feature: UI components
└── protocol/       # CLAUDE-note-feature: MCP implementation
```

### Security-First Patterns
```rust
// CLAUDE-note-pattern: Constant-time comparisons for security
// Location: src/security/timing.rs
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
```

### Configuration Management
```rust
// CLAUDE-note-pattern: Type-safe configuration with serde
// Location: src/config/mod.rs
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub scanner: ScannerConfig,
    
    #[serde(default)]
    pub transport: TransportConfig,
    
    // CLAUDE-note-feature: Optional enhanced features
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enhanced: Option<EnhancedConfig>,
}
```

### Testing Patterns
```rust
// CLAUDE-note-pattern: Comprehensive test coverage
// Location: tests/*, src/**/tests.rs
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    
    // Property-based testing for security components
    proptest! {
        #[test]
        fn unicode_normalization_is_idempotent(input: String) {
            let once = normalize(&input);
            let twice = normalize(&once);
            assert_eq!(once, twice);
        }
    }
    
    // Async test patterns
    #[tokio::test]
    async fn test_concurrent_scanning() {
        let scanner = Scanner::new();
        let results = futures::future::join_all(
            inputs.iter().map(|input| scanner.scan(input))
        ).await;
        assert_all_safe(&results);
    }
}
```

### Performance Patterns
```rust
// CLAUDE-note-pattern: Benchmarking critical paths
// Location: benches/*.rs
use criterion::{black_box, criterion_group, Criterion};

fn bench_scanner(c: &mut Criterion) {
    c.bench_function("unicode_scan", |b| {
        let scanner = Scanner::new();
        b.iter(|| scanner.scan(black_box(MALICIOUS_INPUT)))
    });
}
```

### Dependency Injection
```rust
// CLAUDE-note-pattern: Constructor injection for testability
// Location: src/server/builder.rs
pub struct ServerBuilder {
    scanner: Option<Box<dyn SecurityScanner>>,
    storage: Option<Box<dyn Storage>>,
    transport: Option<Box<dyn Transport>>,
}

impl ServerBuilder {
    pub fn with_scanner(mut self, scanner: impl SecurityScanner + 'static) -> Self {
        self.scanner = Some(Box::new(scanner));
        self
    }
}
```

## Clippy and Formatting

### Clippy Configuration
```toml
# CLAUDE-note-location: .clippy.toml
# Enforce strict linting
warn = [
    "clippy::all",
    "clippy::pedantic",
    "clippy::nursery",
    "clippy::cargo",
]

# Allow certain patterns
allow = [
    "clippy::module_name_repetitions",  # Common in Rust
    "clippy::must_use_candidate",       # Too noisy
]
```

### Format Configuration
```toml
# CLAUDE-note-location: rustfmt.toml
edition = "2021"
max_width = 100
use_field_init_shorthand = true
use_small_heuristics = "Max"
imports_granularity = "Module"
group_imports = "StdExternalCrate"
```

## Common Commands

```bash
# CLAUDE-note-commands: Development workflow
cargo build --workspace           # Build all crates
cargo test --workspace           # Run all tests
cargo clippy -- -D warnings      # Lint with warnings as errors
cargo fmt --all -- --check       # Check formatting
cargo doc --no-deps --open       # Generate documentation

# CLAUDE-note-commands: Release build with security profile
cargo build --profile secure     # Build with overflow checks

# CLAUDE-note-commands: Benchmarking
cargo bench --bench scanner      # Run performance benchmarks
```

## Integration with Enhanced Features

```rust
// CLAUDE-note-pattern: Feature-gated enhanced implementations
// Location: src/scanner/enhanced.rs
#[cfg(feature = "enhanced")]
pub use kindly_guard_core::EnhancedScanner;

#[cfg(not(feature = "enhanced"))]
pub use crate::scanner::standard::StandardScanner as EnhancedScanner;

// CLAUDE-note-pattern: Runtime feature detection
pub fn create_scanner(config: &Config) -> Box<dyn SecurityScanner> {
    if config.enhanced.is_some() && is_enhanced_available() {
        Box::new(EnhancedScanner::new(config))
    } else {
        Box::new(StandardScanner::new(config))
    }
}
```

## Debugging and Troubleshooting

### Logging Configuration
```rust
// CLAUDE-note-pattern: Structured logging with tracing
// Location: src/telemetry/mod.rs
use tracing::{info, warn, error, instrument};

#[instrument(skip(scanner))]
pub async fn process_request(scanner: &Scanner, input: &str) -> Result<Response> {
    info!(input_length = input.len(), "Processing request");
    
    match scanner.scan(input).await {
        Ok(result) => {
            info!(threats_found = result.threats.len(), "Scan completed");
            Ok(Response::from(result))
        }
        Err(e) => {
            error!(error = ?e, "Scan failed");
            Err(e)
        }
    }
}
```

### Common Pitfalls to Avoid

1. **Never expose internal errors to clients**
   ```rust
   // Bad: Exposes internal details
   .map_err(|e| format!("Database error: {}", e))?
   
   // Good: Generic error with logging
   .map_err(|e| {
       error!("Database error: {}", e);
       KindlyError::InternalError
   })?
   ```

2. **Avoid blocking operations in async contexts**
   ```rust
   // Bad: Blocks the executor
   std::fs::read_to_string("config.toml")?
   
   // Good: Use async alternatives
   tokio::fs::read_to_string("config.toml").await?
   ```

3. **Handle Unicode properly**
   ```rust
   // Bad: Assumes valid UTF-8
   String::from_utf8_unchecked(bytes)
   
   // Good: Handle errors gracefully
   String::from_utf8(bytes).unwrap_or_else(|_| {
       String::from_utf8_lossy(&bytes).into_owned()
   })
   ```

## Performance Optimization Tips

1. **Use const generics for compile-time optimization**
   ```rust
   // CLAUDE-note-pattern: Const generics for buffer sizes
   pub struct Scanner<const BUFFER_SIZE: usize = 4096> {
       buffer: [u8; BUFFER_SIZE],
   }
   ```

2. **Leverage SIMD when available**
   ```rust
   // CLAUDE-note-location: src/scanner/simd.rs
   #[cfg(target_arch = "x86_64")]
   use std::arch::x86_64::*;
   
   pub fn fast_scan(input: &[u8]) -> bool {
       // SIMD implementation for x86_64
   }
   ```

3. **Pool expensive resources**
   ```rust
   // CLAUDE-note-pattern: Connection pooling
   use deadpool::managed::Pool;
   
   pub type DbPool = Pool<DbManager>;
   ```

## Security Considerations

1. **Always validate and sanitize input**
2. **Use constant-time operations for security-sensitive comparisons**
3. **Implement rate limiting at multiple levels**
4. **Log security events for audit trails**
5. **Follow principle of least privilege**

## Additional Resources

- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [Async Rust Book](https://rust-lang.github.io/async-book/)
- [The Rustonomicon](https://doc.rust-lang.org/nomicon/) (unsafe Rust)
- Project-specific docs in `/docs` directory