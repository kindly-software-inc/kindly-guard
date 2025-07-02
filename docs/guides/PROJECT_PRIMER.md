# KindlyGuard Project Primer

Welcome to KindlyGuard! This primer will help you understand the project's architecture, development workflow, and key concepts quickly.

## What is KindlyGuard?

KindlyGuard is a **security-focused MCP (Model Context Protocol) server** that acts as a protective shield between AI assistants and potentially malicious inputs. Think of it as a security gateway that:

- 🛡️ **Detects** threats in real-time (Unicode attacks, injections, XSS)
- 🧹 **Neutralizes** dangerous content while preserving intent
- 📊 **Monitors** security events with comprehensive audit trails
- 🚀 **Performs** at microsecond latencies suitable for production use

## Quick Start

### 1. First-Time Setup
```bash
# Clone and enter the project
git clone <repository-url>
cd kindly-guard

# Build everything
cargo build --workspace

# Run tests to verify setup
cargo test --workspace

# Start the MCP server
cargo run --bin kindly-guard-server
```

### 2. Understanding the Codebase Structure
```
kindly-guard/
├── kindly-guard-server/    # Main MCP server implementation
│   └── src/
│       ├── main.rs        # Entry point - start here!
│       ├── scanner/       # Threat detection engines
│       ├── protocol/      # MCP protocol handling
│       └── shield/        # Terminal UI components
├── kindly-guard-cli/      # Command-line interface
├── kindly-guard-shield/   # Desktop UI (Tauri app)
└── docs/                  # Additional documentation
```

## Key Concepts

### 1. The Scanning Pipeline
Every input goes through a multi-stage pipeline:

```rust
// CLAUDE-note-concept: This is the core flow
Input → Normalize → Scan → Assess → Neutralize → Respond
```

**Example Journey**:
```rust
// Input: "Hello <script>alert('xss')</script>"
// 1. Normalize: Convert to canonical form
// 2. Scan: Detect script tag (XSS threat)
// 3. Assess: High severity, injection attempt
// 4. Neutralize: Encode to "Hello &lt;script&gt;alert('xss')&lt;/script&gt;"
// 5. Respond: Return safe version with threat report
```

### 2. Trait-Based Architecture
KindlyGuard uses Rust traits extensively for flexibility:

```rust
// CLAUDE-note-pattern: Core traits you'll encounter
pub trait SecurityScanner {
    async fn scan(&self, input: &str) -> Result<ThreatReport>;
}

pub trait ThreatNeutralizer {
    fn neutralize(&self, threat: &Threat) -> Result<SafeContent>;
}

pub trait Storage {
    async fn store_threat(&self, threat: &Threat) -> Result<()>;
}
```

### 3. Configuration-Driven Behavior
Everything is configurable without recompilation:

```toml
# config.toml - Controls behavior
[scanner]
unicode_detection = true
sensitivity = "high"

[transport]
stdio = true
websocket = false
```

## Common Development Tasks

### Adding a New Threat Detector

1. **Create the detector module**:
```rust
// src/scanner/new_threat.rs
pub struct NewThreatScanner;

impl SecurityScanner for NewThreatScanner {
    async fn scan(&self, input: &str) -> Result<ThreatReport> {
        // Your detection logic here
    }
}
```

2. **Register in the scanner factory**:
```rust
// src/scanner/mod.rs
scanners.push(Box::new(NewThreatScanner::new()));
```

3. **Add tests**:
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_new_threat_detection() {
        // Test your detector
    }
}
```

### Working with the MCP Protocol

The MCP handler is in `src/protocol/handler.rs`. Key entry points:

```rust
// CLAUDE-note-entry: Main request handler
pub async fn handle_request(request: Request) -> Response {
    match request.method.as_str() {
        "scan" => handle_scan(request.params).await,
        "configure" => handle_configure(request.params).await,
        _ => error_response("Unknown method"),
    }
}
```

### Debugging Tips

1. **Enable trace logging**:
```bash
RUST_LOG=trace cargo run
```

2. **Use the Shield UI for real-time monitoring**:
```bash
cargo run --bin kindly-guard-server -- --ui
```

3. **Test specific scanners**:
```bash
echo "test input" | cargo run --bin kindly-guard-cli scan --only unicode
```

## Architecture Decisions

### Why Rust?
- **Memory safety** without garbage collection
- **Concurrent** processing with fearless concurrency
- **Performance** matching C/C++ with better ergonomics
- **Type safety** catching bugs at compile time

### Why MCP?
- **Standard protocol** for AI assistant integration
- **Tool-based** interaction model
- **Language agnostic** client support
- **Future-proof** as AI assistants evolve

### Design Principles
1. **Security First**: Every decision prioritizes security
2. **Performance Second**: Microsecond latencies for real-time use
3. **Usability Third**: Simple API, comprehensive docs
4. **No Surprises**: Predictable behavior, clear errors

## Key Files to Understand

Start with these files to understand the system:

1. **`src/main.rs`** - Application entry point and setup
2. **`src/protocol/handler.rs`** - MCP request processing
3. **`src/scanner/mod.rs`** - Scanner orchestration
4. **`src/scanner/unicode.rs`** - Example threat detector
5. **`tests/integration/full_flow.rs`** - End-to-end test example

## Testing Strategy

### Test Types and Locations
```bash
# Unit tests (next to code)
cargo test --lib

# Integration tests
cargo test --test '*'

# Property tests (fuzzing)
cargo test proptest

# Benchmarks
cargo bench
```

### Writing Good Tests
```rust
// CLAUDE-note-testing: Test pattern
#[test]
fn test_threat_detection() {
    // Arrange
    let scanner = UnicodeScanner::new();
    let malicious_input = "evil\u{202E}good";  // Right-to-left override
    
    // Act
    let result = scanner.scan(malicious_input).unwrap();
    
    // Assert
    assert!(result.has_threats());
    assert_eq!(result.threats[0].type, ThreatType::BidiOverride);
}
```

## Performance Considerations

### Optimization Strategies
1. **Zero-copy parsing** where possible
2. **Parallel scanning** for independent threats
3. **Caching** for repeated inputs
4. **SIMD** for pattern matching (when available)

### Profiling
```bash
# CPU profiling
cargo build --release
perf record --call-graph=dwarf target/release/kindly-guard-server
perf report

# Memory profiling
valgrind --tool=massif target/release/kindly-guard-server
```

## Contributing Guidelines

### Code Style
- Run `cargo fmt` before committing
- Run `cargo clippy -- -D warnings` to catch issues
- Follow Rust naming conventions

### Commit Messages
```
feat(scanner): Add PDF malware detection
fix(protocol): Handle empty input gracefully
docs(primer): Update quick start guide
perf(cache): Optimize LRU implementation
```

### Pull Request Process
1. Create feature branch from `main`
2. Write tests for new functionality
3. Update documentation
4. Ensure CI passes
5. Request review

## Troubleshooting

### Common Issues

**Build fails with "cannot find crate"**
```bash
cargo update
cargo clean
cargo build
```

**Tests fail randomly**
- Check for timing-dependent tests
- Ensure proper async handling
- Verify test isolation

**Performance regression**
```bash
# Compare benchmarks
cargo bench -- --save-baseline main
# Make changes
cargo bench -- --baseline main
```

## Resources

### Internal Documentation
- `ARCHITECTURE.md` - System design details
- `RUST_GUIDE.md` - Rust-specific patterns
- `FEATURES.md` - Complete feature inventory
- `CLAUDE.md` - AI assistant integration guide

### External Resources
- [MCP Specification](https://modelcontextprotocol.io)
- [Rust Book](https://doc.rust-lang.org/book/)
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [Security Best Practices](https://cheatsheetseries.owasp.org/)

## Getting Help

### Where to Ask Questions
1. Check existing documentation
2. Search closed issues
3. Ask in discussions
4. Create an issue with reproduction steps

### Debugging Checklist
- [ ] Enabled trace logging?
- [ ] Checked error messages?
- [ ] Reproduced in isolation?
- [ ] Verified configuration?
- [ ] Tested with minimal example?

## Next Steps

1. **Run the examples** in `examples/` directory
2. **Read a scanner implementation** like `src/scanner/unicode.rs`
3. **Try the CLI** with various inputs
4. **Experiment with configuration** options
5. **Write a simple test** to understand the testing approach

Welcome to the team! Remember: Security First, Performance Second, Features Third. 🛡️🚀