# KindlyGuard Developer Guide 🛡️

Welcome to the KindlyGuard Developer Guide! This comprehensive guide covers everything you need to know to develop, test, and contribute to KindlyGuard.

## Table of Contents

1. [Setting Up the Development Environment](#setting-up-the-development-environment)
2. [Building from Source](#building-from-source)
3. [Project Structure](#project-structure)
4. [Running Tests and Benchmarks](#running-tests-and-benchmarks)
5. [Contributing Guidelines](#contributing-guidelines)
6. [Code Style and Conventions](#code-style-and-conventions)
7. [Adding New Scanners](#adding-new-scanners)
8. [Extending the Wrap Command](#extending-the-wrap-command)
9. [Debugging Tips](#debugging-tips)
10. [Release Process](#release-process)

## Setting Up the Development Environment

### Prerequisites

1. **Rust Toolchain** (MSRV: 1.81)
   ```bash
   # Install Rust
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   
   # Install specific version (our MSRV)
   rustup install 1.81
   rustup default 1.81
   
   # Add required components
   rustup component add rustfmt clippy rust-analyzer
   ```

2. **System Dependencies**
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install build-essential pkg-config libssl-dev libsqlite3-dev
   
   # macOS
   brew install sqlite3
   
   # Windows
   # Install Visual Studio Build Tools or Visual Studio Community
   # SQLite is included with Rust on Windows
   ```

3. **Development Tools**
   ```bash
   # Install essential development tools
   ./scripts/install-dev-tools.sh
   
   # Or install manually:
   cargo install cargo-nextest    # Better test runner
   cargo install cargo-deny       # Security auditing
   cargo install cargo-audit      # CVE scanner
   cargo install bacon           # Background compiler
   cargo install cargo-watch     # File watcher
   cargo install cargo-machete   # Unused dependency detector
   cargo install typos-cli       # Spell checker
   cargo install committed       # Commit message linter
   cargo install cargo-expand    # Macro expansion viewer
   cargo install cargo-udeps     # Unused dependency checker (requires nightly)
   cargo install grcov          # Code coverage
   
   # For nightly-only tools
   rustup toolchain install nightly
   ```

4. **Pre-commit Hooks**
   ```bash
   # Install pre-commit hooks for security shift-left
   ./scripts/install-hooks.sh
   
   # Or manually:
   pip install --user pre-commit
   pre-commit install --install-hooks
   pre-commit install --hook-type commit-msg
   ```

### Editor Setup

#### VS Code
```json
{
  "rust-analyzer.cargo.features": "all",
  "rust-analyzer.checkOnSave.command": "clippy",
  "rust-analyzer.checkOnSave.extraArgs": ["--all-targets", "--all-features"],
  "editor.formatOnSave": true,
  "[rust]": {
    "editor.defaultFormatter": "rust-lang.rust-analyzer"
  }
}
```

#### Neovim/Vim
```vim
" Install rust.vim and configure LSP with rust-analyzer
Plug 'rust-lang/rust.vim'
Plug 'neovim/nvim-lspconfig'

" Format on save
let g:rustfmt_autosave = 1
```

## Building from Source

### Quick Build
```bash
# Clone the repository
git clone https://github.com/kindly-software-inc/kindly-guard.git
cd kindly-guard

# Standard debug build
cargo build

# Release build with optimizations
cargo build --release

# Security-hardened build (recommended for production)
cargo build --profile=secure

# Build all workspace members
cargo build --workspace --all-features
```

### Binary Structure

KindlyGuard uses a modular binary structure:

1. **kindly-tools** - Main CLI binary with all functionality
   ```bash
   cargo build -p kindly-tools --release
   # Binary at: target/release/kindly-tools
   ```

2. **kindlyguard** - Standalone scanner for crates.io distribution
   ```bash
   cargo build -p kindlyguard --release
   # Binary at: target/release/kindlyguard
   ```

3. **kindly-guard-server** - MCP server (built as part of kindly-tools)
4. **kindly-guard-shield** - Desktop UI (Tauri app)
   ```bash
   cd kindly-guard-shield
   npm install
   npm run tauri build
   ```

### Build Profiles

```toml
# Development (default)
cargo build

# Release with full optimizations
cargo build --release

# Security-hardened build
cargo build --profile=secure

# Benchmarking build
cargo build --profile=bench

# Distribution build (for releases)
cargo build --profile=dist
```

### Cross-Compilation

```bash
# Install cross-compilation tools
./scripts/install_cross_tools.sh

# Build for specific targets
cargo build --target x86_64-unknown-linux-musl
cargo build --target aarch64-apple-darwin
cargo build --target x86_64-pc-windows-msvc
```

## Project Structure

```
kindly-guard/
├── kindly-guard-server/     # Core MCP server implementation
│   ├── src/
│   │   ├── scanner/        # Threat detection modules
│   │   │   ├── mod.rs     # Scanner trait and factory
│   │   │   ├── unicode.rs # Unicode threat detection
│   │   │   ├── injection.rs # Injection prevention
│   │   │   ├── xss.rs    # XSS protection
│   │   │   ├── patterns.rs # Pattern matching
│   │   │   └── crypto.rs  # Crypto weakness detection
│   │   ├── protocol/      # MCP protocol handling
│   │   ├── storage/       # Persistence layer
│   │   ├── resilience/    # Circuit breakers, retry logic
│   │   ├── neutralizer/   # Threat neutralization
│   │   └── config/        # Configuration management
│   └── tests/            # Integration tests
├── kindly-tools/         # Main CLI with all commands
│   ├── src/
│   │   ├── commands/     # CLI command implementations
│   │   │   ├── scan.rs   # File/directory scanning
│   │   │   ├── wrap.rs   # AI CLI wrapping
│   │   │   ├── shield.rs # Security shield commands
│   │   │   └── monitor.rs # Real-time monitoring
│   │   └── main.rs       # CLI entry point
├── crates-io-package/    # Standalone scanner for crates.io
│   └── kindlyguard/
├── kindly-guard-shield/  # Desktop UI (Tauri)
├── docs/                # Documentation
├── scripts/             # Development scripts
└── tests/              # Cross-crate integration tests
```

## Running Tests and Benchmarks

### Test Commands

```bash
# Run all tests with better output (recommended)
cargo nextest run

# Run tests for specific package
cargo nextest run -p kindly-guard-server

# Run specific test
cargo nextest run test_unicode_detection

# Run with all features enabled
cargo nextest run --all-features

# Run only failed tests from last run
cargo nextest run --failed

# Run tests with output captured
cargo nextest run --no-capture

# Traditional cargo test (if needed)
cargo test

# Run property-based tests (fuzzing)
cargo test --test property_tests

# Run doc tests
cargo test --doc
```

### Test Categories

1. **Unit Tests** - Fast, isolated tests
   ```bash
   cargo nextest run --lib
   ```

2. **Integration Tests** - End-to-end testing
   ```bash
   cargo nextest run --test '*'
   ```

3. **Security Tests** - Threat detection validation
   ```bash
   cargo nextest run security_
   ```

4. **Property Tests** - Fuzzing with proptest
   ```bash
   cargo test --features proptest
   ```

### Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench scanner

# Run with saving baseline
cargo bench -- --save-baseline main

# Compare with baseline
cargo bench -- --baseline main

# Generate HTML reports
cargo bench -- --output-format html
```

### Code Coverage

```bash
# Install grcov
cargo install grcov

# Generate coverage data
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="cargo-test-%p-%m.profraw"

cargo build
cargo test

# Generate HTML report
grcov . --binary-path ./target/debug/deps/ \
    -s . -t html -o target/coverage/ \
    --ignore-not-existing
```

## Contributing Guidelines

### Workflow

1. **Fork and Clone**
   ```bash
   # Fork on GitHub, then:
   git clone https://github.com/YOUR_USERNAME/kindly-guard.git
   cd kindly-guard
   git remote add upstream https://github.com/kindly-software-inc/kindly-guard.git
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

3. **Development Loop**
   ```bash
   # Start bacon for instant feedback
   bacon
   
   # In another terminal, make changes and run:
   cargo fmt                          # Format code
   cargo clippy --all-features       # Lint
   cargo nextest run                 # Test
   ```

4. **Pre-Commit Checklist**
   ```bash
   # Format code
   cargo fmt
   
   # Fix lints
   cargo clippy --fix --all-targets --all-features
   
   # Check for typos
   typos --write-changes
   
   # Run tests
   cargo nextest run --all-features
   
   # Security checks
   cargo deny check
   cargo audit
   
   # Check commit message
   committed --staged
   ```

5. **Submit PR**
   - Use conventional commit format
   - Include tests for new features
   - Update documentation
   - Ensure CI passes

### Commit Message Format

```
type(scope): subject

[optional body]

[optional footer]
```

Examples:
```bash
# Security fix
git commit -m "security: prevent timing attack in auth validation"

# Feature
git commit -m "feat(scanner): add OWASP Top 10 pattern detection"

# Performance
git commit -m "perf(unicode): implement SIMD acceleration for 8x speedup"

# Breaking change
git commit -m "feat(api)!: change threat response format to array"
```

## Code Style and Conventions

### Core Principles (from CLAUDE.md)

1. **Security First, Performance Second, Features Third**
2. **Always use `Result<T, E>` for fallible operations**
3. **Never use `unwrap()` or `expect()` in production code**
4. **Validate ALL external input**
5. **Document safety invariants for any unsafe blocks**

### Error Handling

```rust
// ✅ GOOD - Explicit error handling
match dangerous_operation() {
    Ok(value) => process(value),
    Err(e) => {
        tracing::error!("Operation failed: {}", e);
        return Err(KindlyError::from(e));
    }
}

// ❌ BAD - Never use unwrap
let value = dangerous_operation().unwrap(); // FORBIDDEN
```

### Type Safety

```rust
// ✅ GOOD - Type-safe threat modeling
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatType {
    UnicodeInvisible { position: usize },
    InjectionAttempt { pattern: String },
}

// ❌ BAD - String-based decisions
if threat_type == "unicode" { /* ... */ }
```

### Performance Guidelines

```rust
// ✅ GOOD - Zero-copy operations
fn scan_text(&self, text: &str) -> Vec<Threat>

// ❌ BAD - Unnecessary allocation
fn scan_text(&self, text: String) -> Vec<Threat>
```

### Import Organization

```rust
// Standard library
use std::{
    sync::Arc,
    time::Duration,
};

// External crates
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

// Internal modules
use crate::{
    scanner::{SecurityScanner, Threat},
    shield::ShieldDisplay,
};
```

## Adding New Scanners

### Step 1: Create Scanner Module

Create a new file in `kindly-guard-server/src/scanner/`:

```rust
// src/scanner/my_scanner.rs
use crate::{Threat, ThreatType, Severity};
use anyhow::Result;

/// Scanner for detecting my specific threat type
pub struct MyScanner {
    config: MyConfig,
}

impl MyScanner {
    pub fn new(config: MyConfig) -> Self {
        Self { config }
    }
    
    pub fn scan(&self, text: &str) -> Result<Vec<Threat>> {
        let mut threats = Vec::new();
        
        // Implement detection logic
        if self.detect_threat(text) {
            threats.push(Threat {
                threat_type: ThreatType::Custom(CustomThreat::MyThreat),
                severity: Severity::High,
                message: "Detected my threat type".to_string(),
                location: Some(0..10),
                confidence: 0.95,
            });
        }
        
        Ok(threats)
    }
    
    fn detect_threat(&self, text: &str) -> bool {
        // Implementation
        false
    }
}
```

### Step 2: Add to Scanner Module

Update `src/scanner/mod.rs`:

```rust
mod my_scanner;
pub use my_scanner::MyScanner;

// In the SecurityScanner implementation
impl SecurityScanner {
    pub fn scan_text(&self, text: &str) -> Result<Vec<Threat>> {
        let mut all_threats = Vec::new();
        
        // Add your scanner
        if self.config.my_detection {
            let scanner = MyScanner::new(self.config.my_config.clone());
            all_threats.extend(scanner.scan(text)?);
        }
        
        // ... other scanners
        
        Ok(all_threats)
    }
}
```

### Step 3: Add Configuration

Update `src/config/scanner.rs`:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct ScannerConfig {
    // ... existing fields
    
    /// Enable my custom detection
    #[serde(default = "default_true")]
    pub my_detection: bool,
    
    /// Configuration for my scanner
    #[serde(default)]
    pub my_config: MyConfig,
}
```

### Step 4: Add Tests

Create tests in the same file or in `tests/`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_my_threat_detection() {
        let scanner = MyScanner::new(MyConfig::default());
        let threats = scanner.scan("malicious input").unwrap();
        assert!(!threats.is_empty());
    }
    
    #[test]
    fn test_safe_input() {
        let scanner = MyScanner::new(MyConfig::default());
        let threats = scanner.scan("safe input").unwrap();
        assert!(threats.is_empty());
    }
}
```

### Step 5: Add Benchmarks

Create `benches/my_scanner.rs`:

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kindly_guard_server::scanner::MyScanner;

fn benchmark_my_scanner(c: &mut Criterion) {
    let scanner = MyScanner::new(Default::default());
    let input = "test input for benchmarking";
    
    c.bench_function("my_scanner", |b| {
        b.iter(|| scanner.scan(black_box(input)))
    });
}

criterion_group!(benches, benchmark_my_scanner);
criterion_main!(benches);
```

## Extending the Wrap Command

The wrap command protects AI CLI tools by intercepting and scanning input. Here's how to extend it:

### Adding New CLI Support

1. **Update Supported Commands** in `kindly-tools/src/config/wrap.rs`:

```rust
impl WrapConfig {
    pub fn default_commands() -> HashSet<String> {
        let mut commands = HashSet::new();
        // Existing commands
        commands.insert("aichat".to_string());
        commands.insert("mods".to_string());
        
        // Add your CLI
        commands.insert("mycli".to_string());
        commands
    }
}
```

2. **Add CLI-Specific Handling** if needed in `kindly-tools/src/commands/wrap.rs`:

```rust
// In wrap_command function
match cmd_name {
    "mycli" => {
        // Special handling for mycli
        // e.g., different scanning rules, output formatting
    }
    _ => {
        // Default handling
    }
}
```

### Adding New Protection Features

1. **Extend Threat Detection**:

```rust
// In wrap_command, after scanning
let threats = scanner.scan_text(&stdin_buf)?;

// Add custom threat analysis
if is_mycli_specific_threat(&stdin_buf) {
    threats.push(Threat {
        threat_type: ThreatType::Custom("MyCLI-Specific"),
        severity: Severity::High,
        // ...
    });
}
```

2. **Add Response Scanning** (for bidirectional protection):

```rust
// Spawn thread to scan stdout
let scanner_clone = scanner.clone();
let stdout_handle = tokio::spawn(async move {
    let reader = BufReader::new(stdout);
    for line in reader.lines() {
        match line {
            Ok(content) => {
                // Scan output for sensitive data leakage
                let output_threats = scanner_clone.scan_text(&content)?;
                if !output_threats.is_empty() {
                    eprintln!("⚠️ Sensitive data in output!");
                }
                println!("{}", content);
            }
            Err(e) => eprintln!("Error reading stdout: {}", e),
        }
    }
});
```

3. **Add Session Logging**:

```rust
// If logging is enabled
if config.log_sessions {
    let session_id = Uuid::new_v4();
    let log_path = config.log_directory.join(format!("{}.log", session_id));
    let mut log_file = File::create(&log_path)?;
    
    // Log all interactions
    writeln!(log_file, "[{}] Input: {}", timestamp, stdin_buf)?;
    writeln!(log_file, "[{}] Threats: {:?}", timestamp, threats)?;
}
```

### Testing Wrap Extensions

```rust
#[tokio::test]
async fn test_wrap_mycli() {
    let config = WrapConfig {
        commands: vec!["mycli".to_string()].into_iter().collect(),
        mode: WrapMode::Warning,
        ..Default::default()
    };
    
    // Test wrapping behavior
    let result = wrap_command_with_config(
        vec!["mycli".to_string(), "arg".to_string()],
        Some(config)
    ).await;
    
    assert!(result.is_ok());
}
```

## Debugging Tips

### Debug Logging

```bash
# Enable debug logging for specific modules
RUST_LOG=kindly_guard=debug cargo run

# More granular logging
RUST_LOG=kindly_guard::scanner=trace,kindly_guard::protocol=debug cargo run

# All debug output
RUST_LOG=debug cargo run

# With timestamps and module paths
RUST_LOG=debug RUST_LOG_STYLE=always cargo run
```

### Common Issues and Solutions

1. **Scanner Not Detecting Threats**
   ```bash
   # Check scanner configuration
   RUST_LOG=kindly_guard::scanner=trace cargo run
   
   # Verify patterns are loaded
   cat ~/.config/kindly-guard/patterns.toml
   ```

2. **Performance Issues**
   ```bash
   # Profile the application
   cargo flamegraph
   
   # Run with release mode
   cargo run --release
   
   # Check for blocking operations
   RUST_LOG=tokio=trace cargo run
   ```

3. **MCP Protocol Issues**
   ```bash
   # Enable protocol logging
   RUST_LOG=kindly_guard::protocol=trace cargo run
   
   # Test with MCP client
   echo '{"method": "scan", "params": {"text": "test"}}' | cargo run -- --stdio
   ```

### Using `cargo expand`

```bash
# Expand macros to see generated code
cargo expand -p kindly-guard-server scanner::unicode

# Expand specific item
cargo expand -p kindly-guard-server 'scanner::unicode::scan_text'
```

### Memory Profiling

```bash
# Install heaptrack
sudo apt-get install heaptrack  # Ubuntu/Debian

# Profile memory usage
heaptrack cargo run
heaptrack_gui heaptrack.cargo.12345.gz
```

### Thread Debugging

```bash
# Check for deadlocks
RUST_LOG=tokio=trace cargo run

# Monitor thread panics
RUST_BACKTRACE=full cargo run
```

## Release Process

### Version Bumping

```bash
# Update version in Cargo.toml files
# The version is synchronized across workspace members

# For workspace-wide version update:
sed -i 's/version = "0.11.0"/version = "0.12.0"/g' \
  kindly-guard-server/Cargo.toml \
  kindly-tools/Cargo.toml \
  crates-io-package/kindlyguard/Cargo.toml
```

### Pre-Release Checklist

```bash
# 1. Run all tests
cargo nextest run --all-features

# 2. Check for security issues
cargo deny check
cargo audit
cargo +nightly udeps

# 3. Update documentation
cargo doc --no-deps --all-features

# 4. Run benchmarks for regression
cargo bench -- --baseline main

# 5. Build all targets
cargo build --workspace --all-features --release

# 6. Test installers locally
cargo dist build --tag v0.12.0
```

### Creating a Release

```bash
# 1. Create and push tag
git tag -a v0.12.0 -m "Release v0.12.0"
git push origin v0.12.0

# 2. GitHub Actions will automatically:
#    - Build binaries for all platforms
#    - Create installers (MSI, PKG, DEB, RPM)
#    - Generate checksums
#    - Create GitHub release
#    - Publish to crates.io
#    - Update Homebrew tap

# 3. Manual verification
# Download and test installers from GitHub release
```

### Post-Release

1. **Update Changelog**
   ```bash
   git cliff --tag v0.12.0 -o CHANGELOG.md
   ```

2. **Announce Release**
   - GitHub Discussions
   - Security mailing list
   - Social media

3. **Monitor Issues**
   - Check for installation problems
   - Monitor performance regression reports
   - Address security concerns immediately

## Additional Resources

### Documentation
- [ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) - System design
- [SECURITY.md](SECURITY.md) - Security policies
- [API_DOCUMENTATION.md](docs/API_DOCUMENTATION.md) - API reference
- [DEVELOPMENT_WORKFLOW.md](docs/DEVELOPMENT_WORKFLOW.md) - Tool details

### Examples
- `examples/` - Usage examples
- `tests/integration/` - Integration test examples
- `benches/` - Performance benchmark examples

### Community
- [GitHub Discussions](https://github.com/kindly-software-inc/kindly-guard/discussions)
- [Issue Tracker](https://github.com/kindly-software-inc/kindly-guard/issues)
- Email: security@kindly.software

---

Remember: **Security First, Performance Second, Features Third** 🛡️