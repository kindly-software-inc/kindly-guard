# KindlyGuard Parallel CI/CD System

A massively parallel CI/CD system that maximizes hardware utilization by running all tests, builds, and security scans simultaneously across multiple OS targets.

## 🚀 Quick Start

```bash
# Run smoke tests only (fastest)
cargo xtask parallel-ci --smoke-tests

# Run full CI with dashboard
cargo xtask parallel-ci --dashboard

# Run specific pipelines
cargo xtask parallel-ci --security-scan --benchmark

# Target specific platforms
cargo xtask parallel-ci --targets linux-x64,macos,windows
```

## 📊 Performance Benefits

- **Sequential CI**: ~10-15 minutes
- **Parallel CI**: ~2-3 minutes (5x faster!)
- **Hardware Utilization**: 80-95% CPU usage
- **Test Execution**: 3x faster with nextest

## 🏗️ Architecture

### Parallel Pipelines

The system runs 6 pipelines concurrently:

1. **Format/Lint** (Priority: 100)
   - rustfmt check
   - clippy analysis
   - cargo-deny policy

2. **Build** (Priority: 90)
   - Cross-compilation for all targets
   - Release mode optimization
   - Binary artifact generation

3. **Test** (Priority: 80)
   - Unit tests (cargo-nextest)
   - Integration tests
   - Doc tests
   - Property tests
   - Coverage generation

4. **Security** (Priority: 70)
   - cargo-audit vulnerability scan
   - cargo-deny license check
   - cargo-geiger unsafe code detection
   - SARIF report generation

5. **Benchmark** (Priority: 50)
   - Performance benchmarks
   - Regression detection
   - Baseline comparison

6. **Package** (Priority: 40)
   - Binary packaging
   - NPM package creation
   - Checksum generation

### Resource Management

- **CPU Allocation**: Dynamic based on available cores
- **Memory Limits**: Per-pipeline restrictions
- **I/O Scheduling**: Prevents disk bottlenecks
- **Semaphore Control**: Limits concurrent tasks

### Caching Strategy

- **sccache**: Compilation caching (50-70% faster)
- **nextest archives**: Build once, test everywhere
- **Dependency caching**: Pre-fetched in parallel
- **Test result caching**: Skip unchanged tests

## 🛠️ Configuration

### Config File: `.ci/parallel/config.toml`

```toml
[parallel_ci]
max_parallel_builds = 4
max_parallel_tests = 8
enable_dashboard = true
fail_fast = false

[targets]
linux = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
macos = ["x86_64-apple-darwin", "aarch64-apple-darwin"]
windows = ["x86_64-pc-windows-msvc"]

[cache]
backend = "sccache"
[cache.sccache]
storage = "local"
max_size = "10GB"
```

## 💻 Local Usage

### Prerequisites

```bash
# Install recommended tools
cargo install cargo-nextest    # 3x faster tests
cargo install sccache          # Build caching
cargo install cross            # Cross-compilation
cargo install cargo-audit      # Security scanning
cargo install cargo-deny       # Policy enforcement
```

### Running Locally

```bash
# Full parallel CI with all features
cargo xtask parallel-ci \
  --dashboard \
  --config .ci/parallel/config.toml

# Quick validation
cargo xtask parallel-ci --smoke-tests

# Security-focused run
cargo xtask parallel-ci --security-scan --full-suite

# Multi-platform build
cargo xtask parallel-ci --targets linux-x64,linux-arm64,macos,windows
```

### Dashboard View

The real-time TUI dashboard shows:
- Pipeline progress bars
- CPU/Memory usage
- Test results as they complete
- Build status per target
- Security findings
- Error logs

## 🔧 GitHub Actions Integration

The parallel CI is configured to run automatically on:
- Version tags (`v*.*.*`)
- Pull requests
- Manual workflow dispatch

### Matrix Strategy

```yaml
strategy:
  matrix:
    include:
      - os: ubuntu-latest
        target: x86_64-unknown-linux-gnu
      - os: macos-latest
        target: aarch64-apple-darwin
      - os: windows-latest
        target: x86_64-pc-windows-msvc
```

## 📈 Monitoring & Reporting

### Generated Reports

- `.ci/reports/coverage_*.lcov` - Test coverage
- `.ci/reports/security_*.sarif` - Security findings
- `.ci/reports/cargo-audit.json` - Vulnerability report
- `.ci/logs/ci_run_*.log` - Execution logs
- `.ci/artifacts/*` - Built binaries

### Metrics Collected

- Pipeline execution times
- Resource utilization
- Test pass/fail rates
- Build artifact sizes
- Security issue counts

## 🎯 Smoke Tests

Quick validation tests that run in <30 seconds:

1. **Binary Execution**: `--version`, `--help`
2. **Server Startup**: MCP server initialization
3. **Basic Scan**: Simple security scan
4. **Config Validation**: Configuration parsing

## 🔒 Security Integration

### SARIF Output

Security findings are exported in SARIF format for:
- GitHub Security tab integration
- IDE security plugins
- Third-party analysis tools

### Vulnerability Management

- Critical vulnerabilities fail the build
- Non-critical issues are warnings
- Policy violations tracked separately
- Unsafe code usage reported

## 🚦 Error Handling

- **Fail-Fast Mode**: Stop on first critical error
- **Independent Pipelines**: One failure doesn't block others
- **Retry Logic**: Automatic retry for flaky operations
- **Consolidated Reporting**: All errors in one summary

## ⚡ Performance Tips

1. **Enable sccache**: 50-70% faster builds
2. **Use nextest**: 3x faster test execution
3. **Limit targets**: Build only needed platforms
4. **Smoke tests first**: Quick validation before full suite
5. **Parallel-safe tests**: Ensure tests don't interfere

## 🐛 Troubleshooting

### Common Issues

**"Too many open files"**
```bash
ulimit -n 4096  # Increase file descriptor limit
```

**"Out of memory"**
```toml
# Reduce parallelism in config.toml
max_parallel_builds = 2
max_parallel_tests = 4
```

**"Cross-compilation fails"**
```bash
# Install cross tool
cargo install cross --git https://github.com/cross-rs/cross
```

## 📚 Advanced Usage

### Custom Pipelines

Add new pipelines by implementing the `Pipeline` trait:

```rust
#[async_trait]
impl Pipeline for MyPipeline {
    fn name(&self) -> &str { "My Pipeline" }
    fn priority(&self) -> u32 { 60 }
    
    async fn execute(&self, ctx: Arc<Context>, ...) -> Result<String> {
        // Your parallel logic here
    }
}
```

### Resource Limits

```rust
// In coordinator.rs
let semaphore = Arc::new(Semaphore::new(num_cpus::get() / 2));
```

## 🎉 Summary

The parallel CI system transforms a 10+ minute sequential process into a 2-minute parallel execution, fully utilizing modern multi-core hardware while maintaining compatibility with GitHub Actions for release builds.