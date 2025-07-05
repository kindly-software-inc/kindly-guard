# xtask Usage Examples

This guide provides practical examples of using the KindlyGuard xtask system for various development and deployment workflows.

## Table of Contents

1. [Basic Command Usage](#basic-command-usage)
2. [Dry-Run Mode Examples](#dry-run-mode-examples)
3. [Verbose Output Examples](#verbose-output-examples)
4. [Release Workflow Walkthrough](#release-workflow-walkthrough)
5. [Local CI Testing](#local-ci-testing)
6. [Cross-Compilation Examples](#cross-compilation-examples)
7. [Docker Multi-Platform Builds](#docker-multi-platform-builds)
8. [NPM Publishing Workflow](#npm-publishing-workflow)
9. [Security Audit Workflow](#security-audit-workflow)
10. [Debugging Failed Builds](#debugging-failed-builds)

## Basic Command Usage

### Running a simple build

```bash
# Build the project with default settings
$ cargo xtask build

[xtask] Starting build...
[xtask] Building kindly-guard-server...
   Compiling kindly-guard-server v0.1.0
    Finished dev [unoptimized + debuginfo] target(s) in 45.23s
[xtask] Build completed successfully
```

### Running tests

```bash
# Run all tests
$ cargo xtask test

[xtask] Running tests...
[xtask] Testing kindly-guard-server...
   Compiling kindly-guard-server v0.1.0
    Finished test [unoptimized + debuginfo] target(s) in 12.45s
     Running unittests src/main.rs (target/debug/deps/kindly_guard_server-abc123)

running 42 tests
test scanner::tests::test_unicode_detection ... ok
test scanner::tests::test_injection_prevention ... ok
...
test result: ok. 42 passed; 0 failed; 0 ignored; 0 measured

[xtask] All tests passed!
```

### Running with specific features

```bash
# Build with specific features enabled
$ cargo xtask build --features enhanced-scanner,sqlite-storage

[xtask] Building with features: enhanced-scanner, sqlite-storage
[xtask] Building kindly-guard-server...
   Compiling kindly-guard-server v0.1.0
    Finished dev [unoptimized + debuginfo] target(s) in 52.11s
[xtask] Build completed with enhanced-scanner, sqlite-storage
```

## Dry-Run Mode Examples

### Preview release process

```bash
# See what would happen during a release without actually doing it
$ cargo xtask release --version 0.2.0 --dry-run

[xtask] DRY RUN: Release v0.2.0
[xtask] Would perform the following actions:
  1. Update version in Cargo.toml files:
     - kindly-guard-server/Cargo.toml: 0.1.0 → 0.2.0
     - kindly-guard-cli/Cargo.toml: 0.1.0 → 0.2.0
     - kindly-guard-shield/Cargo.toml: 0.1.0 → 0.2.0
  2. Update CHANGELOG.md with release notes
  3. Create git commit: "chore: release v0.2.0"
  4. Create git tag: v0.2.0
  5. Build release artifacts for:
     - linux-x64
     - linux-arm64
     - macos-x64
     - macos-arm64
     - windows-x64
  6. Create GitHub release with artifacts
[xtask] DRY RUN complete - no changes made
```

### Preview cross-compilation

```bash
# Check what would be built for cross-compilation
$ cargo xtask cross-build --target aarch64-unknown-linux-gnu --dry-run

[xtask] DRY RUN: Cross-compilation for aarch64-unknown-linux-gnu
[xtask] Would perform:
  1. Check for cross toolchain: aarch64-linux-gnu-gcc
  2. Set environment variables:
     - CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
     - AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
  3. Run: cargo build --target aarch64-unknown-linux-gnu --release
  4. Strip binary: aarch64-linux-gnu-strip target/aarch64-unknown-linux-gnu/release/kindly-guard
  5. Package binary to: dist/kindly-guard-linux-arm64.tar.gz
[xtask] DRY RUN complete
```

## Verbose Output Examples

### Detailed build information

```bash
# Get detailed output during build
$ cargo xtask build --verbose

[xtask] Starting build with verbose output...
[xtask] Environment:
  - Rust version: 1.75.0
  - Target: x86_64-unknown-linux-gnu
  - Profile: dev
  - Features: default
[xtask] Running: cargo build --verbose
   Compiling unicode-security v0.1.0
     Running `rustc --crate-name unicode_security --edition=2021 ...`
   Compiling regex v1.11.0
     Running `rustc --crate-name regex --edition=2021 ...`
   Compiling kindly-guard-server v0.1.0
     Running `rustc --crate-name kindly_guard_server src/main.rs ...`
[xtask] Build artifacts:
  - Binary: target/debug/kindly-guard-server (15.2 MB)
  - Build time: 45.23s
  - Dependencies compiled: 127
[xtask] Build completed successfully
```

### Verbose test output with timing

```bash
# Run tests with detailed timing information
$ cargo xtask test --verbose --show-output

[xtask] Running tests with verbose output...
[xtask] Test environment:
  - RUST_TEST_THREADS: 4
  - RUST_BACKTRACE: 1
[xtask] Running: cargo test --verbose -- --show-output --nocapture

test scanner::tests::test_unicode_detection ... 
[TEST OUTPUT] Scanning text: "Hello\u{202E}World"
[TEST OUTPUT] Found threat: UnicodeBiDi at position 5
ok (12ms)

test scanner::tests::test_injection_prevention ... 
[TEST OUTPUT] Testing SQL injection: "'; DROP TABLE users; --"
[TEST OUTPUT] Detected SQL injection pattern
ok (8ms)

test resilience::tests::test_circuit_breaker ... 
[TEST OUTPUT] Circuit breaker test:
[TEST OUTPUT]   - Initial state: Closed
[TEST OUTPUT]   - After 3 failures: Open
[TEST OUTPUT]   - After timeout: HalfOpen
ok (152ms)

[xtask] Test summary:
  - Total tests: 42
  - Passed: 42
  - Failed: 0
  - Total time: 2.45s
  - Slowest test: resilience::tests::test_circuit_breaker (152ms)
```

## Release Workflow Walkthrough

### Complete release process

```bash
# Step 1: Prepare release
$ cargo xtask release prepare --version 0.2.0

[xtask] Preparing release v0.2.0...
[xtask] Running pre-release checks:
  ✓ Git working directory clean
  ✓ On main branch
  ✓ All tests passing
  ✓ No security vulnerabilities (cargo audit)
  ✓ Code formatted (cargo fmt)
  ✓ No clippy warnings
[xtask] Generating changelog...
  - Added 15 commits since v0.1.0
  - 5 features, 8 fixes, 2 performance improvements
[xtask] Release preparation complete

# Step 2: Create release
$ cargo xtask release create --version 0.2.0

[xtask] Creating release v0.2.0...
[xtask] Updating versions...
  ✓ Updated kindly-guard-server to 0.2.0
  ✓ Updated kindly-guard-cli to 0.2.0
  ✓ Updated kindly-guard-shield to 0.2.0
[xtask] Updating CHANGELOG.md...
[xtask] Creating git commit...
  ✓ Committed: "chore: release v0.2.0"
[xtask] Creating git tag...
  ✓ Tagged: v0.2.0
[xtask] Building release artifacts...
  ✓ linux-x64: kindly-guard-linux-x64.tar.gz (12.3 MB)
  ✓ linux-arm64: kindly-guard-linux-arm64.tar.gz (11.8 MB)
  ✓ macos-x64: kindly-guard-macos-x64.tar.gz (13.1 MB)
  ✓ macos-arm64: kindly-guard-macos-arm64.tar.gz (12.7 MB)
  ✓ windows-x64: kindly-guard-windows-x64.zip (14.2 MB)
[xtask] Release created successfully!

# Step 3: Publish release
$ cargo xtask release publish

[xtask] Publishing release v0.2.0...
[xtask] Pushing to git...
  ✓ Pushed commits to origin/main
  ✓ Pushed tag v0.2.0
[xtask] Creating GitHub release...
  ✓ Created release: https://github.com/yourusername/kindly-guard/releases/tag/v0.2.0
  ✓ Uploaded 5 release artifacts
[xtask] Publishing to crates.io...
  ✓ Published kindly-guard-server v0.2.0
  ✓ Published kindly-guard-cli v0.2.0
[xtask] Release published successfully!
```

## Local CI Testing

### Run full CI pipeline locally

```bash
# Simulate GitHub Actions CI locally
$ cargo xtask ci

[xtask] Running local CI pipeline...
[xtask] Step 1/6: Checking formatting...
  ✓ All files formatted correctly
[xtask] Step 2/6: Running clippy...
  ✓ No warnings found
[xtask] Step 3/6: Running tests...
  ✓ All 42 tests passed
[xtask] Step 4/6: Running security audit...
  ✓ No vulnerabilities found
[xtask] Step 5/6: Building all targets...
  ✓ Debug build successful
  ✓ Release build successful
[xtask] Step 6/6: Running integration tests...
  ✓ MCP protocol tests passed
  ✓ Scanner integration tests passed
[xtask] CI pipeline completed successfully! (3m 42s)
```

### Run specific CI checks

```bash
# Run only security-related CI checks
$ cargo xtask ci --only security

[xtask] Running security CI checks...
[xtask] Running cargo audit...
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
    Scanning Cargo.lock for vulnerabilities (127 crate dependencies)
[xtask] Running dependency license check...
  ✓ All dependencies have compatible licenses
[xtask] Running SAST scan...
  ✓ No security issues found in code
[xtask] Checking for secrets...
  ✓ No secrets or API keys found
[xtask] Security checks passed!
```

## Cross-Compilation Examples

### Build for ARM64 Linux

```bash
# Cross-compile for ARM64 Linux (e.g., Raspberry Pi)
$ cargo xtask cross-build --target aarch64-unknown-linux-gnu

[xtask] Cross-compiling for aarch64-unknown-linux-gnu...
[xtask] Checking prerequisites...
  ✓ Cross toolchain found: aarch64-linux-gnu-gcc
  ✓ Rust target installed: aarch64-unknown-linux-gnu
[xtask] Setting up environment...
  CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
  AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
[xtask] Building...
   Compiling kindly-guard-server v0.2.0
    Finished release [optimized] target(s) in 2m 15s
[xtask] Stripping binary...
  ✓ Reduced size: 45.2 MB → 12.1 MB
[xtask] Packaging...
  ✓ Created: dist/kindly-guard-linux-arm64.tar.gz
[xtask] Cross-compilation complete!
```

### Build for multiple targets

```bash
# Build for all supported platforms
$ cargo xtask cross-build --all-targets

[xtask] Building for all targets...
[xtask] Target 1/5: x86_64-unknown-linux-gnu
  ✓ Built in 45s, packaged to dist/kindly-guard-linux-x64.tar.gz
[xtask] Target 2/5: aarch64-unknown-linux-gnu
  ✓ Built in 2m 15s, packaged to dist/kindly-guard-linux-arm64.tar.gz
[xtask] Target 3/5: x86_64-apple-darwin
  ✓ Built in 1m 30s, packaged to dist/kindly-guard-macos-x64.tar.gz
[xtask] Target 4/5: aarch64-apple-darwin
  ✓ Built in 1m 45s, packaged to dist/kindly-guard-macos-arm64.tar.gz
[xtask] Target 5/5: x86_64-pc-windows-msvc
  ✓ Built in 2m 30s, packaged to dist/kindly-guard-windows-x64.zip
[xtask] All targets built successfully!
[xtask] Total time: 8m 45s
```

## Docker Multi-Platform Builds

### Build Docker image for multiple architectures

```bash
# Build multi-arch Docker image
$ cargo xtask docker-build --platforms linux/amd64,linux/arm64

[xtask] Building multi-platform Docker image...
[xtask] Setting up buildx...
  ✓ Builder: kindly-guard-builder
  ✓ Platforms: linux/amd64, linux/arm64
[xtask] Building images...
[xtask] Platform: linux/amd64
  => [internal] load build definition from Dockerfile
  => [internal] load .dockerignore
  => [build 1/6] FROM rust:1.75-slim
  => [build 2/6] WORKDIR /build
  => [build 3/6] COPY . .
  => [build 4/6] RUN cargo build --release
  => [runtime 1/3] FROM debian:bookworm-slim
  => [runtime 2/3] COPY --from=build /build/target/release/kindly-guard /usr/local/bin/
  => exporting to image
  ✓ Built linux/amd64 (2m 30s)
[xtask] Platform: linux/arm64
  ✓ Built linux/arm64 (4m 15s)
[xtask] Pushing to registry...
  ✓ Pushed: ghcr.io/yourusername/kindly-guard:0.2.0
  ✓ Pushed: ghcr.io/yourusername/kindly-guard:latest
[xtask] Docker build complete!
```

### Build and test Docker image locally

```bash
# Build and test Docker image
$ cargo xtask docker-build --local --test

[xtask] Building local Docker image...
[xtask] Building: kindly-guard:local
  => [build 1/6] FROM rust:1.75-slim
  => [build 2/6] WORKDIR /build
  => [build 3/6] COPY . .
  => [build 4/6] RUN cargo build --release
  => Successfully built kindly-guard:local
[xtask] Running container tests...
[xtask] Test 1: Basic functionality
  $ docker run --rm kindly-guard:local --version
  kindly-guard 0.2.0
  ✓ Version check passed
[xtask] Test 2: MCP server startup
  $ docker run --rm -d --name test-server kindly-guard:local server --stdio
  ✓ Server started successfully
  ✓ Responding to MCP requests
  $ docker stop test-server
[xtask] Test 3: Security scanning
  $ echo '{"text": "test\u202edata"}' | docker run --rm -i kindly-guard:local scan
  ✓ Detected Unicode threat
[xtask] All Docker tests passed!
```

## NPM Publishing Workflow

### Publish NPM packages with binaries

```bash
# Build and publish NPM packages
$ cargo xtask npm-publish --tag latest

[xtask] Preparing NPM packages...
[xtask] Building binaries for NPM...
  ✓ linux-x64: kindly-guard-linux-x64
  ✓ linux-arm64: kindly-guard-linux-arm64
  ✓ darwin-x64: kindly-guard-darwin-x64
  ✓ darwin-arm64: kindly-guard-darwin-arm64
  ✓ win32-x64: kindly-guard-win32-x64.exe
[xtask] Creating NPM packages...
[xtask] Package: @kindly-guard/cli
  - Version: 0.2.0
  - Main package with binary selection logic
  - Size: 2.1 KB
[xtask] Platform packages:
  ✓ @kindly-guard/cli-linux-x64 (12.3 MB)
  ✓ @kindly-guard/cli-linux-arm64 (11.8 MB)
  ✓ @kindly-guard/cli-darwin-x64 (13.1 MB)
  ✓ @kindly-guard/cli-darwin-arm64 (12.7 MB)
  ✓ @kindly-guard/cli-win32-x64 (14.2 MB)
[xtask] Publishing to NPM...
  ✓ Published @kindly-guard/cli-linux-x64@0.2.0
  ✓ Published @kindly-guard/cli-linux-arm64@0.2.0
  ✓ Published @kindly-guard/cli-darwin-x64@0.2.0
  ✓ Published @kindly-guard/cli-darwin-arm64@0.2.0
  ✓ Published @kindly-guard/cli-win32-x64@0.2.0
  ✓ Published @kindly-guard/cli@0.2.0
[xtask] NPM packages published successfully!
[xtask] Users can now install with: npm install -g @kindly-guard/cli
```

### Test NPM package locally

```bash
# Test NPM package before publishing
$ cargo xtask npm-publish --dry-run --test-local

[xtask] DRY RUN: NPM publishing
[xtask] Building NPM packages...
  ✓ Created packages in dist/npm/
[xtask] Testing local installation...
[xtask] Installing @kindly-guard/cli from local...
  $ cd /tmp/npm-test && npm install ../dist/npm/kindly-guard-cli-0.2.0.tgz
  ✓ Installation successful
[xtask] Running installed binary...
  $ npx kindly-guard --version
  kindly-guard 0.2.0
  ✓ Binary executes correctly
[xtask] Testing commands...
  $ npx kindly-guard scan test.json
  ✓ Scan command works
  $ npx kindly-guard server --help
  ✓ Server command available
[xtask] Local NPM test passed!
```

## Security Audit Workflow

### Run comprehensive security audit

```bash
# Full security audit
$ cargo xtask security-audit --comprehensive

[xtask] Running comprehensive security audit...
[xtask] Step 1: Dependency vulnerabilities
  Running cargo audit...
    Fetching advisory database
    Scanning 127 dependencies
  ✓ No known vulnerabilities found

[xtask] Step 2: License compliance
  Checking dependency licenses...
  ✓ All licenses compatible (MIT/Apache-2.0)
  
[xtask] Step 3: Code security scan
  Running cargo-geiger...
  ✓ No unsafe code in public API
  ℹ 3 unsafe blocks in dependencies (all documented)
  
[xtask] Step 4: Secret scanning
  Scanning for hardcoded secrets...
  ✓ No secrets, API keys, or tokens found
  
[xtask] Step 5: SAST analysis
  Running semgrep security rules...
  ✓ No security issues found
  
[xtask] Step 6: Supply chain check
  Verifying crate sources...
  ✓ All crates from crates.io
  ✓ No git dependencies
  
[xtask] Security audit complete - all checks passed!
[xtask] Report saved to: security-audit-2024-01-20.html
```

### Monitor security continuously

```bash
# Set up security monitoring
$ cargo xtask security-audit --monitor

[xtask] Starting security monitoring...
[xtask] Monitoring configuration:
  - Check interval: 6 hours
  - Advisory database: RustSec
  - Notifications: Enabled
[xtask] Initial scan...
  ✓ System secure
[xtask] Monitoring active (press Ctrl+C to stop)

[6 hours later]
[xtask] Running scheduled security check...
  ⚠ New advisory: RUSTSEC-2024-0001
  - Crate: example-crate v1.2.3
  - Severity: Medium
  - Fixed in: v1.2.4
[xtask] Sending notification...
  ✓ Email sent to security@example.com
[xtask] Suggested action: Update example-crate to v1.2.4
```

## Debugging Failed Builds

### Diagnose build failures

```bash
# Build fails - let's debug
$ cargo xtask build
[xtask] Starting build...
[ERROR] Build failed!

# Run with debug information
$ cargo xtask build --debug

[xtask] Debug mode enabled
[xtask] Environment:
  - PATH: /usr/local/bin:/usr/bin:/bin
  - RUST_VERSION: 1.75.0
  - CARGO_HOME: /home/user/.cargo
[xtask] Running: cargo build
error: linking with `cc` failed: exit status: 1
  = note: /usr/bin/ld: cannot find -lsqlite3

[xtask] Build failed with linker error
[xtask] Diagnosing...
  ✗ Missing system library: sqlite3
  ℹ On Ubuntu/Debian: sudo apt install libsqlite3-dev
  ℹ On macOS: brew install sqlite3
  ℹ On Fedora: sudo dnf install sqlite-devel
[xtask] After installing, run: cargo xtask build
```

### Debug test failures

```bash
# Tests failing - get more info
$ cargo xtask test --debug --filter scanner

[xtask] Running tests with filter: scanner
[xtask] Debug output enabled
[xtask] Environment:
  - RUST_TEST_THREADS: 1 (serialized for debugging)
  - RUST_BACKTRACE: full
  - RUST_LOG: debug

running 5 tests
test scanner::tests::test_unicode_detection ... FAILED

failures:

---- scanner::tests::test_unicode_detection stdout ----
[DEBUG kindly_guard::scanner] Scanning text: "Hello\u{202E}World"
[DEBUG kindly_guard::scanner::unicode] Checking character '\u{202E}' at position 5
[ERROR kindly_guard::scanner::unicode] Unicode scanner not initialized
thread 'scanner::tests::test_unicode_detection' panicked at src/scanner/unicode.rs:123:45:
called `Option::unwrap()` on a `None` value

[xtask] Test failed - investigating...
[xtask] Common causes:
  1. Missing test setup/initialization
  2. Race condition in parallel tests
  3. Missing test data files
[xtask] Suggestions:
  - Check test setup in src/scanner/tests.rs
  - Run with RUST_TEST_THREADS=1 for serial execution
  - Verify test data in tests/data/ exists
```

### Debug cross-compilation issues

```bash
# Cross-compilation failing
$ cargo xtask cross-build --target aarch64-unknown-linux-gnu --debug

[xtask] Debug: Cross-compilation for aarch64-unknown-linux-gnu
[xtask] Checking prerequisites...
  ✓ Rust target: aarch64-unknown-linux-gnu installed
  ✗ Cross toolchain not found: aarch64-linux-gnu-gcc
  
[xtask] Attempting to diagnose...
[xtask] Checking common locations:
  - /usr/bin/aarch64-linux-gnu-gcc: not found
  - /usr/local/bin/aarch64-linux-gnu-gcc: not found
  - ~/cross/bin/aarch64-linux-gnu-gcc: not found
  
[xtask] System information:
  - OS: Ubuntu 22.04
  - Arch: x86_64
  
[xtask] Installation instructions:
  On Ubuntu/Debian:
    sudo apt update
    sudo apt install gcc-aarch64-linux-gnu
    
  Alternative: Install cross tool
    cargo install cross
    cargo xtask cross-build --use-cross --target aarch64-unknown-linux-gnu
    
[xtask] After installing, your PATH should include the cross compiler
```

### Debug release packaging

```bash
# Release packaging fails
$ cargo xtask release package --debug

[xtask] Debug: Packaging release artifacts
[xtask] Checking release builds...
  ✓ kindly-guard-server: target/release/kindly-guard-server (45.2 MB)
  ✓ kindly-guard-cli: target/release/kindly-guard-cli (38.7 MB)
  ✗ kindly-guard-shield: not found

[xtask] Missing artifact: kindly-guard-shield
[xtask] Investigating...
[xtask] Checking build log for kindly-guard-shield:
  error: failed to run custom build command for `tauri v2.0.0`
  
  Caused by:
    process didn't exit successfully: exit status: 101
    --- stderr
    Error: Webkit2gtk development files not found
    
[xtask] Diagnosis: Missing Tauri dependencies
[xtask] Solution:
  On Ubuntu/Debian:
    sudo apt install libwebkit2gtk-4.1-dev \
      libgtk-3-dev libayatana-appindicator3-dev
      
  On Fedora:
    sudo dnf install webkit2gtk4.1-devel \
      gtk3-devel libappindicator-gtk3-devel
      
[xtask] After installing dependencies, run:
  cargo xtask build --package kindly-guard-shield
  cargo xtask release package
```

## Tips and Best Practices

1. **Always use dry-run first** for destructive operations
2. **Enable verbose mode** when debugging issues
3. **Check prerequisites** before cross-compilation
4. **Run security audits** before releases
5. **Test locally** before publishing to registries
6. **Use debug mode** to diagnose failures
7. **Save build logs** for complex operations
8. **Monitor CI status** after pushing changes

## Getting Help

```bash
# Show all available commands
$ cargo xtask --help

# Get help for specific command
$ cargo xtask release --help

# Show version and build info
$ cargo xtask --version
```