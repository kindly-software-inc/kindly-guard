# Rust-Based CI/CD System Guide

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Benefits Over Shell Scripts](#benefits-over-shell-scripts)
4. [Getting Started](#getting-started)
5. [Command Reference](#command-reference)
6. [Adding New Commands](#adding-new-commands)
7. [Local Testing Guide](#local-testing-guide)
8. [GitHub Actions Integration](#github-actions-integration)
9. [cargo-make Usage](#cargo-make-usage)
10. [Migration Guide](#migration-guide)
11. [Troubleshooting](#troubleshooting)
12. [Best Practices](#best-practices)

## Overview

The KindlyGuard project uses a Rust-based CI/CD system built on the `xtask` pattern. This provides a type-safe, cross-platform, and maintainable approach to build automation that replaces traditional shell scripts with Rust code.

### Key Features

- **Cross-platform compatibility**: Works on Windows, macOS, and Linux without modification
- **Type safety**: Catch errors at compile time rather than runtime
- **Dependency management**: Uses Cargo for consistent dependency resolution
- **Parallel execution**: Built-in support for concurrent tasks
- **Rich CLI**: Beautiful terminal output with progress bars and colored text
- **Dry-run support**: Test commands without making changes
- **Structured configuration**: TOML-based configuration with validation

## Architecture

### The xtask Pattern

The `xtask` pattern is a convention in the Rust ecosystem where a separate workspace member named `xtask` contains all build automation logic:

```
kindly-guard/
├── Cargo.toml           # Workspace root
├── .cargo/
│   └── config.toml      # Cargo aliases
├── xtask/
│   ├── Cargo.toml       # xtask crate
│   └── src/
│       ├── main.rs      # CLI entry point
│       ├── commands/    # Command implementations
│       ├── config/      # Configuration management
│       └── utils/       # Shared utilities
└── ... other crates
```

### Component Overview

1. **CLI Framework (clap)**: Provides argument parsing and help generation
2. **Command Modules**: Each major operation is a separate module
3. **Utilities**: Shared functionality for process execution, file operations, etc.
4. **Configuration**: TOML-based configuration with environment overrides
5. **Progress Tracking**: Visual feedback using indicatif

## Benefits Over Shell Scripts

### 1. **Type Safety**
```rust
// Rust: Compile-time validation
let version = Version::parse(&version_str)?;

// Shell: Runtime errors
VERSION=$1  # Could be invalid
```

### 2. **Cross-Platform Support**
```rust
// Rust: Automatically handles platform differences
let exe_suffix = if cfg!(windows) { ".exe" } else { "" };

// Shell: Requires separate scripts or complex conditionals
if [[ "$OSTYPE" == "msys" ]]; then
    EXE=".exe"
fi
```

### 3. **Error Handling**
```rust
// Rust: Structured error handling with context
check_git_status(&ctx)
    .await
    .context("Failed to check git status")?;

// Shell: Manual error checking
git status --porcelain || { echo "Git failed"; exit 1; }
```

### 4. **Parallel Execution**
```rust
// Rust: Built-in async/await and concurrency
let handles: Vec<_> = targets
    .iter()
    .map(|target| tokio::spawn(build_target(target)))
    .collect();

// Shell: Complex background job management
for target in "${TARGETS[@]}"; do
    build_target "$target" &
done
wait
```

### 5. **Dependency Management**
```rust
// Rust: Cargo handles all dependencies
use indicatif::ProgressBar;
use semver::Version;

// Shell: Manual tool installation and version checking
command -v jq >/dev/null || { echo "jq required"; exit 1; }
```

## Getting Started

### Prerequisites

1. Rust toolchain (1.70+)
2. Git
3. Platform-specific build tools

### Installation

```bash
# Clone the repository
git clone https://github.com/kindly-software/kindlyguard
cd kindly-guard

# Build xtask
cargo build --package xtask

# Or use the cargo alias
cargo xtask --help
```

### Basic Usage

```bash
# Run tests
cargo xtask test

# Build for all platforms
cargo xtask build --release

# Create a new release
cargo xtask release 1.0.0

# Run security audits
cargo xtask security --all
```

## Command Reference

### Global Options

All commands support these global options:

- `--dry-run`: Preview changes without executing
- `--verbose`, `-v`: Enable detailed output
- `--no-color`: Disable colored output

### Release Command

Orchestrates the entire release process:

```bash
cargo xtask release [VERSION] [OPTIONS]

Options:
  --yes              Skip confirmation prompts
  --skip-tests       Skip running tests
  --skip-security    Skip security audits
  --skip-build       Skip building binaries
  --skip-publish     Skip publishing to registries
  --prerelease       Create a pre-release
  --draft            Create a draft release

Examples:
  # Interactive release (prompts for version)
  cargo xtask release

  # Specific version release
  cargo xtask release 1.2.3

  # Pre-release with skipped steps
  cargo xtask release 1.2.3-beta.1 --prerelease --skip-publish
```

### Build Command

Cross-platform build automation:

```bash
cargo xtask build [OPTIONS]

Options:
  --targets <TARGETS>    Comma-separated list of targets
  --release              Build in release mode
  --strip                Strip debug symbols
  --archive              Create platform archives
  --output-dir <DIR>     Output directory (default: dist)

Examples:
  # Build for default platforms
  cargo xtask build --release

  # Build specific targets
  cargo xtask build --targets x86_64-unknown-linux-gnu,x86_64-apple-darwin

  # Build and create archives
  cargo xtask build --release --strip --archive
```

### Test Command

Comprehensive testing suite:

```bash
cargo xtask test [OPTIONS]

Options:
  --package <PKG>     Test specific package
  --all               Run all test types
  --unit              Run unit tests only
  --integration       Run integration tests only
  --doc               Run doc tests
  --bench             Run benchmarks
  --coverage          Generate coverage report
  --no-fail-fast      Continue on test failure

Examples:
  # Run all tests
  cargo xtask test --all

  # Test specific package
  cargo xtask test --package kindly-guard-server

  # Generate coverage
  cargo xtask test --coverage
```

### Security Command

Security auditing and compliance:

```bash
cargo xtask security [OPTIONS]

Options:
  --all               Run all security checks
  --audit             Run cargo-audit
  --deny              Run cargo-deny
  --geiger            Run cargo-geiger (unsafe code)
  --semgrep           Run Semgrep analysis
  --fix               Attempt to fix issues

Examples:
  # Run all security checks
  cargo xtask security --all

  # Just dependency audit
  cargo xtask security --audit

  # Check for unsafe code
  cargo xtask security --geiger
```

### Version Command

Version management across workspace:

```bash
cargo xtask version [COMMAND]

Commands:
  show                Show current versions
  update <VERSION>    Update all versions
  check               Check version consistency

Examples:
  # Show all versions
  cargo xtask version show

  # Update to new version
  cargo xtask version update 2.0.0

  # Check consistency
  cargo xtask version check
```

### Publish Command

Multi-registry publishing:

```bash
cargo xtask publish [OPTIONS]

Options:
  --crates-io         Publish to crates.io
  --npm               Publish to npm
  --docker            Publish Docker images
  --skip-verification Skip pre-publish verification

Examples:
  # Publish everywhere
  cargo xtask publish --crates-io --npm --docker

  # Just crates.io
  cargo xtask publish --crates-io
```

## Adding New Commands

### 1. Create Command Module

Create a new file in `xtask/src/commands/`:

```rust
// xtask/src/commands/deploy.rs
use anyhow::Result;
use clap::Args;
use crate::utils::Context;

#[derive(Args)]
pub struct DeployCmd {
    /// Environment to deploy to
    #[arg(value_enum)]
    environment: Environment,
    
    /// Skip health checks
    #[arg(long)]
    skip_health_check: bool,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum Environment {
    Staging,
    Production,
}

pub async fn run(cmd: DeployCmd, ctx: Context) -> Result<()> {
    ctx.info(&format!("Deploying to {:?}", cmd.environment));
    
    // Validate prerequisites
    validate_deployment(&ctx)?;
    
    // Build deployment artifacts
    build_artifacts(&ctx).await?;
    
    // Deploy
    match cmd.environment {
        Environment::Staging => deploy_staging(&ctx).await?,
        Environment::Production => deploy_production(&ctx).await?,
    }
    
    // Health check
    if !cmd.skip_health_check {
        run_health_checks(&ctx, cmd.environment).await?;
    }
    
    ctx.success("Deployment completed!");
    Ok(())
}

async fn validate_deployment(ctx: &Context) -> Result<()> {
    // Check git status
    ctx.run_command("git", &["status", "--porcelain"])?;
    
    // Verify credentials
    std::env::var("DEPLOY_TOKEN")
        .map_err(|_| anyhow::anyhow!("DEPLOY_TOKEN not set"))?;
    
    Ok(())
}

async fn build_artifacts(ctx: &Context) -> Result<()> {
    let spinner = crate::utils::spinner("Building deployment artifacts...");
    
    // Build optimized binary
    ctx.run_command("cargo", &["build", "--release", "--features", "production"])?;
    
    // Create deployment package
    create_deployment_package()?;
    
    spinner.finish_with_message("Artifacts ready");
    Ok(())
}
```

### 2. Register in main.rs

```rust
// xtask/src/main.rs
mod commands;
use commands::{build, deploy, publish, release, security, test, version};

#[derive(Subcommand)]
enum Commands {
    // ... existing commands
    
    /// Deploy to environment
    Deploy(deploy::DeployCmd),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        // ... existing matches
        Commands::Deploy(cmd) => deploy::run(cmd, ctx).await,
    }
}
```

### 3. Update mod.rs

```rust
// xtask/src/commands/mod.rs
pub mod build;
pub mod deploy;  // Add this
pub mod publish;
// ... rest
```

## Local Testing Guide

### Running Tests Locally

```bash
# Run all tests with detailed output
cargo xtask test --all --verbose

# Test specific functionality
cargo xtask test --unit --package kindly-guard-server

# Generate and view coverage
cargo xtask test --coverage
open target/coverage/html/index.html
```

### Testing Build Process

```bash
# Test build for current platform
cargo xtask build --dry-run

# Test cross-compilation setup
cargo xtask build --targets aarch64-unknown-linux-gnu --dry-run

# Full build test
cargo xtask build --release --strip --archive
```

### Testing Release Process

```bash
# Dry-run release to see all steps
cargo xtask release --dry-run

# Test version updates
cargo xtask version update 9.9.9 --dry-run
git diff  # Check what would change

# Test publishing process
cargo xtask publish --dry-run --crates-io
```

### Debugging Tips

1. **Use verbose mode**: Add `-v` for detailed output
2. **Check dry-run**: Always test with `--dry-run` first
3. **Inspect commands**: Set `RUST_LOG=debug` for command tracing
4. **Test incrementally**: Test individual commands before full workflows

## GitHub Actions Integration

### Basic CI Workflow

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  RUST_BACKTRACE: 1
  CARGO_TERM_COLOR: always

jobs:
  test:
    name: Test
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        rust: [stable, nightly]
    steps:
      - uses: actions/checkout@v4
      
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ matrix.rust }}
          components: rustfmt, clippy
      
      - uses: Swatinem/rust-cache@v2
      
      - name: Run CI
        run: cargo xtask ci
        env:
          CI_OS: ${{ matrix.os }}
          CI_RUST: ${{ matrix.rust }}

  security:
    name: Security Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      
      - name: Install security tools
        run: |
          cargo install cargo-audit cargo-deny
      
      - name: Run security checks
        run: cargo xtask security --all
```

### Release Workflow

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  release:
    name: Create Release
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: dtolnay/rust-toolchain@stable
      
      - name: Build release artifacts
        run: cargo xtask build --release --strip --archive
      
      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          files: dist/*
          draft: true
          generate_release_notes: true
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Platform-Specific Builds

```yaml
# .github/workflows/build.yml
name: Build

on:
  workflow_dispatch:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  build-matrix:
    name: Build ${{ matrix.target }}
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-latest
          - target: x86_64-unknown-linux-musl
            os: ubuntu-latest
          - target: x86_64-apple-darwin
            os: macos-latest
          - target: aarch64-apple-darwin
            os: macos-latest
          - target: x86_64-pc-windows-msvc
            os: windows-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      
      - name: Install cross
        if: matrix.target == 'x86_64-unknown-linux-musl'
        run: cargo install cross
      
      - name: Build
        run: cargo xtask build --targets ${{ matrix.target }} --release
      
      - uses: actions/upload-artifact@v4
        with:
          name: kindly-guard-${{ matrix.target }}
          path: dist/${{ matrix.target }}/*
```

## cargo-make Usage

While xtask is the primary automation tool, cargo-make can provide additional task running capabilities:

### Installation

```bash
cargo install cargo-make
```

### Basic Makefile.toml

```toml
# Makefile.toml
[config]
default_to_workspace = true
skip_core_tasks = true

[env]
RUST_LOG = "info"

[tasks.dev]
description = "Run development server"
command = "cargo"
args = ["run", "--", "--dev"]
watch = true

[tasks.fmt]
description = "Format all code"
dependencies = ["fmt-rust", "fmt-toml"]

[tasks.fmt-rust]
command = "cargo"
args = ["fmt", "--all"]

[tasks.fmt-toml]
command = "taplo"
args = ["fmt", "**/*.toml"]

[tasks.lint]
description = "Run all lints"
dependencies = ["clippy", "fmt-check"]

[tasks.clippy]
command = "cargo"
args = ["clippy", "--all-targets", "--all-features", "--", "-D", "warnings"]

[tasks.ci]
description = "Run CI pipeline"
dependencies = ["lint", "test", "security"]

[tasks.test]
command = "cargo"
args = ["xtask", "test", "--all"]

[tasks.security]
command = "cargo"
args = ["xtask", "security", "--all"]

[tasks.quick]
description = "Quick build and test"
dependencies = ["build", "test-unit"]

[tasks.build]
command = "cargo"
args = ["build", "--all-features"]

[tasks.test-unit]
command = "cargo"
args = ["test", "--lib"]

[tasks.release-dry]
description = "Dry run release"
command = "cargo"
args = ["xtask", "release", "--dry-run"]
```

### Usage Examples

```bash
# Run development server with auto-reload
cargo make dev

# Run full CI pipeline
cargo make ci

# Quick build and test
cargo make quick

# Format everything
cargo make fmt

# Dry-run release
cargo make release-dry
```

### Integration with xtask

cargo-make works well as a high-level task runner that delegates to xtask:

```toml
[tasks.release]
description = "Create a new release"
command = "cargo"
args = ["xtask", "release"]

[tasks.build-all]
description = "Build for all platforms"
command = "cargo"
args = ["xtask", "build", "--release", "--archive"]

[tasks.publish-all]
description = "Publish to all registries"
command = "cargo"
args = ["xtask", "publish", "--crates-io", "--npm", "--docker"]
```

## Migration Guide

### From Shell Scripts to xtask

#### 1. **Build Script Migration**

Before (build.sh):
```bash
#!/bin/bash
set -e

TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-apple-darwin"
    "x86_64-pc-windows-msvc"
)

for target in "${TARGETS[@]}"; do
    echo "Building for $target..."
    
    if [[ "$target" == *"musl"* ]]; then
        cross build --target "$target" --release
    else
        cargo build --target "$target" --release
    fi
    
    # Copy and strip binaries
    mkdir -p "dist/$target"
    cp "target/$target/release/kindly-guard" "dist/$target/"
    
    if [[ "$OSTYPE" != "msys" ]]; then
        strip "dist/$target/kindly-guard"
    fi
done

echo "Build complete!"
```

After (xtask):
```bash
# Simple command replaces entire script
cargo xtask build --release --strip --archive

# Or with specific targets
cargo xtask build --targets x86_64-unknown-linux-gnu,x86_64-apple-darwin --release
```

#### 2. **Test Script Migration**

Before (test.sh):
```bash
#!/bin/bash

echo "Running tests..."
cargo test --all

echo "Running clippy..."
cargo clippy -- -D warnings

echo "Checking format..."
cargo fmt -- --check

if command -v cargo-audit >/dev/null; then
    echo "Running security audit..."
    cargo audit
fi
```

After (xtask):
```bash
# Run comprehensive test suite
cargo xtask test --all

# Run security checks
cargo xtask security --audit
```

#### 3. **Release Script Migration**

Before (release.sh):
```bash
#!/bin/bash

VERSION=$1
if [ -z "$VERSION" ]; then
    echo "Usage: ./release.sh VERSION"
    exit 1
fi

# Update version
sed -i "s/version = \".*\"/version = \"$VERSION\"/" Cargo.toml

# Run tests
./test.sh || exit 1

# Build
./build.sh || exit 1

# Tag
git add -A
git commit -m "Release v$VERSION"
git tag -a "v$VERSION" -m "Release v$VERSION"

# Publish
cargo publish

echo "Release $VERSION complete!"
```

After (xtask):
```bash
# Interactive release with all checks
cargo xtask release

# Or specify version
cargo xtask release 1.2.3
```

### Migration Checklist

1. **Inventory existing scripts**
   - List all shell scripts in the project
   - Document what each script does
   - Note any platform-specific behavior

2. **Create xtask structure**
   ```bash
   cargo new --bin xtask
   # Add to workspace Cargo.toml
   ```

3. **Implement commands incrementally**
   - Start with simple commands (build, test)
   - Add complex workflows (release, deploy)
   - Preserve existing script behavior

4. **Add configuration**
   - Create config structures for complex options
   - Support environment variable overrides
   - Add config file support

5. **Test thoroughly**
   - Run commands with --dry-run
   - Compare output with shell scripts
   - Test on all platforms

6. **Document changes**
   - Update README with new commands
   - Create migration guide for team
   - Document any behavior changes

7. **Gradual rollout**
   - Keep shell scripts during transition
   - Run both in parallel initially
   - Remove shell scripts once confident

## Troubleshooting

### Common Issues

#### 1. **Command Not Found**

```
Error: cargo xtask: command not found
```

**Solution**: Build xtask first or use full path:
```bash
cargo build --package xtask
cargo run --package xtask -- [ARGS]
```

#### 2. **Cross-Compilation Failures**

```
Error: linker `aarch64-linux-gnu-gcc` not found
```

**Solution**: Install cross or required toolchain:
```bash
# Install cross
cargo install cross

# Or install target toolchain
rustup target add aarch64-unknown-linux-gnu
```

#### 3. **Permission Denied**

```
Error: Permission denied (os error 13)
```

**Solution**: Check file permissions and ownership:
```bash
# Fix executable permissions
chmod +x target/release/kindly-guard

# Run with appropriate permissions
sudo cargo xtask install  # If installing system-wide
```

#### 4. **Dry Run Not Working**

```
Error: Changes made despite --dry-run flag
```

**Solution**: Ensure all commands check ctx.dry_run:
```rust
if !ctx.dry_run {
    // Only execute actual changes here
    std::fs::write(path, content)?;
}
```

#### 5. **Progress Bar Hangs**

```
Building [=>                    ] (stuck)
```

**Solution**: Disable progress in CI or add timeouts:
```rust
if std::env::var("CI").is_ok() {
    // Simple output for CI
    println!("Building {}...", target);
} else {
    // Progress bar for interactive use
    let pb = ProgressBar::new_spinner();
}
```

### Debug Techniques

1. **Enable verbose logging**:
   ```bash
   RUST_LOG=debug cargo xtask build -v
   ```

2. **Print command execution**:
   ```rust
   ctx.debug(&format!("Executing: {:?}", cmd));
   ```

3. **Use RUST_BACKTRACE**:
   ```bash
   RUST_BACKTRACE=full cargo xtask test
   ```

4. **Check configuration**:
   ```bash
   cargo xtask config show
   ```

## Best Practices

### 1. **Command Design**

- **Single Responsibility**: Each command does one thing well
- **Composability**: Commands can call other commands
- **Idempotency**: Running twice produces same result
- **Clear Output**: Use progress bars and colored output appropriately

### 2. **Error Handling**

```rust
// DO: Provide context for errors
std::fs::read_to_string(path)
    .with_context(|| format!("Failed to read {}", path.display()))?;

// DON'T: Lose error context
std::fs::read_to_string(path)?;

// DO: Handle expected failures gracefully
match check_prerequisites() {
    Ok(()) => {},
    Err(e) if e.to_string().contains("not found") => {
        ctx.warn("Optional tool not found, skipping");
    }
    Err(e) => return Err(e),
}
```

### 3. **Configuration Management**

```rust
// DO: Layer configuration sources
pub struct Config {
    // From config file
    #[serde(default)]
    pub file_config: FileConfig,
    
    // From environment
    pub env_overrides: EnvConfig,
    
    // From CLI args
    pub cli_overrides: CliConfig,
}

impl Config {
    pub fn load() -> Result<Self> {
        let mut config = Self::from_file()?;
        config.apply_env_overrides()?;
        Ok(config)
    }
}
```

### 4. **Platform Compatibility**

```rust
// DO: Handle platform differences explicitly
#[cfg(target_os = "windows")]
const BINARY_NAME: &str = "kindly-guard.exe";

#[cfg(not(target_os = "windows"))]
const BINARY_NAME: &str = "kindly-guard";

// DO: Use platform-agnostic paths
use std::path::PathBuf;
let config_path = dirs::config_dir()
    .context("Failed to find config directory")?
    .join("kindly-guard")
    .join("config.toml");
```

### 5. **Testing xtask Commands**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_build_command() {
        let temp = TempDir::new().unwrap();
        let ctx = Context {
            dry_run: true,
            verbose: false,
        };
        
        let cmd = BuildCmd {
            targets: Some(vec!["x86_64-unknown-linux-gnu".to_string()]),
            release: true,
            strip: false,
            archive: false,
            output_dir: Some(temp.path().to_string()),
        };
        
        let result = run(cmd, ctx).await;
        assert!(result.is_ok());
    }
}
```

### 6. **Performance Optimization**

```rust
// DO: Use parallel execution for independent tasks
use futures::future::join_all;

let handles: Vec<_> = targets
    .into_iter()
    .map(|target| tokio::spawn(process_target(target)))
    .collect();

let results = join_all(handles).await;

// DO: Use appropriate buffer sizes
use tokio::io::{BufReader, BufWriter};
let reader = BufReader::with_capacity(64 * 1024, file);

// DO: Reuse expensive resources
lazy_static! {
    static ref REGEX_CACHE: Mutex<HashMap<String, Regex>> = 
        Mutex::new(HashMap::new());
}
```

### 7. **Documentation**

```rust
/// Build the project for multiple platforms.
///
/// This command handles cross-compilation using either cargo or cross,
/// automatically detecting when cross is needed based on the target triple.
///
/// # Examples
///
/// Build for default platforms:
/// ```bash
/// cargo xtask build --release
/// ```
///
/// Build specific targets with archives:
/// ```bash
/// cargo xtask build --targets x86_64-unknown-linux-gnu --archive
/// ```
pub async fn run(cmd: BuildCmd, ctx: Context) -> Result<()> {
    // Implementation
}
```

### 8. **Graceful Degradation**

```rust
// DO: Check for optional tools
if which::which("sccache").is_ok() {
    std::env::set_var("RUSTC_WRAPPER", "sccache");
    ctx.info("Using sccache for faster builds");
}

// DO: Provide fallbacks
let strip_cmd = if target.contains("apple") {
    "strip"
} else if let Ok(path) = which::which(format!("{}-strip", target_arch)) {
    path.to_string_lossy().to_string()
} else {
    ctx.warn("Target-specific strip not found, using system strip");
    "strip"
};
```

### 9. **Security Considerations**

```rust
// DO: Validate external input
fn validate_version(version: &str) -> Result<Version> {
    Version::parse(version)
        .context("Invalid version format")?
}

// DO: Use secure defaults
let temp_dir = tempfile::Builder::new()
    .prefix("kindly-guard-build-")
    .tempdir()
    .context("Failed to create secure temp directory")?;

// DO: Sanitize paths
fn sanitize_path(path: &Path) -> Result<PathBuf> {
    let canonical = path.canonicalize()
        .context("Failed to canonicalize path")?;
    
    // Ensure path is within project
    if !canonical.starts_with(workspace_root()) {
        anyhow::bail!("Path escapes project directory");
    }
    
    Ok(canonical)
}
```

### 10. **Monitoring and Metrics**

```rust
// DO: Track command execution time
let start = std::time::Instant::now();

let result = execute_command().await;

let duration = start.elapsed();
ctx.debug(&format!("Command completed in {:?}", duration));

// DO: Collect metrics for CI
if std::env::var("CI").is_ok() {
    println!("::set-output name=duration::{}", duration.as_secs());
    println!("::set-output name=artifact_size::{}", get_artifact_size()?);
}
```

## Conclusion

The Rust-based CI/CD system provides a robust, type-safe, and maintainable alternative to traditional shell scripts. By leveraging Rust's ecosystem and the xtask pattern, we achieve:

- **Reliability**: Compile-time guarantees and structured error handling
- **Portability**: True cross-platform support without platform-specific scripts
- **Maintainability**: Refactorable, testable code with IDE support
- **Performance**: Parallel execution and efficient resource usage
- **Developer Experience**: Rich CLI with progress tracking and helpful errors

The investment in setting up xtask pays dividends through reduced maintenance, fewer runtime errors, and a superior developer experience. As the project grows, the xtask system scales elegantly, supporting new commands and workflows without the complexity typical of large shell script collections.

For questions or contributions, please refer to the project's contribution guidelines or open an issue on GitHub.