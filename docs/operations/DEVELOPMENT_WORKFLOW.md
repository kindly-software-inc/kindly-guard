# KindlyGuard Development Workflow 🚀

This guide provides a comprehensive overview of the modern Rust development tools and workflows used in KindlyGuard. Our tooling choices prioritize security, developer experience, and code quality.

## Table of Contents

- [Quick Start](#quick-start)
- [Development Tools Overview](#development-tools-overview)
- [Common Workflows](#common-workflows)
- [Tool Reference](#tool-reference)
- [Security-First Development](#security-first-development)
- [Troubleshooting](#troubleshooting)

## Quick Start

```bash
# Clone and setup
git clone https://github.com/kindlyguard/kindlyguard.git
cd kindly-guard

# Install all development tools
./scripts/install-dev-tools.sh

# Run initial checks
cargo deny check        # Check dependencies
cargo nextest run      # Run tests with better output
cargo +nightly udeps   # Find unused dependencies

# Start development
bacon                  # Watch mode with automatic testing
```

## Development Tools Overview

### 🔍 Core Tools

| Tool | Purpose | Why We Use It |
|------|---------|---------------|
| **cargo-nextest** | Next-gen test runner | 60% faster, better output, parallel execution |
| **cargo-deny** | Supply chain security | Blocks vulnerable/duplicate dependencies |
| **cargo-udeps** | Unused dependency finder | Keeps builds lean and secure |
| **cargo-outdated** | Update checker | Proactive security updates |
| **cargo-machete** | Dead code finder | Removes unused dependencies |
| **cargo-msrv** | MSRV verification | Ensures compatibility |
| **bacon** | Background compiler | Instant feedback during development |
| **cargo-release** | Release automation | Consistent, secure releases |
| **grcov** | Code coverage | Ensures test completeness |
| **cargo-leptos** | Hot reload for UI | Faster UI development |
| **typos** | Spell checker | Professional documentation |
| **committed** | Commit linter | Enforces conventional commits |
| **cargo-audit** | Security scanner | CVE detection |
| **cargo-edit** | Dependency manager | Safe dependency updates |

### 🛡️ Security Tools

All security tools run automatically in CI, but you should run them locally before pushing:

```bash
# Security audit workflow
cargo deny check        # License and security check
cargo audit            # CVE scanning
cargo geiger           # Unsafe code detection
cargo +nightly udeps   # Remove attack surface
```

## Common Workflows

### 1. Starting Development

```bash
# Update your branch
git pull --rebase upstream main

# Check project health
cargo deny check
cargo outdated
cargo +nightly udeps

# Start development mode
bacon              # Runs in background
# or
cargo watch -x check -x test -x clippy
```

### 2. Adding Dependencies

```bash
# Add a dependency safely
cargo add serde --features derive

# Verify it's acceptable
cargo deny check

# Check for duplicates
cargo tree -d

# Ensure no unused features
cargo +nightly udeps
```

### 3. Writing Code

```bash
# While coding, bacon runs in background
bacon

# Before committing
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run
cargo doc --no-deps --all-features
```

### 4. Testing

```bash
# Run tests with better output
cargo nextest run

# Run specific test
cargo nextest run test_unicode_security

# Run tests in parallel
cargo nextest run -j 8

# Watch mode testing
cargo watch -x "nextest run"

# Coverage report
cargo grcov
```

### 5. Pre-Commit Workflow

```bash
# Format code
cargo fmt

# Fix lints
cargo clippy --fix --all-targets --all-features

# Check for typos
typos

# Verify commit message
committed --no-merge-commit

# Run final checks
cargo nextest run
cargo deny check
```

### 6. Release Workflow

```bash
# Check everything is ready
cargo release --dry-run

# Create release
cargo release patch  # or minor/major

# This automatically:
# - Updates version numbers
# - Creates git tag
# - Runs all checks
# - Publishes to crates.io
```

## Tool Reference

### cargo-nextest

Next-generation test runner with superior UX:

```bash
# Basic usage
cargo nextest run

# Run failed tests only
cargo nextest run --failed

# Run with specific profile
cargo nextest run --profile ci

# Generate junit output
cargo nextest run --profile ci --junit report.xml
```

**Configuration** (`.config/nextest.toml`):
```toml
[profile.default]
retries = 2
slow-timeout = { period = "30s", terminate-after = 2 }

[profile.ci]
retries = 3
fail-fast = false
```

### cargo-deny

Supply chain security tool:

```bash
# Check all aspects
cargo deny check

# Check specific aspect
cargo deny check licenses
cargo deny check bans
cargo deny check sources

# Generate initial config
cargo deny init
```

**Configuration** (`deny.toml`):
```toml
[licenses]
confidence-threshold = 0.8
allow = ["Apache-2.0", "MIT", "BSD-3-Clause"]

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

### cargo-udeps

Find unused dependencies:

```bash
# Requires nightly
cargo +nightly udeps

# Check all targets
cargo +nightly udeps --all-targets

# In workspace
cargo +nightly udeps --workspace
```

### bacon

Background rust compiler:

```bash
# Start bacon
bacon

# Run specific job
bacon test
bacon clippy
bacon doc

# Custom job
bacon --job check-all
```

**Configuration** (`bacon.toml`):
```toml
[jobs.check-all]
command = ["cargo", "check", "--all-targets", "--all-features"]
need_stdout = false

[jobs.clippy-all]
command = ["cargo", "clippy", "--all-targets", "--all-features", "--", "-D", "warnings"]
need_stdout = false
```

### cargo-machete

Remove unused dependencies:

```bash
# Find unused dependencies
cargo machete

# Automatically fix
cargo machete --fix
```

### cargo-msrv

Verify minimum supported Rust version:

```bash
# Find MSRV
cargo msrv

# Verify current MSRV
cargo msrv verify

# List incompatible dependencies
cargo msrv list
```

### grcov

Code coverage tool:

```bash
# Generate coverage
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="cargo-test-%p-%m.profraw"

cargo build
cargo test

grcov . --binary-path ./target/debug/deps/ -s . -t html -o target/coverage/
```

### typos

Fast spell checker:

```bash
# Check for typos
typos

# Fix automatically
typos --write-changes

# Check specific file types
typos --type rust
```

**Configuration** (`.typos.toml`):
```toml
[default.extend-words]
kindlyguard = "kindlyguard"
mcp = "mcp"

[files]
extend-exclude = ["target", "*.lock"]
```

### committed

Conventional commit linter:

```bash
# Check commits
committed

# Check staged commit
committed --staged

# Install as git hook
committed --install
```

## Security-First Development

### Dependency Security

1. **Before adding any dependency:**
   ```bash
   # Research the dependency
   cargo search <dep>
   cargo info <dep>
   
   # Check its dependencies
   cargo tree -p <dep>
   ```

2. **After adding:**
   ```bash
   cargo deny check
   cargo audit
   cargo +nightly udeps
   ```

3. **Regular maintenance:**
   ```bash
   # Weekly
   cargo outdated
   cargo audit
   
   # Monthly
   cargo deny check
   cargo machete
   ```

### Code Security

1. **Unsafe code:**
   ```bash
   # Count unsafe usage
   cargo geiger
   
   # Find unsafe blocks
   rg "unsafe \{" --type rust
   ```

2. **Security patterns:**
   ```bash
   # Check for unwrap/expect
   cargo clippy -- -W clippy::unwrap_used -W clippy::expect_used
   
   # Check for panics
   cargo clippy -- -W clippy::panic
   ```

### Pre-Push Security Checklist

```bash
#!/bin/bash
# Save as .git/hooks/pre-push

echo "🛡️ Running security checks..."

# Format check
cargo fmt -- --check || exit 1

# Clippy with strict lints
cargo clippy --all-targets --all-features -- -D warnings || exit 1

# Tests
cargo nextest run || exit 1

# Security audit
cargo deny check || exit 1
cargo audit || exit 1

# No unsafe code
if cargo geiger 2>&1 | grep -q "unsafe"; then
  echo "⚠️  Warning: Unsafe code detected"
fi

echo "✅ All checks passed!"
```

## Troubleshooting

### Common Issues

**bacon not updating:**
```bash
# Clear bacon's cache
rm -rf target/bacon-cache
bacon --clear
```

**cargo-nextest failures:**
```bash
# Run with more detail
cargo nextest run --no-capture
```

**cargo-deny conflicts:**
```bash
# See full dependency tree
cargo tree -d
cargo tree -i <package>
```

**Coverage not working:**
```bash
# Ensure llvm-tools installed
rustup component add llvm-tools-preview
```

### Performance Tips

1. **Use sccache for faster builds:**
   ```bash
   cargo install sccache
   export RUSTC_WRAPPER=sccache
   ```

2. **Parallel cargo commands:**
   ```bash
   # In ~/.cargo/config.toml
   [build]
   jobs = 8
   ```

3. **Incremental compilation:**
   ```bash
   export CARGO_INCREMENTAL=1
   ```

## Tool Installation Script

Save this as `scripts/install-dev-tools.sh`:

```bash
#!/bin/bash
set -e

echo "🔧 Installing KindlyGuard development tools..."

# Core tools
cargo install cargo-nextest
cargo install cargo-deny
cargo install cargo-outdated
cargo install cargo-audit
cargo install cargo-edit
cargo install cargo-machete
cargo install cargo-msrv
cargo install bacon
cargo install cargo-release
cargo install grcov
cargo install typos-cli
cargo install committed

# Nightly-only tools
rustup toolchain install nightly
cargo +nightly install cargo-udeps

# Optional tools
cargo install cargo-watch
cargo install cargo-expand
cargo install cargo-criterion

echo "✅ All tools installed!"
echo "🚀 Run 'bacon' to start development"
```

## Summary

KindlyGuard's development workflow emphasizes:

1. **Security First**: Every tool helps maintain security
2. **Fast Feedback**: Instant compilation and test results
3. **Quality Assurance**: Automated checks catch issues early
4. **Developer Experience**: Tools that make development enjoyable

Remember: Good tooling enables good security practices. By making the right thing easy to do, we build more secure software.

---

**Next Steps:**
- Read [TOOLING.md](TOOLING.md) for detailed tool documentation
- Check [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines
- See [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for command cheatsheet