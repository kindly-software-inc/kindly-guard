# KindlyGuard Tooling Guide 🔧

This guide provides detailed documentation for every development tool used in KindlyGuard. Each tool is chosen to enhance security, developer experience, or code quality.

## Table of Contents

- [Testing Tools](#testing-tools)
- [Security Tools](#security-tools)
- [Code Quality Tools](#code-quality-tools)
- [Development Experience Tools](#development-experience-tools)
- [Release Tools](#release-tools)
- [Configuration Examples](#configuration-examples)
- [Troubleshooting](#troubleshooting)

## Testing Tools

### cargo-nextest

**Purpose**: Next-generation test runner that's 60% faster than cargo test with better output.

**Installation**:
```bash
cargo install cargo-nextest
```

**Key Features**:
- Parallel test execution
- Better error messages
- Test retries
- Failure persistence
- Multiple profiles

**Usage**:
```bash
# Basic test run
cargo nextest run

# Run specific tests
cargo nextest run test_unicode

# Run with specific profile
cargo nextest run --profile ci

# Run previously failed tests
cargo nextest run --failed

# Generate junit output
cargo nextest run --profile ci --message-format libtest-json
```

**Configuration** (`.config/nextest.toml`):
```toml
[profile.default]
# Retry flaky tests twice
retries = 2
# Mark tests slow after 30s, kill after 60s
slow-timeout = { period = "30s", terminate-after = 2 }
# Use 8 test threads
test-threads = 8

[profile.ci]
# More retries in CI
retries = 3
# Don't fail fast in CI
fail-fast = false
# Generate junit reports
junit = { path = "target/nextest/junit.xml" }

[profile.coverage]
# Single-threaded for accurate coverage
test-threads = 1
retries = 0
```

### grcov

**Purpose**: Code coverage collection and reporting.

**Installation**:
```bash
cargo install grcov
rustup component add llvm-tools-preview
```

**Usage**:
```bash
# Set up environment
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="cargo-test-%p-%m.profraw"

# Clean and build
cargo clean
cargo build

# Run tests
cargo nextest run

# Generate coverage report
grcov . --binary-path ./target/debug/deps/ \
    -s . \
    -t html \
    -o target/coverage/ \
    --ignore-not-existing \
    --ignore "../*" \
    --ignore "/*" \
    --ignore "target/*" \
    --excl-start "mod tests \{" \
    --excl-stop "^\}"

# View report
open target/coverage/index.html
```

**Integration Script** (`scripts/coverage.sh`):
```bash
#!/bin/bash
set -e

export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="cargo-test-%p-%m.profraw"

cargo clean
cargo build
cargo nextest run

grcov . \
    --binary-path ./target/debug/deps/ \
    -s . \
    -t lcov \
    -o target/coverage.lcov \
    --ignore-not-existing \
    --ignore "../*" \
    --ignore "/*" \
    --ignore "target/*"

echo "Coverage report: target/coverage.lcov"
```

## Security Tools

### cargo-deny

**Purpose**: Audit dependencies for security vulnerabilities, license compliance, and supply chain attacks.

**Installation**:
```bash
cargo install cargo-deny
```

**Key Features**:
- License verification
- Security advisory checking
- Duplicate dependency detection
- Source verification

**Usage**:
```bash
# Check everything
cargo deny check

# Check specific aspects
cargo deny check licenses
cargo deny check bans
cargo deny check advisories
cargo deny check sources

# Initialize config
cargo deny init
```

**Configuration** (`deny.toml`):
```toml
[licenses]
# Confidence threshold for detecting license text
confidence-threshold = 0.8
# Allow these licenses
allow = [
    "Apache-2.0",
    "MIT",
    "BSD-3-Clause",
    "Unicode-DFS-2016",
]
# Deny specific licenses
deny = [
    "GPL-3.0",
    "AGPL-3.0",
]

[bans]
# Deny multiple versions of the same crate
multiple-versions = "warn"
# Deny wildcard dependencies
wildcards = "deny"
# Specific crates to deny
deny = [
    { name = "openssl" },  # Prefer rustls
    { name = "pcre2" },    # Security issues
]
# Skip certain duplicates that are unavoidable
skip = [
    { name = "winapi", version = "0.2.8" },
]

[advisories]
# Database urls
db-urls = [
    "https://github.com/RustSec/advisory-db",
]
# Vulnerability database path
db-path = "~/.cargo/advisory-db"
# Deny advisories based on severity
vulnerability = "deny"
unmaintained = "warn"
yanked = "warn"
notice = "warn"

[sources]
# Deny crates from unknown registries
unknown-registry = "deny"
# Deny git dependencies from unknown sources
unknown-git = "deny"
# Allow github.com and gitlab.com
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = [
    "https://github.com/",
    "https://gitlab.com/",
]
```

### cargo-audit

**Purpose**: Check for known security vulnerabilities in dependencies.

**Installation**:
```bash
cargo install cargo-audit
```

**Usage**:
```bash
# Basic audit
cargo audit

# Fix vulnerable dependencies if possible
cargo audit fix

# Audit with specific database
cargo audit --db ~/.cargo/advisory-db

# Generate JSON report
cargo audit --json > audit-report.json
```

**CI Integration**:
```yaml
# .github/workflows/security.yml
- name: Security Audit
  run: |
    cargo audit --deny warnings
```

### cargo-geiger

**Purpose**: Detect usage of unsafe Rust code.

**Installation**:
```bash
cargo install cargo-geiger
```

**Usage**:
```bash
# Check current project
cargo geiger

# Include dependencies
cargo geiger --all-dependencies

# Generate report
cargo geiger --output-format json > geiger-report.json
```

## Code Quality Tools

### cargo-clippy

**Purpose**: Rust linter with 500+ lints for correctness, performance, and style.

**Built-in with Rust**

**Usage**:
```bash
# Basic linting
cargo clippy

# Strict mode (recommended)
cargo clippy -- -W clippy::all -W clippy::pedantic

# Auto-fix issues
cargo clippy --fix

# Deny warnings in CI
cargo clippy -- -D warnings

# Security-focused lints
cargo clippy -- \
    -W clippy::unwrap_used \
    -W clippy::expect_used \
    -W clippy::panic \
    -W clippy::unimplemented \
    -W clippy::todo
```

**Configuration** (`clippy.toml`):
```toml
# Deny certain lints
disallowed-methods = [
    "std::vec::Vec::with_capacity",  # Use Vec::new() for security
]

# Configure cognitive complexity
cognitive-complexity-threshold = 30

# Too many arguments threshold
too-many-arguments-threshold = 7
```

### cargo-fmt

**Purpose**: Automatic code formatting.

**Built-in with Rust**

**Configuration** (`rustfmt.toml`):
```toml
# Basic settings
edition = "2021"
hard_tabs = false
tab_spaces = 4
newline_style = "Unix"
use_small_heuristics = "Max"

# Import organization
imports_granularity = "Crate"
imports_layout = "Mixed"
group_imports = "StdExternalCrate"

# Other settings
format_code_in_doc_comments = true
normalize_comments = true
wrap_comments = true
comment_width = 100
```

### cargo-machete

**Purpose**: Find and remove unused dependencies.

**Installation**:
```bash
cargo install cargo-machete
```

**Usage**:
```bash
# Find unused dependencies
cargo machete

# Auto-remove unused dependencies
cargo machete --fix

# Check workspace
cargo machete --workspace
```

### cargo-udeps

**Purpose**: Find unused dependencies using nightly Rust.

**Installation**:
```bash
cargo +nightly install cargo-udeps
```

**Usage**:
```bash
# Check for unused dependencies
cargo +nightly udeps

# Check all targets
cargo +nightly udeps --all-targets

# Check workspace
cargo +nightly udeps --workspace
```

### typos

**Purpose**: Fast spell checker for code and documentation.

**Installation**:
```bash
cargo install typos-cli
```

**Usage**:
```bash
# Check for typos
typos

# Fix typos automatically
typos --write-changes

# Check specific file types
typos --type rust
typos --type markdown

# Show context
typos --format long
```

**Configuration** (`.typos.toml`):
```toml
[files]
extend-exclude = [
    "target/",
    "*.lock",
    "*.svg",
]

[default.extend-words]
# Project-specific words
kindlyguard = "kindlyguard"
mcp = "mcp"
bidi = "bidi"

[type.rust.extend-words]
# Rust-specific words
ser = "ser"
de = "de"
```

## Development Experience Tools

### bacon

**Purpose**: Background rust compiler that shows errors as you code.

**Installation**:
```bash
cargo install bacon
```

**Usage**:
```bash
# Start bacon (runs until you stop it)
bacon

# Run specific job
bacon test
bacon clippy
bacon doc

# Watch specific package
bacon --package kindly-guard-server
```

**Configuration** (`bacon.toml`):
```toml
# Default job runs on file change
default_job = "check"

[jobs.check]
command = ["cargo", "check", "--all-targets", "--all-features", "--color", "always"]
need_stdout = false

[jobs.check-all]
command = ["cargo", "check", "--all-targets", "--all-features", "--color", "always"]
need_stdout = false
watch = ["tests", "benches", "examples"]

[jobs.clippy]
command = ["cargo", "clippy", "--all-targets", "--all-features", "--color", "always", "--", "-W", "clippy::all"]
need_stdout = false

[jobs.clippy-pedantic]
command = ["cargo", "clippy", "--all-targets", "--all-features", "--color", "always", "--", "-W", "clippy::pedantic"]
need_stdout = false

[jobs.test]
command = ["cargo", "nextest", "run", "--color", "always"]
need_stdout = true

[jobs.doc]
command = ["cargo", "doc", "--color", "always", "--no-deps", "--all-features"]
need_stdout = false

[jobs.security]
command = ["cargo", "deny", "check"]
need_stdout = true
```

### cargo-watch

**Purpose**: Run commands when files change.

**Installation**:
```bash
cargo install cargo-watch
```

**Usage**:
```bash
# Watch and run tests
cargo watch -x test

# Watch and check, then test
cargo watch -x check -x test

# Clear screen between runs
cargo watch -c -x "nextest run"

# Run arbitrary command
cargo watch -- echo "Files changed"
```

### cargo-expand

**Purpose**: Expand macros to see generated code.

**Installation**:
```bash
cargo install cargo-expand
```

**Usage**:
```bash
# Expand all macros
cargo expand

# Expand specific module
cargo expand scanner::unicode

# Expand and syntax highlight
cargo expand | bat -l rust

# Expand specific test
cargo expand --test test_unicode
```

## Release Tools

### cargo-release

**Purpose**: Automate the release process.

**Installation**:
```bash
cargo install cargo-release
```

**Usage**:
```bash
# Dry run (always do this first!)
cargo release --dry-run

# Release patch version
cargo release patch

# Release minor version
cargo release minor

# Release major version
cargo release major

# Release alpha
cargo release alpha

# Release with custom version
cargo release 1.2.3
```

**Configuration** (`release.toml`):
```toml
# Don't push to crates.io (useful for private repos)
publish = false

# Sign commits and tags
sign-commit = true
sign-tag = true

# Push to remote
push-remote = "origin"

# Tag message
tag-message = "Release {{version}}"

# Pre-release checks
pre-release-hook = ["cargo", "test", "--all-features"]

# Commit message
pre-release-commit-message = "chore: release {{version}}"

# Replacements in files
[[pre-release-replacements]]
file = "README.md"
search = "kindlyguard = \"[0-9.]+\""
replace = "kindlyguard = \"{{version}}\""
```

### cargo-msrv

**Purpose**: Find and verify minimum supported Rust version.

**Installation**:
```bash
cargo install cargo-msrv
```

**Usage**:
```bash
# Find MSRV
cargo msrv

# Verify current MSRV
cargo msrv verify

# List why MSRV is what it is
cargo msrv list

# Set MSRV in Cargo.toml
cargo msrv set
```

### cargo-outdated

**Purpose**: Check for outdated dependencies.

**Installation**:
```bash
cargo install cargo-outdated
```

**Usage**:
```bash
# Check for outdated dependencies
cargo outdated

# Check root dependencies only
cargo outdated --root-deps-only

# Exit with error if outdated
cargo outdated --exit-code 1

# Show only compatible updates
cargo outdated --aggressive false
```

## Configuration Examples

### Complete VS Code Configuration

**`.vscode/settings.json`**:
```json
{
  "rust-analyzer.cargo.features": "all",
  "rust-analyzer.checkOnSave.command": "clippy",
  "rust-analyzer.checkOnSave.extraArgs": [
    "--all-targets",
    "--all-features",
    "--",
    "-W",
    "clippy::all",
    "-W",
    "clippy::pedantic"
  ],
  "rust-analyzer.procMacro.enable": true,
  "rust-analyzer.cargo.buildScripts.enable": true,
  "rust-analyzer.diagnostics.experimental.enable": true,
  "[rust]": {
    "editor.formatOnSave": true,
    "editor.defaultFormatter": "rust-lang.rust-analyzer"
  },
  "files.watcherExclude": {
    "**/target/**": true
  }
}
```

### Complete CI Configuration

**`.github/workflows/ci.yml`**:
```yaml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
      with:
        components: rustfmt, clippy
    
    - name: Install tools
      run: |
        cargo install cargo-nextest
        cargo install cargo-deny
        cargo install cargo-audit
        cargo install typos-cli
    
    - name: Format check
      run: cargo fmt -- --check
    
    - name: Spell check
      run: typos
    
    - name: Clippy
      run: cargo clippy --all-targets --all-features -- -D warnings
    
    - name: Deny check
      run: cargo deny check
    
    - name: Audit
      run: cargo audit
    
    - name: Test
      run: cargo nextest run --all-features
    
    - name: Doc test
      run: cargo test --doc --all-features
```

### Pre-commit Hook

**`.git/hooks/pre-commit`**:
```bash
#!/bin/bash
set -e

echo "🔍 Running pre-commit checks..."

# Format
if ! cargo fmt -- --check; then
    echo "❌ Format check failed. Run 'cargo fmt' to fix."
    exit 1
fi

# Typos
if ! typos; then
    echo "❌ Spell check failed. Run 'typos --write-changes' to fix."
    exit 1
fi

# Clippy
if ! cargo clippy --all-targets --all-features -- -D warnings; then
    echo "❌ Clippy check failed."
    exit 1
fi

echo "✅ All pre-commit checks passed!"
```

## Troubleshooting

### Common Issues and Solutions

**cargo-nextest not finding tests**:
```bash
# Ensure test binaries are built
cargo build --tests
cargo nextest list
```

**bacon using too much CPU**:
```bash
# Limit bacon to specific paths
bacon --path src
```

**cargo-deny version conflicts**:
```bash
# See full dependency tree
cargo tree -d
cargo tree -i conflicting-package
```

**cargo-udeps false positives**:
```bash
# Check with all features
cargo +nightly udeps --all-features --all-targets
```

**Coverage not working on macOS**:
```bash
# Use llvm-cov instead
cargo install cargo-llvm-cov
cargo llvm-cov --html
```

**typos false positives**:
```bash
# Add to .typos.toml
[default.extend-words]
yourword = "yourword"
```

### Performance Optimization

**Speed up builds**:
```bash
# Use sccache
cargo install sccache
export RUSTC_WRAPPER=sccache

# Use mold linker (Linux)
sudo apt install mold
export RUSTFLAGS="-C link-arg=-fuse-ld=mold"

# Use lld linker (cross-platform)
export RUSTFLAGS="-C link-arg=-fuse-ld=lld"
```

**Parallel builds**:
```toml
# ~/.cargo/config.toml
[build]
jobs = 8  # Number of parallel jobs

[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=lld"]
```

### Tool Installation Script

Save as `scripts/install-dev-tools.sh`:

```bash
#!/bin/bash
set -e

echo "📦 Installing KindlyGuard development tools..."

# Core tools
TOOLS=(
    "cargo-nextest"
    "cargo-deny"
    "cargo-audit"
    "cargo-edit"
    "cargo-outdated"
    "cargo-machete"
    "cargo-msrv"
    "cargo-release"
    "cargo-watch"
    "cargo-expand"
    "cargo-criterion"
    "cargo-geiger"
    "bacon"
    "grcov"
    "typos-cli"
    "committed"
    "sccache"
)

# Install each tool
for tool in "${TOOLS[@]}"; do
    echo "Installing $tool..."
    cargo install "$tool" || echo "Failed to install $tool"
done

# Install nightly for udeps
rustup toolchain install nightly
cargo +nightly install cargo-udeps

# Install coverage components
rustup component add llvm-tools-preview

echo "✅ All tools installed!"
echo ""
echo "🚀 Quick start:"
echo "  1. Run 'bacon' for background compilation"
echo "  2. Run 'cargo nextest run' for fast testing"
echo "  3. Run 'cargo deny check' for security audit"
echo ""
echo "📚 See docs/TOOLING.md for detailed documentation"
```

## Summary

These tools form a comprehensive development environment that:

1. **Enhances Security**: Multiple layers of security checking
2. **Improves Quality**: Automated linting and formatting
3. **Speeds Development**: Fast feedback loops with bacon and nextest
4. **Ensures Reliability**: Comprehensive testing and coverage
5. **Simplifies Maintenance**: Easy dependency management

Remember: Good tools make good practices easier to follow. Use them consistently for best results.

---

**See Also**:
- [DEVELOPMENT_WORKFLOW.md](DEVELOPMENT_WORKFLOW.md) - Workflow overview
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
- [QUICK_REFERENCE.md](QUICK_REFERENCE.md) - Command cheatsheet