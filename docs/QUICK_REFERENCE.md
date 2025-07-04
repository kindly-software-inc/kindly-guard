# KindlyGuard Quick Reference 🚀

A quick command reference for KindlyGuard development. Keep this handy!

## 🔥 Most Used Commands

```bash
# Start development
bacon                          # Background compiler (keep running)
cargo nextest run             # Run tests (fast!)
cargo deny check              # Security check

# Before committing
cargo fmt                     # Format code
typos --write-changes         # Fix typos
cargo clippy --fix           # Fix lints
committed --staged           # Check commit message
```

## 🧪 Testing Commands

```bash
# Run tests
cargo nextest run                      # All tests
cargo nextest run test_unicode         # Specific test
cargo nextest run --failed             # Failed tests only
cargo nextest run --profile ci         # CI mode (with retries)

# Coverage
./scripts/coverage.sh                  # Generate coverage report
open target/coverage/index.html        # View coverage

# Benchmarks
cargo bench                            # Run benchmarks
cargo criterion                        # Better benchmarking
```

## 🛡️ Security Commands

```bash
# Security audits
cargo deny check                       # Complete security check
cargo deny check licenses              # License check only
cargo deny check advisories            # CVE check only
cargo audit                           # Alternative CVE scanner
cargo geiger                          # Count unsafe code

# Find issues
cargo +nightly udeps                  # Unused dependencies
cargo machete                         # Alternative unused dep finder
cargo outdated                        # Check for updates
```

## 🔨 Code Quality

```bash
# Formatting and linting
cargo fmt                             # Format code
cargo fmt -- --check                  # Check formatting
cargo clippy                          # Basic linting
cargo clippy -- -W clippy::pedantic   # Strict linting
cargo clippy --fix                    # Auto-fix issues

# Spell check
typos                                 # Check for typos
typos --write-changes                 # Fix typos
typos --format long                   # Show context

# Documentation
cargo doc --no-deps --open            # Build & view docs
cargo doc --no-deps --all-features    # Docs with all features
```

## 🚀 Development Tools

```bash
# Background compilation
bacon                                 # Default check mode
bacon test                           # Test mode
bacon clippy                         # Clippy mode
bacon doc                            # Documentation mode

# Watch mode
cargo watch -x check                  # Watch and check
cargo watch -x "nextest run"          # Watch and test
cargo watch -c -x check               # Clear screen between runs

# Expand macros
cargo expand                          # Expand all macros
cargo expand scanner::unicode         # Expand specific module
```

## 📦 Dependency Management

```bash
# Add dependencies
cargo add serde --features derive     # Add with features
cargo add --dev proptest              # Add dev dependency

# Update dependencies
cargo update                          # Update all
cargo update -p serde                 # Update specific

# Check dependencies
cargo tree                            # Dependency tree
cargo tree -d                         # Show duplicates
cargo tree -i serde                   # Reverse dependencies
```

## 🚢 Release Commands

```bash
# Release process
cargo release --dry-run               # Always dry run first!
cargo release patch                   # Bump patch version
cargo release minor                   # Bump minor version
cargo release major                   # Bump major version

# Version checks
cargo msrv                           # Find minimum Rust version
cargo msrv verify                    # Verify MSRV
```

## 🔍 Analysis Commands

```bash
# Code analysis
tokei                                # Count lines of code
cargo bloat                          # Analyze binary size
cargo bloat --crates                 # By crate
cargo bloat --time                   # Compile time analysis

# Performance
cargo build --timings                # Build performance
cargo clean && cargo build --timings # Fresh timing
```

## 🐛 Debugging Commands

```bash
# Debugging
RUST_LOG=debug cargo run             # Debug logging
RUST_LOG=kindly_guard=trace cargo run # Trace logging
RUST_BACKTRACE=1 cargo run           # With backtrace
RUST_BACKTRACE=full cargo run        # Full backtrace

# Test debugging
cargo test -- --nocapture            # Show print output
cargo nextest run --no-capture       # nextest equivalent
```

## 📝 Git Commands

```bash
# Conventional commits
git commit -m "feat(scanner): add feature"
git commit -m "fix(server): fix bug"
git commit -m "docs: update README"
git commit -m "test: add test coverage"
git commit -m "perf: improve performance"
git commit -m "refactor: clean up code"
git commit -m "chore: update dependencies"

# Useful git aliases
git config --global alias.lg "log --oneline --graph --all"
git config --global alias.st "status -sb"
```

## 🎯 Common Workflows

### Starting work on a new feature
```bash
git checkout -b feature/my-feature
bacon                               # Start in another terminal
cargo nextest run                   # Ensure tests pass
```

### Before creating a PR
```bash
# Format and fix
cargo fmt
typos --write-changes
cargo clippy --fix

# Run all checks
cargo nextest run --all-features
cargo deny check
cargo audit
cargo doc --no-deps

# Commit
committed --staged                  # Verify message
git push
```

### Investigating a bug
```bash
# Find when it was introduced
git bisect start
git bisect bad                      # Current commit is bad
git bisect good v1.0.0             # v1.0.0 was good
cargo nextest run test_name         # Test at each step

# Debug specific test
RUST_LOG=trace cargo nextest run test_name --no-capture
```

### Performance optimization
```bash
# Benchmark baseline
git checkout main
cargo bench -- --save-baseline main

# Make changes
git checkout -
# ... make optimizations ...

# Compare
cargo bench -- --baseline main
```

## 🔧 Environment Setup

### Recommended shell aliases
```bash
# Add to ~/.bashrc or ~/.zshrc
alias ct='cargo nextest run'
alias cb='cargo build'
alias cc='cargo check'
alias cf='cargo fmt'
alias cl='cargo clippy'
alias cd='cargo doc --no-deps --open'
alias cw='cargo watch -c -x check'

# KindlyGuard specific
alias kg='cd ~/kindly-guard'
alias kgtest='cargo nextest run --all-features'
alias kgsec='cargo deny check && cargo audit'
```

### VS Code tasks.json
```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Test",
      "type": "shell",
      "command": "cargo nextest run",
      "group": {
        "kind": "test",
        "isDefault": true
      }
    },
    {
      "label": "Security Check",
      "type": "shell",
      "command": "cargo deny check && cargo audit"
    },
    {
      "label": "Format & Lint",
      "type": "shell",
      "command": "cargo fmt && cargo clippy --fix && typos --write-changes"
    }
  ]
}
```

## 📊 Performance Tips

```bash
# Speed up builds
export RUSTC_WRAPPER=sccache        # Use sccache
export CARGO_INCREMENTAL=1          # Incremental compilation

# Parallel execution
export CARGO_BUILD_JOBS=8           # Parallel cargo jobs

# Fast linking (Linux)
export RUSTFLAGS="-C link-arg=-fuse-ld=mold"

# Profile guided optimization
cargo pgo build                     # If using cargo-pgo
```

## 🆘 Troubleshooting

```bash
# Clean build
cargo clean
rm -rf target/

# Reset bacon
bacon --clear
rm -rf target/bacon-cache

# Update everything
rustup update
cargo update
cargo install-update -a            # Update installed tools

# Check tool versions
cargo --version
rustc --version
cargo nextest --version
```

## 📌 Essential Files

- `Cargo.toml` - Package manifest
- `deny.toml` - cargo-deny configuration
- `.config/nextest.toml` - nextest configuration
- `bacon.toml` - bacon configuration
- `.typos.toml` - typos configuration
- `rustfmt.toml` - formatting rules
- `clippy.toml` - clippy configuration

---

💡 **Pro tip**: Keep `bacon` running in a terminal while you work for instant feedback!

📚 For detailed documentation, see [TOOLING.md](TOOLING.md)