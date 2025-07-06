# CI Coverage Guide

## Overview

KindlyGuard uses cargo-llvm-cov for code coverage in CI. The setup follows Rust ecosystem best practices.

## CI Configuration

The coverage job in `.github/workflows/ci.yml` runs cargo-llvm-cov directly:

```yaml
coverage:
  env:
    CARGO_INCREMENTAL: 0  # Required for accurate coverage
  steps:
    - Install Rust with llvm-tools-preview
    - Install cargo-llvm-cov via taiki-e/install-action
    - Run: cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
    - Upload to Codecov
```

## Local Development

For local coverage generation, use the xtask command:

```bash
cargo xtask coverage
```

This provides additional options like:
- `--html` - Generate HTML report
- `--open` - Open report in browser
- `--nextest` - Use nextest runner
- `--show-missing` - Show uncovered lines

## Why Different Approaches?

- **CI**: Uses cargo-llvm-cov directly for simplicity and reliability
- **Local**: Uses xtask for convenience features and better UX

## Troubleshooting

If coverage fails in CI:
1. Check that llvm-tools-preview is installed
2. Verify CARGO_INCREMENTAL=0 is set
3. Ensure the Rust version is compatible

If coverage fails locally:
1. Run `cargo xtask doctor` to check environment
2. Install cargo-llvm-cov: `cargo install cargo-llvm-cov`
3. Ensure llvm-tools-preview: `rustup component add llvm-tools-preview`