# Local CI/CD Guide

## Overview

KindlyGuard uses a Rust-based local CI/CD system powered by `cargo xtask`. This allows you to run the full CI pipeline locally before pushing changes, saving time and GitHub Actions minutes.

## Quick Start

```bash
# Run full local CI pipeline
cargo xtask local-ci

# Run quick CI (skip slow tests)
cargo xtask local-ci --quick

# Run without security audits
cargo xtask local-ci --no-security

# Clean CI artifacts before running
cargo xtask local-ci --clean
```

## CI Pipeline Steps

The local CI runs the following steps:

1. **Format Check** - Ensures code is properly formatted (`cargo fmt`)
2. **Clippy Lints** - Checks for common mistakes and style issues
3. **Build** - Compiles all features to ensure no compilation errors
4. **Tests** - Runs test suite (with optional coverage)
5. **Security Audit** - Checks dependencies for vulnerabilities
6. **Documentation** - Builds documentation to check for errors

## CI Artifacts

All CI artifacts are stored in the `.ci/` directory:

```
.ci/
├── local/          # Local CI configuration
├── cache/          # Build cache
├── reports/        # Test and security reports
├── artifacts/      # Build artifacts
└── logs/           # CI run logs
```

## Configuration

The local CI configuration is stored in `.ci/local/config.toml`:

```toml
[ci]
# Use nextest for faster test execution
use_nextest = true

# Generate coverage reports
coverage = true

# Run security audits
security_audit = true

# Directory paths
cache_dir = ".ci/cache"
reports_dir = ".ci/reports"
artifacts_dir = ".ci/artifacts"
logs_dir = ".ci/logs"

[test]
# Test timeout in seconds
timeout = 300

# Retry flaky tests
retry_flaky = true
max_retries = 3

[security]
# Fail on high severity vulnerabilities
fail_on_severity = "high"

# Audit dependencies
audit_dependencies = true

# Check for security advisories
check_advisories = true

[build]
# Build all targets
all_targets = true

# Build with all features
all_features = true

# Release optimizations
release = true

[cache]
# Cache provider (local, s3, redis, gha)
provider = "local"

# Cache compression
compression = true

# Max cache size in GB
max_size = 10
```

## GitHub Actions Integration

GitHub Actions workflows are configured to run only on version tags (`v*.*.*`). This ensures that:

1. Regular development doesn't consume Actions minutes
2. CI runs locally during development for fast feedback
3. Official releases get full CI/CD treatment

To trigger GitHub Actions manually:
- Go to Actions tab in GitHub
- Select the workflow
- Click "Run workflow"

## Best Practices

1. **Run Before Committing**: Always run `cargo xtask local-ci --quick` before committing
2. **Full CI Before Release**: Run `cargo xtask local-ci` before creating release tags
3. **Fix Issues Locally**: Address any CI failures locally before pushing
4. **Cache Management**: Periodically clean cache with `cargo xtask cache clear`

## Troubleshooting

### CI Fails Locally but Not on GitHub
- Ensure all required tools are installed: `cargo xtask doctor`
- Check for environment differences
- Clean and rebuild: `cargo xtask local-ci --clean`

### Performance Issues
- Enable caching: `cargo xtask cache setup --backend local`
- Use nextest for faster tests: `cargo install cargo-nextest`
- Run quick mode for iterative development

### Missing Tools
The CI will skip steps for missing tools. Install recommended tools:
```bash
cargo install cargo-audit cargo-deny cargo-llvm-cov
```

## Advanced Usage

### Running Specific Steps
While the local CI runs all steps, you can run individual commands:

```bash
# Just format check
cargo fmt -- --check

# Just tests with coverage
cargo xtask coverage --lcov

# Just security audit
cargo xtask security
```

### Integration with IDEs
Configure your IDE to run local CI:
- **VS Code**: Add task in `.vscode/tasks.json`
- **IntelliJ**: Create run configuration
- **Neovim**: Add command mapping

### Continuous Local CI
For continuous feedback during development:
```bash
# Watch mode (requires cargo-watch)
cargo watch -x "xtask local-ci --quick"
```