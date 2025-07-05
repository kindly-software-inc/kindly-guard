# Pre-commit Hook Enhancements

## Overview

The KindlyGuard project's pre-commit hooks have been enhanced with the new Rust-based tooling to provide faster, more comprehensive checks while maintaining the security-first approach.

## New Hooks Added

### 1. **Rust Environment Check** (`rust-doctor`)
```yaml
- id: rust-doctor
  name: Check Rust environment
  entry: cargo xtask doctor --component rust
  language: system
  stages: [commit]
  types: [rust]
```
- **Purpose**: Validates Rust toolchain health before other operations
- **When**: Every commit with Rust files
- **Speed**: ~1 second

### 2. **Quick Test Suite** (`nextest-quick`)
```yaml
- id: nextest-quick
  name: Run quick tests with nextest
  entry: cargo xtask test --nextest --quick
  language: system
  stages: [push]
  types: [rust]
```
- **Purpose**: Runs fast subset of tests (3x faster with nextest)
- **When**: Only on push to avoid slowing commits
- **Speed**: ~5-10 seconds

### 3. **Cache Validation** (`cache-validation`)
```yaml
- id: cache-validation
  name: Validate build cache
  entry: cargo xtask cache stats
  language: system
  stages: [push]
```
- **Purpose**: Ensures build cache integrity
- **When**: On push to validate artifacts
- **Speed**: <1 second

## Fast Pre-commit Script

Created `/home/samuel/kindly-guard/scripts/pre-commit-rust-fast.sh`:

### Features:
- **Smart Detection**: Only runs when Rust files are changed
- **Environment Check**: Validates Rust setup with 2-second timeout
- **Cache Status**: Shows if sccache is enabled for faster builds
- **Security Scans**: 
  - ❌ Fails on `unwrap()` usage
  - ⚠️  Warns on `expect()` usage
  - ⚠️  Warns on `unsafe` blocks
- **Format Check**: Only on changed files
- **Fast Clippy**: Security-focused lints
- **Beautiful Output**: Color-coded status with fix suggestions

### Usage:
```bash
# Run manually
./scripts/pre-commit-rust-fast.sh

# Or let pre-commit run it
git commit -m "feat: add new feature"
```

## Rust Tools Pre-commit Script

Created `/home/samuel/kindly-guard/scripts/pre-commit-rust-tools.sh`:

### Checks:
1. **Security Scan**: `kindly-tools scan --staged`
2. **Code Quality**: `kindly-tools check --quality`
3. **Project Health**: `xtask doctor --quiet`
4. **Flaky Tests**: `xtask flaky check`
5. **Config Validation**: `xtask validate-config`
6. **Cache Stats**: Shows sccache performance

## Enhanced Installation Script

Updated `scripts/install-hooks.sh` to:

### Auto-build Tools:
```bash
# Automatically builds if not found:
- kindly-tools (in release or debug)
- xtask (in release or debug)
```

### sccache Integration:
- Detects if sccache is installed
- Uses it automatically for faster builds
- Provides installation instructions

### Performance Tips:
```bash
# Install sccache for 70% faster builds
cargo install sccache

# Enable it
export RUSTC_WRAPPER=sccache

# Check stats
sccache --show-stats
```

## Hook Execution Order

1. **Environment** → Rust toolchain validation
2. **Format** → Code style consistency
3. **Lint** → Clippy warnings
4. **Security** → Multiple security checks
5. **Tests** → Quick test suite (push only)
6. **Cache** → Build artifact validation

## Performance Optimizations

### Commit-time Hooks (Fast):
- Format check: ~1s
- Basic linting: ~2s
- Security patterns: ~1s
- **Total**: ~5 seconds

### Push-time Hooks (Thorough):
- Quick tests: ~10s
- Full security audit: ~5s
- Cache validation: ~1s
- **Total**: ~20 seconds

## Manual Testing

```bash
# Test all hooks
pre-commit run --all-files

# Test specific hook
pre-commit run rust-doctor --all-files

# Run new tools directly
cargo xtask doctor
cargo xtask test --nextest --quick
cargo xtask cache stats

# Run fast checks
./scripts/pre-commit-rust-fast.sh
```

## Benefits

1. **Faster Feedback**: Catches issues in seconds, not minutes
2. **Security First**: Multiple layers of security validation
3. **Developer Friendly**: Clear messages with fix suggestions
4. **Cached Builds**: 70% faster with sccache integration
5. **Flexible**: Different checks for commit vs push

## Troubleshooting

### Hooks Not Running?
```bash
# Reinstall
./scripts/install-hooks.sh

# Verify installation
pre-commit --version
ls -la .git/hooks/
```

### Slow Performance?
```bash
# Enable caching
cargo xtask cache setup --backend local

# Check cache
cargo xtask cache stats
```

### False Positives?
```bash
# Skip hooks temporarily
git commit --no-verify

# Disable specific check
# Edit .pre-commit-config.yaml
```

## Next Steps

1. Run `./scripts/install-hooks.sh` to get the enhanced hooks
2. Enable sccache for 70% faster builds
3. Try `cargo xtask --interactive` for guided workflows
4. Use `kindly-tools dev` for development mode

The enhanced pre-commit hooks provide a robust safety net while maintaining fast feedback cycles for developers!