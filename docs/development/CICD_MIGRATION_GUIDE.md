# CI/CD Migration Guide: Shell Scripts to Cargo Xtask

This guide documents the migration from shell scripts to `cargo xtask` for the KindlyGuard project, providing a unified and cross-platform build system.

## Overview

We've migrated from platform-specific shell scripts to a Rust-based `cargo xtask` system. This provides:
- **Cross-platform compatibility** (Windows, macOS, Linux)
- **Type-safe task definitions**
- **Better error handling and reporting**
- **Integrated with Rust toolchain**
- **Self-documenting commands**

## Migration Table

### Build Commands

| Old Script | New Xtask Command | Description |
|------------|-------------------|-------------|
| `scripts/build_all.sh` | `cargo xtask build --all` | Build all components |
| `scripts/build_server.sh` | `cargo xtask build --server` | Build server only |
| `scripts/build_cli.sh` | `cargo xtask build --cli` | Build CLI only |
| `scripts/build_shield.sh` | `cargo xtask build --shield` | Build shield UI only |
| `scripts/build_release.sh` | `cargo xtask build --all --release` | Build all in release mode |
| `scripts/build_secure.sh` | `cargo xtask build-secure` | Build with secure profile |

### Testing Commands

| Old Script | New Xtask Command | Description |
|------------|-------------------|-------------|
| `scripts/test_all.sh` | `cargo xtask test` | Run all tests |
| `scripts/test_unit.sh` | `cargo xtask test --unit` | Run unit tests only |
| `scripts/test_integration.sh` | `cargo xtask test --integration` | Run integration tests |
| `scripts/test_security.sh` | `cargo xtask test --security` | Run security tests |
| `scripts/test_property.sh` | `cargo xtask test --property` | Run property tests |
| `scripts/run_benchmarks.sh` | `cargo xtask bench` | Run benchmarks |

### Quality Assurance Commands

| Old Script | New Xtask Command | Description |
|------------|-------------------|-------------|
| `scripts/lint.sh` | `cargo xtask lint` | Run clippy with all lints |
| `scripts/format_check.sh` | `cargo xtask fmt --check` | Check formatting |
| `scripts/format.sh` | `cargo xtask fmt` | Format code |
| `scripts/check_unsafe.sh` | `cargo xtask check-unsafe` | Audit unsafe code usage |
| `scripts/audit.sh` | `cargo xtask audit` | Security vulnerability audit |
| `scripts/coverage.sh` | `cargo xtask coverage` | Generate code coverage |

### CI/CD Commands

| Old Script | New Xtask Command | Description |
|------------|-------------------|-------------|
| `scripts/ci_build.sh` | `cargo xtask ci` | Full CI pipeline |
| `scripts/pre_commit.sh` | `cargo xtask pre-commit` | Pre-commit checks |
| `scripts/verify_proprietary.sh` | `cargo xtask verify-protection` | Verify proprietary protection |

### Development Commands

| Old Script | New Xtask Command | Description |
|------------|-------------------|-------------|
| `scripts/dev_server.sh` | `cargo xtask dev` | Run development server |
| `scripts/watch.sh` | `cargo xtask watch` | Watch and rebuild |
| `scripts/clean.sh` | `cargo xtask clean` | Clean build artifacts |
| `scripts/doc.sh` | `cargo xtask doc` | Generate documentation |

### Deployment Commands

| Old Script | New Xtask Command | Description |
|------------|-------------------|-------------|
| `scripts/package.sh` | `cargo xtask package` | Create distribution package |
| `scripts/install.sh` | `cargo xtask install` | Install to system |
| `scripts/deploy_local.sh` | `cargo xtask deploy --local` | Deploy locally |

## Benefits of the New System

### 1. **Cross-Platform Compatibility**
- No more maintaining separate `.sh` and `.bat` files
- Works identically on Windows, macOS, and Linux
- No dependency on shell interpreters

### 2. **Type Safety**
```rust
// Old way (error-prone string manipulation)
# scripts/build_all.sh
cargo build --all-features --workspace

// New way (type-safe commands)
cmd!("cargo", "build", "--all-features", "--workspace").run()?;
```

### 3. **Better Error Handling**
- Proper error propagation with `Result<T, E>`
- Detailed error messages
- Automatic cleanup on failure

### 4. **Self-Documenting**
```bash
# List all available tasks
cargo xtask --help

# Get help for specific task
cargo xtask build --help
```

### 5. **Composability**
Tasks can easily call other tasks:
```rust
fn ci() -> Result<()> {
    build(BuildArgs { all: true, release: true })?;
    test(TestArgs::default())?;
    lint()?;
    Ok(())
}
```

### 6. **Integrated Tooling**
- Uses cargo's dependency management
- Integrates with rust-analyzer
- Benefits from Rust's ecosystem

## Quick Start Guide

### For Developers

1. **Running tasks** is now simpler:
   ```bash
   # Instead of:
   ./scripts/build_all.sh
   
   # Use:
   cargo xtask build --all
   ```

2. **Common workflows**:
   ```bash
   # Development cycle
   cargo xtask dev              # Start dev server
   cargo xtask test             # Run tests
   cargo xtask fmt              # Format code
   cargo xtask lint             # Check code quality
   
   # Before committing
   cargo xtask pre-commit       # Run all checks
   
   # Full CI locally
   cargo xtask ci              # Run entire CI pipeline
   ```

3. **Getting help**:
   ```bash
   # See all available tasks
   cargo xtask --help
   
   # Get details on a specific task
   cargo xtask test --help
   ```

### For CI/CD Systems

Update your CI configuration:

**GitHub Actions Example:**
```yaml
# Old
- name: Build
  run: ./scripts/ci_build.sh

# New
- name: Build
  run: cargo xtask ci
```

**GitLab CI Example:**
```yaml
# Old
build:
  script:
    - ./scripts/build_all.sh

# New  
build:
  script:
    - cargo xtask build --all
```

### For Windows Users

No more need for WSL or Git Bash! All commands work natively:
```powershell
# These now work in PowerShell/CMD
cargo xtask build --all
cargo xtask test
cargo xtask lint
```

## Migration Checklist

- [ ] Remove old scripts directory
- [ ] Update CI/CD configurations
- [ ] Update documentation references
- [ ] Update developer onboarding docs
- [ ] Update README with new commands
- [ ] Remove script dependencies from setup instructions

## Troubleshooting

### "cargo xtask not found"
Make sure you're in the workspace root:
```bash
cd kindly-guard
cargo xtask --help
```

### Old muscle memory
Create aliases in your shell config:
```bash
# ~/.bashrc or ~/.zshrc
alias kb="cargo xtask build"
alias kt="cargo xtask test"
alias kl="cargo xtask lint"
```

### Need to run old scripts
During transition, old scripts are archived in `scripts.archive/`. They will be removed after full migration.

## Summary

The migration to `cargo xtask` provides a modern, maintainable, and cross-platform build system that integrates seamlessly with Rust tooling. All functionality from the old shell scripts has been preserved while gaining type safety, better error handling, and improved developer experience.

For questions or issues with the migration, please file an issue in the project repository.