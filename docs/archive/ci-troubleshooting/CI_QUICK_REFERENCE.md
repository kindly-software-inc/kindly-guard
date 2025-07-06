# CI/CD Quick Reference Card

## Common CI Issues and Solutions

### 1. Workspace Member Missing
```toml
# Check Cargo.toml workspace members match actual directories
[workspace]
members = ["kindly-guard-server"]  # Remove any deleted crates
```

### 2. Cross Compilation Failures
```yaml
# Use modern cross version in CI
- uses: taiki-e/install-action@v2
  with:
    tool: cross@0.3.1  # NOT 0.2.5!
```

### 3. Compilation Warnings
```rust
// Fix unused variables properly
let _unused_var = value;  // Add underscore prefix
#[allow(dead_code)]       // Or allow if intentional
```

### 4. GitHub Runner Issues
- Use ubuntu-22.04 or ubuntu-latest
- Install tools via taiki-e/install-action@v2
- Check cross version compatibility

## Essential Tool Versions
- **Rust**: 1.81.0 (MSRV)
- **Cross**: 0.3.1 (for cross-compilation)
- **cargo-audit**: 0.18.3
- **cargo-deny**: 0.14.24

## Quick Debugging Commands
```bash
# Check workspace structure
cargo metadata --no-deps | jq '.workspace_members'

# Test cross locally
cross build --target aarch64-unknown-linux-gnu

# Run CI checks locally
cargo clippy -- -D warnings
cargo test --all-features
cargo audit
```

## CI Configuration Template
```yaml
- uses: taiki-e/install-action@v2
  with:
    tool: cross@0.3.1,cargo-audit@0.18.3,cargo-deny@0.14.24
```

## Platform Matrix
| Platform | Target | Method |
|----------|--------|--------|
| Linux x64 | x86_64-unknown-linux-gnu | Native |
| Linux ARM | aarch64-unknown-linux-gnu | Cross |
| macOS x64 | x86_64-apple-darwin | Native |
| macOS ARM | aarch64-apple-darwin | Native |
| Windows | x86_64-pc-windows-msvc | Native |