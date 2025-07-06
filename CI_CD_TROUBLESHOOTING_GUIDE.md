# CI/CD Troubleshooting Guide for KindlyGuard

## Quick Diagnosis Checklist

### 1. Check Current Build Status
```bash
# View latest runs
gh run list --workflow=release.yml --limit 5

# Get detailed job info for a specific run
gh run view <RUN_ID> --json jobs --jq '.jobs[] | {name: .name, status: .status, conclusion: .conclusion}'

# View logs for failed job
gh run view <RUN_ID> --log-failed
```

### 2. Common Error Patterns & Solutions

#### OpenSSL Linking Errors
**Symptoms:**
- `error: cannot produce cdylib for target x86_64-unknown-linux-musl`
- `undefined reference to SSL_*` functions
- `cannot find -lssl` or `-lcrypto`

**Solutions:**
1. Switch to rustls (what we did in v0.11.13):
   ```toml
   reqwest = { version = "0.11", default-features = false, features = ["json", "rustls-tls"] }
   ```

2. If OpenSSL is required:
   ```yaml
   env:
     OPENSSL_STATIC: "1"
     OPENSSL_LIB_DIR: "/usr/lib/x86_64-linux-musl"
     OPENSSL_INCLUDE_DIR: "/usr/include"
   ```

#### Cross-compilation Target Errors
**Symptoms:**
- `error: failed to run custom build command`
- `target X may not be installed`

**Solutions:**
1. Install target:
   ```yaml
   - name: Install target
     run: rustup target add x86_64-unknown-linux-musl
   ```

2. Use cross tool:
   ```yaml
   - name: Install cross
     run: cargo install cross --version 0.2.5
   ```

#### Workspace Configuration Errors
**Symptoms:**
- `failed to load manifest for workspace member`
- `could not find Cargo.toml`

**Solutions:**
1. Check workspace paths in root Cargo.toml
2. Ensure all member paths are relative and correct
3. Remove non-existent members

### 3. Debugging Strategies

#### Local Testing
```bash
# Test cross-compilation locally
cross build --target x86_64-unknown-linux-musl

# Check dependency tree
cargo tree --target x86_64-unknown-linux-musl

# Find problematic dependencies
cargo tree | grep -E "(openssl|native-tls)"

# Test with same features as CI
cargo build --all-features --target x86_64-unknown-linux-musl
```

#### GitHub Actions Debugging
1. Add debug steps to workflow:
   ```yaml
   - name: Debug - Show environment
     run: |
       echo "Rust version: $(rustc --version)"
       echo "Cargo version: $(cargo --version)"
       echo "Current directory: $(pwd)"
       echo "Directory contents:"
       ls -la
   ```

2. Enable debug logging:
   ```yaml
   env:
     ACTIONS_STEP_DEBUG: true
     RUST_BACKTRACE: 1
   ```

3. Add checkpoint outputs:
   ```yaml
   - name: Check binary exists
     run: |
       ls -la target/release/
       file target/release/kindlyguard
   ```

### 4. Platform-Specific Issues

#### Linux musl
- Most problematic due to static linking requirements
- Avoid C dependencies when possible
- Use Alpine Linux docker image for testing

#### macOS
- Usually straightforward
- Watch for SDK version issues
- May need: `SDKROOT=$(xcrun -sdk macosx --show-sdk-path)`

#### Windows
- Different executable extension (.exe)
- Path separators
- May need Visual C++ redistributables

### 5. Recovery Strategies

#### If Everything Fails
1. **Disable problematic targets temporarily:**
   ```yaml
   matrix:
     include:
       # Comment out problematic targets
       # - { os: ubuntu-latest, target: x86_64-unknown-linux-musl }
   ```

2. **Build only native targets:**
   ```yaml
   - name: Build native
     run: cargo build --release
   ```

3. **Use Docker for consistent environment:**
   ```yaml
   - name: Build in Docker
     run: |
       docker run --rm -v "$PWD":/workspace \
         rust:alpine \
         sh -c "cd /workspace && cargo build --release"
   ```

### 6. Verification Steps

After fixing issues:
1. Check all targets build locally
2. Verify binaries are static: `ldd binary_name`
3. Test on clean environment
4. Create minimal test case

### 7. Useful Commands for Investigation

```bash
# Show all workflow runs
gh workflow view release.yml

# Re-run failed workflow
gh run rerun <RUN_ID>

# Download artifacts from failed run
gh run download <RUN_ID>

# Check specific job logs
gh run view <RUN_ID> --log --job=<JOB_ID>

# List all available targets
rustup target list

# Check installed components
rustup show

# Verify static linking (Linux)
ldd target/x86_64-unknown-linux-musl/release/kindlyguard
# Should output: "not a dynamic executable"
```

### 8. Environment Variables Reference

Key environment variables for builds:
- `OPENSSL_STATIC`: Force static linking of OpenSSL
- `OPENSSL_LIB_DIR`: Path to OpenSSL libraries
- `OPENSSL_INCLUDE_DIR`: Path to OpenSSL headers
- `PKG_CONFIG_ALLOW_CROSS`: Allow pkg-config in cross-compilation
- `RUSTFLAGS`: Additional compiler flags
- `CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER`: Custom linker

### 9. Quick Fixes Tried So Far

| Version | Fix Attempted | Result |
|---------|--------------|---------|
| v0.11.4 | Fixed workspace paths | ❌ Other issues |
| v0.11.5 | Pinned cross version | ❌ Still failing |
| v0.11.6-7 | Fixed warnings | ✅ Warnings gone, ❌ CI failed |
| v0.11.8 | Updated cross tool | ❌ cargo-dist issues |
| v0.11.9 | cargo-dist config | ❌ Fundamental issue |
| v0.11.10 | Custom workflow | ❌ OpenSSL issues |
| v0.11.11 | OpenSSL env vars | ❌ YAML syntax |
| v0.11.12 | Fixed YAML | ❌ OpenSSL linking |
| v0.11.13 | Switch to rustls | ⏳ In progress |

### 10. Next Escalation Steps

If v0.11.13 fails:
1. Check exact error in logs
2. Search for any remaining OpenSSL dependencies
3. Consider building in stages (build then package)
4. Try alternative build methods (Docker, buildx)
5. Temporarily reduce target matrix
6. Engage Rust community for platform-specific help

---

Remember: Each failure teaches us something. Document everything!