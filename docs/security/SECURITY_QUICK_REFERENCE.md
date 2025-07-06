# 🔒 KindlyGuard Security Quick Reference

## 🚀 First Time Setup
```bash
# Clone and setup
git clone https://github.com/kindlyguard/kindlyguard.git
cd kindly-guard
./scripts/install-hooks.sh

# Verify hooks are working
pre-commit run --all-files
```

## 📝 Daily Development

### Before Committing
```bash
# Format code
cargo fmt

# Run lints
cargo clippy --fix

# Check for secrets
detect-secrets scan

# Test all hooks
pre-commit run
```

### Commit Messages
```bash
# ✅ Good examples
git commit -m "feat(scanner): add unicode normalization"
git commit -m "fix(auth): prevent timing attacks"
git commit -m "security: patch SQL injection in query builder"
git commit -m "perf(scanner): optimize pattern matching 3x faster"

# ❌ Bad examples  
git commit -m "fixed stuff"
git commit -m "updates"
```

### Emergency Override
```bash
# Skip hooks (MUST document why in PR)
git commit --no-verify -m "fix: emergency production hotfix"
```

## 🔍 Security Checks

### Dependencies
```bash
# Check for unused dependencies
cargo machete

# Scan for vulnerabilities
cargo audit

# Full supply chain audit
./scripts/check-dependencies.sh
```

### Code Security
```bash
# Find unsafe code
rg "unsafe\s*{" --type rust

# Check for unwrap/expect
rg "\.unwrap\(\)|\.expect\(" --type rust

# Security-focused clippy
cargo clippy -- -W clippy::all -W clippy::pedantic
```

## 🚨 Common Issues & Fixes

### "Unsafe block without SAFETY comment"
```rust
// ❌ Bad
unsafe { 
    ptr.write(value);
}

// ✅ Good
// SAFETY: ptr is valid and aligned, we have exclusive access
unsafe {
    ptr.write(value);
}
```

### "Large file detected"
```bash
# Check file size
ls -lah large_file.bin

# If needed, use Git LFS
git lfs track "*.bin"
```

### "Unused dependency found"
```bash
# Remove from Cargo.toml
# Or if false positive, add to .cargo-machete.toml:
ignored = ["dependency-name"]
```

### "Version mismatch"
```bash
# Update all versions
./scripts/update-version.sh 0.9.8
```

## 🛡️ Security Principles

1. **Never use `unwrap()` or `expect()`** - Use proper error handling
2. **Document all unsafe code** - SAFETY comments required
3. **No secrets in code** - Use environment variables
4. **Validate all input** - Pattern match on external data
5. **Minimize dependencies** - Each one is attack surface

## 📊 Pre-Release Checklist
```bash
# Run full security audit
./scripts/pre-release-checklist.sh

# Key checks performed:
# ✓ Version consistency
# ✓ All tests passing  
# ✓ No security vulnerabilities
# ✓ No unused dependencies
# ✓ Documentation updated
# ✓ Clean git status
```

## 🆘 Getting Help

- **Hook Issues**: Check `.git-hooks/` for manual scripts
- **Security Questions**: Open issue with `security` label
- **Documentation**: See `/docs/SECURITY_SHIFT_LEFT.md`

---
Remember: **Security First, Performance Second, Features Third** 🛡️