# Minimum Supported Rust Version (MSRV) Policy

## Current MSRV: 1.81

KindlyGuard maintains a Minimum Supported Rust Version (MSRV) policy to balance stability, security, and access to modern Rust features.

## Policy Overview

### MSRV: 1.81.0
- **Established**: January 2025
- **Next Review**: July 2025
- **Update Cycle**: Every 6 months

## Rationale

We chose Rust 1.81 as our MSRV for the following reasons:

### Security Features
- **Stable async traits**: Essential for our async security scanning
- **Improved const evaluation**: Enables compile-time security checks
- **Better error handling**: Critical for security-sensitive code
- **Enhanced pattern matching**: Cleaner threat detection code

### Ecosystem Compatibility
- Most production environments have access to Rust 1.81+
- Major Linux distributions ship compatible versions:
  - Ubuntu 24.04 LTS: 1.75+ (can use rustup)
  - RHEL 9: 1.62+ (can use rustup)
  - Debian 12: 1.63+ (can use rustup)
- Enterprise users typically use rustup for version management

### Feature Requirements
KindlyGuard requires these Rust features:
- `async`/`await` (1.39+)
- `const generics` (1.51+)
- Edition 2021 (1.56+)
- `let-else` (1.65+)
- Stabilized async traits (1.75+)
- Improved async performance (1.79+)
- Security-relevant stdlib improvements (1.81+)

## Update Schedule

We review and potentially update the MSRV every 6 months:
- **January**: Major review, consider bumping MSRV
- **July**: Major review, consider bumping MSRV

Minor security updates may prompt earlier MSRV changes if critical security features become available.

## Version Selection Criteria

When updating MSRV, we consider:
1. **Security**: New security features or fixes
2. **Stability**: Version must be at least 6 months old
3. **Adoption**: >70% of surveyed enterprise users must have access
4. **Features**: Significant benefit to KindlyGuard's security mission
5. **Dependencies**: Key dependencies must support the version

## How to Request MSRV Changes

### For Users
If you need a different MSRV:
1. Open an issue with the title "MSRV Request: [version]"
2. Explain your constraints (OS, environment, policies)
3. Describe workarounds you've tried
4. We'll evaluate within 2 weeks

### For Contributors
To propose an MSRV bump:
1. Open a PR titled "chore: Bump MSRV to [version]"
2. Update:
   - `Cargo.toml` (rust-version field)
   - `rust-toolchain.toml`
   - `.github/workflows/test.yml`
   - This document
3. Provide justification for the bump
4. Ensure all CI passes with new version

## Testing Requirements

All code must compile and pass tests on the MSRV:
```bash
# Install MSRV
rustup install 1.81

# Test with MSRV
rustup run 1.81 cargo test --all-features
```

CI automatically tests against:
- MSRV (1.81)
- Stable
- Beta

## Compatibility Promise

We guarantee:
- No MSRV bumps in patch releases (x.y.Z)
- MSRV bumps in minor releases (x.Y.z) only with strong justification
- MSRV bumps in major releases (X.y.z) following our schedule
- Clear documentation of MSRV in all releases

## Security Considerations

### Why MSRV Matters for Security
1. **Predictability**: Security teams need stable deployment targets
2. **Compliance**: Many environments have Rust version restrictions
3. **Validation**: Security audits require known compiler behavior
4. **Trust**: Consistent MSRV builds trust in our stability

### Emergency Security Updates
If a critical security issue requires a newer Rust version:
1. We'll release a security advisory
2. Provide a patch for the current MSRV if possible
3. Document the security trade-off clearly
4. Fast-track the next MSRV update

## Checking MSRV Compatibility

Before each release:
```bash
# Run MSRV checks
cargo +1.81 check --all-features
cargo +1.81 test --all-features
cargo +1.81 clippy --all-features

# Verify rust-version in Cargo.toml
grep rust-version Cargo.toml

# Check CI is green for MSRV
```

## Historical MSRV Changes

| Version | MSRV | Date | Reason |
|---------|------|------|--------|
| 1.0.0   | 1.81 | Jan 2025 | Initial release |

## Related Documentation

- [Development Workflow](DEVELOPMENT_WORKFLOW.md)
- [Release Process](AUTOMATED_RELEASE_GUIDE.md)
- [Security Audit Report](SECURITY_AUDIT_REPORT.md)

## Questions?

For MSRV-related questions:
- Open an issue with the "msrv" label
- Ask in discussions
- Email security@kindlyguard.com for sensitive concerns