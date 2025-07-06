# Supply Chain Security for KindlyGuard

## Overview

KindlyGuard implements comprehensive supply chain security using [cargo-deny](https://github.com/EmbarkStudios/cargo-deny), a tool that helps manage and audit Rust dependencies for security vulnerabilities, license compliance, and other supply chain risks.

## Security Policies

### 1. Security Advisories ✅
- **Zero tolerance** for known vulnerabilities
- Uses the [RustSec Advisory Database](https://github.com/RustSec/advisory-db)
- Denies unmaintained crates
- Warns on security notices and yanked crates
- Daily automated vulnerability scans via GitHub Actions

### 2. License Compliance ⚖️
KindlyGuard is licensed under Apache-2.0, and all dependencies must be compatible:

**Allowed Licenses:**
- Apache-2.0 (including WITH LLVM-exception)
- MIT, MIT-0
- BSD-2-Clause, BSD-3-Clause
- ISC, Unicode-DFS-2016
- CC0-1.0, Unlicense
- Zlib

**Explicitly Denied:**
- All GPL variants (GPL-2.0, GPL-3.0, LGPL, AGPL)
- MPL (Mozilla Public License)
- CDDL, EPL

### 3. Banned Crates 🚫
The following crates are banned for security or architectural reasons:

**Security Concerns:**
- `openssl`, `native-tls` → Use `rustls` instead
- `time < 0.2` → CVE-2020-26235

**Too Heavy (per CLAUDE.md):**
- `reqwest` → Use lighter HTTP clients
- `diesel` → Use simpler database interfaces
- `actix-web` → Use lighter web frameworks

**Deprecated/Unmaintained:**
- `tempdir` → Use `tempfile`
- `term` → Use `crossterm`

### 4. Source Restrictions 🔒
- Only crates from crates.io are allowed
- No Git dependencies in production
- All sources must be explicitly approved

## Implementation

### Configuration File
The policies are defined in `/deny.toml` at the project root.

### CI/CD Integration
GitHub Actions workflow (`.github/workflows/dependency-audit.yml`):
- Runs on all PRs that modify dependencies
- Daily scheduled scans for new vulnerabilities
- Creates issues for security problems
- Blocks merges on security failures

### Pre-release Checks
The `scripts/pre-release-checklist.sh` includes:
```bash
cargo deny check advisories  # Security vulnerabilities
cargo deny check licenses    # License compliance
cargo deny check bans        # Banned crates
cargo deny check sources     # Source validation
```

### Developer Tools

#### Quick Check
```bash
./scripts/check-dependencies.sh
```
Runs all cargo-deny checks with helpful output.

#### Installation
```bash
./scripts/install-cargo-deny.sh
```
Installs cargo-deny and updates the advisory database.

## Security Impact

This implementation provides:

1. **Proactive Vulnerability Detection**: Daily scans catch new CVEs
2. **License Compliance**: Prevents GPL contamination
3. **Supply Chain Protection**: Only trusted sources allowed
4. **Continuous Monitoring**: Automated checks on every change
5. **Developer Awareness**: Local tools for pre-commit checks

## Compliance Benefits

- **OWASP A06:2021**: Addresses "Vulnerable and Outdated Components"
- **CWE-937**: Helps prevent "Using Components with Known Vulnerabilities"
- **SOC 2**: Supports security controls for third-party components
- **ISO 27001**: Aids in supplier relationship management

## Best Practices

1. **Regular Updates**: Run `cargo update` monthly with full testing
2. **Advisory Review**: Check `cargo deny check advisories` before releases
3. **License Audit**: Verify new dependencies are license-compatible
4. **Minimal Dependencies**: Question every new dependency addition
5. **Security First**: Choose secure alternatives over features

## Monitoring and Alerts

- GitHub Issues created for new vulnerabilities
- CI/CD failures on security problems
- Pre-release checklist enforcement
- Developer tooling for local checks

## Future Enhancements

1. **SBOM Generation**: Software Bill of Materials for releases
2. **Dependency Pinning**: Lock files for reproducible builds
3. **Private Registry**: Host security-vetted crates internally
4. **Automated Updates**: Dependabot-style PRs for security fixes

## Resources

- [cargo-deny Documentation](https://embarkstudios.github.io/cargo-deny/)
- [RustSec Advisory Database](https://rustsec.org/)
- [SPDX License List](https://spdx.org/licenses/)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)