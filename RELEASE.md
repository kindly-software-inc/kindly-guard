# KindlyGuard Release Process

This document outlines the release process for KindlyGuard.

## Release Checklist

### Pre-release

- [ ] All tests passing on main branch
- [ ] Security audit completed (`cargo audit`)
- [ ] Dependencies updated (`cargo update`)
- [ ] Benchmarks show no significant regressions
- [ ] Documentation updated
- [ ] CHANGELOG.md updated with all changes
- [ ] Version numbers updated in all Cargo.toml files

### Release Steps

1. **Update Version Numbers**
   ```bash
   # Update version in workspace Cargo.toml
   # Update version in each crate's Cargo.toml
   # Commit changes
   git commit -am "chore: bump version to X.Y.Z"
   ```

2. **Create Release Tag**
   ```bash
   git tag -a vX.Y.Z -m "Release version X.Y.Z"
   git push origin main
   git push origin vX.Y.Z
   ```

3. **GitHub Release**
   - The release workflow will automatically create a draft release
   - Edit the release notes with:
     - Highlights of major features
     - Breaking changes (if any)
     - Security fixes
     - Full changelog
   - Publish the release

4. **Publish to crates.io**
   ```bash
   # The release workflow handles this automatically
   # Manual process if needed:
   cd kindly-guard-server
   cargo publish
   
   cd ../kindly-guard-cli
   cargo publish
   ```

5. **Post-release**
   - [ ] Verify binaries are available on GitHub releases
   - [ ] Verify crates are published on crates.io
   - [ ] Update documentation site
   - [ ] Announce release on relevant channels

## Version Numbering

We follow Semantic Versioning (SemVer):
- MAJOR version for incompatible API changes
- MINOR version for backwards-compatible functionality additions
- PATCH version for backwards-compatible bug fixes

## Release Schedule

- Security patches: As needed (immediate)
- Bug fixes: Bi-weekly
- Feature releases: Monthly
- Major releases: Quarterly or as needed

## Emergency Release Process

For critical security fixes:
1. Create fix on a security branch
2. Test thoroughly but quickly
3. Tag with vX.Y.Z-security
4. Release immediately
5. Notify users through security channels

## Binary Distribution

Binaries are automatically built for:
- Linux (x86_64, musl)
- Windows (x86_64)
- macOS (x86_64, ARM64)

Each release includes:
- kindly-guard-server binary
- kindly-guard-cli binary
- README and LICENSE files

## Rollback Procedure

If a release has critical issues:
1. Yank the crate version: `cargo yank --vers X.Y.Z`
2. Delete the GitHub release (keep tag for history)
3. Notify users immediately
4. Prepare patch release