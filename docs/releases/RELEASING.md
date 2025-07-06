# KindlyGuard Release Process

This document describes the automated and manual processes for creating and publishing releases of KindlyGuard.

## Overview

KindlyGuard releases include:
- Binary releases for multiple platforms (Linux, macOS, Windows)
- NPM packages with platform-specific binaries
- Cargo crates published to crates.io
- Docker images
- GitHub releases with checksums

## Quick Start: Automated Release

For most releases, use the automated release system:

```bash
# Simple one-command release
./scripts/release.sh 0.9.6

# Or with more control
./scripts/update-version.sh --release 0.9.6

# For advanced control
./scripts/release-orchestrator.sh \
  --version 0.9.6 \
  --branch main \
  --draft false
```

The automated system handles:
- ✅ Version updates across all files
- ✅ Git commits and tags
- ✅ Multi-platform builds
- ✅ GitHub release creation
- ✅ Package publishing (with confirmation)
- ✅ Rollback on failures

## Prerequisites

1. **Tools Required**:
   - Rust toolchain (stable)
   - Node.js and npm
   - Docker with buildx support
   - GitHub CLI (`gh`)
   - Git
   - jq (for JSON processing)

2. **Authentication**:
   - GitHub: `gh auth login`
   - NPM: `npm login`
   - Crates.io: `cargo login`
   - Docker Hub: `docker login`

3. **Environment Setup**:
   ```bash
   # Verify all tools are available
   ./scripts/verify-release-setup.sh
   ```

## Release Process

### Option A: Automated Release (Recommended)

Use the automated release system for a streamlined process:

```bash
# Simple release with all defaults
./scripts/release.sh 0.9.6

# The script will:
# 1. Run setup verification
# 2. Update all version numbers
# 3. Commit and tag
# 4. Trigger GitHub Actions build
# 5. Create GitHub release
# 6. Prompt for package publishing
```

#### Advanced Automated Options

```bash
# Full control with orchestrator
./scripts/release-orchestrator.sh \
  --version 0.9.6 \
  --branch main \
  --draft false \
  --auto-publish    # Skip confirmation prompts

# Just update version and prepare for manual release
./scripts/update-version.sh --release 0.9.6 --no-tag

# Dry run to see what would happen
./scripts/release-orchestrator.sh --version 0.9.6 --dry-run
```

### Option B: Manual Release Process

For special cases or when automation needs to be bypassed:

1. **Update Version Numbers**:
   ```bash
   # Use the automated version update script
   ./scripts/update-version.sh X.Y.Z
   
   # Options:
   # --dry-run    Preview changes without modifying files
   # --no-commit  Update files but don't commit
   # --no-tag     Commit but don't create tag
   # --release    Full release mode (triggers workflow)
   ```
   
   This script automatically updates:
   - All Cargo.toml files in the workspace
   - npm-package/package.json
   - Docker labels and tags
   - README.md version badges
   - All other version references

2. **Update Changelog**:
   - Add release notes to `CHANGELOG.md`
   - Document breaking changes, new features, bug fixes

3. **Validate Version Consistency**:
   ```bash
   # Ensure all version numbers are in sync
   ./scripts/validate-versions.sh
   ```

4. **Run Pre-release Checks**:
   ```bash
   ./scripts/pre-release-checklist.sh
   ```

### 2. Build Release Artifacts

#### Local Build (Current Platform)
```bash
# Build binaries and create artifacts for current platform
./scripts/build-release.sh --version 0.9.2
```

#### Full Multi-platform Build
For a complete release, use the GitHub Actions workflow:
```bash
# Create and push tag
git tag -a v0.9.2 -m "Release 0.9.2"
git push origin v0.9.2
```

This triggers the automated workflow that:
- Builds binaries for all platforms
- Creates platform-specific archives
- Generates checksums
- Creates GitHub release

### 3. Create GitHub Release

#### Automated (via GitHub Actions)
When you push a version tag, the workflow automatically:
1. Builds all platform binaries
2. Creates release archives
3. Generates checksums
4. Creates GitHub release with assets

#### Manual Release
```bash
# For manual release creation
./scripts/create-github-release.sh --version 0.9.2

# For draft release
./scripts/create-github-release.sh --version 0.9.2 --draft

# For pre-release
./scripts/create-github-release.sh --version 0.10.0-beta.1 --prerelease
```

### 4. Publish to Package Registries

After GitHub release is created:

```bash
# Publish to crates.io
./scripts/publish-crates.sh

# Publish to NPM
./scripts/publish-npm.sh

# Publish Docker images
./scripts/publish-docker.sh

# Or publish all at once
./scripts/publish-all.sh
```

## Release Assets

Each release includes:

### Binary Archives
- `kindlyguard-{version}-linux-x64.tar.gz` - Linux x64 binaries
- `kindlyguard-{version}-darwin-x64.tar.gz` - macOS Intel binaries
- `kindlyguard-{version}-darwin-arm64.tar.gz` - macOS Apple Silicon binaries
- `kindlyguard-{version}-win-x64.zip` - Windows x64 binaries

### Metadata Files
- `checksums.txt` - SHA-256 checksums for all archives
- `BUILD_INFO.json` - Build metadata (version, date, commit)

### Each Archive Contains
- `kindlyguard` - MCP server binary
- `kindlyguard-cli` - Command-line interface binary

## Platform-Specific Notes

### Linux
- Built on Ubuntu latest
- Requires glibc 2.31+ (Ubuntu 20.04+)
- Static linking where possible

### macOS
- Universal binaries not provided (separate Intel/ARM64)
- Minimum macOS version: 10.15 (Catalina)
- Code signed if certificates available

### Windows
- Built with MSVC
- Requires Visual C++ Redistributables
- Packaged as ZIP (not installer)

## NPM Package Structure

The NPM release includes:
```
@kindlyguard/kindlyguard
├── package.json
├── postinstall.js
└── npm/
    ├── kindlyguard-linux-x64/
    ├── kindlyguard-darwin-x64/
    ├── kindlyguard-darwin-arm64/
    └── kindlyguard-win32-x64/
```

Platform packages are installed based on the user's OS/architecture.

## Verification

Users can verify downloads:

```bash
# Download checksums.txt from GitHub release
curl -LO https://github.com/kindlysoftware/kindlyguard/releases/download/v0.9.2/checksums.txt

# Verify downloaded file
shasum -a 256 -c checksums.txt
```

## Rollback Process

### Automated Rollback

The release orchestrator includes automatic rollback on failures:

```bash
# If release fails, it automatically:
# 1. Deletes the tag (if created)
# 2. Reverts version commits
# 3. Cleans up partial releases
# 4. Restores to pre-release state
```

### Manual Rollback

If issues are discovered post-release:

1. **Quick Rollback** (within 1 hour):
   ```bash
   # Use the rollback script
   ./scripts/rollback-release.sh v0.9.2
   
   # This will:
   # - Mark GitHub release as pre-release
   # - Add warning to release notes
   # - Notify users via release update
   ```

2. **Mark as Pre-release**:
   ```bash
   gh release edit v0.9.2 --prerelease
   ```

3. **Add Warning to Release Notes**:
   ```bash
   gh release edit v0.9.2 --notes "⚠️ KNOWN ISSUES: [describe issues]"
   ```

4. **Yank from Registries** (if critical):
   ```bash
   # Cargo (marks version as yanked)
   cargo yank --version 0.9.2 kindly-guard-server
   
   # NPM (deprecate with message)
   npm deprecate @kindlyguard/kindlyguard@0.9.2 "Critical issue found, use 0.9.3"
   ```

5. **Emergency Response**:
   ```bash
   # For critical security issues
   ./scripts/emergency-rollback.sh v0.9.2 --security-issue
   
   # This performs all rollback steps and:
   # - Creates security advisory
   # - Notifies maintainers
   # - Prepares patch release
   ```

## Security Considerations

1. **Signing**:
   - Git tags should be signed: `git tag -s v0.9.2`
   - Consider GPG signing release artifacts

2. **Checksums**:
   - Always include SHA-256 checksums
   - Consider providing multiple hash algorithms

3. **Build Environment**:
   - Use GitHub Actions for reproducible builds
   - Pin all dependency versions
   - Document build environment in BUILD_INFO.json

## Automation

The release process is partially automated:

- ✅ Multi-platform builds (GitHub Actions)
- ✅ Checksum generation
- ✅ GitHub release creation
- ✅ Asset uploads
- ⚠️  Package registry publishing (manual for security)

## Troubleshooting

### Automated Release Issues

#### Release Script Failures
```bash
# Check setup requirements
./scripts/verify-release-setup.sh

# View detailed logs
tail -f release.log

# Run with debug mode
DEBUG=1 ./scripts/release.sh 0.9.6
```

#### Version Update Problems
- **Symptom**: Version update fails or misses files
- **Solution**: Run `./scripts/validate-versions.sh` to identify mismatches
- **Fix**: Use `--force` flag to override validation

#### GitHub Actions Not Triggering
- **Symptom**: Push tag but workflow doesn't start
- **Solution**: Check workflow permissions and GitHub Actions settings
- **Fix**: Manually trigger with `gh workflow run release.yml`

### Build Failures
- Check Rust toolchain version: `rustup show`
- Verify all dependencies are available: `cargo check --all-features`
- Review platform-specific requirements in CI logs

### Upload Failures
- Ensure GitHub token has appropriate permissions: `gh auth status`
- Check network connectivity and retry
- Verify asset file sizes (GitHub limit: 2GB per file)

### Publishing Failures

#### Crates.io Issues
```bash
# Verify token
cargo login

# Check for existing version
cargo search kindly-guard-server

# Dry run publish
cargo publish --dry-run -p kindly-guard-server
```

#### NPM Issues
```bash
# Verify authentication
npm whoami

# Check for conflicts
npm view @kindlyguard/kindlyguard

# Test publish locally
npm pack ./npm-package
```

### Common Problems and Solutions

| Problem | Cause | Solution |
|---------|-------|----------|
| Version mismatch | Manual edits | Run `validate-versions.sh` |
| Tag already exists | Previous attempt | Delete with `git tag -d v0.9.6` |
| Workflow fails | Missing secrets | Check repository settings |
| NPM 403 error | No publish access | Verify npm organization access |
| Cargo publish hangs | Large files | Check for accidental inclusions |

### Emergency Procedures

```bash
# Abort release in progress
./scripts/abort-release.sh

# Clean up failed release
./scripts/cleanup-failed-release.sh v0.9.6

# Reset to clean state
git reset --hard HEAD~1
git tag -d v0.9.6
git push --delete origin v0.9.6
```

## Release Checklist

### Automated Release
- [ ] Run `./scripts/release.sh X.Y.Z`
- [ ] Monitor progress and respond to prompts
- [ ] Verify release on GitHub
- [ ] Check package registries
- [ ] Announce release

### Manual Release
- [ ] Version numbers updated using `./scripts/update-version.sh X.Y.Z`
- [ ] Version consistency validated with `./scripts/validate-versions.sh`
- [ ] Changelog updated
- [ ] All tests passing
- [ ] Security audit completed (`cargo audit`)
- [ ] Documentation updated
- [ ] Release artifacts built
- [ ] Checksums generated
- [ ] GitHub release created
- [ ] Binaries downloadable and functional
- [ ] Published to crates.io
- [ ] Published to NPM
- [ ] Docker images pushed
- [ ] Release announced

## Support

For release issues:
1. Check troubleshooting guide above
2. Review logs in `./logs/release-*.log`
3. Consult `./docs/AUTOMATED_RELEASE_GUIDE.md`
4. Contact release team