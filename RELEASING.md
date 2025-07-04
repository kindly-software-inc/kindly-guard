# KindlyGuard Release Process

This document describes the process for creating and publishing releases of KindlyGuard.

## Overview

KindlyGuard releases include:
- Binary releases for multiple platforms (Linux, macOS, Windows)
- NPM packages with platform-specific binaries
- Cargo crates published to crates.io
- Docker images
- GitHub releases with checksums

## Prerequisites

1. **Tools Required**:
   - Rust toolchain (stable)
   - Node.js and npm
   - Docker with buildx support
   - GitHub CLI (`gh`)
   - Git

2. **Authentication**:
   - GitHub: `gh auth login`
   - NPM: `npm login`
   - Crates.io: `cargo login`
   - Docker Hub: `docker login`

## Release Process

### 1. Prepare for Release

1. **Update Version Numbers**:
   ```bash
   # Update version in workspace Cargo.toml
   # Update version in npm-package/package.json
   # Update version in docker/Dockerfile labels
   ```

2. **Update Changelog**:
   - Add release notes to `CHANGELOG.md`
   - Document breaking changes, new features, bug fixes

3. **Run Pre-release Checks**:
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

If issues are discovered post-release:

1. **Mark as Pre-release**:
   ```bash
   gh release edit v0.9.2 --prerelease
   ```

2. **Add Warning to Release Notes**:
   ```bash
   gh release edit v0.9.2 --notes "⚠️ KNOWN ISSUES: [describe issues]"
   ```

3. **Yank from Registries** (if critical):
   ```bash
   # Cargo (marks version as yanked)
   cargo yank --version 0.9.2 kindly-guard-server
   
   # NPM (deprecate with message)
   npm deprecate @kindlyguard/kindlyguard@0.9.2 "Critical issue found, use 0.9.3"
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

### Build Failures
- Check Rust toolchain version
- Verify all dependencies are available
- Review platform-specific requirements

### Upload Failures
- Ensure GitHub token has appropriate permissions
- Check network connectivity
- Verify asset file sizes (GitHub has limits)

### Publishing Failures
- Verify authentication tokens are valid
- Check version doesn't already exist
- Ensure package metadata is correct

## Release Checklist

- [ ] Version numbers updated in all files
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