# GitHub Releases Setup for KindlyGuard

This document describes the GitHub releases infrastructure created for KindlyGuard to support the NPM postinstall script.

## Overview

The release system automates the creation of GitHub releases with platform-specific binaries that can be downloaded during NPM package installation.

## Components Created

### 1. Build Script (`scripts/build-release.sh`)
- Builds release binaries for all platforms
- Creates platform-specific archives (`.tar.gz` for Unix, `.zip` for Windows)
- Generates SHA-256 checksums
- Creates release metadata

**Usage:**
```bash
./scripts/build-release.sh --version 0.9.2
```

### 2. GitHub Release Script (`scripts/create-github-release.sh`)
- Creates GitHub releases using the `gh` CLI
- Uploads binary archives as release assets
- Supports draft and pre-release options
- Auto-generates release notes

**Usage:**
```bash
# Create a release
./scripts/create-github-release.sh --version 0.9.2

# Create a draft release
./scripts/create-github-release.sh --version 0.9.2 --draft

# Create a pre-release
./scripts/create-github-release.sh --version 0.10.0-beta.1 --prerelease
```

### 3. GitHub Actions Workflow (`.github/workflows/create-release.yml`)
- Automatically triggered on version tags (`v*.*.*`)
- Builds binaries for all platforms:
  - Linux x64
  - macOS x64
  - macOS ARM64
  - Windows x64
- Creates GitHub release with all assets
- Generates checksums automatically

**Trigger manually:**
```bash
# Push a tag
git tag -a v0.9.2 -m "Release 0.9.2"
git push origin v0.9.2

# Or use workflow dispatch
./scripts/trigger-release-workflow.sh --version 0.9.2
```

### 4. NPM Package Updates

#### Updated `platform.js`:
- Changed GitHub URL to `kindlysoftware/kindlyguard`
- Added support for `.zip` files on Windows
- Proper platform detection

#### Updated `postinstall.js`:
- Added `unzipper` dependency for Windows support
- Handles both `.tar.gz` and `.zip` archives
- Downloads from GitHub releases

#### Updated `package.json`:
- Added `unzipper` dependency
- Updated repository URLs to `kindlysoftware/kindlyguard`

## Release Process

### Quick Release
```bash
# 1. Update version in Cargo.toml and package.json
# 2. Commit and tag
git add -A
git commit -m "chore: Release v0.9.2"
git tag -a v0.9.2 -m "Release 0.9.2"
git push origin main v0.9.2

# 3. GitHub Actions will automatically:
#    - Build all platforms
#    - Create release
#    - Upload binaries
```

### Manual Release
```bash
# 1. Build artifacts locally
./scripts/build-release.sh --version 0.9.2

# 2. Create GitHub release
./scripts/create-github-release.sh --version 0.9.2

# 3. Publish to registries
./scripts/publish-all.sh
```

## Testing

### Test the Release Process
```bash
./scripts/test-release-process.sh
```

### Test NPM Installation
```bash
# Test with specific GitHub release
cd /tmp
npm init -y
KINDLYGUARD_DOWNLOAD_BASE=https://github.com/kindlysoftware/kindlyguard/releases/download \
npm install kindlyguard@0.9.2
```

## Release Assets

Each release includes:

| File | Description |
|------|-------------|
| `kindlyguard-{version}-linux-x64.tar.gz` | Linux x64 binaries |
| `kindlyguard-{version}-darwin-x64.tar.gz` | macOS Intel binaries |
| `kindlyguard-{version}-darwin-arm64.tar.gz` | macOS Apple Silicon binaries |
| `kindlyguard-{version}-win-x64.zip` | Windows x64 binaries |
| `checksums.txt` | SHA-256 checksums for all files |
| `BUILD_INFO.json` | Build metadata |

## Verification

Users can verify downloads:
```bash
# Download checksums
curl -LO https://github.com/kindlysoftware/kindlyguard/releases/download/v0.9.2/checksums.txt

# Verify
shasum -a 256 -c checksums.txt
```

## Troubleshooting

### Common Issues

1. **GitHub CLI not authenticated**
   ```bash
   gh auth login
   ```

2. **Release already exists**
   - Delete the existing release or use a different version

3. **Workflow not triggered**
   - Ensure the tag follows the pattern `v*.*.*`
   - Check GitHub Actions is enabled for the repository

4. **NPM postinstall fails**
   - Check the release exists on GitHub
   - Verify the platform is supported
   - Check network connectivity

## Security Considerations

1. **Checksums**: All releases include SHA-256 checksums
2. **HTTPS Only**: Downloads use HTTPS exclusively
3. **Version Pinning**: NPM packages reference specific versions
4. **Binary Validation**: Postinstall script validates binaries

## Next Steps

1. **Set up code signing** for binaries (especially macOS/Windows)
2. **Add GPG signatures** to releases
3. **Implement binary notarization** for macOS
4. **Add virus scanning** to the release pipeline
5. **Set up release automation** for version bumps