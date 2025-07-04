# KindlyGuard Build Process

This document describes the complete build and release process for KindlyGuard, including cross-platform compilation, npm packaging, and automated releases.

## Overview

The build system consists of several components:

1. **build-binaries.sh** - Main build script for compiling Rust binaries
2. **package-binaries.js** - Node.js script for packaging binaries for npm
3. **test-binaries.sh** - Testing script to validate built binaries
4. **publish-all.sh** - Publishing script for npm packages
5. **.github/workflows/release.yml** - GitHub Actions workflow for automated releases

## Prerequisites

### Required Tools

- **Rust** (latest stable)
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- **Cross** (for cross-compilation)
  ```bash
  cargo install cross --git https://github.com/cross-rs/cross
  ```

- **Node.js** (v14 or later)
  ```bash
  # Install via package manager or nvm
  ```

- **Docker** (required by cross for non-native builds)

### Platform-specific Requirements

#### Linux
- Build essentials: `sudo apt-get install build-essential`
- For Windows cross-compilation: `sudo apt-get install mingw-w64`

#### macOS
- Xcode Command Line Tools: `xcode-select --install`
- For Linux cross-compilation: Additional setup required

#### Windows
- Visual Studio Build Tools or full Visual Studio
- Git Bash or WSL for running shell scripts

## Build Process

### 1. Local Development Build

For development and testing on your current platform:

```bash
# Build for current platform only
cargo build --release

# Or use the build script for current platform
./build-binaries.sh build
```

### 2. Full Cross-Platform Build

To build for all supported platforms:

```bash
# Clean previous builds and build all platforms
./build-binaries.sh all

# Or run steps individually:
./build-binaries.sh clean   # Clean previous builds
./build-binaries.sh build   # Build all binaries
./build-binaries.sh package # Package for distribution
```

The script will:
- Detect your current platform
- Use `cargo` for native builds
- Use `cross` for cross-platform builds
- Generate binaries for:
  - Linux x64 and ARM64
  - macOS x64 and ARM64 (Apple Silicon)
  - Windows x64

### 3. Package for NPM

After building binaries, prepare npm packages:

```bash
# Run the packaging script
node package-binaries.js

# This will:
# - Copy binaries to npm package directories
# - Update version numbers
# - Create platform-specific packages
# - Generate checksums
# - Validate package contents
```

### 4. Test Binaries

Before publishing, test the built binaries:

```bash
# Test all binaries
./test-binaries.sh all

# Test specific components:
./test-binaries.sh current     # Test current platform only
./test-binaries.sh npm        # Test npm packages
./test-binaries.sh integration # Run integration tests
```

## Release Process

### Manual Release

1. **Update Version**
   ```bash
   # Update version in package.json files
   export VERSION="0.3.0"
   node package-binaries.js
   ```

2. **Build and Package**
   ```bash
   ./build-binaries.sh all
   ```

3. **Test**
   ```bash
   ./test-binaries.sh all
   ```

4. **Publish to NPM**
   ```bash
   # Dry run first
   ./publish-all.sh --dry-run

   # Then publish
   ./publish-all.sh
   ```

5. **Create Git Tag**
   ```bash
   ./publish-all.sh --tag
   git push origin v0.3.0
   ```

### Automated Release (GitHub Actions)

The automated release process is triggered by pushing a version tag:

```bash
# Create and push a version tag
git tag -a v0.3.0 -m "Release v0.3.0"
git push origin v0.3.0
```

GitHub Actions will:
1. Create a draft release
2. Build binaries for all platforms in parallel
3. Upload release assets (tar.gz/zip archives)
4. Publish npm packages
5. Generate and upload checksums
6. Publish the release

## Platform Support

### Supported Platforms

| Platform | Architecture | Target Triple | Binary Name |
|----------|-------------|--------------|-------------|
| Linux | x64 | x86_64-unknown-linux-gnu | kindlyguard |
| Linux | ARM64 | aarch64-unknown-linux-gnu | kindlyguard |
| macOS | x64 | x86_64-apple-darwin | kindlyguard |
| macOS | ARM64 | aarch64-apple-darwin | kindlyguard |
| Windows | x64 | x86_64-pc-windows-msvc | kindlyguard.exe |

### NPM Packages

| Package | Platform | Description |
|---------|----------|-------------|
| kindlyguard | All | Main package with automatic platform detection |
| @kindlyguard/linux-x64 | Linux x64 | Platform-specific binaries |
| @kindlyguard/linux-arm64 | Linux ARM64 | Platform-specific binaries |
| @kindlyguard/darwin-x64 | macOS x64 | Platform-specific binaries |
| @kindlyguard/darwin-arm64 | macOS ARM64 | Platform-specific binaries |
| @kindlyguard/win32-x64 | Windows x64 | Platform-specific binaries |

## Directory Structure

```
kindly-guard/
├── build-binaries.sh      # Main build script
├── package-binaries.js    # NPM packaging script
├── test-binaries.sh       # Testing script
├── publish-all.sh         # NPM publishing script
├── dist/                  # Built binaries (git-ignored)
│   ├── linux-x64/
│   ├── linux-arm64/
│   ├── darwin-x64/
│   ├── darwin-arm64/
│   └── win32-x64/
├── release/               # Release archives (git-ignored)
│   ├── kindlyguard-0.2.0-linux-x64.tar.gz
│   ├── kindlyguard-0.2.0-darwin-arm64.tar.gz
│   └── kindlyguard-0.2.0-win32-x64.zip
└── npm-package/
    ├── package.json       # Main npm package
    └── npm/              # Platform packages (git-ignored)
        ├── linux-x64/
        ├── darwin-x64/
        └── win32-x64/
```

## Troubleshooting

### Cross-compilation Issues

If cross-compilation fails:

1. **Ensure Docker is running** (required by cross)
   ```bash
   docker --version
   systemctl status docker  # Linux
   ```

2. **Update cross**
   ```bash
   cargo install --force cross --git https://github.com/cross-rs/cross
   ```

3. **Check target installation**
   ```bash
   rustup target list --installed
   rustup target add x86_64-unknown-linux-gnu  # Add missing targets
   ```

### NPM Publishing Issues

1. **Authentication**
   ```bash
   npm login
   npm whoami  # Verify authentication
   ```

2. **Scope Access**
   ```bash
   npm access grant read-write @kindlyguard:developers
   ```

3. **Registry Issues**
   ```bash
   npm config get registry  # Should be https://registry.npmjs.org/
   ```

### Binary Validation Failures

If binaries fail validation:

1. **Check file permissions**
   ```bash
   ls -la dist/linux-x64/
   chmod +x dist/linux-x64/kindlyguard  # Fix permissions
   ```

2. **Verify checksums manually**
   ```bash
   cd dist/linux-x64
   sha256sum -c checksums.txt
   ```

3. **Test binary directly**
   ```bash
   ./dist/linux-x64/kindlyguard --version
   ```

## Security Considerations

1. **Code Signing** (Future enhancement)
   - Binaries should be signed for macOS and Windows
   - Use GitHub Actions secrets for signing certificates

2. **Checksum Verification**
   - Always verify checksums before distribution
   - Checksums are generated automatically during build

3. **Dependency Audit**
   ```bash
   cargo audit
   npm audit
   ```

## Continuous Integration

The GitHub Actions workflow runs on:
- Push to main branch (build only)
- Pull requests (build and test)
- Version tags (full release)

### Workflow Jobs

1. **create-release** - Creates GitHub release draft
2. **build** - Builds binaries for all platforms (matrix build)
3. **publish-npm** - Publishes packages to npm registry
4. **checksums** - Generates and uploads checksum file
5. **finalize** - Publishes the release

### Secrets Required

Configure these in GitHub repository settings:
- `NPM_TOKEN` - npm authentication token for publishing
- `GITHUB_TOKEN` - Automatically provided by GitHub Actions

## Maintenance

### Updating Dependencies

```bash
# Update Rust dependencies
cargo update

# Update npm dependencies
cd npm-package && npm update

# Update build tools
cargo install --force cross --git https://github.com/cross-rs/cross
```

### Adding New Platforms

To add a new platform:

1. Add target to `TARGETS` in `build-binaries.sh`
2. Add platform to `CONFIG.platforms` in `package-binaries.js`
3. Update GitHub Actions matrix in `.github/workflows/release.yml`
4. Update documentation

### Version Bumping

Use semantic versioning (MAJOR.MINOR.PATCH):
- MAJOR: Breaking changes
- MINOR: New features, backward compatible
- PATCH: Bug fixes

Update version in:
- `npm-package/package.json`
- `Cargo.toml` files
- Documentation

## Support

For build issues:
1. Check the troubleshooting section
2. Review GitHub Actions logs
3. Open an issue with build logs and platform details