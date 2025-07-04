# NPM Package Publishing Instructions

This document contains instructions for publishing the KindlyGuard npm package.

## Prerequisites

1. **Build the Rust binaries**:
   ```bash
   cd ..
   cargo build --release
   cargo build --package kindly-guard-cli --release
   ```

2. **Ensure you're logged into npm**:
   ```bash
   npm login
   npm whoami  # Should show: samduchaine
   ```

3. **Set up NPM_TOKEN** in GitHub Secrets for automated publishing

## Manual Publishing Process

### 1. Build Platform Package

Build the package for your current platform:

```bash
./build-npm-package.sh
```

This creates the platform-specific package in `npm/{platform}-{arch}/`

### 2. Test Locally

Test the package installation:

```bash
./test-local-install.sh
```

### 3. Publish Platform Package

```bash
cd npm/{platform}-{arch}
npm publish --access public
```

### 4. Publish Main Package

After all platform packages are published:

```bash
cd ../..
npm publish --access public
```

## Automated Publishing (GitHub Actions)

The project includes a GitHub Actions workflow that automatically:

1. Builds binaries for all platforms
2. Creates platform-specific packages
3. Publishes all packages to npm

To trigger automated publishing:

1. **Create a new release tag**:
   ```bash
   git tag v0.9.1
   git push origin v0.9.1
   ```

2. The workflow will automatically:
   - Build for Linux x64, macOS x64/arm64, Windows x64
   - Create @kindlyguard/{platform}-{arch} packages
   - Publish all packages to npm

## Version Management

- Current version: 0.9.1
- Platform packages use same version as main package
- Follow semantic versioning (MAJOR.MINOR.PATCH)

## Package Structure

```
@kindlyguard/kindlyguard (main package)
├── @kindlyguard/linux-x64
├── @kindlyguard/darwin-x64
├── @kindlyguard/darwin-arm64
└── @kindlyguard/win32-x64
```

## Quick Update Process

For quick updates without full rebuild:

```bash
./publish.sh
```

This will publish the current package version.

## Troubleshooting

### Binary not found after installation

- Check that platform package was published
- Verify postinstall.js ran successfully
- Check bin/ directory permissions

### Platform not supported

Currently supported platforms:
- Linux x64
- macOS x64 (Intel)
- macOS arm64 (Apple Silicon)
- Windows x64

To add a new platform:
1. Update the build matrix in `.github/workflows/npm-publish.yml`
2. Add platform mapping in `postinstall.js`
3. Test on target platform

### Permission errors

- Make sure you're logged in as the correct npm user
- Use `--access public` for scoped packages

## Security Notes

- All binaries should be built in clean environments
- Use GitHub Actions for reproducible builds
- Include checksums in platform packages
- Sign releases with GPG when possible

## After Publishing

1. Verify the package at: https://www.npmjs.com/package/@kindlyguard/kindlyguard
2. Test installation: `npm install -g @kindlyguard/kindlyguard`
3. Update documentation with new version
4. Create GitHub release with changelog