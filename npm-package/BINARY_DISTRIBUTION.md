# KindlyGuard Binary Distribution Strategy

This document explains how KindlyGuard distributes native binaries through npm, following best practices from projects like esbuild and swc.

## Architecture

### Main Package (`@kindlyguard/kindlyguard`)
- Contains Node.js wrapper code and CLI scripts
- Has optional dependencies on platform-specific packages
- Automatically downloads the correct binary during `postinstall`
- Provides fallback download mechanism if platform package is unavailable

### Platform Packages (`@kindlyguard/*`)
- Separate packages for each platform/architecture combination:
  - `@kindlyguard/linux-x64` - Linux x64
  - `@kindlyguard/darwin-x64` - macOS x64 (Intel)
  - `@kindlyguard/darwin-arm64` - macOS ARM64 (Apple Silicon)
  - `@kindlyguard/win32-x64` - Windows x64
- Each contains only the platform-specific binaries
- Published independently with matching versions

## Directory Structure

```
npm-package/
├── package.json          # Main package
├── lib/
│   ├── main.js          # Node.js API
│   ├── main.d.ts        # TypeScript definitions
│   ├── platform.js      # Platform detection utilities
│   └── postinstall.js   # Binary installation script
├── bin/
│   ├── kindlyguard      # CLI wrapper (installed by postinstall)
│   └── kindlyguard-cli  # CLI tool wrapper
├── scripts/
│   └── build-platform-packages.js  # Build script
└── npm/                 # Platform packages
    ├── kindlyguard-linux-x64/
    ├── kindlyguard-darwin-x64/
    ├── kindlyguard-darwin-arm64/
    └── kindlyguard-win32-x64/
```

## Installation Flow

1. User runs `npm install @kindlyguard/kindlyguard`
2. npm installs the main package and attempts to install the optional platform dependency
3. `postinstall.js` runs and:
   - Detects the current platform
   - Tries to copy binaries from the platform package (if installed)
   - Falls back to direct download from GitHub releases (if needed)
   - Validates the binary works correctly

## Building and Publishing

### Build All Platform Packages
```bash
npm run build-platform-packages
```

This script:
- Builds binaries for all supported platforms (requires cross-compilation setup)
- Copies binaries to respective platform package directories
- Updates version numbers to match main package

### Publish All Packages
```bash
npm run publish-all
```

This script:
- Publishes all platform packages first
- Waits for packages to be available on npm
- Publishes the main package

### Manual Platform Build
For building a specific platform:

```bash
# Linux x64
cargo build --release --target x86_64-unknown-linux-gnu

# macOS x64
cargo build --release --target x86_64-apple-darwin

# macOS ARM64
cargo build --release --target aarch64-apple-darwin

# Windows x64
cargo build --release --target x86_64-pc-windows-msvc
```

## Environment Variables

- `KINDLYGUARD_SKIP_DOWNLOAD` - Skip binary download during install
- `KINDLYGUARD_DOWNLOAD_BASE` - Override download URL base
- `CI` - Skip install in CI environments

## Platform Detection

The platform detection logic (`lib/platform.js`) handles:
- Mapping Node.js platform/arch to our naming scheme
- Detecting musl libc on Linux (Alpine)
- Validating binary executability
- Generating download URLs

## Security Considerations

- Binaries are downloaded over HTTPS
- Each binary is validated before use
- Platform packages are scoped to `@kindlyguard` namespace
- Fallback mechanism ensures users can always install

## Troubleshooting

### Binary Not Found
If the binary isn't found after installation:
1. Check if the platform is supported
2. Verify the platform package was installed
3. Check file permissions (Unix)
4. Try manual download from GitHub releases

### Cross-Platform Building
To build for all platforms from a single machine:
1. Install Rust cross-compilation targets
2. Install required linkers (e.g., mingw for Windows)
3. Use the build script or cargo directly

## Future Improvements

- Add support for more platforms (linux-arm64, etc.)
- Implement binary signing/verification
- Add automatic cross-compilation in CI
- Support for musl libc variants