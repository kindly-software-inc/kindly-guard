# Cross-Compilation Setup for KindlyGuard

This document describes the cross-compilation setup for building KindlyGuard for multiple platforms.

## Overview

KindlyGuard now supports cross-compilation for the following platforms:
- Linux x86_64 (native)
- macOS x86_64 (Intel)
- macOS ARM64 (Apple Silicon)
- Windows x86_64

## Prerequisites

1. **Rust Toolchain**: Ensure you have Rust installed with rustup
2. **Target Support**: The required targets have been added to your Rust toolchain
3. **Cross-compilation Tools**:
   - For Windows targets on Linux: `sudo apt-get install mingw-w64`
   - For better cross-compilation: `cargo install cross --git https://github.com/cross-rs/cross`

## Installed Targets

The following Rust targets have been added:
- `x86_64-unknown-linux-gnu` (default/native)
- `x86_64-apple-darwin` (macOS Intel)
- `aarch64-apple-darwin` (macOS ARM)
- `x86_64-pc-windows-gnu` (Windows)

## Building for All Platforms

### Using the Build Script

A convenience script has been created to build for all platforms:

```bash
./scripts/build-all-platforms.sh
```

This script will:
- Check for required tools
- Optionally install `cross` for better cross-compilation support
- Build for all supported platforms
- Create release artifacts in `release-artifacts/`
- Generate checksums for all builds

### Manual Building

To build for a specific platform manually:

```bash
# Linux (native)
cargo build --release --target x86_64-unknown-linux-gnu

# macOS Intel
cargo build --release --target x86_64-apple-darwin

# macOS ARM
cargo build --release --target aarch64-apple-darwin

# Windows
cargo build --release --target x86_64-pc-windows-gnu
```

## Using Cross for Better Compatibility

For more reliable cross-compilation, especially for non-native platforms, you can use `cross`:

### Installing Cross

```bash
./scripts/install-cross.sh
```

Or manually:
```bash
cargo install cross --git https://github.com/cross-rs/cross
```

### Building with Cross

```bash
# Automatically uses Docker for cross-compilation
cross build --release --target x86_64-pc-windows-gnu
cross build --release --target aarch64-unknown-linux-gnu
```

## GitHub Actions Integration

A GitHub workflow has been set up at `.github/workflows/cross-compile.yml` that:

1. **Matrix Build**: Builds for all major platforms in parallel
2. **Caching**: Caches dependencies for faster builds
3. **Artifacts**: Uploads build artifacts for each platform
4. **Release**: Automatically creates releases with all platform binaries

The workflow triggers on:
- Push to main/master branches
- Pull requests
- Git tags (creates releases)
- Manual dispatch

## Platform-Specific Notes

### Linux
- Native compilation works out of the box
- For static linking, consider using `x86_64-unknown-linux-musl`

### macOS
- Cross-compilation from Linux requires macOS SDK
- Best built on macOS runners in CI
- Universal binaries can be created with `lipo`

### Windows
- Uses MinGW for cross-compilation from Linux
- Alternatively, `x86_64-pc-windows-msvc` can be used on Windows hosts

## Limitations

1. **macOS Cross-Compilation**: 
   - Building macOS binaries from Linux is complex due to SDK requirements
   - Recommended to use GitHub Actions or actual macOS hardware

2. **Windows Cross-Compilation**:
   - Some Windows-specific features may require native compilation
   - MinGW cross-compilation works for most use cases

3. **Binary Size**:
   - Cross-compiled binaries may be larger than native builds
   - Use `strip` and LTO for smaller binaries

## Testing Cross-Compiled Binaries

Always test cross-compiled binaries on the target platform:

1. **Basic Functionality**:
   ```bash
   ./kindlyguard --version
   ./kindlyguard --help
   ```

2. **MCP Server Mode**:
   ```bash
   ./kindlyguard --stdio
   ```

3. **CLI Operations**:
   ```bash
   ./kindly-guard-cli scan test-file.json
   ```

## Troubleshooting

### Missing Linker
If you get linker errors for Windows targets:
```bash
sudo apt-get install mingw-w64
```

### Docker Issues with Cross
Ensure Docker is running:
```bash
sudo systemctl start docker
```

### Target Not Found
Add the target first:
```bash
rustup target add <target-triple>
```

## Release Process

1. Run the build script:
   ```bash
   ./scripts/build-all-platforms.sh
   ```

2. Test binaries on each platform

3. Create a git tag:
   ```bash
   git tag -a v0.9.2 -m "Release v0.9.2"
   git push origin v0.9.2
   ```

4. GitHub Actions will automatically create a release with all platform binaries

## Future Enhancements

- [ ] Add ARM Linux targets (armv7, aarch64)
- [ ] Add musl targets for fully static Linux binaries
- [ ] Create universal macOS binaries
- [ ] Add FreeBSD support
- [ ] Implement binary signing for all platforms