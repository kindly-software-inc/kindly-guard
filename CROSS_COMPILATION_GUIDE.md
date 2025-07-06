# KindlyGuard Cross-Compilation Guide

## Overview

This guide addresses the OpenSSL dependency issue when cross-compiling KindlyGuard for musl targets. Good news: **your project already uses rustls** for TLS operations, so OpenSSL shouldn't be a direct dependency!

## Current Status

✅ **No OpenSSL dependency found** - The project uses `rustls-tls` for all HTTP/TLS operations
⚠️ **Some C dependencies exist** - jemalloc, compression libraries (bzip2, lzma, zstd)

## Quick Solutions

### 1. Basic Cross-Compilation (Recommended)

```bash
# Install the musl target
rustup target add x86_64-unknown-linux-musl

# Build for musl
cargo build --release --target x86_64-unknown-linux-musl --bin kindly-guard-server
```

### 2. If You Encounter OpenSSL Errors

Even though we use rustls, some transitive dependencies might pull in OpenSSL. Use the provided script:

```bash
./switch_to_rustls.sh
```

This script will:
- Ensure all `reqwest` dependencies use `rustls-tls`
- Check for any direct OpenSSL usage
- Update Cargo.toml files as needed

### 3. For Fully Static Binaries

Use the static musl build script:

```bash
# Standard static build
./build_static_musl.sh

# Or use zigbuild (easier, no system dependencies)
./build_static_musl.sh --zigbuild

# Or use cross (Docker-based, most reliable)
./build_static_musl.sh --cross
```

### 4. Build for All Targets

```bash
./cross_compile_all_targets.sh
```

This will build for:
- Linux (x86_64, aarch64, armv7) - both GNU and musl
- macOS (x86_64, aarch64)
- Windows (MSVC and GNU)

## Troubleshooting

### "error: failed to run custom build command for `openssl-sys`"

This shouldn't happen since we use rustls, but if it does:

1. Check for transitive dependencies:
   ```bash
   cargo tree | grep openssl
   ```

2. Update all dependencies to use rustls:
   ```bash
   ./switch_to_rustls.sh
   ```

3. Clean and rebuild:
   ```bash
   cargo clean
   cargo build --release --target x86_64-unknown-linux-musl
   ```

### C Library Dependencies

The project has some C dependencies (jemalloc, compression libs) that might cause issues:

1. **Option 1**: Use pre-built tools
   ```bash
   # Install cargo-zigbuild (bundles its own toolchain)
   cargo install cargo-zigbuild
   cargo zigbuild --release --target x86_64-unknown-linux-musl
   ```

2. **Option 2**: Use Docker-based cross
   ```bash
   # Install cross
   cargo install cross --git https://github.com/cross-rs/cross
   cross build --release --target x86_64-unknown-linux-musl
   ```

3. **Option 3**: Disable problematic features
   ```toml
   # In Cargo.toml, make jemalloc optional
   [dependencies]
   jemallocator = { version = "0.5", optional = true }
   
   [features]
   default = []
   jemalloc = ["jemallocator"]
   ```

### Missing musl-tools

Install the required tools for your system:

```bash
# Ubuntu/Debian
sudo apt-get install musl-tools

# Arch
sudo pacman -S musl

# Alpine
apk add musl-dev

# macOS (for cross-compilation)
brew install FiloSottile/musl-cross/musl-cross
```

## Verification

After building, verify your binary:

1. **Check it's statically linked**:
   ```bash
   ldd target/x86_64-unknown-linux-musl/release/kindly-guard-server
   # Should output: "not a dynamic executable"
   ```

2. **Check for OpenSSL dependency**:
   ```bash
   ldd target/x86_64-unknown-linux-musl/release/kindly-guard-server | grep ssl
   # Should return nothing
   ```

3. **Test the binary**:
   ```bash
   ./target/x86_64-unknown-linux-musl/release/kindly-guard-server --version
   ```

## Best Practices

1. **Always use rustls**: Already done in this project ✅
2. **Vendor C dependencies when possible**: Use `*-sys` crates with vendored features
3. **Test cross-compiled binaries**: Use QEMU or actual hardware
4. **Use CI for builds**: GitHub Actions can build for multiple targets

## Scripts Provided

1. **`switch_to_rustls.sh`** - Ensures all dependencies use rustls instead of OpenSSL
2. **`build_static_musl.sh`** - Builds truly static musl binaries
3. **`cross_compile_all_targets.sh`** - Builds for all supported platforms
4. **`fix_musl_build.sh`** - Fixes common musl build issues

## Further Resources

- [rust-cross Guide](https://github.com/japaric/rust-cross)
- [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild)
- [cross-rs](https://github.com/cross-rs/cross)
- [rustls Documentation](https://docs.rs/rustls/)