# Building KindlyGuard for All Platforms

## Current Status (v0.9.4)
- ✅ Linux x64: Built successfully
- ⏳ macOS x64: Requires macOS system or CI
- ⏳ macOS ARM64: Requires macOS system or CI  
- ⏳ Windows x64: Requires Windows system or CI

## Build Instructions

### Linux (x64)
```bash
cargo build --release --target x86_64-unknown-linux-gnu --package kindly-guard-server
cargo build --release --target x86_64-unknown-linux-gnu --package kindly-guard-cli
```

### macOS (x64 - Intel)
```bash
cargo build --release --target x86_64-apple-darwin --package kindly-guard-server
cargo build --release --target x86_64-apple-darwin --package kindly-guard-cli
```

### macOS (ARM64 - Apple Silicon)
```bash
cargo build --release --target aarch64-apple-darwin --package kindly-guard-server
cargo build --release --target aarch64-apple-darwin --package kindly-guard-cli
```

### Windows (x64)
```bash
cargo build --release --target x86_64-pc-windows-gnu --package kindly-guard-server
cargo build --release --target x86_64-pc-windows-gnu --package kindly-guard-cli
```

## GitHub Actions Workflow
For automated cross-platform builds, use the GitHub Actions workflow in `.github/workflows/release.yml`.

## Manual Cross-Compilation
If you need to build for other platforms from Linux, ensure you have:
1. `cross` installed: `cargo install cross --git https://github.com/cross-rs/cross`
2. Docker running for cross-compilation environments

Then use:
```bash
cross build --release --target <target> --package kindly-guard-server
```