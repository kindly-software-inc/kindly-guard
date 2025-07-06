# KindlyGuard v0.9.4 Release Notes

## Release Date
January 20, 2025

## Overview
This release focuses on improving cross-platform support and fixing critical issues with the NPM package distribution. The v0.9.3 release was missing platform binaries for macOS and Windows, which has been resolved in this release.

## Key Improvements

### 🐛 Bug Fixes
- **Fixed missing platform binaries**: The NPM package now includes binaries for all supported platforms:
  - Linux x64
  - macOS x64 (Intel)
  - macOS ARM64 (Apple Silicon)
  - Windows x64
  
### 🚀 Enhancements
- **Cross-platform build support**: Improved build scripts to ensure all platform binaries are generated during the release process
- **Better NPM package structure**: Enhanced the postinstall script to properly detect and install the correct binary for each platform

### 📦 Platform Support
The NPM package now correctly supports:
- **Linux**: x64 architecture
- **macOS**: Both Intel (x64) and Apple Silicon (arm64)
- **Windows**: x64 architecture

## Installation

### NPM (All Platforms)
```bash
npm install -g kindlyguard@0.9.4
```

### Cargo (Rust)
```bash
cargo install kindlyguard --version 0.9.4
```

## Checksums
SHA256 checksums for all release binaries are provided in the release assets.

## What's Next
- Continued improvements to cross-platform compatibility
- Enhanced security features for AI model protection
- Performance optimizations for large-scale deployments

## Contributors
Thank you to everyone who reported issues and contributed to this release!

---

For detailed documentation and usage instructions, visit our [GitHub repository](https://github.com/samduchaine/kindly-guard).