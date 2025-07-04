# KindlyGuard v0.9.5 Release Notes

Release Date: January 20, 2025

## Summary

KindlyGuard v0.9.5 focuses on improving cross-platform compatibility and installation reliability, with significant enhancements for Linux users.

## Key Improvements

### Fixed Linux Compatibility with Static musl Builds
- Resolved critical issues with Linux binary compatibility by implementing static musl builds
- Linux binaries now work across all major distributions without glibc version conflicts
- Eliminated dependency on specific system library versions
- Ensures consistent behavior across different Linux environments

### Enhanced Error Messages in NPM Installation
- Improved error reporting during NPM package installation
- Clearer diagnostic messages when binary downloads fail
- Better guidance for troubleshooting installation issues
- More informative output for platform-specific problems

### Improved Cross-Platform Support
- Streamlined binary distribution for all supported platforms
- Enhanced platform detection logic
- Better handling of edge cases in different operating system configurations
- Consistent installation experience across Windows, macOS, and Linux

## Technical Details

- All binaries now use static linking on Linux to avoid runtime dependencies
- NPM postinstall script provides detailed error context and recovery suggestions
- Platform-specific packages are properly versioned and synchronized

## Compatibility

- **Node.js**: >= 14.0.0
- **Platforms**: 
  - Linux (x64) - Now with full static musl builds
  - macOS (x64, arm64)
  - Windows (x64)

## Installation

### Cargo
```bash
cargo install kindlyguard
```

### NPM
```bash
npm install kindlyguard
```

## Acknowledgments

Thanks to all users who reported Linux compatibility issues and helped test the static musl builds.

---

For more information, visit the [KindlyGuard repository](https://github.com/samduchaine/kindly-guard).