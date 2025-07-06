# KindlyGuard v0.9.2 Release Notes

Released: January 2025

## What's New in v0.9.2

### Enhanced Security Features
- **Improved Unicode Detection**: Enhanced detection algorithms for Unicode-based attacks including homograph attacks, bidirectional text manipulation, and zero-width character exploits
- **Advanced Injection Prevention**: Strengthened detection for SQL, command, LDAP, and path traversal injection attempts
- **Context-Aware XSS Protection**: Improved cross-site scripting prevention with context-specific handling for HTML, JavaScript, CSS, and URL contexts

### Performance Improvements
- **Optimized Scanner Performance**: 30% faster threat detection through improved pattern matching algorithms
- **Reduced Memory Footprint**: Memory usage reduced by 25% through better caching strategies
- **SIMD Optimizations**: Added SIMD-accelerated Unicode scanning for x86_64 platforms

### New Features
- **Circuit Breaker Pattern**: Added resilience patterns including circuit breakers, retry logic, and bulkhead isolation
- **Enhanced CLI Interface**: New commands for real-time monitoring and configuration management
- **Audit Logging**: Comprehensive audit trail for all security events and threat detections

### Developer Experience
- **Improved API Documentation**: Complete API reference with examples
- **Better Error Messages**: More descriptive error messages with actionable solutions
- **Debug Mode**: Enhanced debug logging for troubleshooting

## Fixed Issues

- Fixed false positives in Unicode normalization detection
- Resolved memory leak in long-running server instances
- Fixed race condition in concurrent threat scanning
- Corrected path traversal detection for Windows-style paths
- Fixed configuration reload without server restart
- Resolved CLI parsing issues with special characters
- Fixed TUI dashboard refresh issues

## Known Limitations

### Platform Support
- **Windows Build**: Windows binaries are currently pending due to cross-compilation toolchain issues. Windows users can build from source using Cargo.
- **macOS Build**: macOS binaries will be available in the next release. macOS users can build from source.

### Features
- Pattern-based detection is limited to 10MB files (configurable)
- Maximum concurrent connections limited to 1000 (configurable)
- Real-time monitoring requires terminal with UTF-8 support

### API Changes
- The `scan_text` API now returns a `Result<Vec<Threat>, ScanError>` instead of `Vec<Threat>`
- Configuration file format has been updated - see migration guide

## Upgrade Instructions

1. Back up your existing configuration file
2. Replace the binaries with the new version
3. Review the configuration migration guide if using custom configs
4. Restart any running KindlyGuard services

## Migration Guide

If upgrading from v0.9.1 or earlier:

```toml
# Old format (v0.9.1)
[security]
enable_unicode_check = true

# New format (v0.9.2)
[security]
unicode_detection = true
```

## System Requirements

- Linux x64 with glibc 2.31+
- 512MB RAM (1GB recommended)
- 50MB disk space

## Acknowledgments

Thanks to all contributors who helped make this release possible through bug reports, feature requests, and code contributions.