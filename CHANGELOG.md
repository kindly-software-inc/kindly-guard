# Changelog

All notable changes to KindlyGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Preparing for v1.0 Release
- Documentation completion in progress
- Platform testing ongoing
- Release artifacts preparation

## [0.15.0] - 2025-01-06

### Added
- **Enhanced Threat System with Quarantine Support**
  - New `ThreatInfo` struct with comprehensive threat metadata
  - Quarantine system for isolating suspicious content
  - Encrypted quarantine storage using ChaCha20Poly1305
  - Threat severity levels (Critical, High, Medium, Low, Info)
  - Protection modes (Monitor, Block, BlockAndLog, Quarantine)
  - Friendly, educational threat messages for better user experience

- **New MCP Tools for Quarantine Management**
  - `quarantine_list`: List all quarantined items with metadata
  - `quarantine_get`: Retrieve specific quarantined content securely
  - `quarantine_delete`: Remove items from quarantine
  - `quarantine_restore`: Safely restore quarantined content
  - `quarantine_analyze`: Deep analysis of quarantined threats
  - `quarantine_export`: Export quarantine data for analysis

- **Enhanced Scan Tools**
  - New `includeMetadata` parameter for detailed threat information
  - `protectionMode` parameter to control threat handling behavior
  - `severityThreshold` for filtering threats by severity
  - Support for batch operations with progress tracking
  - Real-time threat statistics during scanning

- **Security Infrastructure Improvements**
  - ChaCha20Poly1305 authenticated encryption for quarantine
  - Per-item encryption keys with secure key derivation
  - Integrity verification for all quarantined content
  - Audit logging for all quarantine operations
  - Secure temporary file handling with automatic cleanup

- **Performance Optimizations**
  - Streaming encryption/decryption for large files
  - Parallel threat analysis for multi-core utilization
  - Optimized pattern matching with caching
  - Memory-efficient large file handling
  - Background quarantine maintenance tasks

### Changed
- **API Enhancements**
  - Scanner trait now returns `ThreatInfo` instead of simple `Threat`
  - Neutralizer supports protection mode-aware operations
  - Enhanced error types with more context
  - Improved JSON serialization for MCP compatibility
  - Better separation of concerns between detection and action

- **Threat Detection Improvements**
  - More granular threat categorization
  - Context-aware severity assignment
  - Enhanced pattern recognition accuracy
  - Reduced false positive rate
  - Better handling of edge cases

- **User Experience**
  - Friendly, educational threat messages
  - Clear explanations of why content was flagged
  - Actionable recommendations for users
  - Non-alarmist tone in security messages
  - Progress indicators for long operations

### Fixed
- Improved error handling in scanner implementations
- Better resource cleanup in error paths
- Fixed race conditions in concurrent operations
- Resolved memory leaks in long-running scans
- Corrected threat severity calculations

### Security
- **Encryption**: All quarantined content encrypted with ChaCha20Poly1305
- **Authentication**: HMAC-based integrity verification
- **Key Management**: Secure key derivation and storage
- **Access Control**: Permission-based quarantine operations
- **Audit Trail**: Complete logging of security operations
- **Input Validation**: Enhanced validation for all API inputs

### Documentation
- Comprehensive API documentation for new features
- Security best practices guide
- Quarantine management documentation
- Migration guide from v0.10.x
- Updated examples and tutorials
- Performance tuning guide

### Compatibility
- Backward compatible with v0.10.x scanner API
- MCP protocol compliance maintained
- Configuration format unchanged
- Smooth upgrade path with auto-migration

## [0.10.3] - 2025-07-05

### Changed
- Simplified distribution to only include MCP server (as 'kindlyguard') and development tools
- Excluded CLI from public distribution (kept for internal use only)
- MCP server binary is now the primary 'kindlyguard' executable

### Fixed
- Regenerated WiX configurations for streamlined distribution

## [0.10.2] - 2025-07-05

### Fixed
- Resolved WiX installer configuration with outdated binary names
- Fixed binary name conflict between CLI and server (server now uses 'kindlyguard-server')
- Excluded Tauri app and xtask from cargo-dist to prevent build conflicts
- Regenerated all WiX installer definitions with correct binary paths
- Added validate-dist command to catch configuration issues early

## [0.10.1] - 2025-07-05

### Fixed
- Added missing `dist = true` metadata to enable cargo-dist builds
- Fixed CLI binary name to 'kindlyguard' for consistency
- Cargo-dist now properly builds release artifacts for all platforms

## [0.10.0] - 2025-01-05

### Added
- **Resilience Architecture**: Comprehensive trait-based resilience components
  - Circuit breaker pattern with configurable thresholds
  - Retry mechanism with exponential backoff and jitter
  - Bulkhead isolation for resource protection
  - All components use trait abstraction for flexibility

- **Enhanced Security Features**
  - Improved Unicode threat detection with better performance
  - Advanced XSS context-aware filtering
  - Enhanced SQL injection prevention patterns
  - Better command injection detection for Windows/Unix

- **Performance Improvements**
  - Optimized scanner performance (200+ MB/s for large files)
  - Reduced memory usage through streaming
  - Lock-free atomic statistics collection
  - SIMD optimizations for Unicode scanning

- **Developer Experience**
  - Improved xtask build system
  - Better error messages and diagnostics
  - Enhanced CLI with more commands
  - Comprehensive test suite with property tests

### Changed
- Migrated all resilience components to trait-based architecture
- Updated minimum Rust version to 1.81
- Improved configuration schema with better defaults
- Enhanced MCP protocol compliance
- Better separation of concerns between modules

### Fixed
- Various compilation warnings and clippy lints
- Improved error handling throughout codebase
- Better handling of edge cases in threat detection
- Fixed race conditions in concurrent operations

### Security
- All security operations now use constant-time comparisons
- Enhanced protection against timing attacks
- Improved input validation across all APIs
- Better isolation of security-critical operations

## [0.9.5] - 2024-01-XX

### Added
- ✅ **Cross-Platform Security**
  - Windows command injection detection (cmd.exe, PowerShell)
  - Windows-specific path traversal patterns
  - Enhanced Unix command detection patterns
  
- ✅ **DoS Protection**
  - Configurable content size limits (default 5MB)
  - Chunk-based scanning for large payloads
  - Timeout protection (5-second scan limit)
  - New `DosPotential` threat type
  
- ✅ **Security Enhancements**
  - Constant-time token comparison using `subtle` crate
  - High-entropy token generation methods
  - Enhanced path traversal detection (URL-encoded patterns)
  - Recursive threat neutralization
  
- ✅ **Testing Infrastructure**
  - Trait compliance tests
  - Behavioral equivalence tests
  - Performance regression tests
  - Security property tests
  - Integration scenarios
  - Chaos engineering tests
  - Load testing scenarios
  - Comparative benchmarks

### Changed
- Improved neutralization logic for nested threats
- Enhanced aggressive neutralization for edge cases
- Updated MCP protocol response format for compliance
- Refactored event buffer to use trait-based architecture
- Enhanced internal buffering implementation

### Fixed
- Runtime configuration issues (`block_in_place` errors)
- All 4 failing unit tests
- 51 compilation errors in enhanced mode
- Type compatibility between server and core
- Missing `futures` dependency
- JSON field naming in MCP protocol
- Batch neutralization delegation in wrapper neutralizers

### Security
- Fixed timing attack vulnerability in token comparison
- Added protection against compression bombs
- Enhanced SQL injection neutralization
- Improved command injection detection
- Added LDAP and NoSQL injection handling

### Performance
- Optimized large content scanning (150+ MB/s)
- Reduced memory usage with streaming approach
- Added early termination for oversized content
- Improved regex pattern matching efficiency

## [0.9.0] - 2024-01-XX

### Added
- Initial trait-based architecture implementation
- Factory pattern for component selection
- Enhanced implementations with proprietary optimizations
- OAuth 2.0 authentication support
- Distributed tracing with OpenTelemetry
- Circuit breaker pattern implementation
- Comprehensive audit logging

### Changed
- Separated public traits from proprietary implementations
- Moved to configuration-based implementation selection
- Enhanced scanner interface for better extensibility

## [0.8.0] - 2023-12-XX

### Added
- Unicode threat detection (homograph, BiDi, invisible)
- SQL injection prevention
- XSS protection with context awareness
- Command injection detection
- Path traversal prevention
- Rate limiting with token bucket
- WebSocket transport support

## [0.1.0] - 2023-11-XX

### Added
- Initial MCP server implementation
- Basic threat scanner
- Simple neutralizer
- HTTP transport
- Configuration system
- Basic authentication

[Unreleased]: https://github.com/yourusername/kindly-guard/compare/v0.15.0...HEAD
[0.15.0]: https://github.com/yourusername/kindly-guard/compare/v0.10.3...v0.15.0
[0.10.3]: https://github.com/yourusername/kindly-guard/compare/v0.10.2...v0.10.3
[0.10.2]: https://github.com/yourusername/kindly-guard/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/yourusername/kindly-guard/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/yourusername/kindly-guard/compare/v0.9.5...v0.10.0
[0.9.5]: https://github.com/yourusername/kindly-guard/compare/v0.9.0...v0.9.5
[0.9.0]: https://github.com/yourusername/kindly-guard/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/yourusername/kindly-guard/compare/v0.1.0...v0.8.0
[0.1.0]: https://github.com/yourusername/kindly-guard/releases/tag/v0.1.0