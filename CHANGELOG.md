# Changelog

All notable changes to KindlyGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Preparing for v1.0 Release
- Documentation completion in progress
- Platform testing ongoing
- Release artifacts preparation

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
- Moved `AtomicBitPackedEventBuffer` to `kindly-guard-core`

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
- Enhanced implementations in `kindly-guard-core`
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

[Unreleased]: https://github.com/yourusername/kindly-guard/compare/v0.9.5...HEAD
[0.9.5]: https://github.com/yourusername/kindly-guard/compare/v0.9.0...v0.9.5
[0.9.0]: https://github.com/yourusername/kindly-guard/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/yourusername/kindly-guard/compare/v0.1.0...v0.8.0
[0.1.0]: https://github.com/yourusername/kindly-guard/releases/tag/v0.1.0