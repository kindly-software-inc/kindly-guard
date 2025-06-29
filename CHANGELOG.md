# Changelog

All notable changes to KindlyGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- API versioning system with stability levels (experimental, beta, stable)
- JWT signature verification with HMAC-SHA256
- Version metadata in API responses (`_meta` field)
- Comprehensive testing infrastructure
  - Unit tests with mocking support (mockall)
  - Integration tests for MCP protocol compliance
  - End-to-end test scenarios
  - Security-specific test suite
  - Property-based testing with proptest
  - Fuzzing with cargo-fuzz (6 targets)
  - Performance regression benchmarks
- Testing documentation (TESTING_GUIDE.md, MOCKING.md, PERFORMANCE_TESTING.md)
- Code coverage reporting with cargo-llvm-cov (70% minimum)
- CI/CD workflows for comprehensive testing
- Performance regression detection scripts

### Changed
- Replaced all `unwrap()` calls in production code with proper error handling
- Enhanced auth module to support JWT signature verification
- Updated AuthConfig to include JWT secret and signature verification settings

### Security
- Implemented full JWT signature verification to prevent token forgery
- Added constant-time token comparison
- Enhanced error handling to prevent panics in production

## [0.1.0] - 2024-01-01

### Added
- Initial release of KindlyGuard MCP Security Server
- Core security scanning capabilities
  - Unicode threat detection (BiDi override, homoglyphs, invisible characters)
  - Injection detection (SQL, command, path traversal)
  - Pattern-based threat detection
- MCP protocol implementation
  - Full JSON-RPC 2.0 compliance
  - Tools, resources, and prompts support
  - Protocol version 2024-11-05
- Authentication and authorization
  - OAuth 2.0 with Resource Indicators (RFC 8707)
  - Token-based authentication
  - Scope-based permissions
- Rate limiting with token bucket algorithm
- Message signing with HMAC-SHA256 and Ed25519
- Real-time threat shield display
- Docker support with multi-stage builds
- Systemd service integration
- Comprehensive documentation
  - README with quick start guide
  - API documentation
  - Configuration guide
  - Architecture overview

### Security
- No unsafe code (enforced with #[forbid(unsafe_code)])
- Input validation on all external data
- Secure defaults for all configuration
- Rate limiting to prevent DoS attacks
- Cryptographic message signing

[Unreleased]: https://github.com/yourusername/kindly-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourusername/kindly-guard/releases/tag/v0.1.0