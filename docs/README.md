# KindlyGuard Documentation

Welcome to the KindlyGuard documentation. This directory contains all project documentation organized by category.

## 🚀 Latest Updates

### Version 0.9.4 - Cross-Platform Support

This release focuses on improving cross-platform compatibility:

- **Fixed NPM package installation** for all platforms
- **Added Windows binary support** via cross-compilation
- **Enhanced build infrastructure** with Docker improvements
- **Comprehensive deployment documentation** added

See [RELEASE_NOTES_v0.9.4.md](../RELEASE_NOTES_v0.9.4.md) for full details.

## Documentation Structure

### 📐 [Architecture](architecture/)
- [ARCHITECTURE.md](architecture/ARCHITECTURE.md) - System design and architecture overview

### 📚 [Guides](guides/)
- [PROJECT_PRIMER.md](guides/PROJECT_PRIMER.md) - Quick start guide for new developers
- [RUST_GUIDE.md](guides/RUST_GUIDE.md) - Rust-specific patterns and best practices

### 🛠️ [Development](development/)
- [TESTING.md](development/TESTING.md) - Testing strategy and guidelines
- [CURRENT_TEST_STATUS.md](development/CURRENT_TEST_STATUS.md) - Current test suite status
- [MULTI_PROTOCOL_SECURITY_TEST_PLAN.md](development/MULTI_PROTOCOL_SECURITY_TEST_PLAN.md) - Security test planning

### 🔒 Security
- [SECURITY_AUDIT_REPORT.md](./SECURITY_AUDIT_REPORT.md) - Security analysis and findings
- [API_DOCUMENTATION.md](./API_DOCUMENTATION.md) - API security guidelines

### ✨ [Features](features/)
- [FEATURES.md](features/FEATURES.md) - Complete feature inventory with locations

### 🐳 Deployment
- [DOCKER_DEPLOYMENT.md](./DOCKER_DEPLOYMENT.md) - Comprehensive Docker deployment guide
- [DOCKER_SECURITY.md](./DOCKER_SECURITY.md) - Docker security hardening checklist
- [CONFIGURATION.md](./CONFIGURATION.md) - Configuration reference
- [MCP_SERVER_SETUP.md](./MCP_SERVER_SETUP.md) - MCP integration setup

### 📦 [Archive](archive/)
Contains session-specific documentation and historical records:
- Session summaries
- Test execution reports
- Implementation status updates

## Quick Links

- **Getting Started**: See [PROJECT_PRIMER.md](guides/PROJECT_PRIMER.md)
- **Architecture Overview**: See [ARCHITECTURE.md](architecture/ARCHITECTURE.md)
- **Feature List**: See [FEATURES.md](features/FEATURES.md)
- **Contributing**: See [RUST_GUIDE.md](guides/RUST_GUIDE.md)

## API Documentation

For API documentation, run:
```bash
cargo doc --no-deps --open
```

## Additional Resources

- [Security Audit Reports](../kindly-guard-server/docs/)
- [Benchmarks](../kindly-guard-server/benches/README.md)
- [Examples](../kindly-guard-server/examples/)