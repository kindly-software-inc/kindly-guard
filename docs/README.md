# KindlyGuard Documentation

Welcome to the KindlyGuard documentation. This directory contains all project documentation organized by category.

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

### ✨ [Features](features/)
- [FEATURES.md](features/FEATURES.md) - Complete feature inventory with locations

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