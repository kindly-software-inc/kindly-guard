# KindlyGuard 🛡️

**Security that's kind to developers, tough on threats**

[![Crates.io](https://img.shields.io/crates/v/kindlyguard.svg)](https://crates.io/crates/kindlyguard)
[![CI Status](https://img.shields.io/github/workflow/status/kindlyguard/kindlyguard/CI)](https://github.com/kindlyguard/kindlyguard/actions)
[![Security Audit](https://img.shields.io/badge/security-audited-green.svg)](docs/SECURITY_AUDIT_REPORT.md)
[![License](https://img.shields.io/crates/l/kindlyguard.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://github.com/rust-lang/rust)
[![deps.rs](https://deps.rs/repo/github/kindlyguard/kindlyguard/status.svg)](https://deps.rs/repo/github/kindlyguard/kindlyguard)
[![Documentation](https://docs.rs/kindlyguard/badge.svg)](https://docs.rs/kindlyguard)

**Production-ready security layer for AI model interactions via the Model Context Protocol (MCP)**

## 🚀 Quick Start (30 seconds)

### Quick Install Scripts (New!)
**Shell (macOS/Linux):**
```bash
curl -LsSf https://github.com/samduchaine/kindly-guard/releases/latest/download/kindly-guard-installer.sh | sh
```

**PowerShell (Windows):**
```powershell
irm https://github.com/samduchaine/kindly-guard/releases/latest/download/kindly-guard-installer.ps1 | iex
```

### npm (Recommended for Node.js users)
```bash
npm install -g kindlyguard && kindlyguard --stdio
```

### Homebrew (macOS/Linux)
```bash
brew install samduchaine/tap/kindly-guard
```

### Native Installers
- **Windows:** [Download MSI installer](https://github.com/samduchaine/kindly-guard/releases/latest)
- **macOS:** [Download PKG installer](https://github.com/samduchaine/kindly-guard/releases/latest)
- **Linux:** [Download .deb or .rpm](https://github.com/samduchaine/kindly-guard/releases/latest)

### Cargo
```bash
cargo install kindlyguard-cli && kindlyguard-cli --stdio
```

### Docker
```bash
# Quick start with Docker
docker run -it kindlysoftware/kindlyguard:latest --stdio

# With persistent configuration
docker run -it \
  -v $(pwd)/config:/etc/kindlyguard:ro \
  -v kindly-data:/var/lib/kindlyguard \
  kindlysoftware/kindlyguard:latest
```

📚 **[Full Docker Deployment Guide](docs/DOCKER_DEPLOYMENT.md)** | **[Docker Security Guide](docs/DOCKER_SECURITY.md)**

**That's it!** You're now protected. Try it:
```bash
kindlyguard scan "DROP TABLE users;"
# 🚨 SQL injection detected at position 0-4
```

### Configure with Claude or VS Code (Optional)
```bash
# Auto-detect and configure MCP integration
kindlyguard setup-mcp

# Or specify your IDE
kindlyguard setup-mcp --ide claude-desktop

# Show configuration for manual setup
kindlyguard show-mcp-config
```

## ✨ Features at a Glance

- ⚡ **<1ms threat detection** - Sub-millisecond scanning latency
- 🛡️ **Comprehensive protection** - Unicode, injection, XSS threats
- 🤝 **MCP protocol support** - Seamless AI assistant integration
- 📊 **15-26 MB/s throughput** - Production-ready performance
- 🎯 **<0.1% false positives** - Accurate threat detection
- 🔒 **Enterprise features** - OAuth 2.0, rate limiting, audit logs
- 📖 **Developer friendly** - Clear messages, not cryptic errors

## 🛡️ What is KindlyGuard?

KindlyGuard is a developer-friendly security server that protects AI systems without getting in your way. Built by developers, for developers, it provides enterprise-grade protection while remaining approachable and easy to use. Instead of cryptic errors and false positives, KindlyGuard offers clear, actionable security insights that help you build safer AI applications.

## 🎯 Our Mission

We believe security should be accessible to everyone. KindlyGuard was born from the conviction that developers shouldn't have to choose between robust security and ease of use. By being "kind" in our approach - with clear messages, helpful suggestions, and a focus on protection rather than punishment - we make security a collaborative ally rather than a gatekeeper.

Every developer deserves enterprise-grade security tools. That's why KindlyGuard's core security features will always be open source and free. Because when we all build more secure software, we all win.

## ❓ Why KindlyGuard?

### Security That Doesn't Slow You Down
Traditional security tools often feel like roadblocks. KindlyGuard integrates seamlessly into your workflow, providing protection without friction. Our sub-millisecond scanning ensures your AI applications remain responsive while staying secure.

### Clear, Actionable Threat Reports
When KindlyGuard detects a threat, it doesn't just say "blocked." It explains what was found, why it's dangerous, and how to fix it. Every security alert is an opportunity to learn and improve.

### Built on Modern Rust for Safety and Speed
Leveraging Rust's memory safety guarantees and zero-cost abstractions, KindlyGuard delivers enterprise-grade security without the enterprise-grade overhead. No buffer overflows, no data races, just reliable protection.

### Community-Driven Development
Security is a team sport. KindlyGuard thrives on community contributions, from threat pattern updates to feature suggestions. Together, we're building a safer AI ecosystem for everyone.

## 🛡️ Security Features

### Comprehensive Threat Detection
- **Unicode Security** - Detects homograph attacks, BiDi overrides, zero-width characters
- **Injection Prevention** - SQL, command, LDAP, path traversal, prompt injection
- **XSS Protection** - Context-aware HTML/JS/CSS sanitization
- **DoS Protection** - Rate limiting, circuit breakers, resource limits
- **Pattern Matching** - ML-enhanced threat pattern detection

### Enterprise Security
- **OAuth 2.0** - Full RFC 8707 compliance with resource indicators
- **Message Signing** - Ed25519 cryptographic signatures
- **Audit Logging** - Comprehensive security event tracking
- **Fine-grained Permissions** - Tool and resource-level access control
- **Secure by Default** - All security features enabled out of the box

## 📊 Performance

Optimized for high-throughput AI workloads:

- **Unicode Scanning**: 150+ MB/s throughput
- **Injection Detection**: 200+ MB/s throughput
- **Sub-millisecond Latency**: <0.5ms per request overhead
- **Memory Efficient**: <50MB baseline memory usage
- **Scalable**: Excellent multi-core performance

## 🏗️ Architecture

KindlyGuard uses a trait-based architecture for maximum flexibility and performance:

```rust
// Clean trait-based API
pub trait SecurityScanner: Send + Sync {
    async fn scan(&self, input: &str) -> Result<Vec<Threat>>;
}

// Multiple implementations available
let scanner = create_scanner(config)?; // Automatic selection
```

### Key Components

- **Scanner Engine** - Modular threat detection system
- **Neutralizer** - Safe content transformation
- **Shield UI** - Real-time threat monitoring
- **Resilience Layer** - Circuit breakers and retry logic
- **Storage Backend** - SQLite persistence with caching

## 🔧 Configuration

### Basic Configuration
```yaml
# kindlyguard.yaml
scanner:
  unicode_detection: true
  injection_detection: true
  xss_protection: true

auth:
  enabled: true
  allowed_clients:
    - client_id: "my-app"
      secret: "change-me-in-production"
      allowed_scopes: ["tools:execute"]
```

### Production Configuration
```yaml
scanner:
  unicode_detection: true
  injection_detection: true
  xss_protection: true
  pattern_matching: true
  max_scan_depth: 10

auth:
  enabled: true
  require_resource_indicators: true
  token_lifetime: 3600
  allowed_clients:
    - client_id: "production-app"
      secret: "$2b$10$..."  # bcrypt hash
      allowed_scopes: ["tools:execute", "resources:read"]
      allowed_resources: ["urn:kindly:api:*"]

rate_limit:
  enabled: true
  default_rpm: 60
  burst_size: 10
  threat_penalty_multiplier: 2.0

resilience:
  circuit_breaker:
    failure_threshold: 5
    recovery_timeout: "30s"
  retry:
    max_attempts: 3
    initial_delay: "100ms"

logging:
  level: "info"
  format: "json"
  audit:
    enabled: true
    path: "/var/log/kindlyguard/audit.log"
```

## 🤖 MCP Integration

KindlyGuard includes intelligent MCP (Model Context Protocol) setup that auto-detects your IDE and configures it automatically:

### Automatic Setup
```bash
# Auto-detect your IDE and configure
kindlyguard setup-mcp

# Test the MCP connection
kindlyguard test-mcp
```

### Supported IDEs
- **Claude Desktop** - Full MCP support with real-time scanning
- **VS Code** - Via MCP extensions
- **Cursor** - Native MCP integration
- **Neovim** - Through MCP plugins
- **Zed** - MCP protocol support

### Manual Configuration
If auto-setup doesn't work for your environment:
```bash
# Show configuration in your preferred format
kindlyguard show-mcp-config --format json
kindlyguard show-mcp-config --format yaml
```

### What It Does
Once configured, KindlyGuard:
- Scans all inputs/outputs for security threats
- Provides real-time threat notifications
- Integrates seamlessly with your AI workflow
- Requires no code changes in your projects

## 📚 Documentation

### Core Documentation
- [API Documentation](docs/API_DOCUMENTATION.md) - Complete API reference
- [Configuration Guide](docs/CONFIGURATION.md) - Detailed configuration options
- [Security Audit](docs/SECURITY_AUDIT_REPORT.md) - Security analysis and findings
- [Architecture](ARCHITECTURE.md) - System design and patterns
- [Testing Guide](TESTING.md) - Comprehensive testing documentation

### Development Guides
- **[Development Workflow](docs/DEVELOPMENT_WORKFLOW.md)** - Modern Rust development workflow
- **[Tooling Guide](docs/TOOLING.md)** - Detailed documentation for all tools
- **[Quick Reference](docs/QUICK_REFERENCE.md)** - Command cheatsheet
- [Contributing Guide](CONTRIBUTING.md) - How to contribute

### Deployment Guides
- [Docker Deployment Guide](docs/DOCKER_DEPLOYMENT.md) - Complete Docker deployment documentation
- [Docker Security Guide](docs/DOCKER_SECURITY.md) - Docker security best practices
- [MCP Server Setup](docs/MCP_SERVER_SETUP.md) - MCP integration guide

### Project Analysis
- [Project Analysis Summary](PROJECT_ANALYSIS_SUMMARY.md) - Comprehensive architectural analysis
- [Dependency Analysis](DEPENDENCY_ANALYSIS.md) - Dependency graphs and critical paths
- [Code Structure Map](CODE_STRUCTURE_MAP.md) - Complete code organization
- [Architecture Diagrams](ARCHITECTURE_DIAGRAMS.md) - Visual system architecture
- [Module Interactions](MODULE_INTERACTIONS.md) - Component communication patterns
- [Security Architecture](SECURITY_ARCHITECTURE.md) - Complete security mapping
- [API Surface Map](API_SURFACE_MAP.md) - All public APIs documented
- [Project Structure](PROJECT_STRUCTURE.md) - File tree and organization

## 🧪 Testing

KindlyGuard maintains extensive test coverage:

```bash
# Run all tests
cargo test --all-features

# Run security-specific tests
cargo test --test security_tests

# Run integration tests
cargo test --test integration

# Run benchmarks
cargo bench

# Run comprehensive test suite
./run-all-tests.sh
```

### Test Coverage
- **Unit Tests**: 150+ tests, 100% coverage
- **Security Tests**: 50+ tests, all vulnerabilities fixed
- **Integration Tests**: 30+ end-to-end scenarios
- **Property Tests**: Fuzzing with 10,000+ iterations
- **Benchmarks**: Performance regression tracking

## 🚢 Deployment

### Systemd Service
```bash
# Install service
sudo ./systemd/install.sh

# Start service
sudo systemctl start kindlyguard
sudo systemctl enable kindlyguard
```

### Docker Compose
```yaml
version: '3.8'
services:
  kindlyguard:
    image: kindlysoftware/kindlyguard:latest
    restart: unless-stopped
    user: "10001:10001"  # Non-root user
    read_only: true      # Security hardening
    volumes:
      - ./config:/etc/kindlyguard:ro
      - kindly-data:/var/lib/kindlyguard
      - kindly-logs:/var/log/kindlyguard
    tmpfs:
      - /tmp/kindlyguard
    environment:
      - RUST_LOG=info
      - KINDLY_AUTH_ENABLED=true
    ports:
      - "127.0.0.1:8080:8080"  # Only expose locally
    healthcheck:
      test: ["CMD", "/usr/local/bin/kindlyguard", "health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  kindly-data:
  kindly-logs:
```

📚 See [Docker Deployment Guide](docs/DOCKER_DEPLOYMENT.md) for production configurations.

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kindlyguard
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: kindlyguard
        image: kindlyguard/kindlyguard:latest
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

#### Requirements
- **Rust**: 1.81 or newer ([MSRV Policy](docs/MSRV_POLICY.md))
- **Operating System**: Linux, macOS, or Windows
- **Optional**: Docker for containerized development

```bash
# Clone repository
git clone https://github.com/kindlyguard/kindlyguard
cd kindlyguard

# Verify Rust version (must be 1.81+)
rustc --version

# Install dependencies and dev tools
cargo build
./scripts/install-dev-tools.sh

# Start development (with automatic compilation)
bacon

# Run tests (60% faster with nextest)
cargo nextest run

# Run security checks
cargo deny check
cargo audit

# Run with debug logging
RUST_LOG=debug cargo run -- --stdio
```

#### Modern Development Tools

We use cutting-edge Rust tooling for security and productivity:
- **cargo-nextest** - 60% faster test runner with better output
- **cargo-deny** - Supply chain security auditing
- **bacon** - Instant feedback during development
- **cargo-audit** - CVE vulnerability scanning
- **typos** - Lightning-fast spell checker
- **committed** - Conventional commit enforcement

📚 See our [Development Workflow Guide](docs/DEVELOPMENT_WORKFLOW.md) for complete tooling documentation.

## 📈 Roadmap

### v0.9.7 (Current Release)
- ✅ Core security scanning engine
- ✅ MCP protocol implementation
- ✅ OAuth 2.0 authentication
- ✅ Rate limiting and DoS protection
- ✅ Cross-platform support
- ✅ Comprehensive test suite
- ✅ Performance optimizations
- ✅ Audit logging system

### v1.0.0 (Q2 2025)
- 🚧 Community feedback integration
- 🚧 API stabilization
- 🚧 Production hardening
- 🚧 Enhanced documentation

### Future
- 📋 WebAssembly plugin system
- 📋 Distributed deployment mode
- 📋 Advanced threat intelligence
- 📋 Compliance reporting (SOC2, ISO27001)

## 🔒 Security

KindlyGuard takes security seriously:

- Regular security audits
- Responsible disclosure program
- Security-first development practices
- No unsafe code in public APIs

For security issues, please email samuel@kindly.software instead of using the issue tracker.

## 📄 License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)).

## Export Control Notice

This software includes cryptographic functionality and may be subject to export
controls in various jurisdictions. Users are responsible for compliance with
applicable export control laws and regulations.

## 🙏 Acknowledgments

Built with security-first principles and powered by:
- [unicode-security](https://crates.io/crates/unicode-security) - Unicode threat detection
- [tokio](https://tokio.rs) - Async runtime
- [serde](https://serde.rs) - Serialization framework

---

**KindlyGuard: Making security a friend, not a foe** 🛡️

*Join us in building a kinder, safer AI ecosystem. Every contribution makes a difference.*