# KindlyGuard

[![Docker Pulls](https://img.shields.io/docker/pulls/kindlysoftware/kindlyguard)](https://hub.docker.com/r/kindlysoftware/kindlyguard)
[![Docker Image Size](https://img.shields.io/docker/image-size/kindlysoftware/kindlyguard)](https://hub.docker.com/r/kindlysoftware/kindlyguard)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/kindlysoftware/kindlyguard/blob/main/LICENSE)

🛡️ **Security-focused MCP server that protects against unicode attacks, injection attempts, and other threats**

KindlyGuard is a high-performance security scanner designed to protect Model Context Protocol (MCP) communications from various attack vectors including unicode exploits, injection attacks, and XSS attempts.

## 🚀 Quick Start

```bash
# Run with Docker (recommended)
docker run --rm -it kindlysoftware/kindlyguard:latest --help

# Start as MCP server
docker run --rm -i kindlysoftware/kindlyguard:latest server --stdio

# Scan a file for threats
docker run --rm -v $(pwd):/data kindlysoftware/kindlyguard:latest scan /data/suspicious.json
```

## 🛡️ Security Features

- **Unicode Threat Detection**: Detects homograph attacks, bidirectional text exploits, and zero-width characters
- **Injection Prevention**: Guards against SQL, command, LDAP, and path traversal injection attempts
- **XSS Protection**: Context-aware prevention for HTML, JavaScript, CSS, and URL contexts
- **Pattern Recognition**: Extensible pattern matching engine with regex and ML-based detection
- **Real-time Monitoring**: Live threat dashboard with detailed statistics
- **Audit Logging**: Comprehensive threat logging with SQLite persistence

## 🖥️ Supported Platforms

- `linux/amd64` - Standard x86_64 Linux
- `linux/arm64` - ARM64/aarch64 (Apple Silicon, AWS Graviton)

## 📦 Available Tags

- `latest` - Latest stable release
- `v0.1.0` - Specific version tags
- `dev` - Development builds (use with caution)

## 🔧 Configuration

Mount a configuration file to customize behavior:

```bash
docker run --rm -i \
  -v $(pwd)/config.toml:/config/config.toml \
  kindlysoftware/kindlyguard:latest \
  server --config /config/config.toml
```

Example configuration:

```toml
[scanner]
enable_unicode_checks = true
enable_injection_checks = true
enable_xss_checks = true
pattern_matching_enabled = true

[server]
log_level = "info"
max_request_size = 10485760  # 10MB

[storage]
database_path = "/data/kindlyguard.db"
cache_size = 1000
```

## 🔗 Links

- **GitHub Repository**: [github.com/kindlysoftware/kindlyguard](https://github.com/kindlysoftware/kindlyguard)
- **Documentation**: [Full documentation](https://github.com/kindlysoftware/kindlyguard/tree/main/docs)
- **Issue Tracker**: [Report issues](https://github.com/kindlysoftware/kindlyguard/issues)
- **MCP Specification**: [Model Context Protocol](https://modelcontextprotocol.com/)

## 📄 License

MIT License - see [LICENSE](https://github.com/kindlysoftware/kindlyguard/blob/main/LICENSE) for details.

## 🤝 Contributing

Contributions are welcome! Please see our [Contributing Guide](https://github.com/kindlysoftware/kindlyguard/blob/main/CONTRIBUTING.md) for details.

---

Built with ❤️ by [Kindly Software](https://github.com/kindlysoftware)