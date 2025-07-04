# KindlyGuard + Claude: User Guide

## Quick Start

### 1. Installation (One-Time Setup)
```bash
# Clone and build
git clone https://github.com/yourusername/kindly-guard.git
cd kindly-guard
cargo build --release

# Automatic setup
./target/release/kindly-guard setup-mcp

# Restart Claude Desktop
```

### 2. Verify Installation
```bash
# Check if configured
cat ~/.claude/settings.local.json | grep kindly-guard

# Test scanning
./target/release/kindly-guard scan /tmp/test.txt
```

## How It Works

When you use Claude Desktop, KindlyGuard automatically:
- 🛡️ Scans all inputs for security threats
- 🔍 Detects SQL injection, XSS, unicode attacks
- ⚡ Neutralizes threats in real-time
- 📊 Logs security events for audit

## Common Commands

### Scan Files
```bash
# Scan a single file
kindly-guard scan suspicious_file.txt

# Scan with detailed output
kindly-guard scan file.js --format json
```

### Check Status
```bash
# View security status
kindly-guard status

# Show telemetry
kindly-guard telemetry

# Display features
kindly-guard info
```

### Advanced Features
```bash
# Start web dashboard
kindly-guard dashboard

# Enable enhanced security
kindly-guard advancedsecurity enable
```

## Threat Types Detected

| Threat | Severity | Example |
|--------|----------|---------|
| SQL Injection | High | `'; DROP TABLE users; --` |
| XSS | High | `<script>alert('xss')</script>` |
| Unicode Attacks | High | Zero-width characters, BiDi overrides |
| Command Injection | Critical | `; rm -rf /` |
| Path Traversal | High | `../../../etc/passwd` |

## Troubleshooting

### KindlyGuard not working in Claude?
1. Restart Claude Desktop
2. Check logs: `RUST_LOG=debug kindly-guard --stdio`
3. Re-run setup: `kindly-guard setup-mcp`

### False positives?
- Report to: security@kindlyguard.dev
- Temporarily disable: Set severity thresholds in config

### Performance impact?
- Typical overhead: <5ms per request
- Heavy files: Use streaming mode
- Monitor with: `kindly-guard telemetry`

## Configuration

### Basic Config (`~/.kindly-guard/config.toml`)
```toml
[security]
threat_threshold = "medium"
auto_neutralize = true

[performance]
max_file_size_mb = 100
timeout_seconds = 30

[logging]
level = "info"
file = "~/.kindly-guard/security.log"
```

## Security Best Practices

1. **Keep Updated**: Run `git pull && cargo build --release` monthly
2. **Review Logs**: Check `~/.kindly-guard/security.log` weekly
3. **Test Regularly**: Use test files in `/tmp/` to verify detection
4. **Report Issues**: Security concerns to security@kindlyguard.dev

## Support

- Documentation: `/docs` directory
- Issues: GitHub Issues
- Security: security@kindlyguard.dev
- Community: Discord/Slack (coming soon)

---

*KindlyGuard: Your AI's Security Guardian* 🛡️