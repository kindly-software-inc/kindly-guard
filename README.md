# 🛡️ KindlyGuard

**Your AI's security guardian. Running locally. No cloud. No proxy. Pure stealth.**

[![Version](https://img.shields.io/badge/version-0.15.0-blue)](https://github.com/kindly-software-inc/kindly-guard/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![Security](https://img.shields.io/badge/security-first-red)](docs/security/README.md)

## ⚡ Instant Install

```bash
npm install -g kindlyguard
```

That's it! No Rust, no compilation, no waiting. Works on Windows, macOS, and Linux.

**Everything in one command.** The `kindlyguard` binary includes:
- 🛡️ MCP Security Server
- 🔍 CLI Scanner Tools  
- 📊 Real-time Monitor
- 🎯 Multi-protocol Support
- 🚀 All protection features

### Other Installation Methods

<details>
<summary>🦀 For Rust developers</summary>

```bash
cargo install kindlyguard
# or from source
cargo install --git https://github.com/kindly-software-inc/kindly-guard
```
</details>

<details>
<summary>🍺 Using Homebrew (macOS/Linux)</summary>

```bash
brew tap kindly-software-inc/tap
brew install kindlyguard
```
</details>

<details>
<summary>📦 Direct binary download</summary>

Download from [GitHub Releases](https://github.com/kindly-software-inc/kindly-guard/releases) and add to PATH.
</details>

That's it. You're protected in seconds. No accounts. No API keys. No tracking.

## 🔒 Why Local Security Matters

**Your security should never depend on someone else's server.**

KindlyGuard runs entirely on your machine:
- ✅ **No cloud dependencies** - Works offline, always
- ✅ **No proxy servers** - Your data never leaves your device
- ✅ **No MITM risks** - Direct protection, no intermediaries
- ✅ **No single point of failure** - Your security, your control
- ✅ **Pure stealth mode** - Invisible to attackers, no external signatures

## 🎯 What is KindlyGuard?

KindlyGuard is an enterprise-grade security layer for AI assistants that detects and neutralizes:
- 🦠 Prompt injection attacks
- 🎭 Unicode manipulation and homograph attacks
- 💉 SQL/Command/LDAP injection attempts
- 🕸️ Cross-site scripting (XSS) payloads
- 📁 Path traversal exploits
- 🔐 And much more...

**Built with Rust for maximum performance and safety.**

## ⚡ Quick Start

### For Claude Desktop Users

1. Install KindlyGuard:
   ```bash
   npm install -g kindlyguard
   ```

2. Configure Claude Desktop:
   ```bash
   kindlyguard mcp setup
   ```

3. Restart Claude Desktop. You're protected!

### For Developers

```bash
# Install once, use everywhere
npm install -g kindlyguard

# Scan files for threats
kindlyguard scan suspicious.txt

# Start MCP server (stdio mode - default)
kindlyguard serve

# Start with real-time shield display
kindlyguard serve --shield

# Monitor threats in real-time
kindlyguard monitor

# Development mode (all services)
kindlyguard dev

# MCP Multi-Tool Support
kindlyguard mcp setup    # Configure MCP
kindlyguard mcp status   # Check status
kindlyguard mcp list     # List all servers
```

## 🌟 Key Features

### 🔐 Advanced Threat Detection
- **Multi-layer scanning** with pattern, behavioral, and heuristic analysis
- **Zero-day protection** through anomaly detection
- **Context-aware analysis** that understands intent

### 🗄️ Intelligent Quarantine
- **Encrypted isolation** of threats (ChaCha20Poly1305)
- **Safe preview** without risk of execution
- **Automatic retention** policies with secure deletion

### 🎚️ Flexible Protection Modes
- **🛡️ Auto-Protect** (default) - Threats are neutralized automatically
- **🤝 Interactive** - Review threats before action
- **📊 Report-Only** - Monitor without intervention

### 💬 Friendly Security
- **Educational feedback** that helps you understand threats
- **Positive reinforcement** - "Kind to you, tough on threats"
- **No scary warnings** - Clear, actionable information

## 🏗️ Architecture

```
Your Machine
├── KindlyGuard (Rust binary)
│   ├── Scanner Engine
│   ├── Neutralizer
│   ├── Quarantine (encrypted)
│   └── MCP Server
└── Your AI Assistant
    └── Protected by KindlyGuard
```

**No external connections. No telemetry. No surprises.**

## 🔧 Advanced Installation Options

### Recommended: npm (All Platforms)
```bash
# The fastest way - prebuilt binaries, no compilation
npm install -g kindlyguard
```

### Alternative Methods

#### macOS/Linux Script
```bash
curl -sSfL https://install.kindlyguard.com | sh
```

#### Windows PowerShell
```powershell
irm https://install.kindlyguard.com/windows | iex
```

#### Package Managers
```bash
# Homebrew (macOS/Linux)
brew install kindlyguard

# Cargo (Rust developers)
cargo install kindlyguard
```

#### Docker
```bash
docker run -it kindlyguard/kindlyguard scan /path/to/file
```

## 📊 Performance

- ⚡ **1.2M chars/sec** Unicode scanning throughput
- 🚀 **< 5ms** overhead for typical operations  
- 💾 **50MB** memory footprint
- 🔥 **Zero** network latency (it's local!)

## 🛠️ Configuration

KindlyGuard works out of the box, but you can customize:

```toml
# ~/.kindlyguard/config.toml
[protection]
mode = "auto"  # auto, interactive, report

[quarantine]
encrypt = true
retention_days = 90

[scanner]
sensitivity = "balanced"  # low, balanced, high
```

## 🤝 Integration

### Claude Desktop
Auto-configured during installation.

### VS Code
```bash
kindlyguard integrate vscode
```

### Custom Integration
```javascript
// MCP protocol - works with any MCP client
const response = await client.call('scan_text', {
  text: userInput,
  protection_mode: 'auto'
});
```

### MCP Multi-Tool Support
KindlyGuard now supports multiple MCP tools in a single server:
- `scan_text` - Scan text for threats
- `scan_file` - Scan files with quarantine support
- `check_url` - Validate URLs for safety
- `neutralize` - Clean threats from content
- `quarantine_list` - View isolated threats

## 🔍 How It Works

1. **Intercepts** content before it reaches your AI
2. **Scans** for 50+ threat patterns in parallel
3. **Neutralizes** threats while preserving meaning
4. **Quarantines** original for forensics
5. **Delivers** clean content to your AI

All in under 5 milliseconds. Locally. Privately.

## 🙋 FAQ

**Q: Does KindlyGuard send my data anywhere?**  
A: No. KindlyGuard runs entirely on your machine. No network connections except for optional update checks.

**Q: What if it blocks legitimate content?**  
A: Use Interactive mode to review decisions, or check quarantine to restore false positives.

**Q: How does it compare to cloud-based security?**  
A: No latency, no privacy concerns, no service outages. Your security runs at the speed of your CPU.

**Q: Is it really "kind"?**  
A: Yes! Instead of scary warnings, you get friendly explanations that help you understand security.

## 📚 Documentation

- [Quick Start Guide](docs/getting-started/QUICK_START.md)
- [Protection Modes](docs/guides/PROTECTION_MODES_GUIDE.md)
- [Architecture Overview](docs/architecture/ARCHITECTURE.md)
- [API Reference](docs/api/API_REFERENCE_v0.15.0.md)
- [Security Model](docs/security/SECURITY_ARCHITECTURE.md)

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📜 License

Apache 2.0 - see [LICENSE](LICENSE) for details.

## 🔗 Links

- [Documentation](https://docs.kindlyguard.com)
- [Releases](https://github.com/kindly-software/kindly-guard/releases)
- [Security Policy](SECURITY.md)

---

<p align="center">
  <strong>KindlyGuard: Kind to you, tough on threats.</strong><br>
  <em>Your security. Your control. Your machine.</em>
</p>