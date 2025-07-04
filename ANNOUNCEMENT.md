# 🚀 Announcing KindlyGuard v0.9.0 - Security That's Kind to Developers

We're excited to announce the first open source release of KindlyGuard, a security-focused MCP server that protects AI interactions from unicode attacks, injection attempts, and other threats.

## Why KindlyGuard?

In the age of AI, security shouldn't be an afterthought. But too often, security tools are:
- Cryptic in their error messages
- Slow and resource-intensive  
- Difficult to integrate
- Expensive for small teams

We built KindlyGuard to change that. Security that's **kind to developers, tough on threats**.

## Key Features

🛡️ **Comprehensive Threat Detection**
- Unicode attacks (homographs, BiDi, zero-width)
- SQL/Command/LDAP injection
- XSS in multiple contexts
- Custom pattern matching

⚡ **Blazing Fast Performance**
- <1ms threat detection
- 15-26 MB/s throughput
- 11.8MB memory footprint
- <0.1% false positives

🤝 **Developer Friendly**
- Clear, actionable security insights
- MCP protocol for AI integration
- Simple CLI interface
- Extensive documentation

## Quick Start

```bash
# Install
cargo install kindly-guard

# Run as MCP server
kindly-guard --stdio

# Scan a file
kindly-guard scan suspicious.json
```

## Our Mission

We believe security should be accessible to everyone. Core features will always be open source under Apache 2.0. Because when we all build more secure software, we all win.

## What's Next?

- v0.9.x - Community feedback and stabilization
- v1.0.0 - Production release (Q2 2025)
- 🚀 Enhanced performance features for enterprise teams (coming soon)

## Join Us!

⭐ Star us on [GitHub](https://github.com/kindlyguard/kindly-guard)
🐛 Report issues or contribute
💬 Join our [Discord](https://github.com/kindly-software/kindly-guard/discussions)
📖 Read the [docs](https://github.com/kindly-software/kindly-guard)

Together, let's make AI interactions safer for everyone.

#opensource #rust #security #ai #mcp