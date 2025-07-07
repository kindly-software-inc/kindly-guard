# Migration Guide: v0.11.x to v0.15.0

## Overview

KindlyGuard v0.15.0 introduces groundbreaking security features focused on making protection both powerful and user-friendly. This major release adds an advanced quarantine system, protection modes, and a completely redesigned threat messaging system that embodies our "Kind to you, tough on threats™" philosophy.

## Major Changes

### 1. Enhanced Threat System with Quarantine

The most significant addition in v0.15.0 is the comprehensive quarantine system:

- **Advanced Threat Classification**: New `ThreatInfo` struct with detailed metadata
- **Secure Quarantine Storage**: ChaCha20Poly1305 encrypted isolation for threats
- **Protection Modes**: Choose between Monitor, Block, BlockAndLog, and Quarantine
- **Threat Severity Levels**: Critical, High, Medium, Low, and Info classifications
- **Audit Trail**: Complete logging of all security operations

### 2. Friendly Messaging System

A complete overhaul of how KindlyGuard communicates with users:

- **Educational Messages**: Clear explanations of why content was flagged
- **Non-Alarmist Tone**: Security alerts that inform without causing panic
- **Positive Reinforcement**: Celebrates security achievements
- **Contextual Personality**: Adapts messaging based on situation

### 3. New MCP Tools

Six new MCP tools for comprehensive quarantine management:

- `quarantine_list`: View all quarantined items
- `quarantine_get`: Securely retrieve quarantined content
- `quarantine_delete`: Remove items from quarantine
- `quarantine_restore`: Safely restore false positives
- `quarantine_analyze`: Deep threat analysis
- `quarantine_export`: Export data for external analysis

### 4. API Enhancements

Significant improvements to the scanner and neutralizer APIs:

- Scanner now returns `ThreatInfo` instead of simple `Threat`
- New parameters: `includeMetadata`, `protectionMode`, `severityThreshold`
- Batch operation support with progress tracking
- Real-time statistics during scanning

## Configuration Changes

### New Configuration Options

Update your `kindly-guard.toml` with these new sections:

```toml
# Protection mode configuration
[protection]
# Options: "monitor", "block", "block_and_log", "quarantine"
default_mode = "quarantine"
severity_threshold = "medium"

# Quarantine configuration
[quarantine]
enabled = true
storage_path = "~/.kindlyguard/quarantine"
encryption = true
retention_days = 90

# Encryption settings
[quarantine.encryption]
algorithm = "chacha20poly1305"
key_derivation = "argon2id"

# Retention policies
[quarantine.retention]
compress_after_days = 30
delete_after_days = 90

[quarantine.retention.overrides]
critical_severity_days = 365
legal_hold_pattern = "evidence-*"

# Friendly messages configuration
[messages]
personality = "balanced"  # Options: "friendly", "professional", "balanced"
show_tips = true
celebration_milestones = true
educational_mode = true
```

### Environment Variable Updates

New environment variables for v0.15.0:

```bash
# Protection mode override
export KINDLY_GUARD_PROTECTION_MODE=quarantine

# Quarantine path
export KINDLY_GUARD_QUARANTINE_PATH=/secure/quarantine

# Message personality
export KINDLY_GUARD_MESSAGE_PERSONALITY=friendly

# Severity threshold
export KINDLY_GUARD_SEVERITY_THRESHOLD=high
```

## API Changes and Compatibility

### Scanner API Changes

The scanner trait has been enhanced with richer return types:

**v0.11.x (Old)**:
```rust
pub trait Scanner {
    fn scan(&self, content: &str) -> Result<Vec<Threat>>;
}

pub struct Threat {
    pub threat_type: ThreatType,
    pub location: Location,
}
```

**v0.15.0 (New)**:
```rust
pub trait Scanner {
    fn scan(&self, content: &str) -> Result<Vec<ThreatInfo>>;
}

pub struct ThreatInfo {
    pub id: String,
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub confidence: f32,
    pub location: Location,
    pub description: String,
    pub recommendation: String,
    pub metadata: HashMap<String, Value>,
}
```

### MCP Tool Changes

Enhanced scan tools with new parameters:

**v0.11.x (Old)**:
```json
{
  "tool": "security/scan",
  "arguments": {
    "content": "..."
  }
}
```

**v0.15.0 (New)**:
```json
{
  "tool": "security/scan",
  "arguments": {
    "content": "...",
    "includeMetadata": true,
    "protectionMode": "quarantine",
    "severityThreshold": "medium"
  }
}
```

### Backward Compatibility

- v0.11.x scanner API calls still work but return simplified threat data
- Old configuration files are auto-migrated on first run
- Existing MCP tools continue to function with default protection mode

## Step-by-Step Migration Instructions

### 1. Backup Current Installation

```bash
# Backup configuration
cp -r ~/.kindlyguard ~/.kindlyguard.backup

# Export current settings
kindly-guard config export > config-backup.json

# Note current version
kindly-guard --version > version-backup.txt
```

### 2. Update to v0.15.0

```bash
# Update via cargo
cargo install kindly-guard --version 0.15.0

# Or download pre-built binaries
curl -fsSL https://github.com/kindlyguard/kindlyguard/releases/download/v0.15.0/install.sh | sh

# Verify installation
kindly-guard --version
# Should show: kindly-guard 0.15.0
```

### 3. Initialize Quarantine System

```bash
# Initialize quarantine storage
kindly-guard quarantine init

# Verify quarantine is working
kindly-guard quarantine status

# Output should show:
# ✅ Quarantine system initialized
# 📁 Storage: ~/.kindlyguard/quarantine
# 🔐 Encryption: Enabled (ChaCha20Poly1305)
# 📊 Items: 0 quarantined, 0 MB used
```

### 4. Update Configuration

```bash
# Auto-migrate configuration
kindly-guard config migrate

# Or manually edit configuration
$EDITOR ~/.kindlyguard/config.toml

# Add new v0.15.0 sections (see Configuration Changes above)

# Validate configuration
kindly-guard config validate
```

### 5. Test New Features

```bash
# Test quarantine with a sample threat
echo "SELECT * FROM users WHERE id = '\$id'" > test.sql
kindly-guard scan test.sql --mode quarantine

# List quarantined items
kindly-guard quarantine list

# Test friendly messages
kindly-guard scan test.sql --verbose
# Should show friendly, educational messages
```

### 6. Update MCP Configuration

For Claude Desktop users:

```json
// Update claude_desktop_config.json
{
  "mcpServers": {
    "kindly-guard": {
      "command": "kindly-guard",
      "args": ["mcp"],
      "env": {
        "KINDLY_GUARD_PROTECTION_MODE": "quarantine",
        "KINDLY_GUARD_MESSAGE_PERSONALITY": "friendly"
      }
    }
  }
}
```

### 7. Verify Protection Modes

```bash
# Test different protection modes
kindly-guard scan suspicious.txt --mode monitor     # Log only
kindly-guard scan suspicious.txt --mode block       # Block threats
kindly-guard scan suspicious.txt --mode quarantine  # Isolate threats

# Check shield status with new indicators
kindly-guard monitor --dashboard
# Look for new colored shield indicators
```

## New Features and How to Enable Them

### 1. Quarantine System

Enable and configure the quarantine system:

```bash
# Enable quarantine globally
kindly-guard config set protection.default_mode quarantine

# Configure retention
kindly-guard config set quarantine.retention.delete_after_days 180

# Set encryption preferences
kindly-guard config set quarantine.encryption.algorithm chacha20poly1305
```

### 2. Protection Modes

Use protection modes for different scenarios:

```bash
# Development: Interactive mode
kindly-guard scan --mode interactive

# Production: Auto-quarantine mode  
kindly-guard server --protection-mode quarantine

# Testing: Report-only mode
kindly-guard scan --mode report-only
```

### 3. Friendly Messages

Enable the enhanced messaging system:

```bash
# Set personality
kindly-guard config set messages.personality friendly

# Enable educational mode
kindly-guard config set messages.educational_mode true

# Test messages
kindly-guard test-messages
```

### 4. Batch Operations

Use new batch scanning capabilities:

```bash
# Batch scan with progress
kindly-guard scan --batch file1.txt file2.txt file3.txt --progress

# Batch quarantine operations
kindly-guard quarantine restore --batch --pattern "*.txt"
```

## Deprecations and Removals

### Deprecated Features

1. **Simple Threat struct**: Use `ThreatInfo` for richer threat data
2. **Binary threat decisions**: Use protection modes instead
3. **Silent neutralization**: All actions now provide user feedback

### Removed Features

No features have been removed in v0.15.0. All v0.11.x functionality remains available.

### Future Deprecations

The following features will be deprecated in v0.16.0:
- Legacy scanner API without metadata support
- Plain text quarantine storage (encryption will be mandatory)
- Silent mode operations

## Common Migration Issues and Solutions

### Issue 1: Scanner Returns Different Data Structure

**Problem**: Code expecting old `Threat` struct fails with new `ThreatInfo`.

**Solution**:
```rust
// Update code to handle ThreatInfo
let threats = scanner.scan(content)?;
for threat in threats {
    // Old: threat.threat_type
    // New: threat.threat_type (still works)
    
    // New fields available:
    println!("Severity: {:?}", threat.severity);
    println!("Confidence: {:.2}%", threat.confidence * 100.0);
    println!("Description: {}", threat.description);
}
```

### Issue 2: Quarantine Permission Errors

**Problem**: "Permission denied" when accessing quarantine.

**Solution**:
```bash
# Fix permissions
chmod 700 ~/.kindlyguard/quarantine
chmod 600 ~/.kindlyguard/quarantine/index.db

# Re-initialize if needed
kindly-guard quarantine init --force
```

### Issue 3: MCP Tools Not Showing New Features

**Problem**: New quarantine tools not appearing in Claude.

**Solution**:
```bash
# Restart MCP server
pkill kindly-guard
kindly-guard mcp

# Or restart Claude Desktop
# The new tools should appear after restart
```

### Issue 4: Configuration Migration Fails

**Problem**: Auto-migration reports errors.

**Solution**:
```bash
# Manual migration
cp ~/.kindlyguard/config.toml ~/.kindlyguard/config.toml.old
kindly-guard config init --force

# Merge old settings manually
diff ~/.kindlyguard/config.toml.old ~/.kindlyguard/config.toml
# Add your custom settings to the new file
```

### Issue 5: Performance Degradation

**Problem**: Scanning slower with new features.

**Solution**:
```bash
# Optimize for performance
kindly-guard config set performance.mode fast
kindly-guard config set protection.default_mode block  # Faster than quarantine

# Use batch operations
kindly-guard scan *.txt --batch --parallel
```

## Performance Considerations

### Quarantine Overhead

The quarantine system adds minimal overhead:
- ~5% slower for quarantine mode vs block mode
- Encryption is hardware-accelerated when available
- Background maintenance runs during idle time

### Optimization Tips

```toml
# Performance-focused configuration
[performance]
mode = "fast"
parallel_scanning = true
cache_size_mb = 512

[quarantine]
# Faster compression
compression.algorithm = "lz4"
compression.level = 1

# Async operations
async_operations = true
background_maintenance = true
```

## Rollback Instructions

If you need to rollback to v0.11.x:

```bash
# 1. Export quarantined items (if any)
kindly-guard quarantine export --all --format json > quarantine-backup.json

# 2. Uninstall v0.15.0
cargo uninstall kindly-guard

# 3. Install v0.11.x
cargo install kindly-guard --version 0.11.14

# 4. Restore old configuration
cp ~/.kindlyguard.backup/config.toml ~/.kindlyguard/config.toml

# 5. Verify rollback
kindly-guard --version
```

## Getting Help

### Resources

- **Documentation**: https://docs.kindlyguard.com/v0.15.0
- **Migration Support**: https://github.com/kindlyguard/kindlyguard/discussions/migration
- **Issue Tracker**: https://github.com/kindlyguard/kindlyguard/issues
- **Security Advisories**: https://github.com/kindlyguard/kindlyguard/security

### Quick Help

```bash
# Built-in migration help
kindly-guard migrate --help

# Check system health
kindly-guard doctor

# Generate diagnostic bundle
kindly-guard debug --full --output debug.tar.gz
```

## Summary

v0.15.0 represents a major leap forward in making security both powerful and approachable. The new quarantine system provides enterprise-grade threat isolation, while the friendly messaging system ensures users feel supported rather than alarmed. Protection modes offer flexibility for different use cases, from development to production.

Key takeaways:
- **Quarantine System**: Encrypted, auditable threat isolation
- **Protection Modes**: Choose the right balance for your needs
- **Friendly Messages**: Security that educates and encourages
- **Enhanced APIs**: Richer data for better security decisions
- **Backward Compatible**: Smooth upgrade path from v0.11.x

Welcome to KindlyGuard v0.15.0 - where security meets kindness! 🛡️💜