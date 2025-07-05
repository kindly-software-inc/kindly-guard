# Migration Guide: v0.10.x to v0.11.0

## Overview

KindlyGuard v0.11.0 introduces significant improvements to the command-line experience through binary consolidation, enhanced visual feedback, and new auto-protection features. This guide will help you smoothly transition from v0.10.x to v0.11.0.

## Major Changes

### 1. Binary Consolidation

The most significant change in v0.11.0 is the consolidation of binaries:

- **REMOVED**: `kindlyguard-cli` binary
- **ENHANCED**: `kindly-tools` now includes all CLI functionality
- **UNCHANGED**: `kindlyguard` (MCP server) remains the same

**Impact**: All commands previously run with `kindlyguard-cli` should now use `kindly-tools`.

### 2. New Features

- **Colored Output**: Visual threat indicators with color-coded feedback
- **Auto-Wrap Protection**: Automatic security wrapping for AI CLI tools
- **Configuration Files**: TOML-based configuration for wrap behavior
- **Enhanced Shield Command**: New `shield auto-wrap` for automatic protection

### 3. Improved User Experience

- **Fixed False Positives**: Newlines and tabs no longer flagged as threats in CLI mode
- **Better Visual Feedback**: Immediate color indicators for threat levels
- **Non-Breaking**: All existing functionality preserved with better UX

## Command Mapping

### Basic Commands

| v0.10.x | v0.11.0 |
|---------|---------|
| `kindlyguard-cli scan` | `kindly-tools scan` |
| `kindlyguard-cli wrap` | `kindly-tools wrap` |
| `kindlyguard-cli monitor` | `kindly-tools monitor` |
| `kindlyguard-cli server` | `kindly-tools server` (deprecated, use `kindlyguard`) |
| `kindlyguard-cli config` | `kindly-tools config` |

### New Commands in v0.11.0

- `kindly-tools shield auto-wrap` - Generate automatic protection for AI CLIs
- `kindly-tools wrap --init` - Initialize wrap configuration
- `kindly-tools wrap --config` - Show current wrap configuration
- `kindly-tools wrap --add <command>` - Add command to auto-wrap list
- `kindly-tools wrap --remove <command>` - Remove command from auto-wrap list

## Step-by-Step Upgrade Instructions

### 1. Backup Current Configuration

```bash
# Backup your current configuration
cp ~/.kindlyguard/config.toml ~/.kindlyguard/config.toml.backup
```

### 2. Uninstall Old Version

```bash
# If installed via cargo
cargo uninstall kindlyguard-cli

# If installed via package manager (example for Debian/Ubuntu)
sudo apt remove kindlyguard-cli

# For other platforms, use appropriate uninstall method
```

### 3. Install New Version

```bash
# Install via cargo
cargo install kindly-tools --version 0.11.0

# Or download pre-built binaries
# Linux/macOS
curl -fsSL https://github.com/kindlyguard/kindlyguard/releases/download/v0.11.0/kindly-tools-$(uname -m)-$(uname -s).tar.gz | tar xz
sudo mv kindly-tools /usr/local/bin/

# Verify installation
kindly-tools --version
```

### 4. Update Shell Configuration

If you have shell aliases or scripts using `kindlyguard-cli`, update them:

```bash
# Update shell aliases
sed -i 's/kindlyguard-cli/kindly-tools/g' ~/.bashrc
sed -i 's/kindlyguard-cli/kindly-tools/g' ~/.zshrc

# Reload shell configuration
source ~/.bashrc  # or ~/.zshrc
```

### 5. Enable New Features (Optional)

#### Enable Auto-Wrap Protection

```bash
# Generate auto-wrap functions
kindly-tools shield auto-wrap -o ~/.kindly-shield.sh

# Add to shell startup
echo "source ~/.kindly-shield.sh" >> ~/.bashrc
source ~/.bashrc

# Now AI commands are automatically protected
claude "Help me write code"  # Automatically wrapped with security scanning
```

#### Configure Wrap Behavior

```bash
# Initialize wrap configuration
kindly-tools wrap --init

# Edit configuration
$EDITOR ~/.kindlyguard/wrap.toml
```

Example configuration:
```toml
enabled = true
mode = "warning"  # or "blocking" for stricter security
server = "http://localhost:8080"
verbose = false
log_sessions = true

commands = [
    "claude",
    "openai",
    "gemini",
    "anthropic",
    "gpt",
    "ai",
    "llm"
]

custom_commands = [
    "company-ai-tool",
    "internal-llm"
]
```

### 6. Verify Installation

```bash
# Test basic functionality
kindly-tools scan --help
kindly-tools wrap --help
kindly-tools shield --help

# Test scanning
echo "SELECT * FROM users" > test.txt
kindly-tools scan test.txt

# Test wrap protection
kindly-tools wrap -- echo "Testing wrap protection"
```

## Breaking Changes

### 1. Binary Name Change

- Scripts or CI/CD pipelines using `kindlyguard-cli` must be updated to `kindly-tools`
- Package manager configurations may need updates

### 2. Configuration Location

- Some configuration options have moved from command-line flags to configuration files
- The `~/.kindlyguard/wrap.toml` file is new and controls wrap behavior

### 3. Output Format Changes

- Colored output is now enabled by default
- Use `NO_COLOR=1` environment variable to disable colors
- JSON output format remains unchanged for programmatic use

## New Configuration Options

### Wrap Configuration (`~/.kindlyguard/wrap.toml`)

```toml
# Global settings
enabled = true                    # Enable/disable auto-wrapping
mode = "warning"                  # "warning" or "blocking"
server = "http://localhost:8080"  # KindlyGuard server URL
verbose = false                   # Show detailed threat info
log_sessions = false              # Save session logs
log_directory = "~/.kindlyguard/logs"  # Where to save logs

# Commands to auto-wrap
commands = ["claude", "openai", "gemini"]

# Additional custom commands
custom_commands = ["my-ai-tool"]
```

### Scanner Configuration

The scanner now supports `allow_text_control_chars` option for CLI usage:

```toml
[scanner]
# Allow newlines, tabs, and carriage returns in CLI mode
allow_text_control_chars = true
```

## Troubleshooting

### "Command not found: kindlyguard-cli"

Update your scripts to use `kindly-tools` instead:
```bash
# Old
kindlyguard-cli scan file.txt

# New
kindly-tools scan file.txt
```

### Colors Not Displaying

Ensure your terminal supports colors and the `NO_COLOR` environment variable is not set:
```bash
unset NO_COLOR
kindly-tools scan file.txt
```

### Auto-Wrap Not Working

1. Verify shield script is sourced:
   ```bash
   grep "kindly-shield.sh" ~/.bashrc
   ```

2. Check if protection is disabled:
   ```bash
   echo $KINDLY_SHIELD_DISABLED  # Should be empty or 0
   ```

3. Regenerate shield script:
   ```bash
   kindly-tools shield auto-wrap -o ~/.kindly-shield.sh
   source ~/.kindly-shield.sh
   ```

### Performance Issues

The new colored output adds minimal overhead. If you experience performance issues:

1. Disable colors for large batch operations:
   ```bash
   NO_COLOR=1 kindly-tools scan large-directory/ --recursive
   ```

2. Use JSON output for programmatic processing:
   ```bash
   kindly-tools scan file.txt --format json
   ```

## Rollback Instructions

If you need to rollback to v0.10.x:

```bash
# Uninstall v0.11.0
cargo uninstall kindly-tools

# Reinstall v0.10.x
cargo install kindlyguard-cli --version 0.10.3
cargo install kindly-tools --version 0.10.3

# Restore old configuration
cp ~/.kindlyguard/config.toml.backup ~/.kindlyguard/config.toml

# Remove new configuration files
rm ~/.kindlyguard/wrap.toml
rm ~/.kindly-shield.sh
```

## Getting Help

- **Documentation**: https://docs.kindlyguard.com
- **GitHub Issues**: https://github.com/kindlyguard/kindlyguard/issues
- **Discord**: https://discord.gg/kindlyguard
- **Email**: support@kindlyguard.com

## Summary

v0.11.0 streamlines the KindlyGuard experience by consolidating binaries and adding powerful new features like auto-wrap protection and visual threat indicators. While the binary name change requires updating scripts and configurations, the migration is straightforward and the new features provide significant security and usability improvements.

The key points to remember:
- Replace `kindlyguard-cli` with `kindly-tools` in all commands
- Enable auto-wrap for automatic AI CLI protection
- Enjoy the new colored output for better threat visibility
- Configure wrap behavior via `~/.kindlyguard/wrap.toml`

Welcome to KindlyGuard v0.11.0! 🛡️