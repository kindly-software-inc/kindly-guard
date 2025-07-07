# Documentation Update Summary - kindly-tools CLI

This document summarizes the documentation updates made to reflect the renaming from `kindly-guard-cli` to `kindly-tools` and the new command structure.

## Files Updated

### 1. INSTALLATION.md
- Updated all references from `kindly-guard-cli` to `kindly-tools`
- Changed NPM package name from `@kindlyguard/cli` to `@kindlyguard/tools`
- Updated command examples from `kindly-guard` to `kindly`
- Corrected MCP server configuration to use `kindly-guard-server`

### 2. QUICK_REFERENCE.md
- Added new section "🛡️ KindlyGuard CLI Commands" with examples for:
  - `kindly scan` - File scanning commands
  - `kindly wrap` - Command wrapping for security
  - `kindly monitor` - Real-time monitoring

### 3. FEATURES.md
- Updated CLI section title to "CLI Interface (kindly-tools)"
- Updated location from `kindly-guard-cli/src/` to `kindly-tools/src/`
- Expanded sub-features documentation for:
  - Scan Command: Added directory scanning, output formats
  - Wrap Command: New feature documentation
  - Monitor Command: New feature documentation

### 4. CONFIGURATION.md
- Added new section "CLI Tools Configuration" with:
  - Scan command configuration options
  - Wrap command configuration options
  - Monitor command configuration options
  - Environment variable overrides for CLI

### 5. README.md (docs folder)
- Added new "Tools & CLI" section with links to:
  - KINDLY_TOOLS_CLI.md
  - INSTALLATION.md
  - QUICK_REFERENCE.md
  - SHIELD_AUTO_WRAP.md

## New Files Created

### KINDLY_TOOLS_CLI.md
Comprehensive CLI reference documentation including:
- Installation instructions
- Detailed command usage for scan, wrap, and monitor
- Options and examples for each command
- Configuration guide
- Integration examples (Git hooks, CI/CD, shell aliases)
- Troubleshooting guide

## Key Changes

1. **Binary Name**: `kindly-guard` → `kindly`
2. **Package Name**: `kindly-guard-cli` → `kindly-tools`
3. **Commands Structure**:
   - `kindly scan <input>` - Security scanning
   - `kindly wrap -- <command>` - Protected execution
   - `kindly monitor` - Real-time monitoring

## Configuration Schema Updates

Added CLI-specific configuration sections:
```toml
[cli.scan]
default_format = "human"
verbose = false
max_files = 1000

[cli.wrap]
default_threshold = "medium"
allow_safe = false

[cli.monitor]
refresh_interval_ms = 1000
detailed = false
```

## Next Steps

1. Update any remaining references in code examples
2. Update the main project README if needed
3. Consider adding more integration examples
4. Update any automated documentation generation scripts