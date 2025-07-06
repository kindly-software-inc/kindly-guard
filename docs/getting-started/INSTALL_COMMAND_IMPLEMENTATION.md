# KindlyGuard Install Command Implementation

## Overview

I've successfully implemented a cross-platform installation command for the KindlyGuard CLI that replaces the shell script functionality. The new command is fully integrated into the existing `kindly-guard-cli` binary.

## Features Implemented

### 1. **Platform Detection**
- Automatically detects OS (Linux, macOS, Windows)
- Detects architecture (x86_64, aarch64/arm64)
- Provides platform-specific binary suffixes (.exe for Windows)

### 2. **Smart Installation Directories**
- **Linux/macOS**: Prefers `~/.local/bin` (user-writable), falls back to `/usr/local/bin`
- **Windows**: Uses `%LOCALAPPDATA%\Programs\KindlyGuard`
- Supports custom installation directory via `--dir` flag

### 3. **Component Management**
- Install all components by default:
  - `kindly-guard-cli` → `kindly-guard` binary
  - `kindly-guard-server` → MCP server
  - `kindly-guard-shield` → Desktop UI
- Support selective installation via `--components` flag

### 4. **Download & Verification**
- Downloads from GitHub releases
- Progress bar showing download status
- Optional SHA256 checksum verification (skip with `--no-verify`)
- Automatic retry with timeout handling

### 5. **Archive Extraction**
- Supports `.tar.gz` for Unix systems
- Supports `.zip` for Windows
- Automatic cleanup of temporary files

### 6. **Cross-Platform Features**
- Proper file permissions (755 on Unix)
- PATH update instructions for each platform
- Platform-specific shell commands

### 7. **Safety Features**
- Checks for existing binaries (use `--force` to overwrite)
- Validates download responses
- Comprehensive error handling with context

## Usage Examples

```bash
# Install latest version (all components)
kindly-guard install

# Install specific version
kindly-guard install --version 0.9.7

# Install to custom directory
kindly-guard install --dir /opt/kindlyguard

# Install specific components only
kindly-guard install --components kindly-guard-cli,kindly-guard-server

# Force overwrite existing binaries
kindly-guard install --force

# Skip checksum verification (faster but less secure)
kindly-guard install --no-verify

# Complete example with all options
kindly-guard install \
  --version 0.9.7 \
  --dir ~/.local/bin \
  --components kindly-guard-cli \
  --force \
  --no-verify
```

## Implementation Details

### File Structure
```
kindly-guard-cli/
├── src/
│   ├── main.rs          # Updated with Install command
│   ├── commands/
│   │   ├── mod.rs       # Module declarations
│   │   └── install.rs   # Installation logic
│   └── output.rs        # Existing output formatting
```

### Key Components

1. **Platform Detection** (`Platform` struct)
   - OS and architecture detection
   - Platform-specific path handling
   - Binary naming conventions

2. **Installation Config** (`InstallConfig` struct)
   - Version management
   - Directory configuration
   - Force and verification flags

3. **Component Registry** (`Component` struct)
   - Component metadata
   - Asset naming conventions
   - Binary name mapping

4. **Installer** (`Installer` struct)
   - HTTP client for downloads
   - Progress tracking
   - File operations
   - Checksum verification

### Dependencies Added

```toml
# For HTTP downloads
reqwest = { version = "0.12", features = ["stream"] }

# For checksum verification
sha2 = "0.10"

# For async stream processing
futures-util = "0.3"

# For archive extraction
flate2 = "1.0"  # gzip decompression
tar = "0.4"     # tar archive handling
zip = "2.2"     # zip archive handling (Windows)
```

## Error Handling

The implementation follows KindlyGuard's security-first approach:
- All operations return `Result<T, E>`
- No `unwrap()` or `expect()` calls
- Detailed error context with `anyhow`
- Graceful fallbacks where appropriate

## Future Enhancements

1. **Version Discovery**
   - Query GitHub API for latest release
   - List available versions

2. **Update Command**
   - Check for newer versions
   - Self-update capability

3. **Uninstall Command**
   - Remove installed binaries
   - Clean up configuration

4. **System Package Integration**
   - Generate .deb packages
   - Generate .rpm packages
   - Homebrew formula support

5. **Signature Verification**
   - GPG signature verification
   - Code signing on Windows/macOS

## Testing

The implementation can be tested with:
```bash
# Build and test locally
cd kindly-guard
cargo build --release -p kindly-guard-cli
./target/release/kindly-guard-cli install --help
```

## Benefits Over Shell Script

1. **Cross-Platform**: Single implementation for all platforms
2. **Type Safety**: Rust's strong typing prevents errors
3. **Better Error Handling**: Detailed error messages with context
4. **Progress Tracking**: Built-in progress bars
5. **No Dependencies**: No need for curl, wget, tar, etc.
6. **Integrated**: Part of the main CLI, not a separate script

## Security Considerations

- HTTPS-only downloads
- Optional but recommended checksum verification
- No shell command injection vulnerabilities
- Memory-safe implementation
- Proper permission handling