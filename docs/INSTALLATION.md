# KindlyGuard Installation Guide

KindlyGuard provides multiple installation methods to suit different needs and platforms. Choose the method that works best for your environment.

## Quick Install (Recommended)

The fastest way to install KindlyGuard is using our automated installers:

### Shell Script (macOS/Linux)

```bash
curl -LsSf https://github.com/samduchaine/kindly-guard/releases/latest/download/kindly-guard-installer.sh | sh
```

This installer will:
- Detect your platform and architecture
- Download the appropriate binary
- Install to `/usr/local/bin` (or `$HOME/.local/bin` if no sudo access)
- Set up necessary permissions
- Verify the installation

### PowerShell (Windows)

```powershell
irm https://github.com/samduchaine/kindly-guard/releases/latest/download/kindly-guard-installer.ps1 | iex
```

This installer will:
- Download the Windows binary
- Install to `%LOCALAPPDATA%\Programs\KindlyGuard`
- Add to PATH automatically
- Create Start Menu shortcuts

## Platform-Specific Installers

For enterprise deployments or when you prefer native package managers:

### Windows (MSI Installer)

1. Download `kindly-guard-{version}-x64.msi` from the [releases page](https://github.com/samduchaine/kindly-guard/releases)
2. Double-click to run the installer
3. Follow the installation wizard

Features:
- Automatic PATH configuration
- Windows service registration (optional)
- Proper uninstaller registration
- Code signed for security

### macOS (PKG Installer)

1. Download `kindly-guard-{version}.pkg` from the [releases page](https://github.com/samduchaine/kindly-guard/releases)
2. Double-click to run the installer
3. Follow the installation prompts

Features:
- Installs to `/usr/local/bin`
- macOS Gatekeeper compatible
- Automatic PATH configuration
- LaunchAgent support (optional)

### Linux Packages

#### Debian/Ubuntu (.deb)

```bash
# Download the .deb package
wget https://github.com/samduchaine/kindly-guard/releases/latest/download/kindly-guard_{version}_amd64.deb

# Install with dpkg
sudo dpkg -i kindly-guard_{version}_amd64.deb

# Or with apt
sudo apt install ./kindly-guard_{version}_amd64.deb
```

#### RHEL/Fedora (.rpm)

```bash
# Download the .rpm package
wget https://github.com/samduchaine/kindly-guard/releases/latest/download/kindly-guard-{version}-1.x86_64.rpm

# Install with rpm
sudo rpm -i kindly-guard-{version}-1.x86_64.rpm

# Or with dnf/yum
sudo dnf install ./kindly-guard-{version}-1.x86_64.rpm
```

## Package Managers

### Homebrew (macOS/Linux)

```bash
# Add the tap
brew tap samduchaine/tap

# Install KindlyGuard
brew install kindly-guard
```

### Cargo (Rust Package Manager)

```bash
# Install from crates.io
cargo install kindlyguard

# Or install specific components
cargo install kindly-guard-server
cargo install kindly-guard-cli
```

### NPM (Node.js)

```bash
# Install the CLI globally
npm install -g @kindlyguard/cli

# Or use with npx
npx @kindlyguard/cli scan file.json
```

## Docker

```bash
# Pull the latest image
docker pull kindlyguard/kindlyguard:latest

# Run as MCP server
docker run -p 3000:3000 kindlyguard/kindlyguard:latest

# Run CLI commands
docker run --rm -v $(pwd):/workspace kindlyguard/kindlyguard:latest scan /workspace/file.json
```

## Building from Source

### Prerequisites

- Rust 1.75 or later
- Git

### Build Steps

```bash
# Clone the repository
git clone https://github.com/samduchaine/kindly-guard.git
cd kindly-guard

# Build in release mode
cargo build --release

# Install to cargo bin directory
cargo install --path kindly-guard-cli
cargo install --path kindly-guard-server
```

## Post-Installation

### Verify Installation

```bash
# Check version
kindly-guard --version

# Run a test scan
echo '{"test": "data"}' | kindly-guard scan -
```

### Configuration

KindlyGuard uses a TOML configuration file. Create one at:
- Linux/macOS: `~/.config/kindlyguard/config.toml`
- Windows: `%APPDATA%\kindlyguard\config.toml`

Example configuration:

```toml
[scanner]
max_depth = 10
timeout_ms = 5000

[threats]
unicode_normalization = true
detect_homographs = true
detect_bidi = true

[server]
port = 3000
host = "127.0.0.1"
```

### MCP Integration

To use KindlyGuard as an MCP server:

1. Add to your MCP configuration:

```json
{
  "mcpServers": {
    "kindlyguard": {
      "command": "kindly-guard",
      "args": ["server", "--stdio"],
      "env": {}
    }
  }
}
```

2. Restart your MCP client (e.g., Claude Desktop)

## Troubleshooting

### Common Issues

**Binary not found after installation:**
- Ensure the installation directory is in your PATH
- Try opening a new terminal session
- Run `echo $PATH` (Linux/macOS) or `echo %PATH%` (Windows) to verify

**Permission denied errors:**
- On Linux/macOS, you may need to use `sudo` for system-wide installation
- Consider installing to your user directory instead

**macOS Gatekeeper warnings:**
- The PKG installer is signed, but if you download the raw binary:
  ```bash
  xattr -d com.apple.quarantine kindly-guard
  ```

**Windows Defender warnings:**
- The MSI installer is signed, but for raw binaries you may need to:
  1. Right-click the file
  2. Select "Properties"
  3. Check "Unblock" if present
  4. Click "OK"

### Getting Help

- GitHub Issues: https://github.com/samduchaine/kindly-guard/issues
- Documentation: https://docs.kindlyguard.dev
- Discord: https://discord.gg/kindlyguard

## Uninstallation

### Installed via Script

```bash
# Linux/macOS
sudo rm -f /usr/local/bin/kindly-guard /usr/local/bin/kindly-guard-cli

# Windows (PowerShell as Admin)
Remove-Item -Path "$env:LOCALAPPDATA\Programs\KindlyGuard" -Recurse -Force
```

### Package Manager Uninstallation

```bash
# Homebrew
brew uninstall kindly-guard

# Cargo
cargo uninstall kindlyguard

# NPM
npm uninstall -g @kindlyguard/cli

# Debian/Ubuntu
sudo apt remove kindlyguard

# RHEL/Fedora
sudo dnf remove kindlyguard
```

### Windows MSI

Use "Add or Remove Programs" in Windows Settings, or:

```powershell
# PowerShell as Admin
Get-Package "KindlyGuard" | Uninstall-Package
```

### macOS PKG

```bash
# Remove installed files
sudo rm -rf /usr/local/bin/kindly-guard*
sudo pkgutil --forget com.kindlyguard.pkg
```