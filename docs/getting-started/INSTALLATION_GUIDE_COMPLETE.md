# KindlyGuard Complete Installation Guide

> **No cloud. No proxy. Pure stealth.**

This guide provides all available installation methods for KindlyGuard. Every method includes automatic error recovery with an interactive menu system that helps you resolve any installation issues.

## 🚀 Quick Install (Choose One)

### Method 1: Using Cargo (Recommended for Rust Developers)
```bash
cargo install --git https://github.com/kindly-software-inc/kindly-guard kindly-tools && kindly-tools install
```

### Method 2: Universal Installer Script
```bash
curl -sSfL https://raw.githubusercontent.com/samuel-lucas6/kindly-guard/main/install.sh | bash
```

### Method 3: Using NPM/NPX (Cross-Platform)
```bash
npx @kindlyguard/cli install
```

### Method 4: Direct Binary Download
```bash
# Detect platform and download
curl -L https://github.com/kindly-software-inc/kindly-guard/releases/latest/download/kindly-tools-$(uname -m)-unknown-linux-gnu.tar.gz | tar xz
./kindly-tools install --interactive
```

## 🔄 Automatic Recovery System

All installation methods include an intelligent recovery system that activates on any failure:

### Recovery Menu Options
When installation fails, you'll see:

```
❌ Installation failed. How would you like to proceed?

> Try with sudo (elevated privileges)
  Install to home directory (~/.local)
  Use different package manager
  Download binary directly
  Offline installation guide
  Show system diagnostics
  Cancel installation

Use arrow keys to navigate, Enter to select
```

### Recovery Features
- **Smart Detection**: Identifies the specific failure reason
- **Platform-Aware**: Suggests platform-specific alternatives
- **Multiple Attempts**: Try different methods without restarting
- **Diagnostic Tools**: Built-in system analysis
- **Offline Support**: Instructions for airgapped environments

## 📋 Platform-Specific Instructions

### Linux

#### Ubuntu/Debian
```bash
# Option 1: Universal installer
curl -sSfL https://raw.githubusercontent.com/samuel-lucas6/kindly-guard/main/install.sh | bash

# Option 2: Direct binary
wget https://github.com/kindly-software-inc/kindly-guard/releases/latest/download/kindly-tools-x86_64-unknown-linux-gnu.tar.gz
tar xzf kindly-tools-x86_64-unknown-linux-gnu.tar.gz
sudo mv kindly-tools /usr/local/bin/
kindly-tools install
```

#### Arch Linux
```bash
# AUR package (coming soon)
yay -S kindlyguard

# Or use universal installer
curl -sSfL https://raw.githubusercontent.com/samuel-lucas6/kindly-guard/main/install.sh | bash
```

#### Fedora/RHEL
```bash
# Option 1: Universal installer
curl -sSfL https://raw.githubusercontent.com/samuel-lucas6/kindly-guard/main/install.sh | bash

# Option 2: RPM package (coming soon)
sudo dnf install kindlyguard
```

### macOS

#### Using Homebrew (Coming Soon)
```bash
brew tap kindly-software/tap
brew install kindlyguard
```

#### Direct Installation
```bash
# Intel Mac
curl -L https://github.com/kindly-software-inc/kindly-guard/releases/latest/download/kindly-tools-x86_64-apple-darwin.tar.gz | tar xz

# Apple Silicon (M1/M2/M3)
curl -L https://github.com/kindly-software-inc/kindly-guard/releases/latest/download/kindly-tools-aarch64-apple-darwin.tar.gz | tar xz

# Run installer
./kindly-tools install --interactive
```

### Windows

#### PowerShell (Recommended)
```powershell
# Download and extract
Invoke-WebRequest -Uri "https://github.com/kindly-software-inc/kindly-guard/releases/latest/download/kindly-tools-x86_64-pc-windows-msvc.zip" -OutFile "kindly.zip"
Expand-Archive -Path "kindly.zip" -DestinationPath "."

# Run installer
.\kindly\kindly-tools.exe install
```

#### Using Scoop (Coming Soon)
```powershell
scoop bucket add kindly-software
scoop install kindlyguard
```

#### Using Chocolatey (Coming Soon)
```powershell
choco install kindlyguard
```

## 🐳 Container Environments

### Docker
```dockerfile
# In your Dockerfile
RUN curl -sSfL https://raw.githubusercontent.com/samuel-lucas6/kindly-guard/main/install.sh | bash

# Or use pre-built image
FROM ghcr.io/samuel-lucas6/kindly-guard:latest
```

### Kubernetes
```yaml
# As init container
initContainers:
- name: install-kindlyguard
  image: curlimages/curl:latest
  command: 
  - sh
  - -c
  - |
    curl -sSfL https://raw.githubusercontent.com/samuel-lucas6/kindly-guard/main/install.sh | sh
    cp /tmp/kindly-tools/kindlyguard /shared/bin/
  volumeMounts:
  - name: shared-bin
    mountPath: /shared/bin
```

## 🤖 CI/CD Integration

### GitHub Actions
```yaml
- name: Install KindlyGuard
  run: |
    curl -sSfL https://raw.githubusercontent.com/samuel-lucas6/kindly-guard/main/install.sh | bash
    echo "$HOME/.local/bin" >> $GITHUB_PATH

# Or use action (coming soon)
- uses: kindly-software/setup-kindlyguard@v1
  with:
    version: latest
```

### GitLab CI
```yaml
before_script:
  - curl -sSfL https://raw.githubusercontent.com/samuel-lucas6/kindly-guard/main/install.sh | bash
  - export PATH="$HOME/.local/bin:$PATH"
```

### Jenkins
```groovy
pipeline {
    agent any
    stages {
        stage('Install KindlyGuard') {
            steps {
                sh '''
                    curl -sSfL https://raw.githubusercontent.com/samuel-lucas6/kindly-guard/main/install.sh | bash
                    export PATH="$HOME/.local/bin:$PATH"
                '''
            }
        }
    }
}
```

## 🔧 Advanced Installation Options

### Custom Installation Directory
```bash
KINDLYGUARD_INSTALL_DIR=/opt/kindlyguard curl -sSfL https://raw.githubusercontent.com/samuel-lucas6/kindly-guard/main/install.sh | bash
```

### Specific Version
```bash
KINDLYGUARD_VERSION=v0.15.0 curl -sSfL https://raw.githubusercontent.com/samuel-lucas6/kindly-guard/main/install.sh | bash
```

### Offline Installation
1. Download the appropriate binary from [releases](https://github.com/kindly-software-inc/kindly-guard/releases)
2. Transfer to target machine
3. Extract and run:
   ```bash
   tar xzf kindly-tools-*.tar.gz
   ./kindly-tools install --offline
   ```

### Building from Source
```bash
# Clone repository
git clone https://github.com/kindly-software-inc/kindly-guard.git
cd kindly-guard

# Use interactive build system
cargo xtask --interactive

# Or build directly
cargo build --release
```

## 🩺 Troubleshooting

### Common Issues

#### "command not found" after installation
The installer adds KindlyGuard to your PATH, but you may need to:
```bash
# Reload your shell configuration
source ~/.bashrc  # or ~/.zshrc, ~/.profile

# Or add manually
export PATH="$HOME/.local/bin:$PATH"
```

#### Permission denied errors
The recovery menu will offer to:
1. Retry with sudo
2. Install to your home directory
3. Show alternative installation methods

#### SSL/TLS certificate errors
```bash
# Bypass certificate checks (not recommended for production)
KINDLYGUARD_INSECURE=1 curl -sSfL --insecure https://raw.githubusercontent.com/samuel-lucas6/kindly-guard/main/install.sh | bash
```

#### Slow downloads
The installer supports resume on failure. If interrupted:
```bash
# Resume installation
kindly-tools install --resume
```

### Getting Help

1. **Run diagnostics**: 
   ```bash
   kindly-tools doctor
   ```

2. **Check installation logs**:
   ```bash
   cat ~/.kindlyguard/install.log
   ```

3. **Report issues**:
   - GitHub Issues: https://github.com/kindly-software-inc/kindly-guard/issues
   - Include output of `kindly-tools doctor --report`

## ✅ Verifying Installation

After installation, verify everything is working:

```bash
# Check version
kindlyguard --version

# Run system check
kindlyguard doctor

# Test scanning
echo "test \u202e content" | kindlyguard scan -

# Check MCP integration
kindlyguard mcp status
```

## 🎯 Next Steps

1. **Configure Claude Desktop**: 
   ```bash
   kindlyguard mcp setup
   ```

2. **Read the quick start guide**:
   ```bash
   kindlyguard docs quick-start
   ```

3. **Explore protection modes**:
   ```bash
   kindlyguard config set protection_mode interactive
   ```

## 📚 Additional Resources

- [Quick Start Guide](QUICK_START.md)
- [Configuration Guide](../operations/CONFIGURATION.md)
- [Protection Modes](../guides/PROTECTION_MODES_GUIDE.md)
- [Troubleshooting](../troubleshooting/README.md)

---

**Remember**: All installation methods include the same powerful recovery system. If something goes wrong, the installer will guide you through fixing it. No cloud. No proxy. Pure stealth. 🛡️