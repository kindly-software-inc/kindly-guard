#!/bin/bash
# KindlyGuard Installation Script
# Automatically detects platform and installs appropriate binaries

set -e

REPO_OWNER="yourusername"
REPO_NAME="kindly-guard"
INSTALL_DIR="/usr/local/bin"
TEMP_DIR=$(mktemp -d)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Detect platform
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case "$os" in
        linux)
            case "$arch" in
                x86_64)
                    echo "linux-x64"
                    ;;
                *)
                    error "Unsupported Linux architecture: $arch"
                    ;;
            esac
            ;;
        darwin)
            case "$arch" in
                x86_64)
                    echo "darwin-x64"
                    ;;
                arm64)
                    echo "darwin-arm64"
                    ;;
                *)
                    error "Unsupported macOS architecture: $arch"
                    ;;
            esac
            ;;
        *)
            error "Unsupported operating system: $os"
            ;;
    esac
}

# Check if running as root (for /usr/local/bin installation)
check_permissions() {
    if [ "$EUID" -ne 0 ] && [ "$1" = "/usr/local/bin" ]; then
        error "Please run with sudo for system-wide installation, or specify a different install directory"
    fi
}

# Download and extract binaries
download_binaries() {
    local platform=$1
    local version=${2:-latest}
    
    info "Downloading KindlyGuard for $platform..."
    
    local download_url="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/${version}/download/kindlyguard-${platform}.tar.gz"
    
    cd "$TEMP_DIR"
    if command -v curl &> /dev/null; then
        curl -sSL "$download_url" -o kindlyguard.tar.gz || error "Failed to download binaries"
    elif command -v wget &> /dev/null; then
        wget -q "$download_url" -O kindlyguard.tar.gz || error "Failed to download binaries"
    else
        error "Neither curl nor wget found. Please install one of them."
    fi
    
    info "Extracting binaries..."
    tar -xzf kindlyguard.tar.gz || error "Failed to extract binaries"
}

# Install binaries
install_binaries() {
    local platform=$1
    local install_dir=$2
    
    info "Installing binaries to $install_dir..."
    
    # Create install directory if it doesn't exist
    mkdir -p "$install_dir"
    
    # Find the extracted directory
    local extract_dir=$(find "$TEMP_DIR" -name "kindlyguard-*" -type d | head -1)
    
    if [ -z "$extract_dir" ]; then
        error "Could not find extracted binaries"
    fi
    
    # Copy binaries
    cp "$extract_dir/kindlyguard" "$install_dir/" || error "Failed to copy kindlyguard binary"
    cp "$extract_dir/kindlyguard-cli" "$install_dir/" || error "Failed to copy kindlyguard-cli binary"
    
    # Make executable
    chmod +x "$install_dir/kindlyguard"
    chmod +x "$install_dir/kindlyguard-cli"
    
    # Remove quarantine on macOS
    if [[ "$platform" == darwin-* ]]; then
        xattr -d com.apple.quarantine "$install_dir/kindlyguard" 2>/dev/null || true
        xattr -d com.apple.quarantine "$install_dir/kindlyguard-cli" 2>/dev/null || true
    fi
}

# Verify installation
verify_installation() {
    local install_dir=$1
    
    info "Verifying installation..."
    
    if [ -x "$install_dir/kindlyguard" ] && [ -x "$install_dir/kindlyguard-cli" ]; then
        local version=$("$install_dir/kindlyguard" --version 2>/dev/null || echo "unknown")
        success "KindlyGuard $version installed successfully!"
        
        # Add to PATH if not already there
        if [[ ":$PATH:" != *":$install_dir:"* ]] && [ "$install_dir" != "/usr/local/bin" ]; then
            echo ""
            info "Add the following to your shell configuration to use KindlyGuard:"
            echo "  export PATH=\"$install_dir:\$PATH\""
        fi
    else
        error "Installation verification failed"
    fi
}

# Setup MCP configuration
setup_mcp_config() {
    info "Would you like to add KindlyGuard to your MCP configuration? (y/N)"
    read -r response
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        local mcp_config="$HOME/.mcp.json"
        local install_dir=$1
        
        if [ -f "$mcp_config" ]; then
            info "Backing up existing MCP configuration..."
            cp "$mcp_config" "$mcp_config.backup.$(date +%Y%m%d_%H%M%S)"
        fi
        
        # Create MCP configuration
        cat > "$mcp_config.kindlyguard" <<EOF
{
  "mcpServers": {
    "kindlyguard": {
      "command": "$install_dir/kindlyguard",
      "args": ["--stdio"],
      "env": {
        "RUST_LOG": "kindly_guard=info"
      }
    }
  }
}
EOF
        
        info "MCP configuration snippet created at: $mcp_config.kindlyguard"
        info "Please merge this with your existing MCP configuration"
    fi
}

# Cleanup
cleanup() {
    rm -rf "$TEMP_DIR"
}

# Main installation flow
main() {
    echo "KindlyGuard Installation Script"
    echo "=============================="
    echo ""
    
    # Parse arguments
    local install_dir="$INSTALL_DIR"
    local version="latest"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dir)
                install_dir="$2"
                shift 2
                ;;
            --version)
                version="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --dir PATH      Installation directory (default: /usr/local/bin)"
                echo "  --version TAG   Version to install (default: latest)"
                echo "  --help          Show this help message"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
    
    # Detect platform
    local platform=$(detect_platform)
    info "Detected platform: $platform"
    
    # Check permissions
    check_permissions "$install_dir"
    
    # Set trap for cleanup
    trap cleanup EXIT
    
    # Download and install
    download_binaries "$platform" "$version"
    install_binaries "$platform" "$install_dir"
    verify_installation "$install_dir"
    
    # Optional MCP setup
    setup_mcp_config "$install_dir"
    
    echo ""
    success "Installation complete!"
    echo ""
    echo "Quick start:"
    echo "  - Run server: kindlyguard --stdio"
    echo "  - Scan file: kindlyguard-cli scan <file>"
    echo "  - Get help: kindlyguard --help"
    echo ""
}

# Run main function
main "$@"