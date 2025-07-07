#!/bin/bash
# Bootstrap script that compiles and runs the Rust installer
# This is the ONLY shell script allowed as it's the bootstrap entry point

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🛡️  KindlyGuard Installer Bootstrap${NC}"
echo -e "${GREEN}No cloud. No proxy. Pure stealth.${NC}"
echo

# Check if Rust is installed
if ! command -v rustc &> /dev/null; then
    echo -e "${YELLOW}Rust is not installed. Trying alternative installation methods...${NC}"
    
    # Try NPX if available
    if command -v npx &> /dev/null; then
        echo -e "${GREEN}Found NPX. Using NPM-based installer...${NC}"
        exec npx @kindlyguard/cli install
    fi
    
    # Try direct binary download
    echo -e "${YELLOW}Attempting direct binary download...${NC}"
    ARCH=$(uname -m)
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    
    case "$OS" in
        linux)
            case "$ARCH" in
                x86_64) PLATFORM="x86_64-unknown-linux-gnu" ;;
                aarch64) PLATFORM="aarch64-unknown-linux-gnu" ;;
                armv7l) PLATFORM="armv7-unknown-linux-gnueabihf" ;;
                *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
            esac
            ;;
        darwin)
            case "$ARCH" in
                x86_64) PLATFORM="x86_64-apple-darwin" ;;
                arm64) PLATFORM="aarch64-apple-darwin" ;;
                *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
            esac
            ;;
        *)
            echo -e "${RED}Unsupported OS: $OS${NC}"
            echo -e "${YELLOW}Please visit: https://github.com/samuel-lucas6/kindly-guard/releases${NC}"
            exit 1
            ;;
    esac
    
    # Download kindly-tools directly
    DOWNLOAD_URL="https://github.com/kindly-software-inc/kindly-guard/releases/latest/download/kindly-tools-${PLATFORM}.tar.gz"
    echo -e "${BLUE}Downloading from: $DOWNLOAD_URL${NC}"
    
    TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" EXIT
    
    if curl -L "$DOWNLOAD_URL" | tar xz -C "$TEMP_DIR"; then
        echo -e "${GREEN}Download successful. Running installer...${NC}"
        chmod +x "$TEMP_DIR/kindly-tools"
        exec "$TEMP_DIR/kindly-tools" install --interactive
    else
        echo -e "${RED}Download failed.${NC}"
        echo -e "${YELLOW}Please install Rust first:${NC}"
        echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        echo -e "${YELLOW}Or visit our releases page:${NC}"
        echo "  https://github.com/kindly-software-inc/kindly-guard/releases"
        exit 1
    fi
fi

# Rust is available, download and compile the installer
echo -e "${GREEN}Rust detected. Compiling installer...${NC}"

# Create a temporary directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Download the Rust installer
INSTALLER_URL="https://raw.githubusercontent.com/kindly-software-inc/kindly-guard/main/install/installer.rs"
INSTALLER_PATH="$TEMP_DIR/installer.rs"

echo -e "${BLUE}Downloading installer...${NC}"
if ! curl -sSfL "$INSTALLER_URL" -o "$INSTALLER_PATH" 2>/dev/null; then
    # If installer.rs doesn't exist yet, use the bootstrap
    echo -e "${YELLOW}Using bootstrap installer...${NC}"
    cat > "$INSTALLER_PATH" << 'EOF'
use std::process::Command;
use std::env;

fn main() {
    println!("🛡️  KindlyGuard Installer");
    println!("No cloud. No proxy. Pure stealth.\n");
    
    // Try to run cargo install
    let status = Command::new("cargo")
        .args(&["install", "--git", "https://github.com/kindly-software-inc/kindly-guard", "kindly-tools"])
        .status();
    
    match status {
        Ok(s) if s.success() => {
            println!("\n✅ kindly-tools installed successfully!");
            println!("🚀 Running kindly-tools install...\n");
            
            // Run kindly-tools install
            let status = Command::new("kindly-tools")
                .args(&["install", "--interactive"])
                .status();
            
            match status {
                Ok(s) if s.success() => {
                    println!("\n✅ KindlyGuard installed successfully!");
                }
                _ => {
                    eprintln!("\n❌ Installation failed. Please check the error messages above.");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("\n❌ Failed to install kindly-tools.");
            eprintln!("\n🔄 Alternative installation methods:");
            eprintln!("1. Download from: https://github.com/kindly-software-inc/kindly-guard/releases");
            eprintln!("2. Use NPM: npx @kindlyguard/cli install");
            eprintln!("3. Build from source: git clone and cargo build --release");
            std::process::exit(1);
        }
    }
}
EOF
fi

# Compile the installer
echo -e "${BLUE}Compiling installer...${NC}"
if rustc "$INSTALLER_PATH" -o "$TEMP_DIR/installer" 2>/dev/null; then
    echo -e "${GREEN}Running installer...${NC}"
    exec "$TEMP_DIR/installer"
else
    echo -e "${RED}Compilation failed.${NC}"
    echo -e "${YELLOW}Trying direct cargo install...${NC}"
    cargo install --git https://github.com/kindly-software-inc/kindly-guard kindly-tools && kindly-tools install --interactive
fi