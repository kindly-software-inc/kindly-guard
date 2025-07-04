#!/bin/bash
# Setup system dependencies for cross-compilation

set -e

echo "🔧 Setting up cross-compilation dependencies"
echo "==========================================="

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "⚠️  Unsupported OS: $OSTYPE"
    exit 1
fi

# Linux setup
if [ "$OS" = "linux" ]; then
    echo "📦 Installing Linux cross-compilation tools..."
    
    # Check if we can use sudo
    if command -v sudo &> /dev/null; then
        echo "Installing MinGW for Windows cross-compilation..."
        sudo apt-get update
        sudo apt-get install -y mingw-w64
        
        echo "Installing additional build tools..."
        sudo apt-get install -y \
            build-essential \
            pkg-config \
            libssl-dev \
            gcc-multilib \
            g++-multilib
    else
        echo "⚠️  sudo not available. Please install the following packages manually:"
        echo "  - mingw-w64"
        echo "  - build-essential"
        echo "  - pkg-config"
        echo "  - libssl-dev"
        echo "  - gcc-multilib"
        echo "  - g++-multilib"
    fi
fi

# macOS setup
if [ "$OS" = "macos" ]; then
    echo "📦 Setting up macOS..."
    
    # Check for Homebrew
    if command -v brew &> /dev/null; then
        echo "Installing cross-compilation tools via Homebrew..."
        brew install mingw-w64
    else
        echo "⚠️  Homebrew not found. Please install Homebrew first:"
        echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
    fi
fi

# Install Rust targets
echo ""
echo "🦀 Installing Rust targets..."
rustup target add \
    x86_64-unknown-linux-gnu \
    x86_64-apple-darwin \
    aarch64-apple-darwin \
    x86_64-pc-windows-gnu

# Check for cross
echo ""
echo "🔍 Checking for cross..."
if command -v cross &> /dev/null; then
    echo "✅ cross is already installed"
else
    echo "📦 cross is not installed."
    echo "Install it with: cargo install cross --git https://github.com/cross-rs/cross"
    echo "Or run: ./scripts/install-cross.sh"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "You can now build for multiple platforms:"
echo "  ./scripts/build-all-platforms.sh"