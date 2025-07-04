#!/bin/bash
# Install cross for cross-compilation support

set -e

echo "🔧 Installing cross for cross-compilation support"
echo "================================================"

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo "❌ Error: cargo is not installed. Please install Rust first."
    exit 1
fi

# Check if cross is already installed
if command -v cross &> /dev/null; then
    echo "✅ cross is already installed at: $(which cross)"
    cross --version
    exit 0
fi

# Install cross from the official repository
echo "📦 Installing cross from GitHub..."
cargo install cross --git https://github.com/cross-rs/cross

# Verify installation
if command -v cross &> /dev/null; then
    echo "✅ cross installed successfully!"
    cross --version
else
    echo "❌ Failed to install cross"
    exit 1
fi

echo ""
echo "🎉 Installation complete!"
echo ""
echo "You can now use cross for cross-compilation:"
echo "  cross build --target x86_64-pc-windows-gnu"
echo "  cross build --target aarch64-unknown-linux-gnu"
echo ""
echo "For Docker-based builds, make sure Docker is running."