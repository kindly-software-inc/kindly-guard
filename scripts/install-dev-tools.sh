#!/bin/bash
# KindlyGuard Development Tools Installation Script
# This script installs all recommended development tools for KindlyGuard

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Header
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║       KindlyGuard Development Tools Installation         ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo

# Check if cargo is installed
if ! command -v cargo &> /dev/null; then
    print_error "Cargo is not installed. Please install Rust first:"
    echo "       curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# Core tools that should always be installed
CORE_TOOLS=(
    "cargo-nextest:Next-generation test runner (60% faster)"
    "cargo-deny:Supply chain security auditing"
    "cargo-audit:CVE vulnerability scanner"
    "cargo-outdated:Check for outdated dependencies"
    "bacon:Background rust compiler"
    "typos-cli:Fast spell checker"
    "committed:Conventional commit linter"
    "grcov:Code coverage tool"
)

# Additional productivity tools
EXTRA_TOOLS=(
    "cargo-edit:Add/remove dependencies from CLI"
    "cargo-watch:Run commands on file change"
    "cargo-expand:Expand macros"
    "cargo-machete:Find unused dependencies"
    "cargo-msrv:Find minimum supported Rust version"
    "cargo-release:Automate releases"
    "cargo-geiger:Detect unsafe code usage"
    "sccache:Shared compilation cache"
    "cargo-criterion:Microbenchmarking"
)

# Nightly-only tools
NIGHTLY_TOOLS=(
    "cargo-udeps:Find unused dependencies (requires nightly)"
)

# Function to install a tool
install_tool() {
    local tool_spec=$1
    local tool_name=${tool_spec%%:*}
    local tool_desc=${tool_spec#*:}
    
    print_status "Installing $tool_name - $tool_desc"
    
    if cargo install --list | grep -q "^$tool_name "; then
        print_warning "$tool_name is already installed, skipping..."
    else
        if cargo install "$tool_name"; then
            print_success "$tool_name installed successfully"
        else
            print_error "Failed to install $tool_name"
            return 1
        fi
    fi
}

# Install core tools
echo -e "\n${GREEN}Installing Core Development Tools${NC}"
echo "These tools are essential for KindlyGuard development:"
echo

for tool in "${CORE_TOOLS[@]}"; do
    install_tool "$tool"
done

# Ask about extra tools
echo
read -p "Install additional productivity tools? [Y/n] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    echo -e "\n${GREEN}Installing Additional Tools${NC}"
    for tool in "${EXTRA_TOOLS[@]}"; do
        install_tool "$tool"
    done
fi

# Install nightly toolchain if not present
echo
print_status "Checking for nightly toolchain..."
if ! rustup toolchain list | grep -q nightly; then
    print_status "Installing nightly toolchain..."
    rustup toolchain install nightly
    print_success "Nightly toolchain installed"
else
    print_success "Nightly toolchain already installed"
fi

# Install nightly-only tools
echo
read -p "Install nightly-only tools? [Y/n] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    echo -e "\n${GREEN}Installing Nightly-Only Tools${NC}"
    for tool in "${NIGHTLY_TOOLS[@]}"; do
        tool_name=${tool%%:*}
        tool_desc=${tool#*:}
        print_status "Installing $tool_name - $tool_desc"
        
        if cargo +nightly install "$tool_name"; then
            print_success "$tool_name installed successfully"
        else
            print_error "Failed to install $tool_name"
        fi
    done
fi

# Install additional components
echo
print_status "Installing additional Rust components..."

# Install llvm-tools for coverage
if ! rustup component list --installed | grep -q llvm-tools; then
    rustup component add llvm-tools-preview
    print_success "llvm-tools-preview installed (needed for coverage)"
else
    print_success "llvm-tools-preview already installed"
fi

# Install rustfmt and clippy (should already be installed)
rustup component add rustfmt clippy

# Create config directories if they don't exist
echo
print_status "Creating configuration directories..."
mkdir -p .config
mkdir -p scripts

# Summary
echo
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║             Installation Complete! 🎉                    ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo
echo "Installed tools summary:"
echo "  ✓ Core testing and security tools"
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    echo "  ✓ Additional productivity tools"
fi
echo "  ✓ Rust components (rustfmt, clippy, llvm-tools)"
echo
echo -e "${YELLOW}Quick Start:${NC}"
echo "  1. Run 'bacon' in a terminal to start the background compiler"
echo "  2. Run 'cargo nextest run' to run tests with better output"
echo "  3. Run 'cargo deny check' to audit your dependencies"
echo
echo -e "${BLUE}Next Steps:${NC}"
echo "  - Copy example configs: cp examples/configs/* ."
echo "  - Set up git hooks: committed --install"
echo "  - Configure VS Code: see .vscode/settings.json.example"
echo
echo "For detailed documentation, see:"
echo "  - docs/DEVELOPMENT_WORKFLOW.md"
echo "  - docs/TOOLING.md"
echo "  - docs/QUICK_REFERENCE.md"
echo
print_success "Happy coding with KindlyGuard! 🛡️"