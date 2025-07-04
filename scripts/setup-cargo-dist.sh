#!/bin/bash
# Setup script for cargo-dist in KindlyGuard
# This script initializes cargo-dist and prepares the project for distribution

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check for Rust
    if ! command -v cargo &> /dev/null; then
        log_error "Cargo not found. Please install Rust first."
        exit 1
    fi
    
    # Check for git
    if ! command -v git &> /dev/null; then
        log_error "Git not found. Please install git first."
        exit 1
    fi
    
    log_info "Prerequisites satisfied"
}

# Install cargo-dist
install_cargo_dist() {
    log_info "Installing cargo-dist..."
    
    if command -v cargo-dist &> /dev/null; then
        local version=$(cargo-dist --version | cut -d' ' -f2)
        log_info "cargo-dist $version already installed"
    else
        cargo install cargo-dist --version 0.25.1
        log_info "cargo-dist installed successfully"
    fi
}

# Initialize cargo-dist configuration
init_cargo_dist() {
    log_info "Initializing cargo-dist configuration..."
    
    # Check if already initialized
    if grep -q "\[workspace.metadata.dist\]" Cargo.toml; then
        log_warn "cargo-dist already configured in Cargo.toml"
        return 0
    fi
    
    # Initialize with our settings
    cargo dist init \
        --hosting github \
        --installer shell \
        --installer powershell \
        --installer npm \
        --installer homebrew \
        --installer msi \
        --yes
    
    log_info "cargo-dist configuration initialized"
}

# Create necessary directories and files
setup_project_structure() {
    log_info "Setting up project structure for installers..."
    
    # Create directories
    mkdir -p wix macos debian rpm systemd scripts
    
    # Create LICENSE.rtf for Windows installer if LICENSE exists
    if [[ -f LICENSE ]]; then
        log_info "Creating LICENSE.rtf for Windows installer..."
        # Note: This is a simplified conversion. For production, use a proper converter
        echo "{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Times New Roman;}}" > LICENSE.rtf
        echo "\\f0\\fs24" >> LICENSE.rtf
        sed 's/$/\\par /' LICENSE >> LICENSE.rtf
        echo "}" >> LICENSE.rtf
    fi
    
    # Create welcome files for macOS installer
    if [[ ! -f macos/welcome.html ]]; then
        cat > macos/welcome.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 20px; }
        h1 { color: #333; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <h1>Welcome to KindlyGuard</h1>
    <p>KindlyGuard is a security-focused MCP server that protects against unicode attacks, injection attempts, and other threats.</p>
    <p>This installer will guide you through the installation process.</p>
</body>
</html>
EOF
    fi
    
    if [[ ! -f macos/conclusion.html ]]; then
        cat > macos/conclusion.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 20px; }
        h1 { color: #333; }
        p { color: #666; line-height: 1.6; }
        code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>Installation Complete!</h1>
    <p>KindlyGuard has been successfully installed to <code>/usr/local/bin</code>.</p>
    <p>To verify the installation, open Terminal and run:</p>
    <p><code>kindly-guard --version</code></p>
</body>
</html>
EOF
    fi
    
    log_info "Project structure prepared"
}

# Test cargo-dist build
test_cargo_dist() {
    log_info "Testing cargo-dist build..."
    
    # Plan the release
    if cargo dist plan; then
        log_info "cargo-dist plan successful"
    else
        log_error "cargo-dist plan failed"
        return 1
    fi
    
    # Optionally build artifacts (this can take a while)
    read -p "Do you want to test building artifacts? This may take several minutes. (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Building artifacts..."
        if cargo dist build; then
            log_info "Build successful! Artifacts created in target/distrib/"
            ls -la target/distrib/
        else
            log_error "Build failed"
            return 1
        fi
    fi
}

# Generate GitHub Actions workflow
generate_github_workflow() {
    log_info "Checking GitHub Actions workflow..."
    
    if [[ -f .github/workflows/release-dist.yml ]]; then
        log_info "GitHub Actions workflow already exists"
    else
        log_info "Generating GitHub Actions workflow..."
        cargo dist generate-ci github
        log_info "GitHub Actions workflow generated"
    fi
}

# Main function
main() {
    log_info "Setting up cargo-dist for KindlyGuard"
    
    check_prerequisites
    install_cargo_dist
    setup_project_structure
    init_cargo_dist
    generate_github_workflow
    test_cargo_dist
    
    log_info "Setup complete!"
    log_info ""
    log_info "Next steps:"
    log_info "1. Review the generated configuration in Cargo.toml"
    log_info "2. Customize installer files in wix/, macos/, debian/, and rpm/"
    log_info "3. Test the release process with: cargo dist build"
    log_info "4. Create a release with: git tag v1.0.0 && git push --tags"
    log_info ""
    log_info "The GitHub Actions workflow will automatically build and upload artifacts on tagged releases."
}

# Run main function
main "$@"