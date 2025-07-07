#!/usr/bin/env bash
# Release script for KindlyGuard v0.15.0
# This script automates the release process including testing, building, packaging, and tagging

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
readonly VERSION="0.15.0"
readonly PROJECT_NAME="kindly-guard"
readonly RELEASE_DIR="release-${VERSION}"
readonly TARBALL_NAME="${PROJECT_NAME}-${VERSION}.tar.gz"
readonly CARGO_PROFILE="secure"

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if we're in the right directory
check_directory() {
    if [[ ! -f "Cargo.toml" ]] || [[ ! -d "kindly-guard-server" ]]; then
        log_error "This script must be run from the kindly-guard workspace root"
        exit 1
    fi
}

# Clean previous release artifacts
clean_release_artifacts() {
    log_info "Cleaning previous release artifacts..."
    rm -rf "${RELEASE_DIR}"
    rm -f "${TARBALL_NAME}"
    rm -f "${TARBALL_NAME}.sha256"
    rm -f "${TARBALL_NAME}.sha512"
}

# Run all tests
run_tests() {
    log_info "Running all tests..."
    
    # Run tests in parallel for speed
    if command -v cargo-make &> /dev/null; then
        log_info "Using cargo-make for parallel test execution"
        cargo make test-parallel
    else
        log_warning "cargo-make not found, running tests sequentially"
        cargo test --all-features --workspace
    fi
    
    log_success "All tests passed"
}

# Run security checks
run_security_checks() {
    log_info "Running security checks..."
    
    # Check for known vulnerabilities
    if command -v cargo-audit &> /dev/null; then
        cargo audit
    else
        log_warning "cargo-audit not installed, skipping vulnerability check"
    fi
    
    # Check for unsafe code
    if command -v cargo-geiger &> /dev/null; then
        cargo geiger --all-features
    else
        log_warning "cargo-geiger not installed, skipping unsafe code check"
    fi
    
    log_success "Security checks completed"
}

# Build release binaries for multiple platforms
build_releases() {
    log_info "Building release binaries..."
    
    # Create release directory
    mkdir -p "${RELEASE_DIR}/bin"
    
    # Target platforms
    declare -a targets=(
        "x86_64-unknown-linux-gnu"
        "aarch64-unknown-linux-gnu"
        "x86_64-apple-darwin"
        "aarch64-apple-darwin"
        "x86_64-pc-windows-gnu"
    )
    
    # Check if we can build in parallel
    if command -v cargo-make &> /dev/null; then
        log_info "Building all targets in parallel..."
        cargo make build-all-parallel
    else
        # Build each target sequentially
        for target in "${targets[@]}"; do
            log_info "Building for ${target}..."
            
            # Skip if target is not installed
            if ! rustup target list --installed | grep -q "${target}"; then
                log_warning "Target ${target} not installed, skipping..."
                continue
            fi
            
            # Build with the secure profile
            if cargo build --profile="${CARGO_PROFILE}" --target="${target}" 2>/dev/null; then
                # Copy binaries to release directory
                local binary_ext=""
                [[ "${target}" == *"windows"* ]] && binary_ext=".exe"
                
                local target_dir="target/${target}/${CARGO_PROFILE}"
                if [[ -d "${target_dir}" ]]; then
                    # Copy server binary
                    if [[ -f "${target_dir}/kindly-guard-server${binary_ext}" ]]; then
                        cp "${target_dir}/kindly-guard-server${binary_ext}" \
                           "${RELEASE_DIR}/bin/kindly-guard-server-${target}${binary_ext}"
                        log_success "Built kindly-guard-server for ${target}"
                    fi
                    
                    # Copy CLI binary
                    if [[ -f "${target_dir}/kindly-guard-cli${binary_ext}" ]]; then
                        cp "${target_dir}/kindly-guard-cli${binary_ext}" \
                           "${RELEASE_DIR}/bin/kindly-guard-cli-${target}${binary_ext}"
                        log_success "Built kindly-guard-cli for ${target}"
                    fi
                fi
            else
                log_warning "Failed to build for ${target}"
            fi
        done
    fi
    
    # Build for the current platform if no cross-compilation targets succeeded
    if [[ -z "$(ls -A ${RELEASE_DIR}/bin 2>/dev/null)" ]]; then
        log_warning "No cross-compilation targets available, building for current platform only"
        cargo build --profile="${CARGO_PROFILE}"
        
        local binary_ext=""
        [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]] && binary_ext=".exe"
        
        cp "target/${CARGO_PROFILE}/kindly-guard-server${binary_ext}" \
           "${RELEASE_DIR}/bin/kindly-guard-server${binary_ext}"
        cp "target/${CARGO_PROFILE}/kindly-guard-cli${binary_ext}" \
           "${RELEASE_DIR}/bin/kindly-guard-cli${binary_ext}"
    fi
    
    log_success "Release binaries built"
}

# Copy documentation
copy_documentation() {
    log_info "Copying documentation..."
    
    mkdir -p "${RELEASE_DIR}/docs"
    
    # Copy main documentation files
    local docs=(
        "README.md"
        "CHANGELOG.md"
        "LICENSE"
        "SECURITY.md"
        "docs/API_DOCUMENTATION.md"
        "docs/CONFIGURATION.md"
        "docs/SECURITY_AUDIT_REPORT.md"
    )
    
    for doc in "${docs[@]}"; do
        if [[ -f "${doc}" ]]; then
            cp "${doc}" "${RELEASE_DIR}/docs/"
            log_info "Copied ${doc}"
        else
            log_warning "Documentation file ${doc} not found"
        fi
    done
    
    # Copy example configuration
    if [[ -f "kindly-guard.toml.example" ]]; then
        cp "kindly-guard.toml.example" "${RELEASE_DIR}/"
    fi
    
    log_success "Documentation copied"
}

# Create tarball
create_tarball() {
    log_info "Creating release tarball..."
    
    tar -czf "${TARBALL_NAME}" "${RELEASE_DIR}"
    
    log_success "Created ${TARBALL_NAME}"
}

# Generate checksums
generate_checksums() {
    log_info "Generating checksums..."
    
    # SHA256
    if command -v sha256sum &> /dev/null; then
        sha256sum "${TARBALL_NAME}" > "${TARBALL_NAME}.sha256"
    elif command -v shasum &> /dev/null; then
        shasum -a 256 "${TARBALL_NAME}" > "${TARBALL_NAME}.sha256"
    else
        log_warning "No SHA256 tool found"
    fi
    
    # SHA512
    if command -v sha512sum &> /dev/null; then
        sha512sum "${TARBALL_NAME}" > "${TARBALL_NAME}.sha512"
    elif command -v shasum &> /dev/null; then
        shasum -a 512 "${TARBALL_NAME}" > "${TARBALL_NAME}.sha512"
    else
        log_warning "No SHA512 tool found"
    fi
    
    # Display checksums
    if [[ -f "${TARBALL_NAME}.sha256" ]]; then
        log_info "SHA256: $(cat ${TARBALL_NAME}.sha256)"
    fi
    if [[ -f "${TARBALL_NAME}.sha512" ]]; then
        log_info "SHA512: $(cat ${TARBALL_NAME}.sha512)"
    fi
    
    log_success "Checksums generated"
}

# Create git tag
create_git_tag() {
    log_info "Creating git tag..."
    
    # Check if tag already exists
    if git rev-parse "v${VERSION}" >/dev/null 2>&1; then
        log_warning "Tag v${VERSION} already exists"
        read -p "Delete existing tag and create new one? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git tag -d "v${VERSION}"
            git push origin --delete "v${VERSION}" 2>/dev/null || true
        else
            log_info "Skipping tag creation"
            return
        fi
    fi
    
    # Create annotated tag
    git tag -a "v${VERSION}" -m "Release v${VERSION}"
    
    log_success "Created tag v${VERSION}"
    log_info "Push tag with: git push origin v${VERSION}"
}

# Generate release notes
generate_release_notes() {
    log_info "Generating release notes..."
    
    local release_notes="${RELEASE_DIR}/RELEASE_NOTES_v${VERSION}.md"
    
    cat > "${release_notes}" << EOF
# KindlyGuard v${VERSION} Release Notes

Release Date: $(date +"%Y-%m-%d")

## Overview

KindlyGuard v${VERSION} is a security-focused MCP (Model Context Protocol) server that protects against unicode attacks, injection attempts, and other threats.

## Key Features

- **Unicode Security**: Protection against homograph attacks, bidi overrides, and zero-width characters
- **Injection Prevention**: SQL, command, LDAP, and path traversal detection
- **XSS Protection**: Context-aware XSS prevention for HTML, JavaScript, CSS, and URLs
- **Pattern Detection**: Regex and ML-based pattern matching for threat detection
- **Resilience**: Circuit breakers, retry logic, and bulkhead isolation
- **Performance**: Parallel CI/CD pipeline with 5x faster builds

## What's New in v${VERSION}

<!-- TODO: Add specific changes for this version -->
- Enhanced security scanning capabilities
- Improved performance with parallel processing
- Updated dependencies for security patches
- Bug fixes and stability improvements

## Installation

### From Binary

1. Download the appropriate binary for your platform from the release assets
2. Extract the tarball: \`tar -xzf kindly-guard-${VERSION}.tar.gz\`
3. Move binaries to your PATH: \`sudo cp release-${VERSION}/bin/kindly-guard-* /usr/local/bin/\`

### From Source

\`\`\`bash
git clone https://github.com/yourusername/kindly-guard.git
cd kindly-guard
git checkout v${VERSION}
cargo build --profile=secure
\`\`\`

## Configuration

Copy the example configuration and customize:

\`\`\`bash
cp kindly-guard.toml.example kindly-guard.toml
\`\`\`

## Usage

### As MCP Server

\`\`\`bash
kindly-guard-server --stdio
\`\`\`

### CLI Usage

\`\`\`bash
# Scan a file for threats
kindly-guard-cli scan suspicious_file.json

# Start monitoring dashboard
kindly-guard-cli monitor --detailed
\`\`\`

## Checksums

\`\`\`
SHA256: $(cat ${TARBALL_NAME}.sha256 2>/dev/null || echo "Generated during release")
SHA512: $(cat ${TARBALL_NAME}.sha512 2>/dev/null || echo "Generated during release")
\`\`\`

## Contributors

Thank you to all contributors who made this release possible!

## Security

For security issues, please refer to our [Security Policy](SECURITY.md).

---

**Motto**: Security First, Performance Second, Features Third
EOF
    
    log_success "Release notes generated at ${release_notes}"
    log_info "Please update the release notes with specific changes for v${VERSION}"
}

# Main release process
main() {
    log_info "Starting KindlyGuard v${VERSION} release process..."
    
    # Pre-flight checks
    check_directory
    
    # Confirm release
    echo
    log_warning "This will create a release for KindlyGuard v${VERSION}"
    read -p "Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Release cancelled"
        exit 0
    fi
    
    # Execute release steps
    clean_release_artifacts
    run_tests
    run_security_checks
    build_releases
    copy_documentation
    create_tarball
    generate_checksums
    create_git_tag
    generate_release_notes
    
    # Summary
    echo
    log_success "Release v${VERSION} completed successfully!"
    echo
    log_info "Release artifacts:"
    log_info "  - Tarball: ${TARBALL_NAME}"
    log_info "  - Checksums: ${TARBALL_NAME}.sha256, ${TARBALL_NAME}.sha512"
    log_info "  - Release notes: ${RELEASE_DIR}/RELEASE_NOTES_v${VERSION}.md"
    log_info "  - Git tag: v${VERSION}"
    echo
    log_info "Next steps:"
    log_info "  1. Review and update the release notes"
    log_info "  2. Push the tag: git push origin v${VERSION}"
    log_info "  3. Create GitHub release and upload artifacts"
    log_info "  4. Announce the release"
}

# Run main function
main "$@"