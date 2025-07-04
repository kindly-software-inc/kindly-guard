#!/bin/bash

# KindlyGuard Cross-Platform Binary Build Script
# Builds Rust binaries for all supported platforms and prepares them for distribution

set -e

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
NPM_DIR="$PROJECT_ROOT/npm-package"
DIST_DIR="$PROJECT_ROOT/dist"
RELEASE_DIR="$PROJECT_ROOT/release"

# Version from git tag or fallback
VERSION="${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null || echo "0.2.0")}"
VERSION="${VERSION#v}" # Remove 'v' prefix if present

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_header() {
    echo
    echo -e "${BLUE}==== $1 ====${NC}"
    echo
}

# Platform detection
detect_platform() {
    local platform=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case "$platform" in
        linux) PLATFORM="linux" ;;
        darwin) PLATFORM="darwin" ;;
        mingw*|msys*|cygwin*) PLATFORM="win32" ;;
        *) print_error "Unsupported platform: $platform"; exit 1 ;;
    esac
    
    case "$arch" in
        x86_64|amd64) ARCH="x64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) print_error "Unsupported architecture: $arch"; exit 1 ;;
    esac
}

# Check required tools
check_requirements() {
    print_header "Checking Requirements"
    
    local missing=0
    
    # Check for Rust
    if ! command -v cargo &> /dev/null; then
        print_error "cargo not found. Please install Rust."
        missing=1
    else
        print_status "Rust/Cargo found: $(cargo --version)"
    fi
    
    # Check for cross-compilation tool
    if ! command -v cross &> /dev/null; then
        print_warning "cross not found. Installing..."
        cargo install cross --git https://github.com/cross-rs/cross
    else
        print_status "cross found: $(cross --version)"
    fi
    
    # Check for Node.js
    if ! command -v node &> /dev/null; then
        print_error "node not found. Please install Node.js."
        missing=1
    else
        print_status "Node.js found: $(node --version)"
    fi
    
    # Check for checksum tools
    if command -v sha256sum &> /dev/null; then
        CHECKSUM_CMD="sha256sum"
    elif command -v shasum &> /dev/null; then
        CHECKSUM_CMD="shasum -a 256"
    else
        print_warning "No checksum tool found. Checksums will be skipped."
        CHECKSUM_CMD=""
    fi
    
    if [ $missing -eq 1 ]; then
        exit 1
    fi
}

# Clean previous builds
clean_builds() {
    print_header "Cleaning Previous Builds"
    
    rm -rf "$DIST_DIR"
    rm -rf "$RELEASE_DIR"
    rm -rf "$NPM_DIR/npm"
    
    # Clean Rust target directories
    if [ -f "Cargo.toml" ]; then
        cargo clean
    fi
    
    for project in kindly-guard-shield/src-tauri crates-io-package/kindlyguard; do
        if [ -d "$project" ] && [ -f "$project/Cargo.toml" ]; then
            print_info "Cleaning $project"
            (cd "$project" && cargo clean)
        fi
    done
    
    print_status "Clean complete"
}

# Build for a specific target
build_target() {
    local target=$1
    local platform=$2
    local arch=$3
    local use_cross=$4
    
    print_info "Building for $target (${platform}-${arch})"
    
    local build_cmd="cargo"
    if [ "$use_cross" = "true" ]; then
        build_cmd="cross"
    fi
    
    # Build main binary
    if [ -f "Cargo.toml" ]; then
        $build_cmd build --release --target "$target"
    fi
    
    # Build shield if it exists
    if [ -d "kindly-guard-shield/src-tauri" ]; then
        print_info "Building shield for $target"
        (cd "kindly-guard-shield/src-tauri" && $build_cmd build --release --target "$target")
    fi
}

# Build all binaries
build_all_binaries() {
    print_header "Building Binaries"
    
    # Define build targets
    # Using musl for Linux targets to create static binaries
    # Static binaries work across all Linux distributions without dependency issues
    declare -A TARGETS=(
        ["linux-x64"]="x86_64-unknown-linux-musl"        # musl for static linking
        ["linux-arm64"]="aarch64-unknown-linux-musl"    # musl for static linking
        ["darwin-x64"]="x86_64-apple-darwin"
        ["darwin-arm64"]="aarch64-apple-darwin"
        ["win32-x64"]="x86_64-pc-windows-msvc"
    )
    
    # Alternative GNU targets (uncomment if needed for compatibility)
    # declare -A GNU_TARGETS=(
    #     ["linux-x64-gnu"]="x86_64-unknown-linux-gnu"
    #     ["linux-arm64-gnu"]="aarch64-unknown-linux-gnu"
    # )
    
    # Detect current platform
    detect_platform
    local current_target="${PLATFORM}-${ARCH}"
    
    # Build for all targets
    for platform_arch in "${!TARGETS[@]}"; do
        local target="${TARGETS[$platform_arch]}"
        local platform="${platform_arch%-*}"
        local arch="${platform_arch#*-}"
        
        # Use cross for non-native builds
        local use_cross="false"
        if [ "$platform_arch" != "$current_target" ]; then
            use_cross="true"
        fi
        
        build_target "$target" "$platform" "$arch" "$use_cross"
    done
    
    print_status "All binaries built"
}

# Copy binaries to distribution directories
copy_binaries() {
    print_header "Copying Binaries"
    
    mkdir -p "$DIST_DIR"
    
    # Define binary mappings
    # Must match the targets defined in build_all_binaries
    declare -A TARGETS=(
        ["linux-x64"]="x86_64-unknown-linux-musl"        # musl for static linking
        ["linux-arm64"]="aarch64-unknown-linux-musl"    # musl for static linking
        ["darwin-x64"]="x86_64-apple-darwin"
        ["darwin-arm64"]="aarch64-apple-darwin"
        ["win32-x64"]="x86_64-pc-windows-msvc"
    )
    
    for platform_arch in "${!TARGETS[@]}"; do
        local target="${TARGETS[$platform_arch]}"
        local platform="${platform_arch%-*}"
        local arch="${platform_arch#*-}"
        local platform_dir="$DIST_DIR/${platform}-${arch}"
        local npm_platform_dir="$NPM_DIR/npm/${platform}-${arch}"
        
        mkdir -p "$platform_dir"
        mkdir -p "$npm_platform_dir"
        
        # Determine binary extension
        local ext=""
        if [ "$platform" = "win32" ]; then
            ext=".exe"
        fi
        
        # Copy main binary if it exists
        if [ -f "target/$target/release/kindly-guard${ext}" ]; then
            cp "target/$target/release/kindly-guard${ext}" "$platform_dir/kindlyguard${ext}"
            cp "target/$target/release/kindly-guard${ext}" "$npm_platform_dir/kindlyguard${ext}"
            print_status "Copied kindlyguard for ${platform}-${arch}"
        fi
        
        # Copy CLI binary if it exists
        if [ -f "target/$target/release/kindly-guard-cli${ext}" ]; then
            cp "target/$target/release/kindly-guard-cli${ext}" "$platform_dir/kindlyguard-cli${ext}"
            cp "target/$target/release/kindly-guard-cli${ext}" "$npm_platform_dir/kindlyguard-cli${ext}"
            print_status "Copied kindlyguard-cli for ${platform}-${arch}"
        fi
        
        # Copy shield binary if it exists
        if [ -f "kindly-guard-shield/src-tauri/target/$target/release/kindly-guard-shield${ext}" ]; then
            cp "kindly-guard-shield/src-tauri/target/$target/release/kindly-guard-shield${ext}" "$platform_dir/kindly-guard-shield${ext}"
            print_status "Copied kindly-guard-shield for ${platform}-${arch}"
        fi
        
        # Make binaries executable on Unix platforms
        if [ "$platform" != "win32" ]; then
            chmod +x "$platform_dir"/*
            if [ -d "$npm_platform_dir" ]; then
                chmod +x "$npm_platform_dir"/*
            fi
        fi
    done
}

# Generate checksums
generate_checksums() {
    print_header "Generating Checksums"
    
    if [ -z "$CHECKSUM_CMD" ]; then
        print_warning "Skipping checksums (no tool available)"
        return
    fi
    
    # Generate checksums for distribution directory
    for platform_dir in "$DIST_DIR"/*; do
        if [ -d "$platform_dir" ]; then
            print_info "Generating checksums for $(basename "$platform_dir")"
            (cd "$platform_dir" && $CHECKSUM_CMD * > checksums.txt)
        fi
    done
    
    # Generate checksums for npm packages
    for npm_platform_dir in "$NPM_DIR"/npm/*; do
        if [ -d "$npm_platform_dir" ]; then
            print_info "Generating npm checksums for $(basename "$npm_platform_dir")"
            (cd "$npm_platform_dir" && $CHECKSUM_CMD kindlyguard* > checksums.txt 2>/dev/null || true)
        fi
    done
    
    # Generate master checksum file
    print_info "Generating master checksums"
    (cd "$DIST_DIR" && find . -name "kindlyguard*" -type f -exec $CHECKSUM_CMD {} \; > "$PROJECT_ROOT/checksums-${VERSION}.txt")
    
    print_status "Checksums generated"
}

# Create archives
create_archives() {
    print_header "Creating Archives"
    
    mkdir -p "$RELEASE_DIR"
    
    # Create platform-specific archives
    for platform_dir in "$DIST_DIR"/*; do
        if [ -d "$platform_dir" ]; then
            local platform_name=$(basename "$platform_dir")
            local archive_name="kindlyguard-${VERSION}-${platform_name}"
            
            print_info "Creating archive: ${archive_name}.tar.gz"
            
            # Create tar.gz
            (cd "$DIST_DIR" && tar -czf "$RELEASE_DIR/${archive_name}.tar.gz" "$platform_name")
            
            # Create zip for Windows
            if [[ "$platform_name" == "win32-"* ]]; then
                print_info "Creating archive: ${archive_name}.zip"
                (cd "$DIST_DIR" && zip -r "$RELEASE_DIR/${archive_name}.zip" "$platform_name")
            fi
        fi
    done
    
    # Copy checksums to release directory
    if [ -f "$PROJECT_ROOT/checksums-${VERSION}.txt" ]; then
        cp "$PROJECT_ROOT/checksums-${VERSION}.txt" "$RELEASE_DIR/"
    fi
    
    print_status "Archives created in $RELEASE_DIR"
}

# Create npm platform packages
create_npm_packages() {
    print_header "Creating NPM Platform Packages"
    
    for npm_platform_dir in "$NPM_DIR"/npm/*; do
        if [ -d "$npm_platform_dir" ] && [ -f "$npm_platform_dir/kindlyguard" -o -f "$npm_platform_dir/kindlyguard.exe" ]; then
            local platform_name=$(basename "$npm_platform_dir")
            local platform="${platform_name%-*}"
            local arch="${platform_name#*-}"
            
            print_info "Creating npm package for ${platform_name}"
            
            # Create package.json
            cat > "$npm_platform_dir/package.json" <<EOF
{
  "name": "@kindlyguard/${platform}-${arch}",
  "version": "${VERSION}",
  "description": "KindlyGuard binaries for ${platform}-${arch}",
  "author": "samduchaine",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/samduchaine/kindly-guard.git"
  },
  "files": [
    "kindlyguard*",
    "checksums.txt",
    "README.md"
  ],
  "os": ["${platform}"],
  "cpu": ["${arch}"],
  "publishConfig": {
    "access": "public"
  }
}
EOF
            
            # Create README
            cat > "$npm_platform_dir/README.md" <<EOF
# KindlyGuard Binaries for ${platform}-${arch}

This package contains pre-built KindlyGuard binaries for ${platform} ${arch}.

Version: ${VERSION}

## Installation

This package is automatically installed as an optional dependency of the main \`kindlyguard\` package.

### Direct Installation

\`\`\`bash
npm install @kindlyguard/${platform}-${arch}
\`\`\`

### Main Package Installation

For normal usage, install the main package:

\`\`\`bash
npm install -g kindlyguard
\`\`\`

## Files

- \`kindlyguard\` - Main KindlyGuard server binary
- \`kindlyguard-cli\` - Command-line interface
- \`checksums.txt\` - SHA256 checksums for verification

## License

MIT
EOF
            
            print_status "Created npm package for ${platform_name}"
        fi
    done
}

# Update main npm package
update_main_npm_package() {
    print_header "Updating Main NPM Package"
    
    # Update version in package.json
    if [ -f "$NPM_DIR/package.json" ]; then
        print_info "Updating package.json version to ${VERSION}"
        node -e "
            const fs = require('fs');
            const pkg = JSON.parse(fs.readFileSync('$NPM_DIR/package.json', 'utf8'));
            pkg.version = '${VERSION}';
            
            // Update optional dependencies versions
            if (pkg.optionalDependencies) {
                Object.keys(pkg.optionalDependencies).forEach(dep => {
                    if (dep.startsWith('@kindlyguard/')) {
                        pkg.optionalDependencies[dep] = '${VERSION}';
                    }
                });
            }
            
            fs.writeFileSync('$NPM_DIR/package.json', JSON.stringify(pkg, null, 2) + '\n');
            console.log('Updated package.json');
        "
        
        print_status "Main package updated to version ${VERSION}"
    fi
}

# Summary report
print_summary() {
    print_header "Build Summary"
    
    echo "Version: ${VERSION}"
    echo "Platform: ${PLATFORM}-${ARCH}"
    echo
    
    if [ -d "$DIST_DIR" ]; then
        echo "Distribution files:"
        find "$DIST_DIR" -type f -name "kindlyguard*" | while read -r file; do
            echo "  - $file ($(du -h "$file" | cut -f1))"
        done
    fi
    
    echo
    
    if [ -d "$RELEASE_DIR" ]; then
        echo "Release archives:"
        ls -lh "$RELEASE_DIR"/*.{tar.gz,zip} 2>/dev/null | awk '{print "  - " $9 " (" $5 ")"}'
    fi
    
    echo
    
    if [ -d "$NPM_DIR/npm" ]; then
        echo "NPM packages:"
        for pkg in "$NPM_DIR"/npm/*/package.json; do
            if [ -f "$pkg" ]; then
                local name=$(node -p "require('$pkg').name")
                echo "  - $name"
            fi
        done
    fi
    
    echo
    print_status "Build complete!"
    
    echo
    echo "Next steps:"
    echo "  1. Test the binaries: ./test-binaries.sh"
    echo "  2. Package for npm: node package-binaries.js"
    echo "  3. Create release: git tag v${VERSION} && git push --tags"
    echo "  4. Run CI/CD: GitHub Actions will handle the rest"
}

# Main execution
main() {
    print_header "KindlyGuard Cross-Platform Build"
    echo "Version: ${VERSION}"
    echo
    
    check_requirements
    
    # Parse command line arguments
    case "${1:-all}" in
        clean)
            clean_builds
            ;;
        build)
            build_all_binaries
            ;;
        package)
            copy_binaries
            generate_checksums
            create_archives
            create_npm_packages
            update_main_npm_package
            ;;
        all)
            clean_builds
            build_all_binaries
            copy_binaries
            generate_checksums
            create_archives
            create_npm_packages
            update_main_npm_package
            print_summary
            ;;
        *)
            echo "Usage: $0 [clean|build|package|all]"
            echo "  clean   - Clean previous builds"
            echo "  build   - Build binaries for all platforms"
            echo "  package - Package binaries for distribution"
            echo "  all     - Run all steps (default)"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"