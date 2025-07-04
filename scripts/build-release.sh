#!/bin/bash
set -e

# Build Release Artifacts Script for KindlyGuard
# This script builds binaries for all supported platforms

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --platforms)
            PLATFORMS="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 --version <version> [options]"
            echo ""
            echo "Options:"
            echo "  --version <version>    Version to build (required)"
            echo "  --platforms <list>     Comma-separated list of platforms"
            echo "                        Default: linux-x64,darwin-x64,darwin-arm64,win-x64"
            echo ""
            echo "Example:"
            echo "  $0 --version 0.9.2"
            echo "  $0 --version 0.9.2 --platforms linux-x64,darwin-arm64"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Validate inputs
if [ -z "$VERSION" ]; then
    echo -e "${RED}❌ Error: Version is required. Use --version <version>${NC}"
    exit 1
fi

# Default platforms
if [ -z "$PLATFORMS" ]; then
    PLATFORMS="linux-x64,darwin-x64,darwin-arm64,win-x64"
fi

echo -e "${BLUE}🔨 Building Release Artifacts for KindlyGuard v${VERSION}${NC}"
echo "================================================="
echo ""

# Check version in Cargo.toml
CARGO_VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
if [ "$CARGO_VERSION" != "$VERSION" ]; then
    echo -e "${YELLOW}⚠️  Warning: Cargo.toml version ($CARGO_VERSION) doesn't match requested version ($VERSION)${NC}"
    echo -n "Do you want to continue? (y/N) "
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Create release artifacts directory
ARTIFACTS_DIR="release-artifacts/${VERSION}"
mkdir -p "$ARTIFACTS_DIR"

# Function to detect current platform
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case "$os" in
        linux*)
            os="linux"
            ;;
        darwin*)
            os="darwin"
            ;;
        mingw*|msys*|cygwin*)
            os="win"
            ;;
    esac
    
    case "$arch" in
        x86_64|amd64)
            arch="x64"
            ;;
        aarch64|arm64)
            arch="arm64"
            ;;
    esac
    
    echo "${os}-${arch}"
}

CURRENT_PLATFORM=$(detect_platform)
echo -e "${BLUE}📍 Current platform: ${CURRENT_PLATFORM}${NC}"
echo ""

# Build for current platform first
echo -e "${YELLOW}🔧 Building for current platform...${NC}"
cargo build --release --all

# Function to package binaries
package_platform() {
    local platform=$1
    local binary_ext=""
    local tar_opts="-czf"
    
    # Add .exe extension for Windows
    if [[ "$platform" == win-* ]]; then
        binary_ext=".exe"
    fi
    
    # Check if binaries exist
    if [ ! -f "target/release/kindlyguard${binary_ext}" ] || [ ! -f "target/release/kindlyguard-cli${binary_ext}" ]; then
        echo -e "${YELLOW}⚠️  Binaries for $platform not found. Skipping...${NC}"
        return
    fi
    
    echo -e "${BLUE}📦 Packaging $platform...${NC}"
    
    # Create platform-specific archive
    local archive_name="kindlyguard-${VERSION}-${platform}.tar.gz"
    if [[ "$platform" == win-* ]]; then
        archive_name="kindlyguard-${VERSION}-${platform}.zip"
        # Use zip for Windows
        (cd target/release && zip -q "../../${ARTIFACTS_DIR}/${archive_name}" \
            "kindlyguard${binary_ext}" "kindlyguard-cli${binary_ext}")
    else
        # Use tar for Unix-like systems
        tar $tar_opts "${ARTIFACTS_DIR}/${archive_name}" \
            -C target/release \
            "kindlyguard${binary_ext}" "kindlyguard-cli${binary_ext}"
    fi
    
    echo -e "${GREEN}✅ Created ${archive_name}${NC}"
}

# Process each platform
IFS=',' read -ra PLATFORM_ARRAY <<< "$PLATFORMS"
for platform in "${PLATFORM_ARRAY[@]}"; do
    platform=$(echo "$platform" | xargs) # Trim whitespace
    
    if [ "$platform" == "$CURRENT_PLATFORM" ]; then
        # Already built for current platform
        package_platform "$platform"
    else
        echo -e "${YELLOW}⚠️  Cross-compilation for $platform requires additional setup${NC}"
        echo "  Please build on native $platform or use cross-compilation tools"
        
        # Create placeholder for CI/CD to fill
        touch "${ARTIFACTS_DIR}/kindlyguard-${VERSION}-${platform}.tar.gz.placeholder"
    fi
done

# Generate checksums
echo ""
echo -e "${YELLOW}🔐 Generating checksums...${NC}"
cd "$ARTIFACTS_DIR"

# Remove placeholders for checksum generation
rm -f *.placeholder

# Generate SHA-256 checksums
if ls *.tar.gz *.zip 2>/dev/null | grep -q .; then
    shasum -a 256 *.tar.gz *.zip 2>/dev/null > checksums.txt || true
    echo -e "${GREEN}✅ Generated checksums.txt${NC}"
else
    echo -e "${YELLOW}⚠️  No archives found for checksum generation${NC}"
fi

# Generate file list
ls -la > files.txt

cd - > /dev/null

# Create release notes template
cat > "${ARTIFACTS_DIR}/RELEASE_NOTES.md" << EOF
# KindlyGuard v${VERSION} Release Notes

## 🚀 What's New

- Feature 1
- Feature 2
- Bug fixes and improvements

## 📦 Installation

### Via NPM (Recommended)
\`\`\`bash
npm install -g @kindlyguard/kindlyguard@${VERSION}
\`\`\`

### Via Cargo
\`\`\`bash
cargo install kindly-guard-cli@${VERSION}
cargo install kindly-guard-server@${VERSION}
\`\`\`

### Direct Binary Download
Download the appropriate binary for your platform from the GitHub release page.

## 🔐 Verifying Downloads

All release artifacts include SHA-256 checksums:
\`\`\`bash
# Download checksums.txt from release page
shasum -a 256 -c checksums.txt
\`\`\`

## 📚 Documentation

See the [documentation](https://github.com/kindlysoftware/kindlyguard/tree/v${VERSION}/docs) for detailed usage instructions.

## 🐛 Known Issues

None at this time.

## 🙏 Acknowledgments

Thanks to all contributors!
EOF

echo ""
echo -e "${GREEN}🎉 Release Artifacts Built Successfully!${NC}"
echo "======================================="
echo ""
echo -e "${BLUE}📋 Build Summary:${NC}"
echo "  Version: ${VERSION}"
echo "  Artifacts Directory: ${ARTIFACTS_DIR}"
echo ""
echo -e "${BLUE}📦 Generated Files:${NC}"
ls -1 "$ARTIFACTS_DIR" | while read -r file; do
    echo "  - $file"
done
echo ""
echo -e "${BLUE}🚀 Next Steps:${NC}"
echo "  1. Review the artifacts in ${ARTIFACTS_DIR}/"
echo "  2. Edit ${ARTIFACTS_DIR}/RELEASE_NOTES.md with actual release notes"
echo "  3. Build missing platforms using CI/CD or native machines"
echo "  4. Run: ./scripts/create-github-release.sh --version ${VERSION}"
echo ""

# Create a build info file
cat > "${ARTIFACTS_DIR}/BUILD_INFO.json" << EOF
{
  "version": "${VERSION}",
  "build_date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "build_platform": "${CURRENT_PLATFORM}",
  "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo "unknown")",
  "git_branch": "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")",
  "rust_version": "$(rustc --version || echo "unknown")"
}
EOF