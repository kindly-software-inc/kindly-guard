#!/bin/bash
set -e

# GitHub Release Creation Script for KindlyGuard
# This script creates a GitHub release and uploads platform binaries

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DRAFT=false
PRERELEASE=false
GENERATE_NOTES=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --draft)
            DRAFT=true
            shift
            ;;
        --prerelease)
            PRERELEASE=true
            shift
            ;;
        --no-generate-notes)
            GENERATE_NOTES=false
            shift
            ;;
        --help)
            echo "Usage: $0 --version <version> [options]"
            echo ""
            echo "Options:"
            echo "  --version <version>    Version to release (required)"
            echo "  --draft               Create a draft release"
            echo "  --prerelease          Mark as pre-release"
            echo "  --no-generate-notes   Don't auto-generate release notes"
            echo ""
            echo "Example:"
            echo "  $0 --version 0.9.2"
            echo "  $0 --version 0.10.0-beta.1 --prerelease"
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

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo -e "${RED}❌ Error: GitHub CLI (gh) is not installed${NC}"
    echo "Install it from: https://cli.github.com/"
    exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo -e "${RED}❌ Error: Not authenticated with GitHub${NC}"
    echo "Run: gh auth login"
    exit 1
fi

echo -e "${BLUE}🚀 Creating GitHub Release for KindlyGuard v${VERSION}${NC}"
echo "============================================="
echo ""

# Check if tag exists
TAG="v${VERSION}"
if ! git tag | grep -q "^${TAG}$"; then
    echo -e "${YELLOW}⚠️  Tag ${TAG} doesn't exist. Creating it...${NC}"
    git tag -a "${TAG}" -m "Release ${VERSION}"
    git push origin "${TAG}"
    echo -e "${GREEN}✅ Tag created and pushed${NC}"
else
    echo -e "${GREEN}✅ Tag ${TAG} already exists${NC}"
fi

# Ensure release artifacts directory exists
ARTIFACTS_DIR="release-artifacts/${VERSION}"
if [ ! -d "$ARTIFACTS_DIR" ]; then
    echo -e "${RED}❌ Error: Release artifacts not found at ${ARTIFACTS_DIR}${NC}"
    echo "Run ./scripts/build-release.sh --version ${VERSION} first"
    exit 1
fi

# Build release flags
RELEASE_FLAGS=""
if [ "$DRAFT" = true ]; then
    RELEASE_FLAGS="$RELEASE_FLAGS --draft"
fi
if [ "$PRERELEASE" = true ]; then
    RELEASE_FLAGS="$RELEASE_FLAGS --prerelease"
fi
if [ "$GENERATE_NOTES" = true ]; then
    RELEASE_FLAGS="$RELEASE_FLAGS --generate-notes"
fi

# Create release notes file
RELEASE_NOTES_FILE=$(mktemp)
cat > "$RELEASE_NOTES_FILE" << EOF
## KindlyGuard v${VERSION}

### 🚀 What's New

*Auto-generated release notes will appear here if enabled*

### 📦 Installation

#### Via NPM (Recommended)
\`\`\`bash
npm install -g @kindlyguard/kindlyguard@${VERSION}
\`\`\`

#### Via Cargo
\`\`\`bash
cargo install kindly-guard-cli@${VERSION}
cargo install kindly-guard-server@${VERSION}
\`\`\`

#### Direct Binary Download
Download the appropriate binary for your platform from the assets below.

### 🔐 Checksums

All release artifacts include SHA-256 checksums for verification:
\`\`\`bash
# Verify downloaded file
shasum -a 256 -c checksums.txt
\`\`\`

### 📚 Documentation

- [Getting Started Guide](https://github.com/kindlysoftware/kindlyguard/blob/main/docs/getting-started.md)
- [API Documentation](https://github.com/kindlysoftware/kindlyguard/blob/main/docs/api.md)
- [Security Guide](https://github.com/kindlysoftware/kindlyguard/blob/main/docs/security.md)

### 🐛 Bug Reports

Please report any issues at: https://github.com/kindlysoftware/kindlyguard/issues
EOF

# Create the release
echo -e "${YELLOW}📝 Creating GitHub release...${NC}"
if gh release create "${TAG}" \
    --title "KindlyGuard v${VERSION}" \
    --notes-file "$RELEASE_NOTES_FILE" \
    $RELEASE_FLAGS; then
    echo -e "${GREEN}✅ Release created successfully${NC}"
else
    echo -e "${RED}❌ Failed to create release${NC}"
    rm "$RELEASE_NOTES_FILE"
    exit 1
fi

rm "$RELEASE_NOTES_FILE"

# Upload release assets
echo ""
echo -e "${YELLOW}📤 Uploading release assets...${NC}"

# Function to upload with progress
upload_asset() {
    local file=$1
    local filename=$(basename "$file")
    echo -n "  Uploading $filename... "
    if gh release upload "${TAG}" "$file" --clobber; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        return 1
    fi
}

# Upload all artifacts
for artifact in "$ARTIFACTS_DIR"/*; do
    if [ -f "$artifact" ]; then
        upload_asset "$artifact"
    fi
done

# Get release URL
RELEASE_URL=$(gh release view "${TAG}" --json url -q .url)

echo ""
echo -e "${GREEN}🎉 GitHub Release Created Successfully!${NC}"
echo "======================================="
echo ""
echo -e "${BLUE}📋 Release Information:${NC}"
echo "  Version: ${VERSION}"
echo "  Tag: ${TAG}"
echo "  Status: $([ "$DRAFT" = true ] && echo "Draft" || echo "Published")"
echo "  Type: $([ "$PRERELEASE" = true ] && echo "Pre-release" || echo "Release")"
echo "  URL: ${RELEASE_URL}"
echo ""

if [ "$DRAFT" = true ]; then
    echo -e "${YELLOW}⚠️  This is a draft release. To publish it:${NC}"
    echo "  gh release edit ${TAG} --draft=false"
    echo ""
fi

echo -e "${BLUE}📦 Uploaded Assets:${NC}"
for artifact in "$ARTIFACTS_DIR"/*; do
    if [ -f "$artifact" ]; then
        echo "  - $(basename "$artifact")"
    fi
done

echo ""
echo -e "${BLUE}🚀 Next Steps:${NC}"
echo "  1. Review the release at: ${RELEASE_URL}"
echo "  2. Test the download links"
echo "  3. Announce the release"
echo ""