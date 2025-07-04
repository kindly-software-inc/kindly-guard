#!/bin/bash

# Script to create GitHub release v0.9.2 for KindlyGuard

set -e

RELEASE_VERSION="v0.9.2"
RELEASE_DIR="release-v0.9.2"

echo "Creating GitHub release $RELEASE_VERSION for KindlyGuard"
echo "=============================================="
echo ""

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is not installed"
    echo "Please install it from: https://cli.github.com/"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || [ ! -d "$RELEASE_DIR" ]; then
    echo "Error: Please run this script from the kindly-guard root directory"
    exit 1
fi

# Check if already authenticated
if ! gh auth status &> /dev/null; then
    echo "Please authenticate with GitHub:"
    gh auth login
fi

echo "Creating release notes..."
RELEASE_NOTES_FILE="$RELEASE_DIR/RELEASE_NOTES.md"

# Create the release
echo "Creating GitHub release..."
gh release create "$RELEASE_VERSION" \
    --title "KindlyGuard $RELEASE_VERSION" \
    --notes-file "$RELEASE_NOTES_FILE" \
    --draft

# Upload the Linux binaries
echo "Uploading Linux x64 binaries..."
gh release upload "$RELEASE_VERSION" \
    "$RELEASE_DIR/kindlyguard-linux-x64.tar.gz" \
    "$RELEASE_DIR/SHA256SUMS.txt" \
    --clobber

echo ""
echo "✅ Draft release created successfully!"
echo ""
echo "Next steps:"
echo "1. Review the draft release at: https://github.com/samduchaine/kindly-guard/releases"
echo "2. When Windows/macOS binaries are ready, upload them with:"
echo "   gh release upload $RELEASE_VERSION path/to/binary.tar.gz"
echo "3. Publish the release when ready:"
echo "   gh release edit $RELEASE_VERSION --draft=false"
echo ""
echo "To publish the NPM package after release:"
echo "   cd npm-package && npm publish"