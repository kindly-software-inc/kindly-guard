#!/bin/bash
# Script to synchronize versions across Cargo.toml and package.json files

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Function to extract version from Cargo.toml
get_cargo_version() {
    grep -E '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/'
}

# Function to extract version from package.json
get_npm_version() {
    if command -v jq &> /dev/null; then
        jq -r '.version' npm-package/package.json
    else
        grep '"version"' npm-package/package.json | head -1 | sed 's/.*"version": "\([^"]*\)".*/\1/'
    fi
}

# Function to update package.json version
update_npm_version() {
    local new_version=$1
    cd npm-package
    
    # Update main version
    npm version "$new_version" --no-git-tag-version --allow-same-version
    
    # Update optionalDependencies
    if command -v jq &> /dev/null; then
        jq --arg ver "$new_version" '.optionalDependencies = .optionalDependencies | to_entries | map(.value = $ver) | from_entries' package.json > package.json.tmp
        mv package.json.tmp package.json
    else
        for dep in "kindlyguard-linux-x64" "kindlyguard-darwin-x64" "kindlyguard-darwin-arm64" "kindlyguard-win32-x64"; do
            sed -i.bak "s/\"$dep\": \"[^\"]*\"/\"$dep\": \"$new_version\"/g" package.json
        done
        rm -f package.json.bak
    fi
    
    # Update prepublishOnly script
    sed -i.bak "s/Publishing KindlyGuard v[0-9.]\+/Publishing KindlyGuard v$new_version/g" package.json
    rm -f package.json.bak
    
    cd ..
}

# Main script
echo "🔄 Checking version consistency..."

CARGO_VERSION=$(get_cargo_version)
NPM_VERSION=$(get_npm_version)

echo "📦 Cargo.toml version: $CARGO_VERSION"
echo "📦 package.json version: $NPM_VERSION"

if [ "$CARGO_VERSION" = "$NPM_VERSION" ]; then
    echo -e "${GREEN}✅ Versions are synchronized!${NC}"
    exit 0
fi

echo -e "${YELLOW}⚠️  Version mismatch detected!${NC}"

# If --sync flag is provided, synchronize versions
if [ "$1" = "--sync" ]; then
    echo "🔧 Synchronizing package.json to match Cargo.toml version..."
    update_npm_version "$CARGO_VERSION"
    echo -e "${GREEN}✅ Synchronized package.json to version $CARGO_VERSION${NC}"
    
    # Verify the update
    NEW_NPM_VERSION=$(get_npm_version)
    if [ "$CARGO_VERSION" = "$NEW_NPM_VERSION" ]; then
        echo -e "${GREEN}✅ Version synchronization successful!${NC}"
    else
        echo -e "${RED}❌ Version synchronization failed!${NC}"
        exit 1
    fi
else
    echo ""
    echo "To synchronize versions, run:"
    echo "  ./scripts/sync-versions.sh --sync"
    echo ""
    echo "This will update package.json to match Cargo.toml version ($CARGO_VERSION)"
    exit 1
fi