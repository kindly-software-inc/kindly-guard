#!/bin/bash
set -e

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

echo "🚀 Publishing kindly-guard to npm"
echo "==================================="

# Check if token is available
if [ -z "$NPM_TOKEN" ]; then
    echo "❌ Error: NPM_TOKEN not found in environment"
    echo "   Please set NPM_TOKEN environment variable or add to .env file"
    echo "   See SECURITY.md for secure token management"
    exit 1
fi

# Validate token format (basic check)
if [[ ! "$NPM_TOKEN" =~ ^npm_[A-Za-z0-9_-]{36,}$ ]]; then
    echo "⚠️  Warning: NPM_TOKEN format looks unusual"
    echo "   Expected format: npm_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
fi

# Set npm auth token (suppress output to avoid token exposure)
echo "📝 Setting npm authentication..."
npm config set //registry.npmjs.org/:_authToken "$NPM_TOKEN" 2>/dev/null || {
    echo "❌ Failed to set npm authentication"
    exit 1
}

# Navigate to npm package directory
cd npm-package

# Check current version
CURRENT_VERSION=$(node -p "require('./package.json').version")
echo "📦 Current version: $CURRENT_VERSION"

# Build platform packages first
echo "🔨 Building platform-specific packages..."
npm run build-platform-packages

# Run tests
echo "🧪 Running tests..."
npm test

# Dry run (with minimal output to avoid token exposure)
echo "🔍 Running npm publish dry-run..."
npm publish --dry-run --silent 2>&1 | grep -v "npm notice" | grep -v "tarball" || true

# Auto-confirm publishing
echo ""
echo "✅ Auto-confirming publish of kindly-guard@$CURRENT_VERSION"

# Publish main package (suppress verbose output)
echo "📤 Publishing main package..."
npm publish --access public --silent || {
    echo "❌ Failed to publish main package"
    exit 1
}

echo "✅ Published kindly-guard@$CURRENT_VERSION"

# Publish platform packages
echo ""
echo "📦 Publishing platform-specific packages..."

for pkg_dir in npm/kindlyguard-*; do
    if [ -d "$pkg_dir" ]; then
        echo "📤 Publishing $(basename $pkg_dir)..."
        (cd "$pkg_dir" && npm publish --access public)
    fi
done

echo ""
echo "🎉 All packages published successfully!"
echo ""
echo "📚 View your package at:"
echo "   https://www.npmjs.com/package/@kindlyguard/kindlyguard"
echo ""
echo "📥 Install with:"
echo "   npm install -g @kindlyguard/kindlyguard"