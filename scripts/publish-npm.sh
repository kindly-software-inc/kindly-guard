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
    echo "❌ Error: NPM_TOKEN not found in .env"
    exit 1
fi

# Set npm auth token
echo "📝 Setting npm authentication..."
npm config set //registry.npmjs.org/:_authToken "$NPM_TOKEN"

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

# Dry run
echo "🔍 Running npm publish dry-run..."
npm publish --dry-run

# Ask for confirmation
echo ""
read -p "Continue with publishing kindly-guard@$CURRENT_VERSION? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Publish main package
    echo "📤 Publishing main package..."
    npm publish --access public
    
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
else
    echo "❌ Publishing cancelled"
    exit 1
fi