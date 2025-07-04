#!/bin/bash
set -e

echo "🚀 KindlyGuard Complete Publishing Process"
echo "=========================================="
echo ""
echo "This will publish to:"
echo "  📦 crates.io (Rust packages)"
echo "  📦 npm (Node.js package)"
echo "  🐳 Docker Hub (Container image)"
echo ""

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "❌ Error: .env file not found"
    exit 1
fi

# Check all required tokens
MISSING_TOKENS=0
if [ -z "$CARGO_REGISTRY_TOKEN" ]; then
    echo "❌ Missing: CARGO_REGISTRY_TOKEN"
    MISSING_TOKENS=1
fi
if [ -z "$NPM_TOKEN" ]; then
    echo "❌ Missing: NPM_TOKEN"
    MISSING_TOKENS=1
fi
if [ -z "$DOCKER_USERNAME" ] || [ -z "$DOCKER_TOKEN" ]; then
    echo "❌ Missing: DOCKER_USERNAME or DOCKER_TOKEN"
    MISSING_TOKENS=1
fi

if [ $MISSING_TOKENS -eq 1 ]; then
    echo ""
    echo "Please add missing tokens to .env file"
    exit 1
fi

echo "✅ All tokens found"
echo ""

# Get version
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
echo "📋 Publishing version: $VERSION"
echo ""

echo "✅ Auto-confirming publish of v$VERSION to all registries"

# Run pre-flight checks
echo ""
echo "🔍 Running pre-flight checks..."

# Check git status
if [ -n "$(git status --porcelain)" ]; then
    echo "⚠️  Warning: You have uncommitted changes"
    echo "✅ Auto-confirming to proceed with uncommitted changes"
fi

# Check if we're on main branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo "⚠️  Warning: Not on main branch (current: $CURRENT_BRANCH)"
    echo "✅ Auto-confirming to proceed from $CURRENT_BRANCH branch"
fi

# Start publishing process
echo ""
echo "📦 Step 1/3: Publishing to crates.io..."
echo "----------------------------------------"
./scripts/publish-crates-noninteractive.sh

echo ""
echo "📦 Step 2/3: Publishing to npm..."
echo "---------------------------------"
./scripts/publish-npm-noninteractive.sh

echo ""
echo "🐳 Step 3/3: Publishing to Docker Hub..."
echo "----------------------------------------"
./scripts/publish-docker-noninteractive.sh

echo ""
echo "🎉 All publishing complete!"
echo ""
echo "📚 View your packages at:"
echo "   Rust: https://crates.io/crates/kindly-guard-server"
echo "   Rust: https://crates.io/crates/kindly-guard-cli"
echo "   npm: https://www.npmjs.com/package/kindly-guard"
echo "   Docker: https://hub.docker.com/r/kindlysoftware/kindly-guard"
echo ""
echo "📥 Installation commands:"
echo "   cargo install kindly-guard-cli"
echo "   npm install -g kindly-guard"
echo "   docker pull kindlysoftware/kindly-guard"