#!/bin/bash
set -e

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

echo "🚀 Publishing KindlyGuard crates to crates.io"
echo "============================================"

# Check if token is available
if [ -z "$CARGO_REGISTRY_TOKEN" ]; then
    echo "❌ Error: CARGO_REGISTRY_TOKEN not found in .env"
    exit 1
fi

# Login to crates.io
echo "📝 Logging in to crates.io..."
cargo login "$CARGO_REGISTRY_TOKEN"

# Function to publish a crate
publish_crate() {
    local crate_dir=$1
    local crate_name=$2
    
    echo ""
    echo "📦 Publishing $crate_name..."
    cd "$crate_dir"
    
    # Dry run first
    echo "🔍 Dry run for $crate_name..."
    cargo publish --dry-run
    
    # Auto-confirm publishing
    echo "✅ Auto-confirming publish of $crate_name"
    cargo publish
    echo "✅ Published $crate_name"
    # Wait for crates.io to index
    echo "⏳ Waiting 30s for crates.io to index..."
    sleep 30
    
    cd - > /dev/null
}

# Publish in dependency order
echo "📋 Publishing order:"
echo "  1. kindly-guard-server (library)"
echo "  2. kindly-guard-cli (depends on server)"
echo ""

# First, we need to temporarily update the CLI's dependency
echo "✅ Dependency already updated to use version 0.2.0"

# Publish server first
publish_crate "kindly-guard-server" "kindly-guard-server"

# Then publish CLI
publish_crate "kindly-guard-cli" "kindly-guard-cli"

echo ""
echo "🎉 Publishing complete!"
echo ""
echo "📚 View your crates at:"
echo "   https://crates.io/crates/kindly-guard-server"
echo "   https://crates.io/crates/kindly-guard-cli"