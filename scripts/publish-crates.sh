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
    
    # Ask for confirmation
    read -p "Continue with publishing $crate_name? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cargo publish
        echo "✅ Published $crate_name"
        # Wait for crates.io to index
        echo "⏳ Waiting 30s for crates.io to index..."
        sleep 30
    else
        echo "⏭️  Skipped $crate_name"
    fi
    
    cd - > /dev/null
}

# Publish in dependency order
echo "📋 Publishing order:"
echo "  1. kindly-guard-server (library)"
echo "  2. kindly-guard-cli (depends on server)"
echo ""

# First, we need to temporarily update the CLI's dependency
echo "⚠️  Note: You need to update kindly-guard-cli/Cargo.toml to use:"
echo '    kindly-guard-server = { version = "0.1.0" }'
echo "    instead of the path dependency before publishing."
echo ""
read -p "Have you updated the dependency? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Please update the dependency first"
    exit 1
fi

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