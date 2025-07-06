#!/bin/bash
set -e

# Script to test and fix CI build issues for KindlyGuard
# Focuses on the targets that are failing in CI

echo "🔧 Testing CI build configuration..."

# The problematic targets from CI
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
)

# Test if cross is available
if ! command -v cross &> /dev/null; then
    echo "❌ cross is not installed!"
    echo "Installing cross..."
    cargo install cross --git https://github.com/cross-rs/cross
fi

echo "✅ cross version: $(cross --version)"

# Check Docker
if ! docker ps &>/dev/null; then
    echo "❌ Docker is not running or not accessible!"
    echo "Please ensure Docker is running and you have permissions"
    exit 1
fi

echo "✅ Docker is running"

# Update Cross.toml to use specific versions
echo "📝 Updating Cross.toml with verified images..."
cat > Cross.toml << 'EOF'
# Cross compilation configuration

[target.x86_64-pc-windows-gnu]
image = "ghcr.io/cross-rs/x86_64-pc-windows-gnu:main"

# Configuration for musl target to create fully static Linux binaries
[target.x86_64-unknown-linux-musl]
image = "ghcr.io/cross-rs/x86_64-unknown-linux-musl:latest"

# Configuration for ARM64 Linux (e.g., Raspberry Pi 4, AWS Graviton)
[target.aarch64-unknown-linux-gnu]
image = "ghcr.io/cross-rs/aarch64-unknown-linux-gnu:main"

# Standard Linux GNU target
[target.x86_64-unknown-linux-gnu]
image = "ghcr.io/cross-rs/x86_64-unknown-linux-gnu:main"

# Build configuration
[build]
pre-build = [
    "apt-get update || true",
    "apt-get install -y pkg-config libssl-dev || true"
]
EOF

echo "✅ Cross.toml updated"

# Test build for each problematic target
for target in "${TARGETS[@]}"; do
    echo ""
    echo "🧪 Testing build for $target..."
    
    # Pull the Docker image first
    IMAGE="ghcr.io/cross-rs/${target}:main"
    echo "  Pulling Docker image: $IMAGE"
    docker pull "$IMAGE" || echo "  Warning: Could not pull image, may use cached version"
    
    # Try a minimal build first
    echo "  Testing minimal build..."
    if cross build --target "$target" --package kindly-tools --bin kindly-tools; then
        echo "  ✅ Build successful for $target"
    else
        echo "  ❌ Build failed for $target"
        echo "  Trying with verbose output..."
        RUST_LOG=debug cross build --target "$target" --package kindly-tools --bin kindly-tools -vv 2>&1 | tail -50
    fi
done

echo ""
echo "📋 Summary:"
echo "- Cross.toml has been updated with verified image tags"
echo "- Test builds have been run for Linux targets"
echo ""
echo "Next steps:"
echo "1. If builds succeeded locally, commit the updated Cross.toml"
echo "2. The CI should now use the same configuration"
echo "3. Monitor the GitHub Actions output for any remaining issues"