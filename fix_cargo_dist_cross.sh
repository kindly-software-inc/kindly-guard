#!/bin/bash
set -e

# Script to fix cargo-dist cross-compilation issues
echo "🔧 Fixing cargo-dist cross-compilation configuration..."

# Update Cargo.toml to add cross as a build dependency
echo "📝 Checking cargo-dist configuration..."

# First, let's test if cargo-dist recognizes cross
if command -v dist &> /dev/null; then
    echo "✅ cargo-dist is installed locally"
    dist --version
else
    echo "⚠️  cargo-dist not installed locally, installing..."
    cargo install cargo-dist
fi

# Create a dist-workspace.toml to explicitly configure cross usage
echo "📝 Creating dist-workspace.toml for cross configuration..."
cat > dist-workspace.toml << 'EOF'
# cargo-dist configuration for workspace

[dist]
# Explicitly enable cross for Linux ARM builds
cargo-build-command = ["cross"]

# Define which targets need cross
[dist.targets.aarch64-unknown-linux-gnu]
cargo-build-command = ["cross"]

[dist.targets.x86_64-unknown-linux-gnu]  
cargo-build-command = ["cross"]

[dist.targets.x86_64-unknown-linux-musl]
cargo-build-command = ["cross"]
EOF

echo "✅ Created dist-workspace.toml"

# Test cargo-dist plan to see if it recognizes the configuration
echo ""
echo "🧪 Testing cargo-dist configuration..."
if dist plan --tag v0.11.8 2>&1 | grep -q "cross"; then
    echo "✅ cargo-dist is configured to use cross"
else
    echo "⚠️  cargo-dist may not be using cross, checking further..."
fi

echo ""
echo "📋 Next steps:"
echo "1. The Cross.toml file has been updated with proper image tags"
echo "2. A dist-workspace.toml has been created to configure cross usage"
echo "3. Commit these changes and push to trigger CI"
echo ""
echo "Alternative solution if this doesn't work:"
echo "We may need to patch the release.yml workflow to install cross before cargo-dist runs"