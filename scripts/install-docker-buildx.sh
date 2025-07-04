#!/bin/bash
# Install Docker buildx plugin for multi-platform builds

set -e

echo "🔧 Installing Docker buildx plugin..."

# Create docker cli-plugins directory if it doesn't exist
DOCKER_CONFIG=${DOCKER_CONFIG:-$HOME/.docker}
mkdir -p $DOCKER_CONFIG/cli-plugins

# Download buildx binary
BUILDX_VERSION="v0.12.1"
ARCH=$(uname -m)
case $ARCH in
    x86_64) ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
esac

echo "📥 Downloading buildx for $ARCH..."
wget -O $DOCKER_CONFIG/cli-plugins/docker-buildx \
    https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}/buildx-${BUILDX_VERSION}.linux-${ARCH}

# Make it executable
chmod +x $DOCKER_CONFIG/cli-plugins/docker-buildx

# Verify installation
echo "✅ Verifying installation..."
docker buildx version

# Create and use a new builder instance
echo "🏗️ Creating multi-platform builder..."
docker buildx create --name kindlyguard-builder --use --platform=linux/amd64,linux/arm64,linux/arm/v7
docker buildx inspect --bootstrap

echo "✅ Docker buildx is ready for multi-platform builds!"
echo ""
echo "You can now use the build scripts:"
echo "  ./scripts/build-docker-multiplatform.sh"
echo "  ./scripts/test-multiplatform-build.sh"