#!/bin/bash
set -e

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

echo "🐳 Publishing kindly-guard to Docker Hub"
echo "========================================"

# Check if credentials are available
if [ -z "$DOCKER_USERNAME" ] || [ -z "$DOCKER_TOKEN" ]; then
    echo "❌ Error: DOCKER_USERNAME or DOCKER_TOKEN not found in .env"
    exit 1
fi

# Login to Docker Hub
echo "📝 Logging in to Docker Hub..."
echo "$DOCKER_TOKEN" | docker login -u "$DOCKER_USERNAME" --password-stdin

# Get version from Cargo.toml
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
echo "📦 Version: $VERSION"

# Image name
IMAGE_NAME="kindlysoftware/kindly-guard"

# Build multi-platform image
echo "🔨 Building multi-platform Docker image..."
docker buildx create --use --name kindly-guard-builder || true
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --tag "$IMAGE_NAME:$VERSION" \
    --tag "$IMAGE_NAME:latest" \
    --build-arg VERSION="$VERSION" \
    --push \
    .

echo "✅ Successfully pushed $IMAGE_NAME:$VERSION"
echo "✅ Successfully pushed $IMAGE_NAME:latest"

# Clean up builder
docker buildx rm kindly-guard-builder

echo ""
echo "🎉 Docker image published successfully!"
echo ""
echo "🐳 Pull the image with:"
echo "   docker pull $IMAGE_NAME:latest"
echo "   docker pull $IMAGE_NAME:$VERSION"
echo ""
echo "🚀 Run with:"
echo "   docker run --rm -it $IMAGE_NAME:latest --help"