#!/bin/bash
# Build script for multi-platform Docker images of KindlyGuard

set -e

# Default values
VERSION="${VERSION:-0.9.2}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
REGISTRY="${REGISTRY:-kindlysoftware/kindlyguard}"
DOCKERFILE="${DOCKERFILE:-Dockerfile.multiplatform}"
PUSH="${PUSH:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building KindlyGuard multi-platform Docker image...${NC}"
echo "Version: $VERSION"
echo "Platforms: $PLATFORMS"
echo "Registry: $REGISTRY"
echo "Dockerfile: $DOCKERFILE"
echo "Push to registry: $PUSH"

# Check if Docker buildx is available
if ! docker buildx version > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker buildx is not available${NC}"
    exit 1
fi

# Ensure builder exists
BUILDER_NAME="kindlyguard-builder"
if ! docker buildx ls | grep -q "$BUILDER_NAME"; then
    echo -e "${YELLOW}Creating buildx builder instance...${NC}"
    docker buildx create --name "$BUILDER_NAME" --driver docker-container --use
else
    echo -e "${YELLOW}Using existing buildx builder: $BUILDER_NAME${NC}"
    docker buildx use "$BUILDER_NAME"
fi

# Inspect builder
docker buildx inspect --bootstrap

# Build arguments
BUILD_ARGS=(
    "--platform" "$PLATFORMS"
    "-t" "${REGISTRY}:${VERSION}"
    "-t" "${REGISTRY}:latest"
    "-f" "$DOCKERFILE"
    "--progress=plain"
)

# Add build arguments
BUILD_ARGS+=(
    "--build-arg" "VERSION=$VERSION"
    "--build-arg" "BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    "--build-arg" "VCS_REF=$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
)

# Add push flag if requested
if [ "$PUSH" = "true" ]; then
    BUILD_ARGS+=("--push")
else
    echo -e "${YELLOW}Note: Build will remain in cache. Use PUSH=true to push to registry.${NC}"
fi

# Execute build
echo -e "${GREEN}Starting build...${NC}"
docker buildx build "${BUILD_ARGS[@]}" .

# Check build status
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build completed successfully!${NC}"
    
    if [ "$PUSH" = "true" ]; then
        echo -e "${GREEN}Images pushed to registry:${NC}"
        echo "  - ${REGISTRY}:${VERSION}"
        echo "  - ${REGISTRY}:latest"
    else
        echo -e "${YELLOW}To push the images, run:${NC}"
        echo "  PUSH=true $0"
    fi
else
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

# Show cache usage
echo -e "\n${YELLOW}Builder cache usage:${NC}"
docker buildx du --filter 'since=1h'