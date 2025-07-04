#!/bin/bash
set -e

# Script for building multi-platform Docker images using buildx
# Supports: linux/amd64, linux/arm64, linux/arm/v7, linux/386, linux/ppc64le, linux/s390x

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Configuration
BUILDER_NAME="${BUILDER_NAME:-kindly-guard-builder}"
IMAGE_NAME="${IMAGE_NAME:-kindlysoftware/kindly-guard}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64,linux/arm/v7}"
BUILD_TYPE="${BUILD_TYPE:-build}" # Options: build, push, load
CACHE_FROM=""
CACHE_TO=""

# Get version from Cargo.toml
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)

echo -e "${BLUE}🐳 Building Multi-Platform Docker Image for KindlyGuard${NC}"
echo -e "${BLUE}=================================================${NC}"
echo -e "${GREEN}📦 Version: $VERSION${NC}"
echo -e "${GREEN}🏗️  Platforms: $PLATFORMS${NC}"
echo ""

# Function to check if buildx is available
check_buildx() {
    if ! docker buildx version &> /dev/null; then
        echo -e "${RED}❌ Docker buildx is not available. Please install Docker Desktop or enable experimental features.${NC}"
        exit 1
    fi
}

# Function to setup buildx builder
setup_builder() {
    echo -e "${YELLOW}🔧 Setting up buildx builder...${NC}"
    
    # Check if builder already exists
    if docker buildx inspect $BUILDER_NAME &> /dev/null; then
        echo -e "${GREEN}✓ Builder '$BUILDER_NAME' already exists${NC}"
    else
        echo -e "${YELLOW}📝 Creating new builder '$BUILDER_NAME'...${NC}"
        docker buildx create \
            --name $BUILDER_NAME \
            --driver docker-container \
            --driver-opt network=host \
            --buildkitd-flags '--allow-insecure-entitlement network.host' \
            --use
    fi
    
    # Bootstrap builder
    docker buildx inspect --bootstrap $BUILDER_NAME
    
    # Set as current builder
    docker buildx use $BUILDER_NAME
    
    echo -e "${GREEN}✓ Builder is ready${NC}"
}

# Function to show builder info
show_builder_info() {
    echo -e "${BLUE}📊 Builder Information:${NC}"
    docker buildx inspect $BUILDER_NAME
    echo ""
}

# Function to setup cache options
setup_cache() {
    if [ -n "$REGISTRY_CACHE" ]; then
        CACHE_FROM="--cache-from type=registry,ref=$IMAGE_NAME:buildcache"
        CACHE_TO="--cache-to type=registry,ref=$IMAGE_NAME:buildcache,mode=max"
        echo -e "${GREEN}✓ Registry cache enabled${NC}"
    elif [ -n "$LOCAL_CACHE" ]; then
        CACHE_FROM="--cache-from type=local,src=/tmp/.buildx-cache"
        CACHE_TO="--cache-to type=local,dest=/tmp/.buildx-cache-new,mode=max"
        echo -e "${GREEN}✓ Local cache enabled${NC}"
        mkdir -p /tmp/.buildx-cache
    fi
}

# Function to build the image
build_image() {
    local action=""
    
    case "$BUILD_TYPE" in
        "push")
            action="--push"
            echo -e "${YELLOW}🚀 Building and pushing to registry...${NC}"
            ;;
        "load")
            # Load only works with single platform
            if [[ "$PLATFORMS" == *","* ]]; then
                echo -e "${RED}❌ Error: --load requires exactly one platform. Use --push for multi-platform.${NC}"
                exit 1
            fi
            action="--load"
            echo -e "${YELLOW}📥 Building and loading locally...${NC}"
            ;;
        *)
            echo -e "${YELLOW}🔨 Building without push...${NC}"
            ;;
    esac
    
    # Build arguments
    BUILD_ARGS=""
    BUILD_ARGS="$BUILD_ARGS --build-arg VERSION=$VERSION"
    BUILD_ARGS="$BUILD_ARGS --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    BUILD_ARGS="$BUILD_ARGS --build-arg VCS_REF=$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    
    # Labels
    LABELS=""
    LABELS="$LABELS --label org.opencontainers.image.version=$VERSION"
    LABELS="$LABELS --label org.opencontainers.image.created=$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    LABELS="$LABELS --label org.opencontainers.image.source=https://github.com/kindlysoftware/kindly-guard"
    LABELS="$LABELS --label org.opencontainers.image.vendor=KindlySoftware"
    LABELS="$LABELS --label org.opencontainers.image.title=KindlyGuard"
    LABELS="$LABELS --label org.opencontainers.image.description='Security-focused MCP server for managing sensitive operations'"
    
    # Build command
    docker buildx build \
        --platform "$PLATFORMS" \
        --tag "$IMAGE_NAME:$VERSION" \
        --tag "$IMAGE_NAME:latest" \
        $BUILD_ARGS \
        $LABELS \
        $CACHE_FROM \
        $CACHE_TO \
        $action \
        --progress=plain \
        .
    
    # Move cache if using local cache
    if [ -n "$LOCAL_CACHE" ] && [ -d "/tmp/.buildx-cache-new" ]; then
        rm -rf /tmp/.buildx-cache
        mv /tmp/.buildx-cache-new /tmp/.buildx-cache
    fi
    
    echo -e "${GREEN}✅ Build completed successfully${NC}"
}

# Function to inspect the built image
inspect_image() {
    echo -e "${BLUE}🔍 Inspecting built image...${NC}"
    docker buildx imagetools inspect "$IMAGE_NAME:$VERSION" || true
}

# Function to cleanup
cleanup() {
    if [ "$CLEANUP_BUILDER" = "true" ]; then
        echo -e "${YELLOW}🧹 Cleaning up builder...${NC}"
        docker buildx rm $BUILDER_NAME || true
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --push)
            BUILD_TYPE="push"
            shift
            ;;
        --load)
            BUILD_TYPE="load"
            shift
            ;;
        --platforms)
            PLATFORMS="$2"
            shift 2
            ;;
        --image-name)
            IMAGE_NAME="$2"
            shift 2
            ;;
        --builder-name)
            BUILDER_NAME="$2"
            shift 2
            ;;
        --registry-cache)
            REGISTRY_CACHE="true"
            shift
            ;;
        --local-cache)
            LOCAL_CACHE="true"
            shift
            ;;
        --cleanup)
            CLEANUP_BUILDER="true"
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --push              Build and push to registry"
            echo "  --load              Build and load locally (single platform only)"
            echo "  --platforms PLATFORMS  Comma-separated list of target platforms"
            echo "                      Default: linux/amd64,linux/arm64,linux/arm/v7"
            echo "  --image-name NAME   Docker image name (default: kindlysoftware/kindly-guard)"
            echo "  --builder-name NAME Builder instance name (default: kindly-guard-builder)"
            echo "  --registry-cache    Use registry for build cache"
            echo "  --local-cache       Use local directory for build cache"
            echo "  --cleanup           Remove builder after build"
            echo "  --help              Show this help message"
            echo ""
            echo "Examples:"
            echo "  # Build for multiple platforms without pushing"
            echo "  $0"
            echo ""
            echo "  # Build and push to registry"
            echo "  $0 --push"
            echo ""
            echo "  # Build for specific platforms"
            echo "  $0 --platforms linux/amd64,linux/arm64 --push"
            echo ""
            echo "  # Build and load locally (single platform)"
            echo "  $0 --platforms linux/amd64 --load"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Main execution
trap cleanup EXIT

check_buildx
setup_builder
show_builder_info
setup_cache
build_image
inspect_image

echo ""
echo -e "${GREEN}🎉 Multi-platform build completed!${NC}"
echo ""
echo -e "${BLUE}📝 Summary:${NC}"
echo -e "   Image: $IMAGE_NAME:$VERSION"
echo -e "   Platforms: $PLATFORMS"
echo -e "   Builder: $BUILDER_NAME"

if [ "$BUILD_TYPE" = "push" ]; then
    echo ""
    echo -e "${BLUE}🐳 Pull the image with:${NC}"
    echo -e "   docker pull $IMAGE_NAME:latest"
    echo -e "   docker pull $IMAGE_NAME:$VERSION"
elif [ "$BUILD_TYPE" = "load" ]; then
    echo ""
    echo -e "${BLUE}🐳 Run the image with:${NC}"
    echo -e "   docker run --rm -it $IMAGE_NAME:latest --help"
fi