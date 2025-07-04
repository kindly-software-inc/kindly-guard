#!/bin/bash
# KindlyGuard Docker Multi-Registry Publish Script
# Publishes to both Docker Hub and GitHub Container Registry

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
DOCKER_HUB_USER="kindlysoftware"
DOCKER_HUB_REPO="kindlyguard"
GHCR_REPO="ghcr.io/kindlysoftware/kindlyguard"
PLATFORMS="linux/amd64,linux/arm64"

# Version handling
VERSION="${1:-latest}"
if [ "$VERSION" != "latest" ]; then
    VERSION="v${VERSION#v}" # Ensure 'v' prefix
fi

echo -e "${GREEN}🚀 KindlyGuard Docker Publisher${NC}"
echo -e "${YELLOW}Version: ${VERSION}${NC}"
echo ""

# Function to check if logged in to a registry
check_registry_auth() {
    local registry=$1
    local name=$2
    
    if [ "$registry" = "docker.io" ]; then
        if docker info | grep -q "Username: ${DOCKER_HUB_USER}"; then
            echo -e "${GREEN}✓ Already logged in to ${name}${NC}"
            return 0
        fi
    else
        # For ghcr.io, try a simple pull to test auth
        if docker pull "${registry}/kindlysoftware/test-auth:latest" &>/dev/null || [ $? -eq 1 ]; then
            echo -e "${GREEN}✓ Already logged in to ${name}${NC}"
            return 0
        fi
    fi
    
    return 1
}

# Docker Hub authentication
echo "Checking Docker Hub authentication..."
if ! check_registry_auth "docker.io" "Docker Hub"; then
    if [ -z "${DOCKER_TOKEN:-}" ]; then
        echo -e "${YELLOW}DOCKER_TOKEN not set. Attempting to use existing Docker login...${NC}"
        if ! docker login --username "${DOCKER_HUB_USER}" 2>/dev/null; then
            echo -e "${RED}✗ Failed to authenticate with Docker Hub${NC}"
            echo "Please set DOCKER_TOKEN environment variable or run: docker login"
            exit 1
        fi
    else
        echo "Logging in to Docker Hub..."
        echo "${DOCKER_TOKEN}" | docker login --username "${DOCKER_HUB_USER}" --password-stdin
    fi
fi

# GitHub Container Registry authentication
echo ""
echo "Checking GitHub Container Registry authentication..."
if ! check_registry_auth "ghcr.io" "GitHub Container Registry"; then
    if [ -z "${GITHUB_TOKEN:-}" ]; then
        echo -e "${YELLOW}⚠️  GITHUB_TOKEN not set. Skipping ghcr.io publish.${NC}"
        SKIP_GHCR=true
    else
        echo "Logging in to GitHub Container Registry..."
        echo "${GITHUB_TOKEN}" | docker login ghcr.io --username "${GITHUB_USER:-kindlysoftware}" --password-stdin
    fi
fi

# Ensure we're in the right directory
cd "$(dirname "$0")"

# Build multi-platform images
echo ""
echo -e "${YELLOW}Building multi-platform images...${NC}"
echo "Platforms: ${PLATFORMS}"

# Create builder if it doesn't exist
if ! docker buildx ls | grep -q "kindlyguard-builder"; then
    echo "Creating multi-platform builder..."
    docker buildx create --name kindlyguard-builder --use
    docker buildx inspect --bootstrap
else
    docker buildx use kindlyguard-builder
fi

# Build and push to Docker Hub
echo ""
echo -e "${YELLOW}Building and pushing to Docker Hub...${NC}"

DOCKER_HUB_TAGS="-t ${DOCKER_HUB_USER}/${DOCKER_HUB_REPO}:${VERSION}"
if [ "$VERSION" != "latest" ]; then
    DOCKER_HUB_TAGS="${DOCKER_HUB_TAGS} -t ${DOCKER_HUB_USER}/${DOCKER_HUB_REPO}:latest"
fi

docker buildx build \
    --platform "${PLATFORMS}" \
    ${DOCKER_HUB_TAGS} \
    --push \
    .

echo -e "${GREEN}✓ Successfully pushed to Docker Hub${NC}"

# Build and push to GitHub Container Registry
if [ "${SKIP_GHCR:-false}" != "true" ]; then
    echo ""
    echo -e "${YELLOW}Building and pushing to GitHub Container Registry...${NC}"
    
    GHCR_TAGS="-t ${GHCR_REPO}:${VERSION}"
    if [ "$VERSION" != "latest" ]; then
        GHCR_TAGS="${GHCR_TAGS} -t ${GHCR_REPO}:latest"
    fi
    
    docker buildx build \
        --platform "${PLATFORMS}" \
        ${GHCR_TAGS} \
        --push \
        .
    
    echo -e "${GREEN}✓ Successfully pushed to ghcr.io${NC}"
fi

# Clean up builder (optional)
# docker buildx rm kindlyguard-builder

echo ""
echo -e "${GREEN}🎉 Publishing complete!${NC}"
echo ""
echo "Docker Hub:"
echo "  docker pull ${DOCKER_HUB_USER}/${DOCKER_HUB_REPO}:${VERSION}"
if [ "${SKIP_GHCR:-false}" != "true" ]; then
    echo ""
    echo "GitHub Container Registry:"
    echo "  docker pull ${GHCR_REPO}:${VERSION}"
fi

# Update Docker Hub README if it exists
if [ -f "DOCKER_HUB_README.md" ] && [ -n "${DOCKER_TOKEN:-}" ]; then
    echo ""
    echo -e "${YELLOW}Updating Docker Hub README...${NC}"
    
    # Docker Hub API endpoint
    DOCKERHUB_API="https://hub.docker.com/v2"
    
    # Get JWT token
    JWT_TOKEN=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"${DOCKER_HUB_USER}\", \"password\": \"${DOCKER_TOKEN}\"}" \
        "${DOCKERHUB_API}/users/login/" | jq -r .token)
    
    if [ -n "$JWT_TOKEN" ] && [ "$JWT_TOKEN" != "null" ]; then
        # Update README
        README_CONTENT=$(cat DOCKER_HUB_README.md)
        
        curl -s -X PATCH \
            -H "Authorization: JWT ${JWT_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "{\"full_description\": $(echo "$README_CONTENT" | jq -Rs .)}" \
            "${DOCKERHUB_API}/repositories/${DOCKER_HUB_USER}/${DOCKER_HUB_REPO}/" > /dev/null
        
        echo -e "${GREEN}✓ Docker Hub README updated${NC}"
    else
        echo -e "${YELLOW}⚠️  Could not update Docker Hub README (authentication failed)${NC}"
    fi
fi

echo ""
echo "Next steps:"
echo "1. Test the published image: docker run --rm ${DOCKER_HUB_USER}/${DOCKER_HUB_REPO}:${VERSION} --version"
echo "2. Update any documentation with the new version"
echo "3. Create a GitHub release if this is a new version"