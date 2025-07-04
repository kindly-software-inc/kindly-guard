#!/bin/bash
set -e

# Script to test multi-platform builds locally
# This helps verify that the build works across different architectures

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🧪 Testing Multi-Platform Docker Builds${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""

# Configuration
BUILDER_NAME="kindly-guard-test-builder"
IMAGE_NAME="kindly-guard-test"
DOCKERFILE="${DOCKERFILE:-Dockerfile.multiplatform}"

# Platforms to test
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "linux/arm/v7"
    "linux/386"
)

# Optional platforms (might not be available on all systems)
OPTIONAL_PLATFORMS=(
    "linux/ppc64le"
    "linux/s390x"
)

# Function to check if buildx is available
check_buildx() {
    if ! docker buildx version &> /dev/null; then
        echo -e "${RED}❌ Docker buildx is not available${NC}"
        exit 1
    fi
}

# Function to setup test builder
setup_test_builder() {
    echo -e "${YELLOW}🔧 Setting up test builder...${NC}"
    
    # Remove existing test builder if exists
    docker buildx rm $BUILDER_NAME 2>/dev/null || true
    
    # Create new builder
    docker buildx create \
        --name $BUILDER_NAME \
        --driver docker-container \
        --use
    
    # Bootstrap builder
    docker buildx inspect --bootstrap $BUILDER_NAME
    
    echo -e "${GREEN}✓ Test builder ready${NC}"
}

# Function to test build for a platform
test_platform_build() {
    local platform=$1
    local is_optional=$2
    
    echo -e "${YELLOW}🔨 Testing build for $platform...${NC}"
    
    # Build with a unique tag for this platform
    local platform_tag="${IMAGE_NAME}:${platform//\//-}"
    
    if docker buildx build \
        --platform "$platform" \
        --tag "$platform_tag" \
        --file "$DOCKERFILE" \
        --progress=plain \
        --no-cache \
        . 2>&1 | tee "/tmp/build-${platform//\//-}.log"; then
        
        echo -e "${GREEN}✅ $platform: BUILD SUCCESSFUL${NC}"
        return 0
    else
        if [ "$is_optional" = "true" ]; then
            echo -e "${YELLOW}⚠️  $platform: BUILD FAILED (optional platform)${NC}"
        else
            echo -e "${RED}❌ $platform: BUILD FAILED${NC}"
            echo -e "${RED}   Check /tmp/build-${platform//\//-}.log for details${NC}"
        fi
        return 1
    fi
}

# Function to test all platforms
test_all_platforms() {
    local total=0
    local passed=0
    local failed=0
    local skipped=0
    
    echo ""
    echo -e "${BLUE}📋 Testing required platforms:${NC}"
    echo ""
    
    # Test required platforms
    for platform in "${PLATFORMS[@]}"; do
        ((total++))
        if test_platform_build "$platform" "false"; then
            ((passed++))
        else
            ((failed++))
        fi
        echo ""
    done
    
    # Test optional platforms
    if [ "${TEST_OPTIONAL:-false}" = "true" ]; then
        echo -e "${BLUE}📋 Testing optional platforms:${NC}"
        echo ""
        
        for platform in "${OPTIONAL_PLATFORMS[@]}"; do
            ((total++))
            if test_platform_build "$platform" "true"; then
                ((passed++))
            else
                ((skipped++))
            fi
            echo ""
        done
    fi
    
    # Summary
    echo -e "${BLUE}📊 Test Summary:${NC}"
    echo -e "   Total platforms: $total"
    echo -e "   ${GREEN}Passed: $passed${NC}"
    echo -e "   ${RED}Failed: $failed${NC}"
    if [ $skipped -gt 0 ]; then
        echo -e "   ${YELLOW}Skipped (optional): $skipped${NC}"
    fi
    
    if [ $failed -gt 0 ]; then
        echo ""
        echo -e "${RED}❌ Some required platform builds failed!${NC}"
        return 1
    else
        echo ""
        echo -e "${GREEN}✅ All required platform builds passed!${NC}"
        return 0
    fi
}

# Function to test manifest creation
test_manifest() {
    echo -e "${YELLOW}🔧 Testing manifest creation...${NC}"
    
    local manifest_name="${IMAGE_NAME}:manifest-test"
    local platform_images=""
    
    # Build images for manifest
    for platform in "${PLATFORMS[@]:0:2}"; do
        local platform_tag="${IMAGE_NAME}:${platform//\//-}"
        platform_images="$platform_images $platform_tag"
    done
    
    # Create manifest
    if docker buildx imagetools create \
        -t "$manifest_name" \
        $platform_images 2>&1; then
        echo -e "${GREEN}✅ Manifest creation successful${NC}"
        
        # Inspect manifest
        echo -e "${BLUE}📝 Manifest details:${NC}"
        docker buildx imagetools inspect "$manifest_name"
    else
        echo -e "${RED}❌ Manifest creation failed${NC}"
    fi
}

# Function to cleanup
cleanup() {
    echo ""
    echo -e "${YELLOW}🧹 Cleaning up...${NC}"
    docker buildx rm $BUILDER_NAME 2>/dev/null || true
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --optional)
            TEST_OPTIONAL="true"
            shift
            ;;
        --dockerfile)
            DOCKERFILE="$2"
            shift 2
            ;;
        --quick)
            # Only test amd64 and arm64
            PLATFORMS=("linux/amd64" "linux/arm64")
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --optional       Also test optional platforms (ppc64le, s390x)"
            echo "  --dockerfile FILE Use specific Dockerfile (default: Dockerfile.multiplatform)"
            echo "  --quick          Only test amd64 and arm64 platforms"
            echo "  --help           Show this help message"
            echo ""
            echo "This script tests building Docker images for multiple platforms"
            echo "to ensure cross-platform compatibility."
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
setup_test_builder

echo -e "${BLUE}📁 Using Dockerfile: $DOCKERFILE${NC}"
if [ ! -f "$DOCKERFILE" ]; then
    echo -e "${RED}❌ Dockerfile not found: $DOCKERFILE${NC}"
    exit 1
fi

test_all_platforms
test_manifest