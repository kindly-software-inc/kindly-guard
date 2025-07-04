#!/bin/bash
# Quick test script to verify Docker build works before publishing

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}Testing KindlyGuard Docker build...${NC}"

# Test local build
echo -e "\n${YELLOW}1. Testing local platform build...${NC}"
docker build -t kindlyguard:test-local .

# Test running the image
echo -e "\n${YELLOW}2. Testing container execution...${NC}"
docker run --rm kindlyguard:test-local --version

# Test help command
echo -e "\n${YELLOW}3. Testing help output...${NC}"
docker run --rm kindlyguard:test-local --help

# Test with a simple scan (create test file)
echo -e "\n${YELLOW}4. Testing scan functionality...${NC}"
echo '{"test": "Hello\u202eWorld"}' > /tmp/test-unicode.json
docker run --rm -v /tmp:/data kindlyguard:test-local scan /data/test-unicode.json || true
rm -f /tmp/test-unicode.json

# Check image size
echo -e "\n${YELLOW}5. Checking image size...${NC}"
docker images kindlyguard:test-local --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

# Clean up
echo -e "\n${YELLOW}6. Cleaning up test image...${NC}"
docker rmi kindlyguard:test-local

echo -e "\n${GREEN}✓ Docker build test completed successfully!${NC}"
echo -e "\nYou can now run ${YELLOW}./docker-publish.sh${NC} to publish to Docker Hub."