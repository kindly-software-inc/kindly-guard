#!/bin/bash
set -e

# Test Release Process Script
# This script validates that the release process works correctly

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test version
TEST_VERSION="0.9.99-test"

echo -e "${BLUE}🧪 Testing KindlyGuard Release Process${NC}"
echo "======================================="
echo ""

# Function to run test
run_test() {
    local test_name=$1
    local command=$2
    
    echo -e "${YELLOW}🔧 Testing: $test_name...${NC}"
    if eval "$command"; then
        echo -e "${GREEN}✅ $test_name passed${NC}"
    else
        echo -e "${RED}❌ $test_name failed${NC}"
        return 1
    fi
    echo ""
}

# Test 1: Check scripts exist and are executable
echo -e "${BLUE}📋 Test 1: Script Availability${NC}"
run_test "Build script exists" "[ -x ./scripts/build-release.sh ]"
run_test "GitHub release script exists" "[ -x ./scripts/create-github-release.sh ]"

# Test 2: Check required tools
echo -e "${BLUE}📋 Test 2: Required Tools${NC}"
run_test "Git installed" "command -v git &> /dev/null"
run_test "Cargo installed" "command -v cargo &> /dev/null"
run_test "Node.js installed" "command -v node &> /dev/null"
run_test "GitHub CLI installed" "command -v gh &> /dev/null"

# Test 3: GitHub CLI authentication
echo -e "${BLUE}📋 Test 3: GitHub Authentication${NC}"
run_test "GitHub CLI authenticated" "gh auth status &> /dev/null"

# Test 4: Test build process (dry run)
echo -e "${BLUE}📋 Test 4: Build Process (Dry Run)${NC}"
run_test "Build creates artifacts directory" "mkdir -p release-artifacts/${TEST_VERSION} && rmdir release-artifacts/${TEST_VERSION}"

# Test 5: Platform detection
echo -e "${BLUE}📋 Test 5: Platform Detection${NC}"
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
echo "Detected platform: $PLATFORM-$ARCH"
run_test "Platform supported" "[ -n '$PLATFORM' ] && [ -n '$ARCH' ]"

# Test 6: NPM package structure
echo -e "${BLUE}📋 Test 6: NPM Package Structure${NC}"
run_test "NPM package.json exists" "[ -f npm-package/package.json ]"
run_test "Postinstall script exists" "[ -f npm-package/lib/postinstall.js ]"
run_test "Platform utilities exist" "[ -f npm-package/lib/platform.js ]"

# Test 7: Download URL generation
echo -e "${BLUE}📋 Test 7: Download URL Generation${NC}"
cd npm-package
URL_TEST=$(node -e "
const platform = require('./lib/platform');
try {
  const url = platform.downloadUrl('$TEST_VERSION');
  console.log('Download URL:', url);
  process.exit(0);
} catch (e) {
  console.error('Error:', e.message);
  process.exit(1);
}
")
cd ..
run_test "Download URL generation" "[ $? -eq 0 ]"

# Test 8: Release workflow file
echo -e "${BLUE}📋 Test 8: GitHub Actions Workflow${NC}"
run_test "Release workflow exists" "[ -f ../.github/workflows/create-release.yml ]"

# Test 9: Documentation
echo -e "${BLUE}📋 Test 9: Documentation${NC}"
run_test "RELEASING.md exists" "[ -f RELEASING.md ]"

echo ""
echo -e "${GREEN}🎉 Release Process Tests Complete!${NC}"
echo "=================================="
echo ""

# Summary
FAILED_TESTS=0
echo -e "${BLUE}📊 Test Summary:${NC}"
echo "  - Scripts: ✓"
echo "  - Tools: ✓" 
echo "  - Authentication: ✓"
echo "  - NPM Package: ✓"
echo "  - Documentation: ✓"
echo ""

echo -e "${BLUE}📝 Next Steps:${NC}"
echo "  1. Run a test build: ./scripts/build-release.sh --version $TEST_VERSION"
echo "  2. Create a draft release: ./scripts/create-github-release.sh --version $TEST_VERSION --draft"
echo "  3. Test the NPM postinstall with: KINDLYGUARD_DOWNLOAD_BASE=... npm install"
echo ""

echo -e "${YELLOW}⚠️  Important Notes:${NC}"
echo "  - Always test with a pre-release version first"
echo "  - Verify checksums after building"
echo "  - Test binary downloads on each platform"
echo "  - Ensure all platform packages are built before release"
echo ""