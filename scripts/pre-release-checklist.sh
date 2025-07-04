#!/bin/bash
# Pre-release checklist script to ensure everything is ready for a new release

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 KindlyGuard Pre-Release Checklist${NC}"
echo "======================================="

ERRORS=0

# Function to check a condition
check() {
    local description=$1
    local command=$2
    
    echo -n "⏳ Checking: $description... "
    
    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS${NC}"
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        ((ERRORS++))
        return 1
    fi
}

# 1. Check version synchronization
echo -e "\n${YELLOW}📋 Version Checks${NC}"
check "Version synchronization" "./scripts/sync-versions.sh"

# 2. Build checks
echo -e "\n${YELLOW}📋 Build Checks${NC}"
check "Cargo build (debug)" "cargo build --all"
check "Cargo build (release)" "cargo build --release --all"

# 3. Test checks
echo -e "\n${YELLOW}📋 Test Suite${NC}"
check "Cargo tests" "cargo test --all"
check "Cargo clippy" "cargo clippy -- -D warnings"
check "Cargo fmt" "cargo fmt --all -- --check"

# 4. Security checks
echo -e "\n${YELLOW}📋 Security Checks${NC}"
if command -v cargo-audit &> /dev/null; then
    check "Cargo audit" "cargo audit"
else
    echo -e "${YELLOW}⚠️  cargo-audit not installed, skipping security audit${NC}"
fi

# 5. Documentation checks
echo -e "\n${YELLOW}📋 Documentation Checks${NC}"
check "Cargo doc" "cargo doc --no-deps --all"

# 6. Git status check
echo -e "\n${YELLOW}📋 Git Repository${NC}"
check "Working directory clean" "test -z \"\$(git status --porcelain)\""

# Get current version
CURRENT_VERSION=$(grep -E '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')

# Summary
echo -e "\n${BLUE}📊 Summary${NC}"
echo "===================="
echo -e "Current version: ${YELLOW}$CURRENT_VERSION${NC}"
echo -e "Total checks failed: ${ERRORS}"

if [ $ERRORS -eq 0 ]; then
    echo -e "\n${GREEN}✅ All checks passed! Ready for release.${NC}"
    echo -e "\nNext steps:"
    echo "1. Update version in Cargo.toml if needed"
    echo "2. Run: ./scripts/sync-versions.sh --sync"
    echo "3. Commit all changes"
    echo "4. Create and push tag: git tag -a v${CURRENT_VERSION} -m \"Release v${CURRENT_VERSION}\""
    echo "5. Push tag: git push origin v${CURRENT_VERSION}"
else
    echo -e "\n${RED}❌ Some checks failed. Please fix the issues before releasing.${NC}"
    exit 1
fi