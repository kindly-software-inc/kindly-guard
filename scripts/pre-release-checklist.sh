#!/bin/bash
# Pre-release checklist script to ensure everything is ready for a new release

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 KindlyGuard Pre-Release Checklist${NC}"
echo "======================================="

ERRORS=0
WARNINGS=0

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

# Function to check with warnings
check_warn() {
    local description=$1
    local command=$2
    
    echo -n "⏳ Checking: $description... "
    
    if eval "$command" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PASS${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠️  WARNING${NC}"
        ((WARNINGS++))
        return 1
    fi
}

# Get current version
CURRENT_VERSION=$(grep -E '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')

# 1. Version validation checks
echo -e "\n${YELLOW}📋 Version Validation${NC}"
echo -e "Current version: ${MAGENTA}$CURRENT_VERSION${NC}"

# Check if validate-versions.sh exists
if [ -f "./scripts/validate-versions.sh" ]; then
    echo -n "⏳ Validating version consistency... "
    if ./scripts/validate-versions.sh > /tmp/version-check.log 2>&1; then
        echo -e "${GREEN}✅ All versions are synchronized${NC}"
    else
        echo -e "${RED}❌ Version mismatch detected${NC}"
        cat /tmp/version-check.log
        ((ERRORS++))
        
        # Offer to fix version mismatches
        echo -e "\n${YELLOW}Would you like to synchronize all versions to $CURRENT_VERSION? (y/n)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            if [ -f "./scripts/update-version.sh" ]; then
                echo "Running version update..."
                if ./scripts/update-version.sh "$CURRENT_VERSION"; then
                    echo -e "${GREEN}✅ Versions synchronized successfully${NC}"
                    ((ERRORS--))  # Remove the error since we fixed it
                else
                    echo -e "${RED}❌ Failed to synchronize versions${NC}"
                fi
            else
                echo -e "${RED}❌ update-version.sh not found${NC}"
            fi
        fi
    fi
else
    echo -e "${YELLOW}⚠️  validate-versions.sh not found, using legacy sync check${NC}"
    check "Version synchronization" "./scripts/sync-versions.sh"
fi

# Validate version format
echo -n "⏳ Checking version format... "
if [[ "$CURRENT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$ ]]; then
    echo -e "${GREEN}✅ Valid semantic version${NC}"
else
    echo -e "${RED}❌ Invalid version format${NC}"
    echo "    Version must follow semantic versioning: X.Y.Z or X.Y.Z-prerelease"
    ((ERRORS++))
fi

# 2. Check for new version
echo -e "\n${YELLOW}📋 Release Version Check${NC}"
if [ -n "$1" ]; then
    NEW_VERSION="$1"
    echo -e "Target release version: ${MAGENTA}$NEW_VERSION${NC}"
    
    # Compare versions (simple string comparison for now)
    if [[ "$NEW_VERSION" > "$CURRENT_VERSION" ]]; then
        echo -e "${GREEN}✅ New version is greater than current${NC}"
        
        echo -e "\n${YELLOW}Would you like to update all files to version $NEW_VERSION? (y/n)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            if [ -f "./scripts/update-version.sh" ]; then
                echo "Updating version to $NEW_VERSION..."
                if ./scripts/update-version.sh "$NEW_VERSION"; then
                    echo -e "${GREEN}✅ Version updated successfully${NC}"
                    CURRENT_VERSION="$NEW_VERSION"
                else
                    echo -e "${RED}❌ Failed to update version${NC}"
                    ((ERRORS++))
                fi
            fi
        fi
    elif [[ "$NEW_VERSION" == "$CURRENT_VERSION" ]]; then
        echo -e "${YELLOW}⚠️  Target version same as current version${NC}"
        ((WARNINGS++))
    else
        echo -e "${RED}❌ New version ($NEW_VERSION) must be greater than current ($CURRENT_VERSION)${NC}"
        ((ERRORS++))
    fi
fi

# 3. Build checks
echo -e "\n${YELLOW}📋 Build Checks${NC}"
check "Cargo build (debug)" "cargo build --all"
check "Cargo build (release)" "cargo build --release --all"

# 4. Test checks
echo -e "\n${YELLOW}📋 Test Suite${NC}"
# Check if nextest is installed
if command -v cargo-nextest &> /dev/null || cargo nextest --version &> /dev/null 2>&1; then
    check "Cargo tests (nextest)" "cargo nextest run --all"
else
    echo -e "${YELLOW}⚠️  cargo-nextest not installed, falling back to standard tests${NC}"
    check "Cargo tests" "cargo test --all"
fi
# Doc tests still need standard cargo test
check "Cargo doc tests" "cargo test --all --doc"
check "Cargo clippy" "cargo clippy -- -D warnings"
check "Cargo fmt" "cargo fmt --all -- --check"

# MSRV (Minimum Supported Rust Version) check
echo -e "\n${YELLOW}📋 MSRV Compatibility Check${NC}"
MSRV="1.80"
echo -e "Testing against MSRV: ${MAGENTA}$MSRV${NC}"
if rustup toolchain list | grep -q "$MSRV"; then
    check "MSRV build" "cargo +$MSRV build --all-features"
    check "MSRV tests" "cargo +$MSRV test --all-features"
else
    echo -e "${YELLOW}⚠️  MSRV toolchain $MSRV not installed${NC}"
    echo "  Install with: rustup toolchain install $MSRV"
    ((WARNINGS++))
fi

# 5. Security checks
echo -e "\n${YELLOW}📋 Security Checks${NC}"
if command -v cargo-audit &> /dev/null; then
    check "Cargo audit" "cargo audit"
else
    echo -e "${YELLOW}⚠️  cargo-audit not installed, skipping security audit${NC}"
    ((WARNINGS++))
fi

# Cargo deny supply chain security checks
if command -v cargo-deny &> /dev/null; then
    check "Cargo deny - advisories" "cargo deny check advisories"
    check "Cargo deny - licenses" "cargo deny check licenses"
    check "Cargo deny - bans" "cargo deny check bans"
    check "Cargo deny - sources" "cargo deny check sources"
else
    echo -e "${YELLOW}⚠️  cargo-deny not installed, skipping supply chain security checks${NC}"
    echo "  Install with: cargo install cargo-deny"
    ((WARNINGS++))
fi

# Check for unsafe code
if command -v cargo-geiger &> /dev/null; then
    check_warn "Unsafe code scan" "cargo geiger --all-features --all-targets 2>&1 | grep -q '0 unsafe'"
else
    echo -e "${YELLOW}⚠️  cargo-geiger not installed, skipping unsafe code check${NC}"
    ((WARNINGS++))
fi

# Check for unused dependencies
if command -v cargo-machete &> /dev/null; then
    echo -n "⏳ Checking for unused dependencies... "
    MACHETE_OUTPUT=$(cargo machete 2>&1)
    if echo "$MACHETE_OUTPUT" | grep -q "found the following"; then
        echo -e "${RED}❌ Unused dependencies found${NC}"
        echo "$MACHETE_OUTPUT" | grep -A 20 "found the following"
        echo -e "${YELLOW}  Each unused dependency increases attack surface${NC}"
        echo -e "${YELLOW}  Remove unused deps or add to 'ignored' in Cargo.toml${NC}"
        ((ERRORS++))
    else
        echo -e "${GREEN}✅ No unused dependencies${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  cargo-machete not installed, skipping dependency analysis${NC}"
    echo "  Install with: cargo install cargo-machete"
    ((WARNINGS++))
fi

# 6. Documentation checks
echo -e "\n${YELLOW}📋 Documentation Checks${NC}"
check "Cargo doc" "cargo doc --no-deps --all"
check_warn "README exists" "test -f README.md"
check_warn "CHANGELOG exists" "test -f CHANGELOG.md"
check_warn "LICENSE exists" "test -f LICENSE"

# 7. File accessibility checks
echo -e "\n${YELLOW}📋 Critical Files Check${NC}"
check "Cargo.toml accessible" "test -r Cargo.toml"
check "All Cargo.toml files readable" "find . -name Cargo.toml -type f -exec test -r {} +"

# 8. Git status check
echo -e "\n${YELLOW}📋 Git Repository${NC}"
check "Git repository exists" "git rev-parse --git-dir"
check_warn "Working directory clean" "test -z \"\$(git status --porcelain)\""

# Check if on main/master branch
CURRENT_BRANCH=$(git branch --show-current)
if [[ "$CURRENT_BRANCH" == "main" ]] || [[ "$CURRENT_BRANCH" == "master" ]]; then
    echo -e "${GREEN}✅ On main branch ($CURRENT_BRANCH)${NC}"
else
    echo -e "${YELLOW}⚠️  Not on main branch (current: $CURRENT_BRANCH)${NC}"
    ((WARNINGS++))
fi

# Summary
echo -e "\n${BLUE}📊 Summary${NC}"
echo "===================="
echo -e "Current version: ${MAGENTA}$CURRENT_VERSION${NC}"
echo -e "Errors: ${ERRORS}"
echo -e "Warnings: ${WARNINGS}"

if [ $ERRORS -eq 0 ]; then
    echo -e "\n${GREEN}✅ All critical checks passed!${NC}"
    
    if [ $WARNINGS -gt 0 ]; then
        echo -e "${YELLOW}⚠️  There are $WARNINGS warnings to review${NC}"
    fi
    
    echo -e "\n${BLUE}Next steps for release:${NC}"
    echo "1. Ensure CHANGELOG.md is updated with release notes"
    echo "2. Commit all changes: git add -A && git commit -m \"Release v${CURRENT_VERSION}\""
    echo "3. Create annotated tag: git tag -a v${CURRENT_VERSION} -m \"Release v${CURRENT_VERSION}\""
    echo "4. Push changes: git push origin $CURRENT_BRANCH"
    echo "5. Push tag: git push origin v${CURRENT_VERSION}"
    echo "6. Create GitHub release from the tag"
    echo "7. Publish to crates.io: cargo publish -p kindly-guard-server && cargo publish -p kindly-guard-cli"
    
    if [ $WARNINGS -eq 0 ]; then
        exit 0
    else
        exit 0  # Warnings don't fail the checklist
    fi
else
    echo -e "\n${RED}❌ $ERRORS critical checks failed. Please fix the issues before releasing.${NC}"
    exit 1
fi