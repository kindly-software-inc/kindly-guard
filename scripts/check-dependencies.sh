#!/bin/bash
# Quick dependency security check for KindlyGuard developers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔒 KindlyGuard Dependency Security Check${NC}"
echo "========================================"

# Check if cargo-deny is installed
if ! command -v cargo-deny &> /dev/null; then
    echo -e "${YELLOW}⚠️  cargo-deny is not installed${NC}"
    echo "Installing cargo-deny..."
    "$(dirname "$0")/install-cargo-deny.sh"
fi

# Move to project root
cd "$(dirname "$0")/.."

FAILED_CHECKS=0

# Run each check and track failures
run_check() {
    local check_name=$1
    local check_command=$2
    
    echo -e "\n${YELLOW}▶ Running $check_name...${NC}"
    if $check_command; then
        echo -e "${GREEN}✅ $check_name passed${NC}"
    else
        echo -e "${RED}❌ $check_name failed${NC}"
        ((FAILED_CHECKS++))
    fi
}

# Update advisory database
echo -e "${BLUE}📥 Updating advisory database...${NC}"
cargo deny fetch || echo -e "${YELLOW}⚠️  Failed to update advisory database${NC}"

# Run all checks
run_check "Security Advisories" "cargo deny check advisories"
run_check "License Compliance" "cargo deny check licenses"
run_check "Banned Crates" "cargo deny check bans"
run_check "Source Validation" "cargo deny check sources"

# Summary
echo -e "\n${BLUE}📊 Summary${NC}"
echo "=========="

if [ $FAILED_CHECKS -eq 0 ]; then
    echo -e "${GREEN}✅ All dependency checks passed!${NC}"
    echo -e "\nYour dependencies are:"
    echo -e "  • Free from known vulnerabilities"
    echo -e "  • License-compatible with Apache-2.0"
    echo -e "  • From trusted sources"
    echo -e "  • Meeting KindlyGuard's security standards"
    exit 0
else
    echo -e "${RED}❌ $FAILED_CHECKS check(s) failed${NC}"
    echo -e "\n${YELLOW}Please review the errors above and:${NC}"
    echo -e "  1. Update vulnerable dependencies"
    echo -e "  2. Replace incompatible licenses"
    echo -e "  3. Remove banned crates"
    echo -e "  4. Verify all dependency sources"
    echo -e "\nRun ${BLUE}cargo deny check${NC} for detailed information"
    exit 1
fi