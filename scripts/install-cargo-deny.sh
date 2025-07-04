#!/bin/bash
# Install cargo-deny for supply chain security auditing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔒 Installing cargo-deny for KindlyGuard${NC}"
echo "========================================"

# Check if cargo is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ Error: cargo is not installed${NC}"
    echo "Please install Rust first: https://rustup.rs/"
    exit 1
fi

# Check if cargo-deny is already installed
if command -v cargo-deny &> /dev/null; then
    CURRENT_VERSION=$(cargo-deny --version | cut -d' ' -f2)
    echo -e "${YELLOW}⚠️  cargo-deny is already installed (version $CURRENT_VERSION)${NC}"
    echo -n "Do you want to update it? (y/N) "
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}✅ Using existing cargo-deny installation${NC}"
        exit 0
    fi
fi

# Install or update cargo-deny
echo -e "${BLUE}📦 Installing cargo-deny...${NC}"
if cargo install cargo-deny --locked; then
    echo -e "${GREEN}✅ cargo-deny installed successfully${NC}"
else
    echo -e "${RED}❌ Failed to install cargo-deny${NC}"
    exit 1
fi

# Verify installation
if command -v cargo-deny &> /dev/null; then
    VERSION=$(cargo-deny --version)
    echo -e "${GREEN}✅ Installed: $VERSION${NC}"
else
    echo -e "${RED}❌ Installation verification failed${NC}"
    exit 1
fi

# Update advisory database
echo -e "\n${BLUE}📥 Fetching latest advisory database...${NC}"
if cargo deny fetch; then
    echo -e "${GREEN}✅ Advisory database updated${NC}"
else
    echo -e "${YELLOW}⚠️  Failed to fetch advisory database (will be fetched on first run)${NC}"
fi

# Run initial check
echo -e "\n${BLUE}🔍 Running initial security check...${NC}"
cd "$(dirname "$0")/.."

echo -e "\n${YELLOW}Checking for security advisories...${NC}"
cargo deny check advisories || true

echo -e "\n${YELLOW}Checking license compliance...${NC}"
cargo deny check licenses || true

echo -e "\n${YELLOW}Checking for banned crates...${NC}"
cargo deny check bans || true

echo -e "\n${YELLOW}Checking dependency sources...${NC}"
cargo deny check sources || true

echo -e "\n${GREEN}✅ Installation complete!${NC}"
echo -e "\nYou can now run supply chain security checks with:"
echo -e "  ${BLUE}cargo deny check${NC}           # Run all checks"
echo -e "  ${BLUE}cargo deny check advisories${NC} # Check for vulnerabilities"
echo -e "  ${BLUE}cargo deny check licenses${NC}   # Check license compliance"
echo -e "  ${BLUE}cargo deny check bans${NC}       # Check for banned crates"
echo -e "  ${BLUE}cargo deny check sources${NC}    # Check dependency sources"