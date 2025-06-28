#!/bin/bash
set -e

# KindlyGuard Quick Security Check
# Run this before commits to ensure security standards

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🛡️  KindlyGuard Security Check${NC}\n"

# Check if we're in the project root
if [ ! -f "$PROJECT_ROOT/Cargo.toml" ]; then
    echo -e "${RED}Error: Not in KindlyGuard project root${NC}"
    exit 1
fi

cd "$PROJECT_ROOT"

# 1. Run clippy with strict lints
echo -e "${YELLOW}[1/5] Running Clippy analysis...${NC}"
cargo clippy -- -W clippy::all -W clippy::pedantic -D warnings || {
    echo -e "${RED}❌ Clippy found issues${NC}"
    exit 1
}
echo -e "${GREEN}✓ Clippy passed${NC}\n"

# 2. Check for unsafe code
echo -e "${YELLOW}[2/5] Checking for unsafe code...${NC}"
if command -v cargo-geiger &> /dev/null; then
    UNSAFE_COUNT=$(cargo geiger --all-features 2>/dev/null | grep -E "^kindly-guard" | grep -oE "[0-9]+ unsafe" | grep -oE "[0-9]+" | awk '{sum += $1} END {print sum}')
    if [ "${UNSAFE_COUNT:-0}" -gt 0 ]; then
        echo -e "${RED}❌ Found $UNSAFE_COUNT unsafe functions in our code${NC}"
        cargo geiger --all-features
        exit 1
    fi
    echo -e "${GREEN}✓ No unsafe code detected${NC}\n"
else
    echo -e "${YELLOW}⚠ cargo-geiger not installed, skipping unsafe check${NC}\n"
fi

# 3. Run security audit
echo -e "${YELLOW}[3/5] Running security audit...${NC}"
if command -v cargo-audit &> /dev/null; then
    cargo audit || {
        echo -e "${RED}❌ Security vulnerabilities found${NC}"
        exit 1
    }
    echo -e "${GREEN}✓ No known vulnerabilities${NC}\n"
else
    echo -e "${YELLOW}⚠ cargo-audit not installed, skipping vulnerability check${NC}\n"
fi

# 4. Run property tests (quick subset)
echo -e "${YELLOW}[4/5] Running property tests...${NC}"
cd kindly-guard-server
cargo test --test property_tests -- --test-threads=1 scanner_never_panics threats_have_valid_locations --nocapture || {
    echo -e "${RED}❌ Property tests failed${NC}"
    exit 1
}
echo -e "${GREEN}✓ Property tests passed${NC}\n"
cd ..

# 5. Quick fuzz test (30 seconds)
echo -e "${YELLOW}[5/5] Running quick fuzz test...${NC}"
if [ -x "./scripts/fuzz.sh" ] && command -v cargo-fuzz &> /dev/null; then
    ./scripts/fuzz.sh run fuzz_unicode_scanner -t 30 > /dev/null 2>&1 || {
        echo -e "${RED}❌ Fuzzing found issues${NC}"
        echo "Run './scripts/fuzz.sh corpus fuzz_unicode_scanner' to see details"
        exit 1
    }
    echo -e "${GREEN}✓ Quick fuzz test passed${NC}\n"
else
    echo -e "${YELLOW}⚠ Fuzzing not available, skipping${NC}\n"
fi

# Summary
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ All security checks passed!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "For thorough testing before release, run:"
echo "  ./scripts/fuzz.sh run-all -t 3600"
echo "  cargo test --all-features"
echo "  cargo bench"