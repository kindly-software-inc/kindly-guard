#!/usr/bin/env bash
# Test script for pre-commit hooks
# This script verifies that hooks are working correctly

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🧪 Testing KindlyGuard Pre-Commit Hooks${NC}"
echo "========================================"

# Check if pre-commit is installed
if ! command -v pre-commit &> /dev/null; then
    echo -e "${RED}❌ pre-commit not installed${NC}"
    echo "   Please run: ./scripts/install-hooks.sh"
    exit 1
fi

echo -e "\n${YELLOW}1. Testing format check...${NC}"
# Create a badly formatted file
cat > /tmp/test_bad_format.rs << 'EOF'
fn main()  {
    println!("Badly formatted code"  )  ;
        let x=5;
            let     y    =    10   ;
}
EOF

echo "Testing rustfmt hook on badly formatted code..."
if pre-commit run rustfmt --files /tmp/test_bad_format.rs 2>&1 | grep -q "Failed"; then
    echo -e "${GREEN}✅ Format check correctly caught bad formatting${NC}"
else
    echo -e "${RED}❌ Format check failed to catch bad formatting${NC}"
fi

echo -e "\n${YELLOW}2. Testing unsafe code check...${NC}"
# Create file with unsafe without SAFETY comment
cat > /tmp/test_unsafe.rs << 'EOF'
fn dangerous() {
    unsafe {
        // This should fail - no SAFETY comment
        std::ptr::null_mut::<i32>().write(42);
    }
}
EOF

echo "Testing unsafe code hook..."
if ! pre-commit run unsafe-code-check --files /tmp/test_unsafe.rs 2>&1 | grep -q "PASS"; then
    echo -e "${GREEN}✅ Unsafe check correctly caught missing SAFETY comment${NC}"
else
    echo -e "${RED}❌ Unsafe check failed to catch missing SAFETY comment${NC}"
fi

echo -e "\n${YELLOW}3. Testing large file check...${NC}"
# Create a large file
dd if=/dev/zero of=/tmp/test_large_file bs=1M count=2 2>/dev/null

echo "Testing large file hook..."
if pre-commit run check-added-large-files --files /tmp/test_large_file 2>&1 | grep -q "Failed"; then
    echo -e "${GREEN}✅ Large file check correctly caught 2MB file${NC}"
else
    echo -e "${RED}❌ Large file check failed to catch large file${NC}"
fi

echo -e "\n${YELLOW}4. Testing conventional commit...${NC}"
# Test commit message validation
echo "Testing commit message format..."
echo "bad commit message" > /tmp/test_commit_msg
if ! .git-hooks/commit-msg /tmp/test_commit_msg 2>&1; then
    echo -e "${GREEN}✅ Commit message check correctly rejected bad format${NC}"
else
    echo -e "${RED}❌ Commit message check failed to reject bad format${NC}"
fi

echo "fix: good commit message" > /tmp/test_commit_msg
if .git-hooks/commit-msg /tmp/test_commit_msg 2>&1; then
    echo -e "${GREEN}✅ Commit message check correctly accepted good format${NC}"
else
    echo -e "${RED}❌ Commit message check failed to accept good format${NC}"
fi

# Cleanup
rm -f /tmp/test_bad_format.rs /tmp/test_unsafe.rs /tmp/test_large_file /tmp/test_commit_msg

echo -e "\n${GREEN}✅ Hook testing complete!${NC}"
echo -e "${BLUE}Tip: Run 'pre-commit run --all-files' to test all hooks on the entire codebase${NC}"