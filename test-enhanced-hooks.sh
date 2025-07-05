#!/bin/bash
# Test script for enhanced pre-commit hooks

set -e

echo "🔍 Testing Enhanced Pre-commit Hooks for KindlyGuard"
echo "===================================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || [ ! -d ".git" ]; then
    echo -e "${RED}❌ Error: Must run from KindlyGuard project root${NC}"
    exit 1
fi

echo -e "\n${BLUE}1. Checking tool availability...${NC}"
echo "--------------------------------"

# Check for xtask
if [ -f "target/release/xtask" ] || [ -f "target/debug/xtask" ]; then
    echo -e "${GREEN}✓ xtask found${NC}"
else
    echo -e "${YELLOW}⚠ xtask not built, building now...${NC}"
    cargo build --bin xtask
fi

# Check for kindly-tools
if [ -f "kindly-tools/target/release/kindly-tools" ] || [ -f "kindly-tools/target/debug/kindly-tools" ]; then
    echo -e "${GREEN}✓ kindly-tools found${NC}"
else
    echo -e "${YELLOW}⚠ kindly-tools not built, building now...${NC}"
    (cd kindly-tools && cargo build)
fi

# Check for pre-commit
if command -v pre-commit &> /dev/null; then
    echo -e "${GREEN}✓ pre-commit installed${NC}"
else
    echo -e "${RED}❌ pre-commit not installed${NC}"
    echo "  Install with: pip install pre-commit"
fi

# Check for sccache
if command -v sccache &> /dev/null; then
    echo -e "${GREEN}✓ sccache installed${NC}"
    export RUSTC_WRAPPER=sccache
else
    echo -e "${YELLOW}⚠ sccache not installed (builds will be slower)${NC}"
    echo "  Install with: cargo install sccache"
fi

echo -e "\n${BLUE}2. Testing individual hooks...${NC}"
echo "-------------------------------"

# Test rust environment check
echo -e "\n${YELLOW}Testing rust-doctor hook:${NC}"
if cargo xtask doctor --component rust; then
    echo -e "${GREEN}✓ Rust environment check passed${NC}"
else
    echo -e "${RED}❌ Rust environment check failed${NC}"
fi

# Test cache stats
echo -e "\n${YELLOW}Testing cache stats:${NC}"
if cargo xtask cache stats 2>/dev/null; then
    echo -e "${GREEN}✓ Cache stats available${NC}"
else
    echo -e "${YELLOW}⚠ Cache not configured yet${NC}"
    echo "  Configure with: cargo xtask cache setup --backend local"
fi

echo -e "\n${BLUE}3. Testing pre-commit hooks...${NC}"
echo "-------------------------------"

# Create a test file with issues
TEST_FILE="test_hooks_temp.rs"
cat > "$TEST_FILE" << 'EOF'
// Test file with various issues
fn main() {
    let data = vec![1, 2, 3];
    let first = data.get(0).unwrap(); // This should fail
    let second = data.get(1).expect("Should have second"); // This should warn
    
    unsafe {
        // This should warn about unsafe without SAFETY comment
        std::ptr::null::<u8>();
    }
    
    println!("AWS_SECRET_ACCESS_KEY=test123"); // This should be caught
}
EOF

# Stage the test file
git add "$TEST_FILE"

echo -e "\n${YELLOW}Running pre-commit on test file with issues...${NC}"
if pre-commit run --files "$TEST_FILE"; then
    echo -e "${RED}❌ Pre-commit should have failed on test file!${NC}"
else
    echo -e "${GREEN}✓ Pre-commit correctly detected issues${NC}"
fi

# Clean up test file
git reset HEAD "$TEST_FILE" 2>/dev/null
rm -f "$TEST_FILE"

echo -e "\n${BLUE}4. Testing fast pre-commit script...${NC}"
echo "------------------------------------"

if [ -f "scripts/pre-commit-rust-fast.sh" ]; then
    echo -e "${YELLOW}Running fast pre-commit checks...${NC}"
    # Create a good test file
    GOOD_FILE="test_good_temp.rs"
    cat > "$GOOD_FILE" << 'EOF'
// Clean test file
fn main() {
    println!("Hello, KindlyGuard!");
}
EOF
    git add "$GOOD_FILE"
    
    if ./scripts/pre-commit-rust-fast.sh; then
        echo -e "${GREEN}✓ Fast pre-commit passed on clean file${NC}"
    else
        echo -e "${RED}❌ Fast pre-commit failed on clean file${NC}"
    fi
    
    git reset HEAD "$GOOD_FILE" 2>/dev/null
    rm -f "$GOOD_FILE"
else
    echo -e "${RED}❌ Fast pre-commit script not found${NC}"
fi

echo -e "\n${BLUE}5. Performance test...${NC}"
echo "----------------------"

# Create multiple test files
echo -e "${YELLOW}Creating 5 test files...${NC}"
for i in {1..5}; do
    cat > "perf_test_$i.rs" << EOF
fn test_function_$i() {
    println!("Test $i");
}
EOF
    git add "perf_test_$i.rs"
done

# Time the hooks
START_TIME=$(date +%s)
if pre-commit run --files perf_test_*.rs > /dev/null 2>&1; then
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    echo -e "${GREEN}✓ Hooks completed in ${DURATION} seconds${NC}"
    
    if [ $DURATION -lt 10 ]; then
        echo -e "${GREEN}✓ Performance is good (< 10s)${NC}"
    else
        echo -e "${YELLOW}⚠ Hooks are slow (> 10s), consider enabling sccache${NC}"
    fi
fi

# Clean up
git reset HEAD perf_test_*.rs 2>/dev/null
rm -f perf_test_*.rs

echo -e "\n${BLUE}6. Summary${NC}"
echo "----------"

# Check hook installation
if [ -f ".git/hooks/pre-commit" ]; then
    echo -e "${GREEN}✓ Pre-commit hooks installed${NC}"
    
    # Check for our custom hooks
    if grep -q "rust-doctor" .pre-commit-config.yaml 2>/dev/null; then
        echo -e "${GREEN}✓ Enhanced Rust hooks configured${NC}"
    fi
    
    if [ -f ".git/hooks/pre-commit-rust-tools" ]; then
        echo -e "${GREEN}✓ Rust tools hook installed${NC}"
    fi
else
    echo -e "${RED}❌ Pre-commit hooks not installed${NC}"
    echo "  Run: ./scripts/install-hooks.sh"
fi

echo -e "\n${GREEN}✨ Testing complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Enable sccache: export RUSTC_WRAPPER=sccache"
echo "2. Configure cache: cargo xtask cache setup --backend local"
echo "3. Try interactive mode: cargo xtask --interactive"
echo "4. Start development: kindly-tools dev"