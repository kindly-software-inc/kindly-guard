#!/bin/bash
#
# Test script for KindlyGuard pre-commit hook
#

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Testing KindlyGuard pre-commit hook...${NC}\n"

# Create temporary test files
TEST_DIR="/tmp/kindly-guard-hook-test"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

# Test cases that SHOULD be caught
echo -e "${YELLOW}Testing HIGH RISK terms (should be caught):${NC}"

cat > "$TEST_DIR/test1.md" << 'EOF'
# Bad file with proprietary terms
The AtomicBitPackedEventBuffer is our secret weapon.
We use HierarchicalRateLimiter for scaling.
Our CpuTokenBucket design is revolutionary.
EOF

cat > "$TEST_DIR/test2.rs" << 'EOF'
// This mentions proprietary algorithms
// We use the Chase-Lev deque for work stealing
// Our bit-packed atomic state machine is fast
// The per-CPU token bucket eliminates contention
// NUMA-aware stealing improves performance
EOF

cat > "$TEST_DIR/test3.md" << 'EOF'
# Performance metrics that reveal too much
We achieved 27x throughput improvement at scale.
The system shows 9.9x improvement in latency.
Our 90% local hit rate is industry-leading.
Linear scaling to 64+ cores is proven.
EOF

# Test cases that should NOT be caught (generic terms)
echo -e "\n${YELLOW}Testing generic terms (should NOT be caught):${NC}"

cat > "$TEST_DIR/test_ok1.md" << 'EOF'
# Generic documentation
We use atomic operations for thread safety.
The system is hierarchical in nature.
Rate limiting is important for security.
Compression is handled securely.
EOF

cat > "$TEST_DIR/test_ok2.rs" << 'EOF'
// Generic implementation
use std::sync::atomic::AtomicU64;
fn compress_data(data: &[u8]) -> Vec<u8> {
    // Generic compression logic
}
EOF

# Function to test a file
test_file() {
    local file="$1"
    local expected="$2"
    
    # Run the hook's check function directly
    source /home/samuel/kindly-guard/.githooks/pre-commit
    
    if check_sensitive_terms "$file" > /dev/null 2>&1; then
        result="CAUGHT"
    else
        result="PASSED"
    fi
    
    if [[ "$result" == "$expected" ]]; then
        echo -e "  ${GREEN}✓${NC} $(basename "$file"): $result (as expected)"
    else
        echo -e "  ${RED}✗${NC} $(basename "$file"): $result (expected $expected)"
    fi
}

# Run tests
echo -e "\nFiles that should be CAUGHT:"
test_file "$TEST_DIR/test1.md" "CAUGHT"
test_file "$TEST_DIR/test2.rs" "CAUGHT" 
test_file "$TEST_DIR/test3.md" "CAUGHT"

echo -e "\nFiles that should PASS:"
test_file "$TEST_DIR/test_ok1.md" "PASSED"
test_file "$TEST_DIR/test_ok2.rs" "PASSED"

# Test allowed files
echo -e "\n${YELLOW}Testing allowed files (should be skipped):${NC}"
mkdir -p "$TEST_DIR/docs"
cat > "$TEST_DIR/docs/FUTURE_INNOVATIONS.md" << 'EOF'
# This file can contain anything
AtomicBitPackedEventBuffer is amazing!
HierarchicalRateLimiter scales to 64 cores!
Chase-Lev deque is the secret sauce.
EOF

if is_allowed_file "docs/FUTURE_INNOVATIONS.md"; then
    echo -e "  ${GREEN}✓${NC} docs/FUTURE_INNOVATIONS.md: Correctly identified as allowed"
else
    echo -e "  ${RED}✗${NC} docs/FUTURE_INNOVATIONS.md: Should be allowed!"
fi

# Cleanup
rm -rf "$TEST_DIR"

echo -e "\n${GREEN}Test complete!${NC}"
echo -e "To test with actual git commits, run: ${YELLOW}./.githooks/pre-commit${NC}"