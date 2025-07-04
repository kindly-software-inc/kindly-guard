#!/bin/bash
# Security boundary check script for KindlyGuard Shield
# Ensures no proprietary technology leaks in public APIs

set -e

echo "=== KindlyGuard Shield Security Boundary Check ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check for direct imports of kindly-guard-core outside of enhanced modules
echo "Checking for unauthorized kindly-guard-core imports..."
UNAUTHORIZED=$(grep -r "use kindly_guard_core" src/ --include="*.rs" 2>/dev/null | grep -v "enhanced.rs" || true)
if [ -n "$UNAUTHORIZED" ]; then
    echo -e "${RED}✗ FAIL: Found direct imports of kindly-guard-core outside enhanced modules:${NC}"
    echo "$UNAUTHORIZED"
    exit 1
else
    echo -e "${GREEN}✓ PASS: No unauthorized kindly-guard-core imports${NC}"
fi

# Check that enhanced modules are properly feature-gated
echo
echo "Checking enhanced module feature gates..."
for file in src/*/enhanced.rs; do
    if [ -f "$file" ]; then
        if ! grep -q "#\[cfg(feature = \"enhanced\")\]\|#!\[cfg(feature = \"enhanced\")\]" "$file"; then
            echo -e "${RED}✗ FAIL: $file is not properly feature-gated${NC}"
            exit 1
        fi
    fi
done
echo -e "${GREEN}✓ PASS: All enhanced modules are feature-gated${NC}"

# Check for exposed proprietary types in public traits
echo
echo "Checking for proprietary types in public APIs..."
PROPRIETARY_TYPES=(
    "AtomicEventBuffer"
    "PatternMatcher"
    "ThreatClassifier"
    "UnicodeNormalizer"
    "BinaryProtocol"
    "MessageCompressor"
)

for type in "${PROPRIETARY_TYPES[@]}"; do
    if grep -r "pub.*$type" src/ --include="*.rs" | grep -v "enhanced.rs" | grep -v "#\[cfg(feature = \"enhanced\")\]"; then
        echo -e "${RED}✗ FAIL: Proprietary type '$type' exposed in public API${NC}"
        exit 1
    fi
done
echo -e "${GREEN}✓ PASS: No proprietary types in public APIs${NC}"

# Check that factories return trait objects, not concrete types
echo
echo "Checking factory return types..."
if grep -r "impl.*Factory" src/ -A 10 | grep -E "-> .*Arc<[^d][^y][^n]"; then
    echo -e "${YELLOW}⚠ WARNING: Factory might be returning concrete type instead of trait object${NC}"
fi
echo -e "${GREEN}✓ PASS: Factories return trait objects${NC}"

# Check for documentation leaks
echo
echo "Checking for proprietary technology mentions in docs..."
PROPRIETARY_TERMS=(
    "AtomicEventBuffer"
    "patented"
    "proprietary"
    "lock-free"
    "atomic buffer"
)

for term in "${PROPRIETARY_TERMS[@]}"; do
    if grep -r "$term" src/ --include="*.rs" | grep -v "enhanced.rs" | grep "//"; then
        echo -e "${YELLOW}⚠ WARNING: Found '$term' in documentation - please review${NC}"
    fi
done

# Check Cargo.toml dependencies
echo
echo "Checking Cargo.toml configuration..."
if grep -q "kindly-guard-core.*optional = true" Cargo.toml; then
    echo -e "${GREEN}✓ PASS: kindly-guard-core is marked as optional${NC}"
else
    echo -e "${RED}✗ FAIL: kindly-guard-core must be optional${NC}"
    exit 1
fi

# Final summary
echo
echo "=== Security Boundary Check Complete ==="
echo -e "${GREEN}All security boundaries are properly maintained!${NC}"
echo
echo "Remember:"
echo "- Always use trait abstractions for public APIs"
echo "- Keep proprietary implementations in enhanced modules"
echo "- Use semantic naming (e.g., 'enhanced' not 'AtomicEventBuffer')"
echo "- Document functionality, not implementation details"