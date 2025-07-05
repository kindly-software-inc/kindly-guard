#!/bin/bash
# Fast pre-commit hook for Rust - runs only on Rust file changes
# Focuses on quick security and format checks

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Function to print colored headers
print_header() {
    echo -e "\n${BLUE}${BOLD}━━━ $1 ━━━${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

# Check if any Rust files are staged
RUST_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(rs|toml)$' || true)

if [ -z "$RUST_FILES" ]; then
    print_info "No Rust files changed, skipping Rust checks"
    exit 0
fi

echo -e "${BOLD}🦀 Running fast Rust pre-commit checks...${NC}"
print_info "Changed files: $(echo "$RUST_FILES" | wc -l) Rust/TOML files"

# Track overall status
FAILED=0

# 1. Quick environment check
print_header "Environment Check"

# Try xtask with timeout to avoid blocking on build
if timeout 2s cargo xtask doctor --component rust 2>/dev/null; then
    print_success "Rust environment healthy (via xtask)"
else
    # Fallback to basic checks
    if command -v cargo &> /dev/null; then
        print_success "Cargo: $(cargo --version | awk '{print $2}')"
        if command -v rustc &> /dev/null; then
            print_success "Rustc: $(rustc --version | awk '{print $2}')"
        fi
    else
        print_error "Cargo not found"
        FAILED=1
        exit 1
    fi
fi

# 2. Quick cache check
print_header "Cache Status"
if timeout 1s cargo xtask cache stats 2>/dev/null; then
    print_success "Cache enabled and working"
elif [ -d "target" ]; then
    # Quick size check without full traversal
    TARGET_SIZE=$(timeout 1s du -sh target 2>/dev/null | cut -f1 || echo "checking...")
    print_info "Target directory: $TARGET_SIZE"
else
    print_warning "No build cache (first build will be slow)"
fi

# 3. Fast security checks on changed files only
print_header "Security Checks"

# Check for unwrap() in changed Rust files
UNWRAP_FILES=()
for file in $RUST_FILES; do
    if [[ "$file" == *.rs ]] && [ -f "$file" ]; then
        if grep -q "\.unwrap()" "$file" 2>/dev/null; then
            UNWRAP_FILES+=("$file")
        fi
    fi
done

if [ ${#UNWRAP_FILES[@]} -eq 0 ]; then
    print_success "No unwrap() usage in changed files"
else
    print_error "Found unwrap() in ${#UNWRAP_FILES[@]} files:"
    for file in "${UNWRAP_FILES[@]}"; do
        count=$(grep -c "\.unwrap()" "$file")
        echo "    ${YELLOW}→${NC} $file (${count} occurrences)"
    done
    FAILED=1
fi

# Check for expect() - warning only
EXPECT_COUNT=0
for file in $RUST_FILES; do
    if [[ "$file" == *.rs ]] && [ -f "$file" ]; then
        count=$(grep -c "\.expect(" "$file" 2>/dev/null | head -1 || echo "0")
        EXPECT_COUNT=$((EXPECT_COUNT + count))
    fi
done

if [ $EXPECT_COUNT -gt 0 ]; then
    print_warning "Found $EXPECT_COUNT expect() calls (consider Result handling)"
fi

# 4. Format check (very fast)
print_header "Format Check"
# Only check changed files for speed
UNFORMATTED_FILES=()
for file in $RUST_FILES; do
    if [[ "$file" == *.rs ]] && [ -f "$file" ]; then
        if ! cargo fmt -- --check "$file" 2>/dev/null; then
            UNFORMATTED_FILES+=("$file")
        fi
    fi
done

if [ ${#UNFORMATTED_FILES[@]} -eq 0 ]; then
    print_success "All files properly formatted"
else
    print_error "${#UNFORMATTED_FILES[@]} files need formatting:"
    for file in "${UNFORMATTED_FILES[@]}"; do
        echo "    ${YELLOW}→${NC} $file"
    done
    echo -e "    Run: ${CYAN}cargo fmt${NC}"
    FAILED=1
fi

# 5. Quick clippy on changed files (with caching)
print_header "Clippy (Fast Mode)"
# Use --no-deps to only check our code, not dependencies
echo -n "Running targeted clippy checks... "
CLIPPY_FAILED=0

# Create a temp file with changed modules
CHANGED_MODULES=""
for file in $RUST_FILES; do
    if [[ "$file" == src/*.rs ]]; then
        module=$(echo "$file" | sed 's/src\///' | sed 's/\.rs$//' | sed 's/\//::/g')
        CHANGED_MODULES="$CHANGED_MODULES --lib -p $(basename $(pwd))"
        break  # Just check the whole lib if any src file changed
    fi
done

if [ -n "$CHANGED_MODULES" ]; then
    if timeout 30s cargo clippy --quiet $CHANGED_MODULES -- \
        -D warnings \
        -W clippy::unwrap_used \
        -W clippy::expect_used \
        -W clippy::panic \
        -W clippy::unimplemented \
        -W clippy::todo 2>/dev/null; then
        print_success "Clippy checks passed"
    else
        print_error "Clippy found issues"
        CLIPPY_FAILED=1
        FAILED=1
    fi
else
    print_info "No library code changed"
fi

# 6. Quick unsafe code check
print_header "Unsafe Code Check"
UNSAFE_COUNT=0
for file in $RUST_FILES; do
    if [[ "$file" == *.rs ]] && [ -f "$file" ]; then
        count=$(grep -c "unsafe" "$file" 2>/dev/null | head -1 || echo "0")
        if [ "$count" -gt 0 ]; then
            UNSAFE_COUNT=$((UNSAFE_COUNT + count))
            print_warning "Found 'unsafe' in $file ($count occurrences)"
        fi
    fi
done

if [ $UNSAFE_COUNT -eq 0 ]; then
    print_success "No unsafe code in changed files"
else
    print_warning "Total unsafe blocks: $UNSAFE_COUNT (ensure safety docs)"
fi

# Summary
echo ""
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✓ All checks passed!${NC} Ready to commit."
    
    # Show quick stats
    TOTAL_LINES=0
    for file in $RUST_FILES; do
        if [ -f "$file" ]; then
            lines=$(wc -l < "$file" 2>/dev/null || echo "0")
            TOTAL_LINES=$((TOTAL_LINES + lines))
        fi
    done
    print_info "Checked $(echo "$RUST_FILES" | wc -l) files, ~${TOTAL_LINES} lines"
else
    echo -e "${RED}${BOLD}✗ Some checks failed!${NC}"
    echo -e "${YELLOW}Please fix the issues above before committing.${NC}"
    echo ""
    echo -e "Quick fixes:"
    if [ ${#UNFORMATTED_FILES[@]} -gt 0 ]; then
        echo -e "  • Format: ${CYAN}cargo fmt${NC}"
    fi
    if [ $CLIPPY_FAILED -eq 1 ]; then
        echo -e "  • Clippy: ${CYAN}cargo clippy --fix${NC}"
    fi
    if [ ${#UNWRAP_FILES[@]} -gt 0 ]; then
        echo -e "  • Unwrap: Replace ${RED}.unwrap()${NC} with ${GREEN}?${NC} or proper error handling"
    fi
fi

exit $FAILED