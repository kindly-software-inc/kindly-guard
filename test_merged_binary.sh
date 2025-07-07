#!/bin/bash
# Comprehensive test script for the merged KindlyGuard binary

set -e

BINARY="../target/release/kindlyguard"
TEST_DIR="test_kindlyguard_$(date +%s)"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test function
test_command() {
    local description="$1"
    local command="$2"
    echo -e "${BLUE}Testing: ${description}${NC}"
    echo -e "${YELLOW}Command: ${command}${NC}"
    if eval "$command"; then
        echo -e "${GREEN}✓ PASSED${NC}\n"
    else
        echo -e "${RED}✗ FAILED${NC}\n"
    fi
}

echo "=========================================="
echo "KindlyGuard Merged Binary Test Suite"
echo "=========================================="
echo ""

# Create test directory
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# Create test files
echo "Creating test files..."
cat > test_safe.txt << 'EOF'
This is a safe text file with normal content.
No threats here!
EOF

cat > test_sql_injection.txt << 'EOF'
SELECT * FROM users WHERE id = '1' OR '1'='1'; --
DROP TABLE users; --
EOF

cat > test_unicode.txt << 'EOF'
Normal text with hidden‌‍⁠ zero-width characters
Right-to-left override: ‮Hello World
Homograph attack: Раураl (fake PayPal with Cyrillic)
EOF

cat > test_xss.html << 'EOF'
<html>
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<body onload="alert('XSS')">
</html>
EOF

cat > test.json << 'EOF'
{
  "name": "Test",
  "script": "<script>alert('XSS')</script>",
  "sql": "'; DROP TABLE users; --"
}
EOF

echo -e "${GREEN}Test files created${NC}\n"

# Test 1: Basic help and version
echo -e "${BLUE}=== Testing Basic Commands ===${NC}"
test_command "Help output" "$BINARY --help"
test_command "Version output" "$BINARY --version"
test_command "Verbose help" "$BINARY -v --help"

# Test 2: Scan command
echo -e "${BLUE}=== Testing Scan Command ===${NC}"
test_command "Scan safe file" "$BINARY scan test_safe.txt"
test_command "Scan SQL injection file" "$BINARY scan test_sql_injection.txt"
test_command "Scan Unicode threats" "$BINARY scan test_unicode.txt"
test_command "Scan XSS file" "$BINARY scan test_xss.html"
test_command "Scan JSON file" "$BINARY scan test.json"
test_command "Scan with JSON output" "$BINARY scan test_sql_injection.txt --format json"
test_command "Scan non-existent file" "$BINARY scan nonexistent.txt || true"
test_command "Scan directory (should fail without recursive)" "$BINARY scan . || true"

# Test 3: Server command
echo -e "${BLUE}=== Testing Server Command ===${NC}"
test_command "Server help" "$BINARY serve --help"
test_command "Server with stdio (short test)" "timeout 2 $BINARY serve --stdio || true"

# Test 4: Monitor command
echo -e "${BLUE}=== Testing Monitor Command ===${NC}"
test_command "Monitor help" "$BINARY monitor --help"
test_command "Monitor (short test)" "timeout 2 $BINARY monitor || true"

# Test 5: Shield command
echo -e "${BLUE}=== Testing Shield Command ===${NC}"
test_command "Shield help" "$BINARY shield --help"
test_command "Shield minimal mode (short test)" "timeout 2 $BINARY shield --mode minimal || true"

# Test 6: Wrap command
echo -e "${BLUE}=== Testing Wrap Command ===${NC}"
test_command "Wrap help" "$BINARY wrap --help"
test_command "Wrap echo command" "$BINARY wrap echo 'Hello World'"
test_command "Wrap ls command" "$BINARY wrap ls -la"

# Test 7: Install command
echo -e "${BLUE}=== Testing Install Command ===${NC}"
test_command "Install help" "$BINARY install --help"
test_command "Install detect mode" "$BINARY install --detect || true"

# Test 8: Update command
echo -e "${BLUE}=== Testing Update Command ===${NC}"
test_command "Update help" "$BINARY update --help"
test_command "Update check" "$BINARY update --check"

# Test 9: Doctor command
echo -e "${BLUE}=== Testing Doctor Command ===${NC}"
test_command "Doctor help" "$BINARY doctor --help"
test_command "Doctor check" "$BINARY doctor"

# Test 10: Complex scenarios
echo -e "${BLUE}=== Testing Complex Scenarios ===${NC}"
test_command "Verbose scan with color" "$BINARY -v scan test_unicode.txt"
test_command "No color scan" "$BINARY --no-color scan test_xss.html"

# Cleanup
cd ..
rm -rf "$TEST_DIR"

echo "=========================================="
echo "Test suite completed!"
echo "=========================================="