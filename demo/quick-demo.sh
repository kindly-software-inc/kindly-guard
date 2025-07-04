#!/bin/bash
# Quick demo that works with just the core server

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}KindlyGuard Quick Demo${NC}"
echo "========================"
echo ""

# Build if needed
if [ ! -f "../target/release/kindly-guard" ]; then
    echo -e "${YELLOW}Building KindlyGuard...${NC}"
    (cd .. && cargo build --release --bin kindly-guard)
fi

# Demo 1: CLI Scanner
echo -e "\n${GREEN}1. Testing CLI Scanner${NC}"
echo "Scanning for unicode threats..."

# Create a test file with threats
cat > test-input.json << EOF
{
  "message": "Hello\u202Eworld",
  "filename": "safe\u200B.exe",
  "query": "SELECT * FROM users WHERE id='1' OR '1'='1'"
}
EOF

../target/release/kindly-guard scan test-input.json

# Demo 2: Direct threat testing
echo -e "\n${GREEN}2. Testing Specific Threats${NC}"

echo -e "\n${YELLOW}Testing Unicode Attack:${NC}"
echo '{"text": "admin\u200Bpassword"}' | ../target/release/kindly-guard scan -

echo -e "\n${YELLOW}Testing SQL Injection:${NC}"
echo '{"query": "SELECT * FROM users WHERE id=1 OR 1=1"}' | ../target/release/kindly-guard scan -

echo -e "\n${YELLOW}Testing XSS:${NC}"
echo '{"input": "<script>alert(\"XSS\")</script>"}' | ../target/release/kindly-guard scan -

# Demo 3: Performance test
echo -e "\n${GREEN}3. Performance Test${NC}"
echo "Creating test files..."

# Small file
echo '{"data": "safe content"}' > perf-small.json

# Medium file (generate ~10KB)
echo '{"users": [' > perf-medium.json
for i in {1..100}; do
    echo '{"id": '$i', "name": "User'$i'", "email": "user'$i'@example.com"},' >> perf-medium.json
done
echo '{"id": 101, "name": "Last", "email": "last@example.com"}]}' >> perf-medium.json

echo -e "\nScanning small file:"
time ../target/release/kindly-guard scan perf-small.json

echo -e "\nScanning medium file:"
time ../target/release/kindly-guard scan perf-medium.json

# Cleanup
rm -f test-input.json perf-small.json perf-medium.json

echo -e "\n${GREEN}Demo Complete!${NC}"
echo -e "This was a quick demo of KindlyGuard's CLI scanner."
echo -e "For the full demo with UI, run: ${BLUE}./showcase.sh${NC}"