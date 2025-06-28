#!/bin/bash
# KindlyGuard CLI Shield Integration Demo

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🛡️  KindlyGuard CLI Shield Integration Demo${NC}\n"

# Build if needed
if [ ! -f ./target/debug/kindly-guard-cli ]; then
    echo -e "${YELLOW}Building KindlyGuard...${NC}"
    cargo build --package kindly-guard-cli
fi

# Create alias for convenience
alias kindly-guard="$(pwd)/target/debug/kindly-guard-cli"

echo -e "${GREEN}1. Shield Status Commands:${NC}"
echo -e "   Compact format:"
kindly-guard shield status --format compact
echo -e "\n   Minimal format:"
kindly-guard shield status --format minimal
echo -e "\n   JSON format:"
kindly-guard shield status --format json | jq '.' 2>/dev/null || kindly-guard shield status --format json

echo -e "\n${GREEN}2. Shell Integration:${NC}"
echo -e "   To integrate KindlyGuard into your shell, add this to your ~/.bashrc:"
echo -e "   ${YELLOW}eval \"\$(kindly-guard shell-init bash)\"${NC}"

echo -e "\n${GREEN}3. Simulating Shield with Threats:${NC}"
# Create a test file with threats
cat > /tmp/test-threat.txt << 'EOF'
Normal text here
‮⁦This text appears reversed⁩⁮
SQL injection: ' OR '1'='1
Path traversal: ../../../etc/passwd
Unicode homograph: pаypal.com (with Cyrillic 'а')
EOF

echo -e "   Scanning file with threats..."
kindly-guard scan /tmp/test-threat.txt --format brief

echo -e "\n${GREEN}4. Live Monitoring (press Ctrl+C to stop):${NC}"
echo -e "   Starting monitor for 5 seconds..."
timeout 5 kindly-guard monitor || true

echo -e "\n${BLUE}✅ Demo complete!${NC}"
echo ""
echo "To fully integrate KindlyGuard into your terminal:"
echo "1. Install: cargo install --path kindly-guard-cli"
echo "2. Add to shell: eval \"\$(kindly-guard shell-init bash)\""
echo "3. Restart your terminal"
echo ""
echo "Your terminal prompt will then show the KindlyGuard shield status!"

# Cleanup
rm -f /tmp/test-threat.txt