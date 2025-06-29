#\!/bin/bash

echo "🧪 Testing KindlyGuard Server..."

# Test 1: Initialize
echo -e "\n📍 Test 1: Initialize"
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocol_version":"2024-11-05","capabilities":{},"client_info":{"name":"test-client","version":"1.0.0"}},"id":1}'  < /dev/null |  ./target/release/kindly-guard --stdio

echo ""
