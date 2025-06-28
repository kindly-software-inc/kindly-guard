#!/bin/bash
# Test script for KindlyGuard MCP server

echo "Testing KindlyGuard MCP server..."
echo

# Test 1: Simple text scan
echo '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}' | cargo run --bin kindly-guard

echo
echo "Test complete. Check output above for MCP response."