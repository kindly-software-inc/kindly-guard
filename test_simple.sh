#!/bin/bash
# Simple test of MCP server

echo "Testing KindlyGuard MCP server..."

# Build first
echo "Building..."
cargo build --bin kindly-guard --release 2>/dev/null

# Create test input
cat > test_input.txt << EOF
{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}
{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}
{"jsonrpc":"2.0","method":"shutdown","params":{},"id":3}
EOF

echo "Running server with test input..."
./target/release/kindly-guard --stdio < test_input.txt 2>server_errors.log

echo -e "\nServer errors (if any):"
cat server_errors.log

# Cleanup
rm -f test_input.txt server_errors.log