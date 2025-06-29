#\!/bin/bash

# Send multiple requests to test the server
(
echo '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0.0"}},"id":1}'
sleep 0.1
echo '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}'
sleep 0.1
echo '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"scan_text","arguments":{"text":"Hello\u202EWorld"}},"id":3}'
sleep 0.1
echo '{"jsonrpc":"2.0","method":"security/status","params":{},"id":4}'
sleep 0.1
echo '{"jsonrpc":"2.0","method":"shutdown","params":{},"id":5}'
)  < /dev/null |  ./target/release/kindly-guard --stdio 2>&1 | grep -E '^{' | jq -c '.'
