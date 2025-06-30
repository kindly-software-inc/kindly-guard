#!/bin/bash

echo "==================================================="
echo "   KindlyGuard Shield Demo - Universal Display     "
echo "==================================================="
echo ""
echo "This demo shows how KindlyGuard's shield display works"
echo "in any environment - including Claude Code!"
echo ""

# Build first
echo "Building KindlyGuard..."
cd /home/samuel/kindly-guard
cargo build --release 2>/dev/null

echo -e "\n1. Starting server with shield enabled..."
echo "   (This would normally show a terminal UI, but we'll see the universal display)"
echo ""

# Start server in background with config
cd /home/samuel/kindly-guard
timeout 5s ./target/release/kindly-guard --shield --config test-config.toml 2>&1 | grep -v "warning:" &
SERVER_PID=$!

sleep 1

echo -e "\n2. Checking shield status via /kindlyguard command:"
./kindlyguard status

echo -e "\n3. Enabling advanced security mode:"
./kindlyguard advancedsecurity enable

echo -e "\n4. Shield status with advanced mode:"
./kindlyguard status

echo -e "\n5. Testing threat detection:"
echo "   Scanning text with unicode attack..."
./kindlyguard scan "Hello \u202e World" --text

echo -e "\n6. Checking telemetry:"
./kindlyguard telemetry --detailed

echo -e "\n7. Viewing all features:"
./kindlyguard info

echo -e "\n8. Status file contents:"
if [ -f /tmp/kindlyguard-status.json ]; then
    echo "Status saved to /tmp/kindlyguard-status.json:"
    cat /tmp/kindlyguard-status.json | python3 -m json.tool 2>/dev/null | head -20
fi

echo -e "\n9. Dashboard command (would start web UI on port 3000):"
echo "   ./kindlyguard dashboard --port 3000"
echo "   (Not running to avoid blocking)"

echo -e "\n==================================================="
echo "Demo complete! KindlyGuard's universal display works everywhere:"
echo "• In terminals without TTY support"
echo "• In Claude Code, Gemini CLI, Codex"
echo "• Via status files for programmatic access"
echo "• Through a clean web dashboard"
echo ""
echo "The /kindlyguard command provides consistent access to all features!"
echo "==================================================="

# Cleanup
kill $SERVER_PID 2>/dev/null || true