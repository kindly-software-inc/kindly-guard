#!/bin/bash

echo "Testing KindlyGuard with Plugin System"
echo "======================================="
echo ""

# Create a test input with various threats
cat > test_input.json << EOF
{
  "method": "test",
  "params": {
    "sql": "SELECT * FROM users WHERE id = '1' OR '1'='1'",
    "xss": "<script>alert('XSS')</script>",
    "command": "ls; cat /etc/passwd",
    "unicode": "Hello\u202EWorld",
    "clean": "This is a clean message"
  }
}
EOF

# Run the scanner with plugins enabled
echo "Running scanner with plugins enabled..."
KINDLY_GUARD_CONFIG=kindly-guard-plugins.toml cargo run --release -- scan test_input.json

# Clean up
rm test_input.json

echo ""
echo "Test complete!"