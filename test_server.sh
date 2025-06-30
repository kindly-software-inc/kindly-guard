#\!/bin/bash

echo "Starting KindlyGuard server..."
echo "Press Ctrl+C to stop"
echo ""

# Start the server with our test config
./target/release/kindly-guard -c test-config.toml --stdio
