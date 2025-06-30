#\!/bin/bash

echo "Starting KindlyGuard with Shield Display..."
echo "==========================================="
echo ""
echo "The shield will show real-time threat detection."
echo "Send some test requests to see it in action\!"
echo ""

# Run the server with shield display
./target/release/kindly-guard --shield
