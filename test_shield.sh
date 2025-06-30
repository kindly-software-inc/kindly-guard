#!/bin/bash

# Test KindlyGuard with shield display in a pseudo-terminal
echo "Testing KindlyGuard with shield display..."

# Create a test script that runs in a pty
cat > run_with_pty.py << 'EOF'
import pty
import os
import sys
import time
import subprocess

# Run the command in a pseudo-terminal
master, slave = pty.openpty()

# Start the process
proc = subprocess.Popen(
    ["./target/release/kindly-guard", "--shield", "--config", "test-config.toml"],
    stdin=slave,
    stdout=slave,
    stderr=slave,
    close_fds=True
)

# Close slave fd in parent
os.close(slave)

# Read output for a few seconds
start_time = time.time()
while time.time() - start_time < 3:
    try:
        data = os.read(master, 1024)
        if data:
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
    except OSError:
        break
    time.sleep(0.1)

# Terminate the process
proc.terminate()
proc.wait()
os.close(master)
EOF

# Enable shield in config
sed -i 's/\[shield\]\nenabled = false/[shield]\nenabled = true/' test-config.toml

# Run with pty
python3 run_with_pty.py

# Clean up
rm -f run_with_pty.py