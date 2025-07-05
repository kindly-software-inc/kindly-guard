#!/bin/bash
# Test script to build and run xtask doctor command

cd /home/samuel/kindly-guard

# Build just the xtask binary
cargo build -p xtask 2>/dev/null

# Run the doctor command if build succeeded
if [ -f target/debug/xtask ]; then
    echo "Running xtask doctor command..."
    ./target/debug/xtask doctor
else
    echo "Failed to build xtask. Checking for existing binary..."
    # Try to run existing binary
    if command -v xtask &> /dev/null; then
        xtask doctor
    else
        echo "xtask binary not found"
        exit 1
    fi
fi