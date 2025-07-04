#!/bin/bash

# Simple test to see shield display

echo "Testing shield display for 5 seconds..."
timeout 5 ./target/release/kindly-guard --config minimal-config.toml --shield status