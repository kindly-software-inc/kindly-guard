#!/bin/bash

# KindlyGuard Crates.io Publishing Script
# This script helps publish the placeholder package to reserve the name

set -e

echo "=== KindlyGuard Crates.io Publisher ==="
echo ""

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo "Error: cargo is not installed. Please install Rust first."
    exit 1
fi

# Check if we're in the correct directory
if [ ! -f "Cargo.toml" ]; then
    echo "Error: Cargo.toml not found. Please run this script from the kindlyguard directory."
    exit 1
fi

# Step 1: Check if logged in to crates.io
echo "Step 1: Checking crates.io login status..."
if ! cargo login --help > /dev/null 2>&1; then
    echo "Error: Cannot check login status."
    echo "Please run: cargo login <your-api-token>"
    echo "Get your API token from: https://crates.io/me"
    exit 1
fi

echo "✓ Cargo login available"
echo ""
echo "Make sure you're logged in with: cargo login <your-api-token>"
echo "Press Enter to continue or Ctrl+C to abort..."
read

# Step 2: Run tests
echo ""
echo "Step 2: Running tests..."
cargo test

# Step 3: Check package validity
echo ""
echo "Step 3: Validating package..."
cargo package --list

# Step 4: Perform a dry run
echo ""
echo "Step 4: Performing dry run..."
cargo publish --dry-run

# Step 5: Final confirmation
echo ""
echo "=== Ready to Publish ==="
echo "Package: kindlyguard"
echo "Version: 0.0.1"
echo "Author: samduchaine"
echo ""
echo "This will reserve the 'kindlyguard' name on crates.io."
echo ""
echo "Press Enter to publish or Ctrl+C to abort..."
read

# Step 6: Publish
echo ""
echo "Publishing to crates.io..."
cargo publish

echo ""
echo "✓ Successfully published kindlyguard v0.0.1!"
echo ""
echo "Next steps:"
echo "1. Verify at: https://crates.io/crates/kindlyguard"
echo "2. Update the main kindly-guard repo when ready for full release"