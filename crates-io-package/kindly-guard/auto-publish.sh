#!/bin/bash

echo "🚀 Auto-publishing KindlyGuard crate to crates.io..."
echo ""

# Run tests
echo "Running tests..."
cargo test --quiet
if [ $? -ne 0 ]; then
    echo "❌ Tests failed! Please fix before publishing."
    exit 1
fi
echo "✅ Tests passed"
echo ""

# Package validation
echo "Validating package..."
cargo package --list > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "❌ Package validation failed!"
    exit 1
fi
echo "✅ Package is valid"
echo ""

# Show what will be published
echo "Files to be published:"
cargo package --list
echo ""

# Publish the crate
echo "Publishing to crates.io..."
cargo publish

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 Success! The 'kindlyguard' crate is now reserved on crates.io!"
    echo "📦 View it at: https://crates.io/crates/kindlyguard"
    echo ""
    echo "📝 Important: For security, please:"
    echo "   1. Go to https://crates.io/settings/tokens"
    echo "   2. Revoke the token you just used"
    echo "   3. Create a new token for future use"
else
    echo ""
    echo "❌ Publishing failed. The crate name might already be taken."
fi