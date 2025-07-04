#!/bin/bash
# Auto-generated publish script

set -e

echo "Publishing KindlyGuard 0.9.1 packages..."

# Publish platform packages first
echo "Publishing @kindlyguard/linux-x64..."
cd npm/kindlyguard-linux-x64 && npm publish --access public
cd ../..

echo "Publishing @kindlyguard/darwin-x64..."
cd npm/kindlyguard-darwin-x64 && npm publish --access public
cd ../..

echo "Publishing @kindlyguard/darwin-arm64..."
cd npm/kindlyguard-darwin-arm64 && npm publish --access public
cd ../..

echo "Publishing @kindlyguard/win32-x64..."
cd npm/kindlyguard-win32-x64 && npm publish --access public
cd ../..

# Wait a moment for packages to be available
echo "Waiting for platform packages to be available..."
sleep 10

# Publish main package
echo "Publishing main kindlyguard package..."
npm publish

echo "All packages published successfully!"
