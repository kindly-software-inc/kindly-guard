#!/bin/bash

# Build script for Kindly-Guard Chrome Extension

echo "Building Kindly-Guard extension..."

# Create dist directory
mkdir -p dist

# Copy manifest
cp manifest.json dist/

# Copy source files
cp -r src dist/
cp -r assets dist/

# Create zip for Chrome Web Store
cd dist
zip -r ../kindly-guard-claude-ai.zip *
cd ..

echo "Build complete! Files:"
echo "  - dist/         (unpacked extension)"
echo "  - kindly-guard-claude-ai.zip (for Chrome Web Store)"

# Generate icons if needed
if [ ! -f "assets/icon-128.png" ]; then
  echo ""
  echo "Note: PNG icons not found. To generate them:"
  echo "  1. Run: node src/utils/generate-icons.js"
  echo "  2. Open assets/generate-icons.html in a browser"
  echo "  3. Save each canvas as icon-{size}.png"
fi