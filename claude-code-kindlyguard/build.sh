#!/bin/bash

echo "Building KindlyGuard Extension for Claude Code..."

# Install dependencies
echo "Installing dependencies..."
npm install

# Compile TypeScript
echo "Compiling TypeScript..."
npm run compile

# Create distribution directory
echo "Creating distribution..."
mkdir -p dist
cp -r out/* dist/
cp package.json dist/
cp extension.manifest.json dist/
cp README.md dist/

echo "Build complete! Extension ready in ./dist"