#!/bin/bash
# Simple publish script for KindlyGuard v0.15.0

set -e

# Check NPM_TOKEN
if [ -z "$NPM_TOKEN" ]; then
    echo "Error: NPM_TOKEN not set"
    exit 1
fi

# Set auth
npm config set //registry.npmjs.org/:_authToken "$NPM_TOKEN"

# Navigate to package directory
cd "$(dirname "$0")"

# Publish main package
echo "Publishing kindlyguard v0.15.0..."
npm publish --access public

echo "✅ Published successfully!"
echo "Install with: npm install -g kindlyguard"