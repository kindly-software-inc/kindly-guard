#!/bin/bash
set -e

echo "=== Updating Release Workflow ==="

# 1. Let cargo-dist regenerate the workflow
echo "1. Regenerating release workflow with cargo-dist..."
~/.cargo/bin/dist generate --ci=github

# 2. Add cross installation back if it was removed
echo "2. Checking if cross installation needs to be added..."
if ! grep -q "Install cross for cross-compilation" .github/workflows/release.yml; then
    echo "Adding cross installation to release workflow..."
    python3 patch_release.py
fi

# 3. Show the changes
echo "=== Changes to release.yml ==="
git diff .github/workflows/release.yml | head -50

echo "=== Update complete ==="