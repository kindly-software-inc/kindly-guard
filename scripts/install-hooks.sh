#!/bin/bash
# Install git hooks for the project

set -e

echo "🔧 Installing git hooks..."

# Configure git to use our hooks directory
git config core.hooksPath .githooks

echo "✅ Git hooks installed successfully!"
echo ""
echo "The following hooks are now active:"
echo "  - pre-commit: Prevents committing forbidden terms"
echo ""
echo "To bypass hooks temporarily (NOT RECOMMENDED):"
echo "  git commit --no-verify"
echo ""
echo "To uninstall hooks:"
echo "  git config --unset core.hooksPath"