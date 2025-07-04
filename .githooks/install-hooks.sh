#!/bin/bash
#
# Install Git hooks for KindlyGuard
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_DIR="$(git -C "$SCRIPT_DIR" rev-parse --git-dir)"
HOOKS_DIR="$GIT_DIR/hooks"

echo "Installing KindlyGuard Git hooks..."

# Create hooks directory if it doesn't exist
mkdir -p "$HOOKS_DIR"

# Install pre-commit hook
if [ -L "$HOOKS_DIR/pre-commit" ]; then
    echo "Removing existing pre-commit symlink..."
    rm "$HOOKS_DIR/pre-commit"
elif [ -f "$HOOKS_DIR/pre-commit" ]; then
    echo "Backing up existing pre-commit hook..."
    mv "$HOOKS_DIR/pre-commit" "$HOOKS_DIR/pre-commit.backup.$(date +%Y%m%d_%H%M%S)"
fi

echo "Installing pre-commit hook..."
ln -sf ../../.githooks/pre-commit "$HOOKS_DIR/pre-commit"

# Verify installation
if [ -L "$HOOKS_DIR/pre-commit" ] && [ -e "$HOOKS_DIR/pre-commit" ]; then
    echo "✓ Pre-commit hook installed successfully!"
    echo ""
    echo "The hook will prevent commits containing:"
    echo "  - Hierarchical rate limiter references"
    echo "  - Atomic event buffer implementation details"
    echo "  - Proprietary performance metrics"
    echo ""
    echo "To test the hook: ./.githooks/pre-commit"
    echo "To bypass (NOT RECOMMENDED): git commit --no-verify"
else
    echo "✗ Failed to install pre-commit hook"
    exit 1
fi