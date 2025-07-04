#!/bin/bash

# Setup git commit template for KindlyGuard project

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Setting up KindlyGuard commit template..."

# Set the commit template for this repository
git config --local commit.template "$PROJECT_ROOT/.gitmessage"

echo "✓ Commit template configured for this repository"
echo ""
echo "To use globally for all projects:"
echo "  git config --global commit.template $PROJECT_ROOT/.gitmessage"
echo ""
echo "The template will be shown when you run 'git commit' without -m flag."