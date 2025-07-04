#!/bin/bash

# Pre-commit hook to check version consistency
# Add this to .git/hooks/pre-commit or integrate with your pre-commit framework

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run the version validation
if ! "$SCRIPT_DIR/validate-versions.sh"; then
    echo ""
    echo "Version mismatch detected!"
    echo "Please ensure all versions are consistent before committing."
    echo ""
    echo "You can run './scripts/validate-versions.sh --fix' to automatically update versions."
    exit 1
fi

# If we get here, all versions match
exit 0