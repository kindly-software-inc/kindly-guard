#!/bin/bash
# Check if all versions are synchronized

set -e

# Get the main version from root Cargo.toml
MAIN_VERSION=$(grep -E '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')

echo "Main version: $MAIN_VERSION"

# Check all Cargo.toml files
MISMATCHED=0
find . -name "Cargo.toml" -type f ! -path "./target/*" ! -path "./.git/*" ! -path "*/node_modules/*" | while read -r file; do
    if grep -q "^version = " "$file"; then
        VERSION=$(grep -E '^version = ' "$file" | head -1 | sed 's/version = "\(.*\)"/\1/')
        if [ "$VERSION" != "$MAIN_VERSION" ]; then
            echo "Mismatch in $file: $VERSION (expected $MAIN_VERSION)"
            MISMATCHED=1
        fi
    fi
done

if [ $MISMATCHED -eq 0 ]; then
    echo "All versions are synchronized!"
    exit 0
else
    echo "Version mismatch detected!"
    exit 1
fi