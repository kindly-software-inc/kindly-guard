#!/bin/bash
# Update all versions to the specified version

set -e

NEW_VERSION="${1:-0.15.0}"

echo "Updating all versions to: $NEW_VERSION"

# Update all Cargo.toml files (except in node_modules and target)
find . -name "Cargo.toml" -type f ! -path "./target/*" ! -path "./.git/*" ! -path "*/node_modules/*" | while read -r file; do
    if grep -q "^version = " "$file"; then
        echo "Updating $file"
        sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" "$file"
    fi
done

# Update package.json files if they exist
find . -name "package.json" -type f ! -path "./target/*" ! -path "./.git/*" ! -path "*/node_modules/*" | while read -r file; do
    if grep -q "\"version\":" "$file"; then
        echo "Updating $file"
        sed -i "s/\"version\": \".*\"/\"version\": \"$NEW_VERSION\"/" "$file"
    fi
done

echo "Version update complete!"