#!/bin/bash
# Quick fix for CI - check if we can manually trigger a retry

echo "=== Quick CI Status Check and Fix ==="

cd /home/samuel/kindly-guard

# 1. Check current git status
echo "Current git status:"
git status --short

# 2. Check if there are uncommitted dist-related changes
if git diff --name-only | grep -E "(dist\.toml|Cargo\.toml)"; then
    echo "Found uncommitted dist configuration changes"
    git add Cargo.toml
    git commit -m "fix(ci): Update dist configuration" || echo "No changes to commit"
    git push origin master
fi

# 3. Re-trigger the v0.11.9 workflow
echo -e "\n=== Re-triggering v0.11.9 release ==="
gh workflow run release.yml --ref v0.11.9

echo -e "\n=== Monitoring new run ==="
sleep 5
gh run list --workflow=release.yml --limit 5

echo -e "\nTo watch the run progress, use:"
echo "gh run watch"