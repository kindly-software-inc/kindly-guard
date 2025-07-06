#!/bin/bash
# Fix CI for v0.11.9

echo "=== Fixing CI for v0.11.9 ==="

# 1. First, let's install cargo-dist locally to regenerate the workflow
echo "Installing cargo-dist..."
cargo install cargo-dist --version 0.25.1

# 2. Regenerate the release workflow
echo "Regenerating release workflow..."
cd /home/samuel/kindly-guard
cargo dist init --yes

# 3. Check if the workflow was updated
if [ -f .github/workflows/release.yml ]; then
    echo "Release workflow regenerated successfully"
    
    # 4. Commit the updated workflow
    git add .github/workflows/release.yml
    git commit -m "fix(ci): Regenerate release.yml with cargo-dist 0.25.1" || echo "No changes to commit"
    
    # 5. Push the fix
    git push origin master
    
    echo "Fix pushed. The CI should now work for v0.11.9"
else
    echo "ERROR: Failed to regenerate release workflow"
    exit 1
fi

echo "=== Done ==="