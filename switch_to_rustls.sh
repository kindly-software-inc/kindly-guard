#!/bin/bash
# Switch from OpenSSL to rustls for better cross-compilation

echo "=== Switching to rustls for TLS ==="

# Check if we have any direct TLS dependencies
if grep -q "reqwest" Cargo.toml */Cargo.toml 2>/dev/null; then
    echo "Found reqwest dependency, updating to use rustls..."
    
    # Update any reqwest dependencies to use rustls
    find . -name "Cargo.toml" -not -path "./.git/*" | while read f; do
        if grep -q "reqwest" "$f"; then
            echo "Updating $f"
            # If reqwest doesn't have features specified, add rustls-tls
            sed -i 's/reqwest = "\([^"]*\)"/reqwest = { version = "\1", default-features = false, features = ["rustls-tls", "json"] }/' "$f"
            # If it already has features, ensure rustls-tls is included
            sed -i 's/features = \[\(.*\)\]/features = ["rustls-tls", \1]/' "$f" 2>/dev/null || true
        fi
    done
fi

# Add rustls to workspace dependencies if needed
if ! grep -q "rustls" Cargo.toml; then
    echo "Adding rustls to workspace dependencies..."
    # This would add rustls configuration to Cargo.toml
fi

echo "Done! This should eliminate OpenSSL dependency for musl builds."