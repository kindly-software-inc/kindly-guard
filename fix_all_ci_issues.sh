#!/bin/bash
set -e

echo "=== Comprehensive CI Fix for KindlyGuard ==="

# 1. Ensure cargo-dist is properly configured
echo "1. Checking cargo-dist configuration..."
if ! grep -q "cargo-dist-version" Cargo.toml; then
    echo "Adding cargo-dist configuration to Cargo.toml..."
    cat >> Cargo.toml << 'EOCONFIG'

[workspace.metadata.dist]
cargo-dist-version = "0.25.1"
ci = ["github"]
installers = ["shell", "powershell"]
targets = [
    "aarch64-apple-darwin",
    "x86_64-apple-darwin", 
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc"
]
pr-run-mode = "skip"
allow-dirty = ["ci"]

[workspace.metadata.dist.github-custom-runners]
aarch64-unknown-linux-gnu = "ubuntu-latest"
x86_64-unknown-linux-musl = "ubuntu-latest"
EOCONFIG
fi

# 2. Generate release workflow with cargo-dist
echo "2. Generating release workflow..."
if command -v dist &> /dev/null || [ -f ~/.cargo/bin/dist ]; then
    echo "cargo-dist is already installed"
    ~/.cargo/bin/dist init --yes --ci=github
    ~/.cargo/bin/dist generate --ci=github
else
    echo "Installing cargo-dist v0.25.1 (compatible with current Rust)..."
    cargo install cargo-dist --version 0.25.1
    ~/.cargo/bin/dist init --yes --ci=github
    ~/.cargo/bin/dist generate --ci=github
fi

# 3. Fix the generated release.yml to include cross
echo "3. Fixing release.yml to support cross-compilation..."
if [ -f .github/workflows/release.yml ]; then
    # Create a Python script to properly patch the workflow
    cat > patch_release.py << 'EOPYTHON'
#!/usr/bin/env python3
import re
import sys

try:
    with open('.github/workflows/release.yml', 'r') as f:
        content = f.read()

    # Add cross installation after cargo-dist
    if "Install cargo-dist" in content and "Install cross" not in content:
        pattern = r'(- name: Install cargo-dist.*?\n.*?with:.*?\n.*?tool: cargo-dist.*?\n.*?tag:[^\n]+)'
        replacement = r'''\1

      - name: Install cross for cross-compilation
        if: ${{ startsWith(matrix.runner, 'ubuntu') && (contains(join(matrix.targets, ','), 'aarch64') || contains(join(matrix.targets, ','), 'musl')) }}
        uses: taiki-e/install-action@v2
        with:
          tool: cross'''
        
        content = re.sub(pattern, replacement, content, flags=re.DOTALL)
        
        # Add environment variable for cross
        pattern2 = r'(- name: Build archives\s*\n)(\s*run:)'
        replacement2 = r'''\1        env:
          CARGO_DIST_CARGO_BUILD_WRAPPER: ${{ (startsWith(matrix.runner, 'ubuntu') && (contains(join(matrix.targets, ','), 'aarch64') || contains(join(matrix.targets, ','), 'musl'))) && 'cross' || '' }}
\2'''
        
        content = re.sub(pattern2, replacement2, content)
        
        with open('.github/workflows/release.yml', 'w') as f:
            f.write(content)
        
        print("Successfully patched release.yml")
    else:
        print("release.yml already patched or has unexpected format")
        
except Exception as e:
    print(f"Error patching release.yml: {e}")
    sys.exit(1)
EOPYTHON

    python3 patch_release.py
fi

# 4. Ensure Cross.toml is properly configured
echo "4. Checking Cross.toml configuration..."
if [ ! -f Cross.toml ]; then
    echo "Creating Cross.toml..."
    cat > Cross.toml << 'EOCROSS'
# Cross compilation configuration

[target.x86_64-pc-windows-gnu]
image = "ghcr.io/cross-rs/x86_64-pc-windows-gnu:latest"

[target.x86_64-unknown-linux-musl]
image = "ghcr.io/cross-rs/x86_64-unknown-linux-musl:latest"

[target.aarch64-unknown-linux-gnu]
image = "ghcr.io/cross-rs/aarch64-unknown-linux-gnu:latest"

[target.x86_64-unknown-linux-gnu]
image = "ghcr.io/cross-rs/x86_64-unknown-linux-gnu:latest"
EOCROSS
fi

echo "=== CI fixes complete ==="
echo "Changes made:"
git status --short