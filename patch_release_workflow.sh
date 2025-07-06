#!/bin/bash
set -e

# Script to generate a patch for the release workflow
echo "🔧 Generating patch for release workflow to add cross support..."

# Create a patch file
cat > release_workflow.patch << 'EOF'
--- a/.github/workflows/release.yml
+++ b/.github/workflows/release.yml
@@ -128,6 +128,15 @@ jobs:
           merge-multiple: true
       - name: Install dependencies
         run: |
+          # Install cross for cross-compilation support
+          if [[ "${{ matrix.targets }}" == *"linux"* ]] && [[ "${{ matrix.runner }}" == "ubuntu"* ]]; then
+            echo "Installing cross for Linux cross-compilation..."
+            cargo install cross --git https://github.com/cross-rs/cross
+            # Ensure cross uses our Cross.toml configuration
+            export CROSS_CONFIG=$PWD/Cross.toml
+            echo "CROSS_CONFIG=$PWD/Cross.toml" >> $GITHUB_ENV
+            echo "CARGO_DIST_CARGO_BUILD_WRAPPER=cross" >> $GITHUB_ENV
+          fi
           ${{ matrix.packages_install }}
       - name: Build artifacts
         run: |
EOF

echo "✅ Patch created: release_workflow.patch"

# Also create a direct modification suggestion
echo ""
echo "📝 Or you can directly modify .github/workflows/release.yml"
echo "Add this after line 128 (in the 'Install dependencies' step):"
echo ""
cat << 'EOF'
          # Install cross for cross-compilation support
          if [[ "${{ matrix.targets }}" == *"linux"* ]] && [[ "${{ matrix.runner }}" == "ubuntu"* ]]; then
            echo "Installing cross for Linux cross-compilation..."
            cargo install cross --git https://github.com/cross-rs/cross
            # Ensure cross uses our Cross.toml configuration
            export CROSS_CONFIG=$PWD/Cross.toml
            echo "CROSS_CONFIG=$PWD/Cross.toml" >> $GITHUB_ENV
            echo "CARGO_DIST_CARGO_BUILD_WRAPPER=cross" >> $GITHUB_ENV
          fi
EOF

echo ""
echo "📋 Alternative approach - Update workspace Cargo.toml:"
echo "Add this to the [workspace.metadata.dist] section:"
echo ""
echo '[workspace.metadata.dist.dependencies.apt]'
echo 'gcc-aarch64-linux-gnu = "*"'
echo 'g++-aarch64-linux-gnu = "*"'
echo ''
echo '[workspace.metadata.dist.cargo-build-config]'
echo 'enable-cross = true'