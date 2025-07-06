#!/usr/bin/env python3
import re

# Read the release workflow
with open('.github/workflows/release.yml', 'r') as f:
    content = f.read()

# Find the build job and add OpenSSL setup for musl
# We need to add a step before the actual build
build_step_pattern = r'(- name: Build Release Binary\s*\n\s*run: \|)'

# Create the OpenSSL setup step
openssl_setup = '''      - name: Setup musl tools and OpenSSL
        if: matrix.target == 'x86_64-unknown-linux-musl'
        run: |
          sudo apt-get update
          sudo apt-get install -y musl-tools musl-dev
          # Install OpenSSL for musl
          sudo apt-get install -y pkg-config libssl-dev
          # Set environment variables for musl OpenSSL
          echo "OPENSSL_STATIC=1" >> $GITHUB_ENV
          echo "OPENSSL_DIR=/usr" >> $GITHUB_ENV
          echo "PKG_CONFIG_ALLOW_CROSS=1" >> $GITHUB_ENV
          echo "PKG_CONFIG_ALL_STATIC=1" >> $GITHUB_ENV
          # For cross compilation
          echo "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc" >> $GITHUB_ENV

\1'''

# Apply the fix
content = re.sub(build_step_pattern, openssl_setup, content)

# Also need to handle the cross build case
cross_pattern = r'(\s*if \[ "\$USE_CROSS" = "true" \]; then)'
cross_fix = '''          # Set OpenSSL environment for cross compilation
          if [ "${{ matrix.target }}" = "x86_64-unknown-linux-musl" ]; then
            export OPENSSL_STATIC=1
            export PKG_CONFIG_ALLOW_CROSS=1
            export PKG_CONFIG_ALL_STATIC=1
          fi
\1'''

content = re.sub(cross_pattern, cross_fix, content)

# Write the fixed workflow
with open('.github/workflows/release.yml', 'w') as f:
    f.write(content)

print("Fixed release.yml with OpenSSL musl support")