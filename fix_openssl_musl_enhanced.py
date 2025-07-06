#!/usr/bin/env python3
import re

# Read the release workflow
with open('.github/workflows/release.yml', 'r') as f:
    content = f.read()

# Find the build release binary step and enhance it
build_step_pattern = r'(- name: Build release binary\s*\n\s*run: \|)'

# Enhanced build step with better OpenSSL handling
enhanced_build_step = '''      - name: Setup musl tools and OpenSSL
        if: matrix.target == 'x86_64-unknown-linux-musl'
        run: |
          sudo apt-get update
          sudo apt-get install -y musl-tools musl-dev
          # Install static OpenSSL for musl
          sudo apt-get install -y libssl-dev pkg-config
          # Set environment variables for musl OpenSSL
          echo "OPENSSL_STATIC=1" >> $GITHUB_ENV
          echo "OPENSSL_DIR=/usr" >> $GITHUB_ENV
          echo "PKG_CONFIG_ALLOW_CROSS=1" >> $GITHUB_ENV
          echo "PKG_CONFIG_ALL_STATIC=1" >> $GITHUB_ENV
          echo "CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc" >> $GITHUB_ENV
          # Additional OpenSSL configuration
          echo "OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu" >> $GITHUB_ENV
          echo "OPENSSL_INCLUDE_DIR=/usr/include" >> $GITHUB_ENV

\1'''

# Apply the enhanced fix
content = re.sub(build_step_pattern, enhanced_build_step, content)

# Also update the build step to use the environment variables properly
build_command_pattern = r'(# Set OpenSSL environment variables for musl targets\s*\n\s*if \[\[ "\$\{\{ matrix\.target \}\}" == \*"musl"\* \]\]; then\s*\n\s*export OPENSSL_STATIC=1\s*\n\s*export PKG_CONFIG_ALLOW_CROSS=1\s*\n\s*export PKG_CONFIG_ALL_STATIC=1\s*\n\s*fi)'

# Replace with enhanced version
build_command_replacement = '''# Set OpenSSL environment variables for musl targets
          if [[ "${{ matrix.target }}" == *"musl"* ]]; then
            export OPENSSL_STATIC=1
            export PKG_CONFIG_ALLOW_CROSS=1
            export PKG_CONFIG_ALL_STATIC=1
            export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
            # Use vendored OpenSSL if system OpenSSL fails
            export OPENSSL_NO_VENDOR=0
          fi'''

content = re.sub(build_command_pattern, build_command_replacement, content, flags=re.DOTALL)

# Write the enhanced workflow
with open('.github/workflows/release.yml', 'w') as f:
    f.write(content)

print("Enhanced release.yml with better OpenSSL musl support")