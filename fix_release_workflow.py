#!/usr/bin/env python3
import re

# Read the backup file as a template
with open('.github/workflows/release-cargo-dist.yml.backup', 'r') as f:
    content = f.read()

# Update Ubuntu version to 22.04
content = content.replace('ubuntu-20.04', 'ubuntu-22.04')

# Find the install dependencies step and enhance it
deps_pattern = r'(- name: Install dependencies \(Ubuntu\)\s*\n\s*if: startsWith\(matrix\.os, \'ubuntu\'\)\s*\n\s*run: \|\s*\n\s*sudo apt-get update\s*\n\s*sudo apt-get install -y libssl-dev pkg-config)'

enhanced_deps = r'''\1
          # Install musl tools for musl targets
          if [[ "${{ matrix.target }}" == *"musl"* ]]; then
            sudo apt-get install -y musl-tools
          fi'''

content = re.sub(deps_pattern, enhanced_deps, content)

# Add a new step for musl OpenSSL setup before the build step
build_pattern = r'(- name: Build release binary)'

musl_setup_step = '''      - name: Setup musl tools and OpenSSL
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

content = re.sub(build_pattern, musl_setup_step, content)

# Update the build step to add environment variables
build_run_pattern = r'(- name: Build release binary\s*\n\s*run: \|\s*\n)'

build_run_replacement = r'''\1          # Set OpenSSL environment variables for musl targets
          if [[ "${{ matrix.target }}" == *"musl"* ]]; then
            export OPENSSL_STATIC=1
            export PKG_CONFIG_ALLOW_CROSS=1
            export PKG_CONFIG_ALL_STATIC=1
            export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
            # Use vendored OpenSSL if system OpenSSL fails
            export OPENSSL_NO_VENDOR=0
          fi
          
          '''

content = re.sub(build_run_pattern, build_run_replacement, content)

# Update package artifacts to use the correct binary name
content = content.replace('kindly-guard-server', 'kindlyguard')
content = content.replace('kindly-guard-cli', 'kindlyguard')
content = content.replace('kindly-guard\n', 'kindlyguard\n')
content = content.replace('kindly-guard.exe', 'kindlyguard.exe')
content = content.replace('-Path kindly-guard-server.exe,kindly-guard-cli.exe,kindly-guard.exe', '-Path kindlyguard.exe')

# Write the fixed workflow
with open('.github/workflows/release.yml', 'w') as f:
    f.write(content)

print("Fixed release.yml with proper OpenSSL musl support and correct binary names")