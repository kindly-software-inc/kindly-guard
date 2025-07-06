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
