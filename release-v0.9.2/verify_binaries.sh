#!/bin/bash
# Verification script for KindlyGuard release binaries

echo "=== KindlyGuard v0.9.2 Release Verification ==="
echo

# Function to check binary
check_binary() {
    local platform=$1
    local binary=$2
    
    if [ -f "$platform/$binary" ]; then
        echo "✅ $platform/$binary:"
        echo "   Size: $(ls -lh "$platform/$binary" | awk '{print $5}')"
        echo "   Type: $(file "$platform/$binary" | cut -d: -f2 | xargs)"
        if [ "$platform" = "linux-x64" ]; then
            echo "   SHA256: $(sha256sum "$platform/$binary" | awk '{print $1}')"
        fi
    else
        echo "❌ $platform/$binary: NOT FOUND"
    fi
    echo
}

# Check Linux x64
echo "### Linux x64 Platform ###"
check_binary "linux-x64" "kindly-guard"
check_binary "linux-x64" "kindly-guard-cli"

# Check Windows x64
echo "### Windows x64 Platform ###"
check_binary "windows-x64" "kindly-guard.exe"
check_binary "windows-x64" "kindly-guard-cli.exe"

# Check macOS x64
echo "### macOS x64 Platform ###"
check_binary "macos-x64" "kindly-guard"
check_binary "macos-x64" "kindly-guard-cli"

# Check macOS ARM64
echo "### macOS ARM64 Platform ###"
check_binary "macos-arm64" "kindly-guard"
check_binary "macos-arm64" "kindly-guard-cli"

# Summary
echo "### Summary ###"
echo "Total platforms with binaries: $(find . -name "kindly-guard*" -type f | grep -v "verify_binaries.sh" | grep -v "RELEASE_NOTES.md" | wc -l | xargs) binaries found"