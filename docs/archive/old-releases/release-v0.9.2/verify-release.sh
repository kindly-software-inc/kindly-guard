#!/bin/bash

echo "KindlyGuard v0.9.2 Release Verification"
echo "======================================="
echo

echo "Release Contents:"
ls -la

echo
echo "Archive Contents:"
tar -tzf kindlyguard-linux-x64.tar.gz

echo
echo "Checksums:"
cat SHA256SUMS.txt

echo
echo "Verifying checksums..."
sha256sum -c SHA256SUMS.txt

echo
echo "File sizes:"
du -h kindlyguard-linux-x64.tar.gz

echo
echo "Release manifest:"
jq . release-manifest.json 2>/dev/null || cat release-manifest.json