# Docker Multi-Platform Build Setup for KindlyGuard

## Overview

This document describes how to build multi-platform Docker images for KindlyGuard using Docker buildx.

## Prerequisites

1. Docker 20.10+ with buildx plugin
2. Docker buildx configured and ready
3. Access to Docker Hub (for pushing images)

## Setup Status

✅ **Docker buildx**: Installed and configured
✅ **Builder instance**: `kindlyguard-builder` created and active
✅ **Supported platforms**: 
   - linux/amd64 ✅
   - linux/arm64 ✅
   - linux/arm/v7 ✅
   - linux/386
   - linux/amd64/v2
   - linux/amd64/v3

## Quick Start

### 1. Single Platform Build (Testing)

```bash
# Build for current platform only
docker buildx build \
  --platform linux/amd64 \
  -t kindlysoftware/kindlyguard:test \
  --load \
  .
```

### 2. Multi-Platform Build (Cache Only)

```bash
# Build for multiple platforms (stays in build cache)
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t kindlysoftware/kindlyguard:0.9.2 \
  -t kindlysoftware/kindlyguard:latest \
  -f Dockerfile.multiplatform \
  .
```

### 3. Multi-Platform Build and Push

```bash
# Build and push to Docker Hub
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t kindlysoftware/kindlyguard:0.9.2 \
  -t kindlysoftware/kindlyguard:latest \
  -f Dockerfile.multiplatform \
  --push \
  .
```

### 4. Using the Build Script

```bash
# Build with default settings (no push)
./build-multiplatform.sh

# Build and push to registry
PUSH=true ./build-multiplatform.sh

# Custom version and platforms
VERSION=0.9.3 PLATFORMS=linux/amd64,linux/arm64 ./build-multiplatform.sh
```

## Builder Management

### Check builder status
```bash
docker buildx ls
```

### Inspect builder details
```bash
docker buildx inspect kindlyguard-builder --bootstrap
```

### Check builder cache usage
```bash
docker buildx du
```

### Clean builder cache
```bash
docker buildx prune
```

## Files Updated

1. **Dockerfile.multiplatform** - Updated for multi-platform support:
   - Updated Rust version from 1.75 to 1.87 (matching regular Dockerfile)
   - Added benchmark stub file creation
   - Fixed binary name from `kindly-guard` to `kindlyguard`
   - Added fallback from secure to release profile

2. **build-multiplatform.sh** - New script for automated builds:
   - Handles builder setup
   - Supports environment variable configuration
   - Provides colored output
   - Shows cache usage

## Known Issues and Solutions

### Issue 1: Cargo.lock Version
- **Problem**: Rust 1.75 doesn't support Cargo.lock v4
- **Solution**: Updated to Rust 1.87 in Dockerfile.multiplatform

### Issue 2: Missing Benchmark Files
- **Problem**: Build fails due to missing benchmark files
- **Solution**: Added benchmark stub creation steps

### Issue 3: Binary Name Mismatch
- **Problem**: Binary is named `kindlyguard` not `kindly-guard`
- **Solution**: Updated COPY commands to use correct name

## Build Performance

- First multi-platform build takes 10-20 minutes (compiling for all platforms)
- Subsequent builds are faster due to Docker layer caching
- Build cache can grow large (9GB+) - clean periodically

## Verification

After building, verify the image architecture:

```bash
# For loaded images (single platform)
docker inspect kindlysoftware/kindlyguard:test | grep Architecture

# For multi-platform images in registry
docker manifest inspect kindlysoftware/kindlyguard:0.9.2
```

## Security Notes

- Images are built with minimal attack surface using distroless base
- Non-root user (UID 1001) for runtime
- Security scanning enabled via labels
- Regular dependency updates recommended

## Next Steps

1. Test the multi-platform build locally
2. Set up CI/CD pipeline for automated builds
3. Configure Docker Hub automated builds
4. Add platform-specific optimizations if needed