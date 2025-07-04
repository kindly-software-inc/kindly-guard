# Docker Multi-Platform Build Guide for KindlyGuard

This guide documents the multi-platform Docker build setup for KindlyGuard, enabling builds for various architectures including linux/amd64, linux/arm64, linux/arm/v7, and more.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Supported Platforms](#supported-platforms)
- [Quick Start](#quick-start)
- [Build Scripts](#build-scripts)
- [Docker Bake](#docker-bake)
- [CI/CD Integration](#cicd-integration)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Overview

KindlyGuard supports multi-platform Docker builds using Docker Buildx, allowing the same container image to run on different CPU architectures. This is essential for:

- Running on ARM-based servers (AWS Graviton, Raspberry Pi)
- Supporting diverse deployment environments
- Providing native performance across platforms
- Reducing the need for emulation

## Prerequisites

1. **Docker 19.03+** with buildx plugin
2. **Docker Desktop** (includes buildx) or **Docker Engine** with experimental features enabled
3. **QEMU** for cross-platform emulation (automatically installed by our scripts)

To check if buildx is available:
```bash
docker buildx version
```

## Supported Platforms

### Primary Platforms (Well-tested)
- `linux/amd64` - Standard x86_64 Linux
- `linux/arm64` - 64-bit ARM (AWS Graviton, Apple Silicon under Linux)
- `linux/arm/v7` - 32-bit ARM (Raspberry Pi 2/3)

### Secondary Platforms (Experimental)
- `linux/386` - 32-bit x86
- `linux/ppc64le` - PowerPC 64-bit Little Endian
- `linux/s390x` - IBM Z mainframes

## Quick Start

### 1. Build for Multiple Platforms (Local)

```bash
# Make scripts executable
chmod +x scripts/*.sh

# Build for default platforms (amd64, arm64, arm/v7)
./scripts/build-docker-multiplatform.sh

# Build and push to registry
./scripts/build-docker-multiplatform.sh --push

# Build for specific platforms
./scripts/build-docker-multiplatform.sh --platforms linux/amd64,linux/arm64
```

### 2. Using Docker Compose with Buildx

```bash
# Build using docker-compose with buildx
docker-compose -f docker-compose.buildx.yml build

# Run on specific platform
DOCKER_DEFAULT_PLATFORM=linux/arm64 docker-compose -f docker-compose.buildx.yml up
```

### 3. Using Docker Bake

```bash
# Build default targets
docker buildx bake

# Build all platforms
docker buildx bake all

# Build for release
VERSION=1.0.0 docker buildx bake release --push

# Build specific platform for testing
docker buildx bake arm64
```

## Build Scripts

### build-docker-multiplatform.sh

Main build script with extensive options:

```bash
# Show help
./scripts/build-docker-multiplatform.sh --help

# Build with registry cache
./scripts/build-docker-multiplatform.sh --registry-cache --push

# Build with local cache
./scripts/build-docker-multiplatform.sh --local-cache

# Clean up builder after build
./scripts/build-docker-multiplatform.sh --cleanup
```

### test-multiplatform-build.sh

Test builds across platforms:

```bash
# Test required platforms only
./scripts/test-multiplatform-build.sh

# Test all platforms including optional
./scripts/test-multiplatform-build.sh --optional

# Quick test (amd64 and arm64 only)
./scripts/test-multiplatform-build.sh --quick
```

### publish-docker.sh

Publish to Docker Hub:

```bash
# Requires DOCKER_USERNAME and DOCKER_TOKEN in .env
./scripts/publish-docker.sh
```

## Docker Bake

Docker Bake provides a high-level build configuration:

### Available Targets

- `default` - Build for primary platforms
- `multiplatform` - Production build for default platforms
- `multiplatform-all` - Build for all supported platforms
- `dev` - Local development build (amd64 only)
- `debug` - Debug build with additional tools
- `release` - Release build with push to registry
- `minimal` - Minimal size optimized build
- Platform-specific: `amd64`, `arm64`, `armv7`

### Examples

```bash
# Build default target
docker buildx bake

# Build with custom registry
REGISTRY=ghcr.io NAMESPACE=myorg docker buildx bake

# Build specific version
VERSION=2.0.0 docker buildx bake release --push

# Build multiple targets
docker buildx bake dev debug
```

## CI/CD Integration

### GitHub Actions

The `.github/workflows/docker-multiplatform.yml` workflow automatically:

1. Builds images for multiple platforms on push to main
2. Creates and pushes manifest lists
3. Tags releases appropriately
4. Runs platform-specific tests on PRs

### Manual Workflow Dispatch

Trigger builds manually via GitHub UI with custom parameters:

- **platforms**: Target platforms (comma-separated)
- **push_image**: Whether to push to registry

## Testing

### Local Platform Testing

```bash
# Test all platforms
./scripts/test-multiplatform-build.sh

# Test with custom Dockerfile
./scripts/test-multiplatform-build.sh --dockerfile Dockerfile.custom
```

### Running Platform-Specific Images

```bash
# Run ARM64 image on AMD64 with emulation
docker run --platform linux/arm64 kindly-guard:latest --help

# Inspect multi-platform image
docker buildx imagetools inspect kindlysoftware/kindly-guard:latest
```

## Troubleshooting

### Common Issues

1. **"buildx not found"**
   - Install Docker Desktop or enable experimental features
   - Run: `docker buildx install`

2. **"failed to solve: exec format error"**
   - QEMU not properly installed
   - Run: `docker run --rm --privileged multiarch/qemu-user-static --reset -p yes`

3. **Build fails for specific platform**
   - Check Rust target support for the platform
   - Verify cross-compilation toolchain in Dockerfile
   - Check build logs: `/tmp/build-<platform>.log`

4. **"no builder instance found"**
   - Create builder: `docker buildx create --use --name mybuilder`

5. **Slow builds**
   - Use registry cache: `--registry-cache`
   - Build only needed platforms
   - Use GitHub Actions for CI builds

### Debugging Builds

```bash
# Verbose build output
docker buildx build --progress=plain --platform linux/arm64 .

# Inspect builder
docker buildx inspect kindly-guard-builder

# Check builder logs
docker logs buildx_buildkit_kindly-guard-builder0
```

### Platform-Specific Notes

#### ARM64 (aarch64)
- Requires `gcc-aarch64-linux-gnu` for cross-compilation
- May need additional time for builds
- Native builds on ARM64 hosts are faster

#### ARM/v7 (armhf)
- 32-bit ARM requires specific Rust targets
- Limited memory on some devices
- Consider minimal builds for embedded systems

#### PowerPC and S390x
- Experimental support
- May require additional dependencies
- Test thoroughly before production use

## Best Practices

1. **Cache Strategy**
   - Use registry cache for CI/CD
   - Use local cache for development
   - Clean cache periodically

2. **Platform Selection**
   - Build only required platforms
   - Use `linux/amd64,linux/arm64` for most cloud deployments
   - Add platforms as needed

3. **Image Size**
   - Multi-stage builds reduce size
   - Platform-specific optimizations in Dockerfile
   - Use minimal base images

4. **Security**
   - Scan images for vulnerabilities
   - Use specific versions, not `latest`
   - Sign images with cosign

5. **Testing**
   - Test on actual target platforms when possible
   - Use emulation for basic verification
   - Implement platform-specific tests

## Advanced Configuration

### Custom Builder Configuration

```bash
# Create builder with custom config
docker buildx create \
  --name custom-builder \
  --driver docker-container \
  --driver-opt network=host \
  --config /path/to/buildkitd.toml
```

### Using BuildKit Features

```dockerfile
# In Dockerfile
# syntax=docker/dockerfile:1.4

# Use cache mounts
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release

# Use secrets
RUN --mount=type=secret,id=mytoken \
    TOKEN=$(cat /run/secrets/mytoken) ./build.sh
```

### Manifest Manipulation

```bash
# Create manifest manually
docker manifest create kindly-guard:latest \
  kindly-guard:amd64 \
  kindly-guard:arm64

# Annotate manifest
docker manifest annotate kindly-guard:latest \
  kindly-guard:arm64 --arch arm64

# Push manifest
docker manifest push kindly-guard:latest
```

## Conclusion

The multi-platform build setup enables KindlyGuard to run efficiently across diverse architectures. Use the provided scripts and configurations to build, test, and deploy platform-specific images as needed.