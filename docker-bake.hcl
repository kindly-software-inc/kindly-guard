# Docker Bake configuration for KindlyGuard
# This file defines build configurations for docker buildx bake
# Usage: docker buildx bake [target]

# Variables
variable "REGISTRY" {
  default = "docker.io"
}

variable "NAMESPACE" {
  default = "kindlysoftware"
}

variable "IMAGE_NAME" {
  default = "kindly-guard"
}

variable "VERSION" {
  default = "dev"
}

variable "PLATFORMS_DEFAULT" {
  default = ["linux/amd64", "linux/arm64", "linux/arm/v7"]
}

variable "PLATFORMS_ALL" {
  default = ["linux/amd64", "linux/arm64", "linux/arm/v7", "linux/386", "linux/ppc64le", "linux/s390x"]
}

# Functions
function "tags" {
  params = [version]
  result = [
    "${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:${version}",
    version == "latest" ? "${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:latest" : "",
  ]
}

# Groups
group "default" {
  targets = ["multiplatform"]
}

group "all" {
  targets = ["multiplatform-all", "dev", "debug"]
}

# Base target with common settings
target "_common" {
  dockerfile = "Dockerfile.multiplatform"
  context = "."
  args = {
    VERSION = VERSION
    BUILD_DATE = timestamp()
    VCS_REF = "${substr(context("git:commit"), 0, 7)}"
  }
  labels = {
    "org.opencontainers.image.title" = "KindlyGuard"
    "org.opencontainers.image.description" = "Security-focused MCP server for managing sensitive operations"
    "org.opencontainers.image.vendor" = "KindlySoftware"
    "org.opencontainers.image.version" = VERSION
    "org.opencontainers.image.created" = timestamp()
    "org.opencontainers.image.source" = "https://github.com/kindlysoftware/kindly-guard"
  }
}

# Production multi-platform build (default platforms)
target "multiplatform" {
  inherits = ["_common"]
  platforms = PLATFORMS_DEFAULT
  tags = tags(VERSION)
  cache-from = [
    "type=gha",
    "type=registry,ref=${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:buildcache"
  ]
  cache-to = [
    "type=gha,mode=max",
    "type=registry,ref=${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:buildcache,mode=max"
  ]
}

# Production multi-platform build (all platforms)
target "multiplatform-all" {
  inherits = ["_common"]
  platforms = PLATFORMS_ALL
  tags = tags(VERSION)
  cache-from = [
    "type=gha",
    "type=registry,ref=${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:buildcache-all"
  ]
  cache-to = [
    "type=gha,mode=max",
    "type=registry,ref=${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:buildcache-all,mode=max"
  ]
}

# Local development build (single platform)
target "dev" {
  inherits = ["_common"]
  tags = ["${IMAGE_NAME}:dev"]
  platforms = ["linux/amd64"]
  output = ["type=docker"]
  cache-from = ["type=local,src=/tmp/.buildx-cache"]
  cache-to = ["type=local,dest=/tmp/.buildx-cache-new,mode=max"]
}

# Debug build with additional tools
target "debug" {
  inherits = ["_common"]
  dockerfile = "Dockerfile.debug"
  tags = ["${IMAGE_NAME}:debug"]
  platforms = ["linux/amd64"]
  output = ["type=docker"]
  target = "debug"
}

# Specific platform targets for testing
target "amd64" {
  inherits = ["_common"]
  platforms = ["linux/amd64"]
  tags = ["${IMAGE_NAME}:amd64"]
  output = ["type=docker"]
}

target "arm64" {
  inherits = ["_common"]
  platforms = ["linux/arm64"]
  tags = ["${IMAGE_NAME}:arm64"]
  output = ["type=docker"]
}

target "armv7" {
  inherits = ["_common"]
  platforms = ["linux/arm/v7"]
  tags = ["${IMAGE_NAME}:armv7"]
  output = ["type=docker"]
}

# Release target with push
target "release" {
  inherits = ["multiplatform"]
  tags = concat(
    tags(VERSION),
    tags("latest")
  )
  output = ["type=registry"]
}

# Minimal size build
target "minimal" {
  inherits = ["_common"]
  dockerfile = "Dockerfile.minimal"
  platforms = PLATFORMS_DEFAULT
  tags = ["${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:minimal"]
  cache-from = ["type=registry,ref=${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:buildcache-minimal"]
  cache-to = ["type=registry,ref=${REGISTRY}/${NAMESPACE}/${IMAGE_NAME}:buildcache-minimal,mode=max"]
}

# Security scan target
target "security-scan" {
  inherits = ["_common"]
  platforms = ["linux/amd64"]
  tags = ["${IMAGE_NAME}:security-scan"]
  output = ["type=docker"]
  target = "security-scan"
}