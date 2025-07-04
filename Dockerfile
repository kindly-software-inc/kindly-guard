# Multi-stage Dockerfile for KindlyGuard MCP Security Server
# Security-focused build with minimal attack surface

# Build stage
FROM rust:1.87-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create build user for security
RUN useradd -m -u 1001 -s /bin/bash builduser

# Set working directory
WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY kindly-guard-server/Cargo.toml ./kindly-guard-server/
COPY kindly-guard-cli/Cargo.toml ./kindly-guard-cli/
COPY kindly-guard-shield/Cargo.toml ./kindly-guard-shield/
COPY crates-io-package/kindlyguard/Cargo.toml ./crates-io-package/kindlyguard/

# Create stub files for dependency caching
RUN mkdir -p kindly-guard-server/src kindly-guard-cli/src kindly-guard-shield/src crates-io-package/kindlyguard/src && \
    echo "fn main() {}" > kindly-guard-server/src/main.rs && \
    touch kindly-guard-server/src/lib.rs && \
    echo "fn main() {}" > kindly-guard-cli/src/main.rs && \
    echo "fn main() {}" > kindly-guard-shield/src/main.rs && \
    touch crates-io-package/kindlyguard/src/lib.rs

# Create stub benchmark files to satisfy Cargo.toml
RUN mkdir -p kindly-guard-server/benches && \
    echo "fn main() {}" > kindly-guard-server/benches/simple_benchmark.rs && \
    echo "fn main() {}" > kindly-guard-server/benches/regression_benchmarks.rs && \
    echo "fn main() {}" > kindly-guard-server/benches/critical_path_benchmarks.rs && \
    echo "fn main() {}" > kindly-guard-server/benches/memory_profile_bench.rs && \
    echo "fn main() {}" > kindly-guard-server/benches/comprehensive_benchmarks.rs && \
    echo "fn main() {}" > kindly-guard-server/benches/rate_limiter_comparison.rs && \
    echo "fn main() {}" > kindly-guard-server/benches/scanner_benchmarks.rs && \
    echo "fn main() {}" > kindly-guard-server/benches/real_world.rs

# Build dependencies only (for caching)
RUN cargo build --release --package kindly-guard-server

# Remove stub files
RUN rm -rf kindly-guard-server/src kindly-guard-cli/src kindly-guard-shield/src crates-io-package/kindlyguard/src kindly-guard-server/benches

# Copy actual source code
COPY . .

# Create stub benchmark files after copying source (since they're excluded by .dockerignore)
RUN mkdir -p kindly-guard-server/benches && \
    for bench in simple_benchmark regression_benchmarks critical_path_benchmarks \
                 memory_profile_bench comprehensive_benchmarks rate_limiter_comparison \
                 scanner_benchmarks real_world cli_bench comparative_benchmarks \
                 display_bench neutralization; do \
        echo "fn main() {}" > kindly-guard-server/benches/${bench}.rs; \
    done && \
    mkdir -p kindly-guard-shield/src-tauri/benches && \
    echo "fn main() {}" > kindly-guard-shield/src-tauri/benches/protocol_benchmark.rs

# Build the server with secure profile (as root for cargo registry access)
# Note: Using release profile as a fallback if secure profile has issues
RUN cargo build --profile=secure --package kindly-guard-server || \
    cargo build --release --package kindly-guard-server

# Copy the built binary to a consistent location
RUN if [ -f /build/target/secure/kindlyguard ]; then \
        cp /build/target/secure/kindlyguard /build/kindly-guard-binary; \
    else \
        cp /build/target/release/kindlyguard /build/kindly-guard-binary; \
    fi

# Change ownership of built artifacts to build user
RUN chown -R builduser:builduser /build/target /build/kindly-guard-binary

# Runtime stage - Using distroless for minimal attack surface
# Pin to specific digest for reproducibility
FROM gcr.io/distroless/cc-debian12:latest@sha256:e1065a1d58800a7294f74e67c32ec4146d09d6cbe471c1fa7ed456b2d2bf06e0 AS runtime-base

# Create directories needed at runtime (distroless doesn't have shell)
FROM debian:bookworm-slim AS runtime-setup
RUN mkdir -p /etc/kindly-guard /var/lib/kindly-guard /var/log/kindly-guard && \
    chmod 755 /etc/kindly-guard /var/lib/kindly-guard /var/log/kindly-guard

# Final runtime stage
FROM runtime-base

# Copy directories from setup stage
COPY --from=runtime-setup /etc/kindly-guard /etc/kindly-guard
COPY --from=runtime-setup /var/lib/kindly-guard /var/lib/kindly-guard
COPY --from=runtime-setup /var/log/kindly-guard /var/log/kindly-guard

# Copy binary from builder with numeric UID
COPY --from=builder --chown=1001:1001 /build/kindly-guard-binary /usr/local/bin/kindly-guard

# Set up configuration directory
WORKDIR /etc/kindly-guard

# Switch to non-root user using numeric UID (distroless doesn't have user names)
USER 1001:1001

# Expose MCP server port (stdio mode doesn't need ports, but included for TCP mode)
EXPOSE 3000

# Add security labels
LABEL org.opencontainers.image.source="https://github.com/kindly-software-inc/kindly-guard"
LABEL org.opencontainers.image.description="Security-focused MCP server protecting against unicode attacks, injection threats, and other AI vulnerabilities"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL security.scan="enabled"
LABEL security.distroless="true"

# Health check for container orchestration
# Using status command which exists in the CLI
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/kindly-guard", "status"] || exit 1

# Default to stdio mode for MCP compatibility
# No shell or init system in distroless, direct execution
CMD ["/usr/local/bin/kindly-guard", "--config", "/etc/kindly-guard/config.toml", "--stdio"]