# Multi-stage Dockerfile for KindlyGuard MCP Security Server
# Security-focused build with minimal attack surface

# Build stage
FROM rust:1.75-slim AS builder

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

# Build dependencies only (for caching)
RUN cargo build --release --package kindly-guard-server

# Remove stub files
RUN rm -rf kindly-guard-server/src kindly-guard-cli/src kindly-guard-shield/src crates-io-package/kindlyguard/src

# Copy actual source code
COPY . .

# Change ownership to build user
RUN chown -R builduser:builduser /build

# Switch to build user
USER builduser

# Build the server with secure profile
RUN cargo build --profile=secure --package kindly-guard-server

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies and security tools
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    dumb-init \
    && rm -rf /var/lib/apt/lists/*

# Create runtime user
RUN useradd -m -u 1001 -s /bin/false kindlyguard && \
    mkdir -p /etc/kindly-guard /var/lib/kindly-guard /var/log/kindly-guard && \
    chown -R kindlyguard:kindlyguard /etc/kindly-guard /var/lib/kindly-guard /var/log/kindly-guard

# Copy binary from builder
COPY --from=builder --chown=kindlyguard:kindlyguard /build/target/secure/kindly-guard /usr/local/bin/kindly-guard

# Set up configuration directory
WORKDIR /etc/kindly-guard

# Switch to non-root user
USER kindlyguard

# Expose MCP server port (stdio mode doesn't need ports, but included for TCP mode)
EXPOSE 3000

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/kindly-guard", "health"] || exit 1

# Use dumb-init to handle signals properly
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Default to stdio mode for MCP compatibility
CMD ["/usr/local/bin/kindly-guard", "--config", "/etc/kindly-guard/config.toml", "--stdio"]