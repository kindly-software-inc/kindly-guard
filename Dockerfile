# Build stage
FROM rust:1.84-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY kindly-guard-server/Cargo.toml ./kindly-guard-server/
COPY kindly-guard-cli/Cargo.toml ./kindly-guard-cli/
# Private dependencies handled separately

# Create dummy files to cache dependencies
RUN mkdir -p kindly-guard-server/src kindly-guard-cli/src && \
    echo "fn main() {}" > kindly-guard-server/src/main.rs && \
    echo "" > kindly-guard-server/src/lib.rs && \
    echo "fn main() {}" > kindly-guard-cli/src/main.rs

# Build dependencies
RUN cargo build --release && \
    rm -rf kindly-guard-*/src

# Copy source code
COPY . .

# Build the application
RUN cargo build --release --bin kindly-guard

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -g 1000 kindly && \
    adduser -D -u 1000 -G kindly kindly

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/kindly-guard /usr/local/bin/kindly-guard

# Copy example config
COPY kindly-guard.toml.example /app/kindly-guard.toml.example

# Switch to non-root user
USER kindly

# Expose port (if using HTTP mode)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD echo '{"jsonrpc": "2.0", "method": "security/status", "id": 1}' | kindly-guard || exit 1

# Default command - stdio mode
CMD ["kindly-guard"]