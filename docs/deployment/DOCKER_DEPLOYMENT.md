# Docker Deployment Guide for KindlyGuard

## Table of Contents
- [Overview](#overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Multi-Platform Builds](#multi-platform-builds)
- [Production Deployment](#production-deployment)
- [Docker Compose](#docker-compose)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Security Best Practices](#security-best-practices)
- [Monitoring and Logging](#monitoring-and-logging)
- [Troubleshooting](#troubleshooting)
- [Performance Tuning](#performance-tuning)

## Overview

KindlyGuard provides official Docker images for easy deployment across various environments. Our images are:
- **Multi-platform**: Supporting linux/amd64, linux/arm64, and linux/arm/v7
- **Minimal**: Alpine-based for smaller attack surface
- **Secure**: Non-root user, read-only filesystem compatible
- **Production-ready**: Health checks, graceful shutdown, signal handling

## Installation

### Prerequisites
- Docker 20.10+ or Docker Desktop
- Docker Compose 2.0+ (for multi-container deployments)
- 512MB available RAM minimum
- 100MB available disk space

### Pull the Official Image

```bash
# Latest stable version
docker pull kindlysoftware/kindlyguard:latest

# Specific version
docker pull kindlysoftware/kindlyguard:0.9.2

# For ARM devices (auto-selected on ARM platforms)
docker pull kindlysoftware/kindlyguard:latest-arm64
```

### Verify Image Signature (Recommended)

```bash
# Download public key
curl -fsSL https://keys.kindly.software/docker-signing.pub | gpg --import

# Verify image signature
docker trust inspect kindlysoftware/kindlyguard:latest
```

## Quick Start

### Basic Usage

```bash
# Run in stdio mode (for MCP integration)
docker run -it kindlysoftware/kindlyguard:latest --stdio

# Run with custom configuration
docker run -it \
  -v $(pwd)/config:/etc/kindlyguard:ro \
  kindlysoftware/kindlyguard:latest

# Run with persistent storage
docker run -it \
  -v kindlyguard-data:/var/lib/kindlyguard \
  kindlysoftware/kindlyguard:latest
```

### Environment Variables

```bash
# Run with environment configuration
docker run -it \
  -e RUST_LOG=info \
  -e KINDLY_PORT=8080 \
  -e KINDLY_AUTH_ENABLED=true \
  -e KINDLY_AUTH_SECRET="your-secret-here" \
  kindlysoftware/kindlyguard:latest
```

## Configuration

### Volume Mounts

KindlyGuard uses several directories that can be mounted as volumes:

| Path | Purpose | Mode |
|------|---------|------|
| `/etc/kindlyguard` | Configuration files | Read-only |
| `/var/lib/kindlyguard` | Persistent data (SQLite, cache) | Read-write |
| `/var/log/kindlyguard` | Log files | Read-write |
| `/tmp/kindlyguard` | Temporary files | Read-write |

### Configuration File

Create a `kindlyguard.yaml` file:

```yaml
# /etc/kindlyguard/kindlyguard.yaml
server:
  host: "0.0.0.0"
  port: 8080
  workers: 4

scanner:
  unicode_detection: true
  injection_detection: true
  xss_protection: true
  pattern_matching: true

auth:
  enabled: true
  token_lifetime: 3600
  allowed_clients:
    - client_id: "docker-client"
      secret: "$2b$10$..."  # bcrypt hash
      allowed_scopes: ["tools:execute", "resources:read"]

storage:
  type: "sqlite"
  path: "/var/lib/kindlyguard/kindly.db"
  cache_size: 1000

logging:
  level: "info"
  format: "json"
  output: "/var/log/kindlyguard/server.log"
```

### Environment Variable Override

All configuration values can be overridden via environment variables:

```bash
# Format: KINDLY_<SECTION>_<KEY>
KINDLY_SERVER_PORT=9090
KINDLY_SCANNER_UNICODE_DETECTION=false
KINDLY_AUTH_ENABLED=true
KINDLY_LOGGING_LEVEL=debug
```

## Multi-Platform Builds

### Building for Multiple Architectures

```bash
# Setup buildx (one time)
docker buildx create --name kindly-builder --use
docker buildx inspect --bootstrap

# Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t kindlysoftware/kindlyguard:latest \
  --push .
```

### Platform-Specific Optimizations

```dockerfile
# In Dockerfile
FROM --platform=$BUILDPLATFORM rust:1.76-alpine AS builder
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Platform-specific compilation flags
RUN case "$TARGETPLATFORM" in \
    "linux/amd64") RUSTFLAGS="-C target-cpu=x86-64-v2" ;; \
    "linux/arm64") RUSTFLAGS="-C target-cpu=cortex-a72" ;; \
    "linux/arm/v7") RUSTFLAGS="-C target-cpu=cortex-a7" ;; \
    esac && \
    cargo build --release --target-dir /target
```

## Production Deployment

### Docker Compose Production Setup

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  kindlyguard:
    image: kindlysoftware/kindlyguard:0.9.2
    container_name: kindlyguard-prod
    restart: unless-stopped
    user: "10001:10001"  # Non-root user
    read_only: true      # Read-only root filesystem
    cap_drop:
      - ALL              # Drop all capabilities
    cap_add:
      - NET_BIND_SERVICE # Only if binding to port < 1024
    security_opt:
      - no-new-privileges:true
    volumes:
      - ./config:/etc/kindlyguard:ro
      - kindly-data:/var/lib/kindlyguard
      - kindly-logs:/var/log/kindlyguard
      - /tmp/kindlyguard:/tmp/kindlyguard
    environment:
      - RUST_LOG=info
      - KINDLY_SERVER_WORKERS=8
      - KINDLY_AUTH_ENABLED=true
    ports:
      - "127.0.0.1:8080:8080"  # Only expose locally
    healthcheck:
      test: ["CMD", "/usr/local/bin/kindlyguard", "health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 128M
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "service=kindlyguard"

  # Reverse proxy for TLS termination
  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - kindlyguard

volumes:
  kindly-data:
    driver: local
  kindly-logs:
    driver: local
```

### Nginx Configuration for TLS

```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream kindlyguard {
        server kindlyguard:8080;
        keepalive 32;
    }

    server {
        listen 80;
        server_name your-domain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        ssl_certificate /etc/nginx/certs/cert.pem;
        ssl_certificate_key /etc/nginx/certs/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        location / {
            proxy_pass http://kindlyguard;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # WebSocket support for MCP
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
```

## Kubernetes Deployment

### Basic Deployment

```yaml
# kindlyguard-deployment.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kindlyguard
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: kindlyguard-config
  namespace: kindlyguard
data:
  kindlyguard.yaml: |
    server:
      host: "0.0.0.0"
      port: 8080
    scanner:
      unicode_detection: true
      injection_detection: true
    # ... rest of config
---
apiVersion: v1
kind: Secret
metadata:
  name: kindlyguard-secrets
  namespace: kindlyguard
type: Opaque
stringData:
  auth-secret: "your-secret-here"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kindlyguard
  namespace: kindlyguard
  labels:
    app: kindlyguard
spec:
  replicas: 3
  selector:
    matchLabels:
      app: kindlyguard
  template:
    metadata:
      labels:
        app: kindlyguard
    spec:
      serviceAccountName: kindlyguard
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
      containers:
      - name: kindlyguard
        image: kindlysoftware/kindlyguard:0.9.2
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: RUST_LOG
          value: "info"
        - name: KINDLY_AUTH_SECRET
          valueFrom:
            secretKeyRef:
              name: kindlyguard-secrets
              key: auth-secret
        volumeMounts:
        - name: config
          mountPath: /etc/kindlyguard
          readOnly: true
        - name: data
          mountPath: /var/lib/kindlyguard
        - name: logs
          mountPath: /var/log/kindlyguard
        - name: tmp
          mountPath: /tmp/kindlyguard
        resources:
          requests:
            memory: "128Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: http
          initialDelaySeconds: 5
          periodSeconds: 10
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: config
        configMap:
          name: kindlyguard-config
      - name: data
        emptyDir: {}
      - name: logs
        emptyDir: {}
      - name: tmp
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: kindlyguard
  namespace: kindlyguard
spec:
  selector:
    app: kindlyguard
  ports:
  - port: 80
    targetPort: 8080
    name: http
  type: ClusterIP
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: kindlyguard-pdb
  namespace: kindlyguard
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: kindlyguard
```

### Helm Chart

```bash
# Install via Helm
helm repo add kindly https://charts.kindly.software
helm install kindlyguard kindly/kindlyguard \
  --namespace kindlyguard \
  --create-namespace \
  --set image.tag=0.9.2 \
  --set auth.enabled=true \
  --set persistence.enabled=true
```

## Security Best Practices

### 1. Use Non-Root User

```dockerfile
# Already configured in official image
USER 10001:10001
```

### 2. Read-Only Root Filesystem

```yaml
# docker-compose.yml
services:
  kindlyguard:
    read_only: true
    tmpfs:
      - /tmp/kindlyguard
```

### 3. Resource Limits

```yaml
# Always set resource limits
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 512M
```

### 4. Network Isolation

```yaml
# Use custom networks
networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true

services:
  kindlyguard:
    networks:
      - backend
```

### 5. Secrets Management

```bash
# Use Docker secrets
echo "your-secret" | docker secret create kindly-auth-secret -

# In docker-compose.yml
services:
  kindlyguard:
    secrets:
      - kindly-auth-secret
    environment:
      - KINDLY_AUTH_SECRET_FILE=/run/secrets/kindly-auth-secret

secrets:
  kindly-auth-secret:
    external: true
```

### 6. Security Scanning

```bash
# Scan for vulnerabilities
docker scout cves kindlysoftware/kindlyguard:latest

# Or use Trivy
trivy image kindlysoftware/kindlyguard:latest
```

## Monitoring and Logging

### Prometheus Metrics

```yaml
# docker-compose.yml with monitoring
services:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

### Log Aggregation

```yaml
# Fluentd configuration
services:
  fluentd:
    image: fluent/fluentd:v1.16-debian
    volumes:
      - ./fluent.conf:/fluentd/etc/fluent.conf
      - kindly-logs:/var/log/kindlyguard:ro
```

### Health Monitoring

```bash
# Built-in health endpoint
curl http://localhost:8080/health

# Response
{
  "status": "healthy",
  "version": "0.9.2",
  "uptime": 3600,
  "scanner": {
    "threats_detected": 42,
    "requests_processed": 1000
  }
}
```

## Troubleshooting

### Common Issues

#### 1. Container Won't Start

```bash
# Check logs
docker logs kindlyguard

# Common fixes:
# - Ensure config file is valid YAML
# - Check file permissions (should be readable by UID 10001)
# - Verify volume mounts exist
```

#### 2. Permission Denied Errors

```bash
# Fix ownership
docker run --rm -v kindly-data:/data alpine \
  chown -R 10001:10001 /data
```

#### 3. High Memory Usage

```bash
# Monitor memory
docker stats kindlyguard

# Adjust cache settings
KINDLY_STORAGE_CACHE_SIZE=500  # Reduce from default 1000
```

#### 4. Connection Refused

```bash
# Verify container is running
docker ps | grep kindlyguard

# Check port binding
docker port kindlyguard

# Test connectivity
docker exec kindlyguard wget -O- http://localhost:8080/health
```

### Debug Mode

```bash
# Run with debug logging
docker run -it \
  -e RUST_LOG=debug \
  -e RUST_BACKTRACE=1 \
  kindlysoftware/kindlyguard:latest
```

### Interactive Shell

```bash
# Access container shell for debugging
docker run -it --entrypoint /bin/sh \
  kindlysoftware/kindlyguard:latest

# Or exec into running container
docker exec -it kindlyguard /bin/sh
```

## Performance Tuning

### CPU Optimization

```yaml
# Optimize for multi-core
environment:
  - KINDLY_SERVER_WORKERS=0  # Auto-detect CPU cores
  - TOKIO_WORKER_THREADS=4   # Async runtime threads
```

### Memory Optimization

```yaml
# Tune for low memory environments
environment:
  - KINDLY_STORAGE_CACHE_SIZE=100
  - KINDLY_SCANNER_MAX_DEPTH=5
  - RUST_LOG=warn  # Reduce logging overhead
```

### Network Optimization

```yaml
# Enable keep-alive and connection pooling
environment:
  - KINDLY_SERVER_KEEP_ALIVE=75
  - KINDLY_SERVER_CLIENT_TIMEOUT=30
```

### Storage Optimization

```bash
# Use tmpfs for temporary files
docker run -v kindly-tmp:/tmp/kindlyguard:tmpfs \
  kindlysoftware/kindlyguard:latest

# Or mount host SSD
docker run -v /mnt/ssd/kindly:/var/lib/kindlyguard \
  kindlysoftware/kindlyguard:latest
```

## Advanced Configurations

### Multi-Stage Deployment

```yaml
# docker-compose.multi-stage.yml
version: '3.8'

services:
  kindlyguard-primary:
    extends:
      file: docker-compose.base.yml
      service: kindlyguard
    environment:
      - KINDLY_ROLE=primary
      - KINDLY_CLUSTER_ENABLED=true

  kindlyguard-secondary:
    extends:
      file: docker-compose.base.yml
      service: kindlyguard
    environment:
      - KINDLY_ROLE=secondary
      - KINDLY_PRIMARY_URL=http://kindlyguard-primary:8080
    depends_on:
      - kindlyguard-primary
```

### Custom Entrypoint

```bash
#!/bin/sh
# custom-entrypoint.sh

# Pre-flight checks
echo "Running pre-flight checks..."
if [ ! -f /etc/kindlyguard/kindlyguard.yaml ]; then
    echo "ERROR: Configuration file not found!"
    exit 1
fi

# Start with custom args
exec /usr/local/bin/kindlyguard "$@"
```

### Signal Handling

KindlyGuard properly handles Unix signals:
- `SIGTERM`: Graceful shutdown
- `SIGINT`: Immediate shutdown
- `SIGHUP`: Reload configuration (future feature)
- `SIGUSR1`: Dump statistics to log

```bash
# Graceful shutdown
docker stop --time=30 kindlyguard
```

## Migration Guide

### From Native Installation

```bash
# 1. Export existing configuration
kindlyguard config export > kindlyguard.yaml

# 2. Copy data files
cp -r /var/lib/kindlyguard ./data

# 3. Run Docker with migrated data
docker run -v $(pwd)/kindlyguard.yaml:/etc/kindlyguard/kindlyguard.yaml:ro \
           -v $(pwd)/data:/var/lib/kindlyguard \
           kindlysoftware/kindlyguard:latest
```

### Version Upgrades

```bash
# 1. Backup current data
docker run --rm -v kindly-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/kindly-backup.tar.gz /data

# 2. Stop current version
docker-compose down

# 3. Update image version
docker-compose pull

# 4. Start new version
docker-compose up -d

# 5. Verify health
docker-compose ps
docker-compose logs --tail=50
```

## Support

For Docker-specific issues:
- GitHub Issues: https://github.com/kindlyguard/kindlyguard/issues
- Docker Hub: https://hub.docker.com/r/kindlysoftware/kindlyguard
- Documentation: https://docs.kindly.software/docker

---

**Note**: This guide assumes familiarity with Docker. For KindlyGuard-specific configuration, see the [Configuration Guide](CONFIGURATION.md).