# Docker Compose Deployment Guide

This directory contains Docker Compose configurations for deploying KindlyGuard in various environments.

## Available Configurations

### 1. Development/Basic Deployment (`docker-compose.yml`)
Basic single-instance deployment suitable for development and testing.

```bash
# Start the service
docker-compose up -d

# View logs
docker-compose logs -f kindly-guard

# Stop the service
docker-compose down
```

### 2. Production Deployment (`docker-compose.prod.yml`)
Full production stack with monitoring, logging, and high availability.

```bash
# Copy environment template
cp .env.example .env
# Edit .env with your values

# Start all services
docker-compose -f docker-compose.prod.yml up -d

# Scale KindlyGuard instances
docker-compose -f docker-compose.prod.yml up -d --scale kindly-guard=3
```

### 3. Multi-platform Build (`docker-compose.buildx.yml`)
For building multi-architecture images.

```bash
# Setup buildx (first time only)
docker buildx create --use

# Build for multiple platforms
docker-compose -f docker-compose.buildx.yml build

# Build and push to registry
docker buildx bake -f docker-compose.buildx.yml --push
```

## Key Changes for Distroless

The Docker Compose files have been updated to work with the distroless-based container:

1. **Removed `/tmp` volume mount** - Distroless doesn't have `/tmp`
2. **Updated command format** - Matches the Dockerfile CMD format
3. **Removed `RUST_BACKTRACE`** - Not needed in production
4. **Added health check support** - Uses the binary directly

## Directory Structure

```
deploy/
├── nginx/                 # Nginx reverse proxy configuration
│   ├── nginx.conf        # Main nginx configuration
│   └── conf.d/           # Server blocks
├── prometheus/           # Metrics collection
│   └── prometheus.yml    # Prometheus configuration
├── grafana/              # Metrics visualization
│   └── provisioning/     # Auto-provisioned dashboards/datasources
├── loki/                 # Log aggregation
│   └── loki-config.yml   # Loki configuration
├── promtail/             # Log shipping
│   └── promtail-config.yml
└── postgres/             # Database initialization
    └── init.sql          # Schema and initial data
```

## Security Considerations

1. **Read-only root filesystem** - All containers use read-only root
2. **No new privileges** - Security option enabled
3. **Dropped capabilities** - Only necessary capabilities added
4. **Non-root user** - Containers run as UID 1001
5. **Network isolation** - Internal networks for service communication

## SSL/TLS Setup

For production, you need to provide SSL certificates:

```bash
# Create SSL directory
mkdir -p deploy/nginx/ssl

# Copy your certificates
cp /path/to/cert.pem deploy/nginx/ssl/
cp /path/to/key.pem deploy/nginx/ssl/

# Or use Let's Encrypt
docker run -it --rm \
  -v $(pwd)/deploy/nginx/ssl:/etc/letsencrypt \
  certbot/certbot certonly --standalone \
  -d your-domain.com
```

## Monitoring Access

- **Grafana**: http://localhost:3000 (admin/GRAFANA_PASSWORD)
- **Prometheus**: http://localhost:9090 (internal only in production)

## Backup Strategy

The production compose includes automatic backups:

```bash
# Manual backup
docker-compose -f docker-compose.prod.yml exec backup backup

# Restore from backup
docker-compose -f docker-compose.prod.yml down
docker run --rm -v kindly-guard_kindly-guard-data:/data \
  -v $(pwd)/backups:/backup \
  busybox tar -xzf /backup/kindly-guard-backup-2024-01-20.tar.gz -C /
docker-compose -f docker-compose.prod.yml up -d
```

## Troubleshooting

### Container won't start
- Check logs: `docker-compose logs kindly-guard`
- Verify config file exists: `ls -la config/production.toml`
- Ensure proper permissions on volumes

### Health check failing
- Verify the binary supports health command: `docker-compose exec kindly-guard /usr/local/bin/kindly-guard health`
- Check network connectivity between containers

### Performance issues
- Monitor resource usage: `docker stats`
- Check Grafana dashboards for bottlenecks
- Scale instances if needed