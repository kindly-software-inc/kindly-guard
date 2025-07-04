# KindlyGuard Deployment Guide

This directory contains deployment configurations for KindlyGuard MCP Security Server.

## Quick Start

### Docker Deployment

1. **Build the Docker image:**
   ```bash
   docker build -t kindly-guard:latest .
   ```

2. **Configure the application:**
   ```bash
   cp config/production.toml.example config/production.toml
   # Edit config/production.toml with your settings
   ```

3. **Run with Docker Compose:**
   ```bash
   docker-compose up -d
   ```

### Systemd Deployment (Linux)

1. **Build the binary:**
   ```bash
   cargo build --profile=secure
   ```

2. **Run the installation script:**
   ```bash
   cd deploy/systemd
   sudo ./install.sh
   ```

3. **Start the service:**
   ```bash
   sudo systemctl start kindly-guard
   sudo systemctl enable kindly-guard  # Enable auto-start
   ```

## Deployment Options

### 1. Docker (Recommended)

**Files:**
- `Dockerfile` - Multi-stage build with security hardening
- `docker-compose.yml` - Basic deployment
- `docker-compose.prod.yml` - Full production stack with monitoring

**Security Features:**
- Non-root user execution
- Read-only root filesystem
- Dropped capabilities
- Resource limits
- Security options enabled

**Commands:**
```bash
# Basic deployment
docker-compose up -d

# Production deployment with monitoring
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# View logs
docker-compose logs -f kindly-guard

# Update deployment
docker-compose pull
docker-compose up -d
```

### 2. Systemd (Linux Systems)

**Files:**
- `deploy/systemd/kindly-guard.service` - Systemd service unit
- `deploy/systemd/install.sh` - Installation script

**Security Features:**
- Sandboxed execution
- Restricted system calls
- Private /tmp
- Read-only system directories
- Memory and CPU limits

**Commands:**
```bash
# Install
cd deploy/systemd
sudo ./install.sh

# Service management
sudo systemctl start kindly-guard
sudo systemctl stop kindly-guard
sudo systemctl restart kindly-guard
sudo systemctl status kindly-guard

# View logs
sudo journalctl -u kindly-guard -f
```

### 3. Kubernetes (Coming Soon)

Helm charts and Kubernetes manifests will be provided in a future release.

## Configuration

### Environment Variables

KindlyGuard supports environment variable overrides using the pattern:
`KINDLY_GUARD__<SECTION>__<KEY>=value`

Examples:
```bash
KINDLY_GUARD__SERVER__HOST=0.0.0.0
KINDLY_GUARD__SERVER__PORT=3000
KINDLY_GUARD__SCANNER__ENHANCED_MODE=true
KINDLY_GUARD__LOGGING__LEVEL=debug
```

### Configuration File

The main configuration file (`config/production.toml`) supports:
- Server settings (host, port, limits)
- Scanner configuration (threat detection options)
- Authentication (JWT, API keys)
- Rate limiting
- Storage backends (SQLite, PostgreSQL)
- Logging and metrics
- Resilience patterns (circuit breaker, retry)

## Monitoring

### Metrics

Prometheus metrics are exposed at `http://localhost:9090/metrics` when enabled.

Key metrics:
- `kindly_guard_requests_total` - Total requests by endpoint
- `kindly_guard_threats_detected` - Threats detected by type
- `kindly_guard_scan_duration` - Scan performance
- `kindly_guard_circuit_breaker_state` - Circuit breaker status

### Health Checks

Health endpoint: `GET /health`

Returns:
```json
{
  "status": "healthy",
  "version": "0.2.0",
  "uptime_seconds": 3600,
  "components": {
    "scanner": "healthy",
    "storage": "healthy",
    "cache": "healthy"
  }
}
```

### Logging

Structured JSON logs include:
- Request tracing
- Threat detection events
- Performance metrics
- Error tracking
- Audit trail (when enabled)

## Security Considerations

### Network Security

1. **Default Configuration:**
   - Binds to localhost only
   - Use reverse proxy for external access
   - Enable TLS/SSL termination at proxy

2. **Firewall Rules:**
   ```bash
   # Allow only from trusted sources
   sudo ufw allow from 10.0.0.0/8 to any port 3000
   ```

### Authentication

1. **JWT Authentication:**
   - Configure trusted issuers
   - Set appropriate expiration
   - Use RS256 or ES256 algorithms

2. **API Key Authentication:**
   - Generate strong keys
   - Rotate regularly
   - Store hashed in config

### Secrets Management

1. **Docker Secrets:**
   ```yaml
   secrets:
     db_password:
       external: true
   ```

2. **Environment Files:**
   ```bash
   # Create .env file (don't commit!)
   DB_PASSWORD=secure_password
   REDIS_PASSWORD=another_secure_password
   ```

### Hardening Checklist

- [ ] Change default passwords
- [ ] Enable authentication
- [ ] Configure rate limiting
- [ ] Set up TLS/SSL
- [ ] Enable audit logging
- [ ] Configure backups
- [ ] Set resource limits
- [ ] Enable monitoring
- [ ] Configure log rotation
- [ ] Set up firewall rules

## Backup and Recovery

### Automated Backups

The production docker-compose includes automated backup service:
- Daily backups
- 7-day retention
- Compressed archives
- Includes database and application data

### Manual Backup

```bash
# Backup data
docker run --rm -v kindly-guard_kindly-guard-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/kindly-guard-backup-$(date +%Y%m%d).tar.gz -C /data .

# Restore data
docker run --rm -v kindly-guard_kindly-guard-data:/data -v $(pwd):/backup \
  alpine tar xzf /backup/kindly-guard-backup-20240101.tar.gz -C /data
```

## Troubleshooting

### Common Issues

1. **Service won't start:**
   - Check logs: `docker-compose logs` or `journalctl -u kindly-guard`
   - Validate config: `kindly-guard config validate`
   - Check permissions on data directories

2. **High memory usage:**
   - Adjust `max_content_size` in scanner config
   - Reduce `buffer_size_mb` in event processor
   - Enable memory limits in deployment

3. **Performance issues:**
   - Enable enhanced mode if licensed
   - Increase worker threads
   - Check rate limiting settings
   - Review scanner depth settings

### Debug Mode

Enable debug logging:
```bash
RUST_LOG=kindly_guard=debug,tower_http=debug kindly-guard server
```

## Support

- Documentation: https://github.com/samduchaine/kindly-guard
- Issues: https://github.com/samduchaine/kindly-guard/issues
- Security: security@kindlyguard.com