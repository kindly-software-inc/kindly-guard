# Production Deployment Guide

This guide covers deploying KindlyGuard in production environments with best practices for security, performance, and reliability.

## Prerequisites

- Linux server (Ubuntu 20.04+ or RHEL 8+)
- Rust 1.75.0+ (for building from source)
- Docker (optional, for container deployment)
- systemd (for service management)
- TLS certificates (if using HTTPS transport)

## Deployment Options

### 1. Binary Deployment

#### Download Pre-built Binary

```bash
# Download latest release
wget https://github.com/yourusername/kindly-guard/releases/latest/download/kindly-guard-linux-x86_64.tar.gz

# Extract
tar xzf kindly-guard-linux-x86_64.tar.gz

# Install
sudo install -m 755 kindly-guard /usr/local/bin/

# Verify installation
kindly-guard --version
```

#### Build from Source

```bash
# Clone repository
git clone https://github.com/yourusername/kindly-guard.git
cd kindly-guard

# Build release binary
cargo build --release

# Install
sudo install -m 755 target/release/kindly-guard /usr/local/bin/
```

### 2. Docker Deployment

```bash
# Pull image
docker pull kindlyguard/kindly-guard:latest

# Run container
docker run -d \
  --name kindly-guard \
  --restart unless-stopped \
  -v /etc/kindly-guard:/etc/kindly-guard:ro \
  -v /var/log/kindly-guard:/var/log/kindly-guard \
  --memory="512m" \
  --cpus="1.0" \
  kindlyguard/kindly-guard:latest
```

### 3. Systemd Service

```bash
# Install service files
sudo ./systemd/install.sh

# Start service
sudo systemctl start kindly-guard
sudo systemctl enable kindly-guard

# Check status
sudo systemctl status kindly-guard
```

## Production Configuration

### 1. Create Configuration File

```bash
sudo mkdir -p /etc/kindly-guard
sudo cp kindly-guard.toml.example /etc/kindly-guard/config.toml
sudo chmod 600 /etc/kindly-guard/config.toml
```

### 2. Essential Settings

Edit `/etc/kindly-guard/config.toml`:

```toml
# Server Configuration
[server]
mode = "stdio"  # or "http" for HTTP transport
host = "127.0.0.1"  # Bind to localhost only
port = 8080

# Security Scanner
[scanner]
unicode_detection = true
injection_detection = true
path_traversal_detection = true
max_scan_depth = 10

# Authentication (REQUIRED for production)
[auth]
enabled = true
require_signature_verification = true
jwt_secret = "YOUR_BASE64_ENCODED_SECRET_HERE"  # Generate with: openssl rand -base64 32
trusted_issuers = ["https://auth.yourcompany.com"]

# Rate Limiting
[rate_limit]
enabled = true
requests_per_minute = 100
burst_size = 20
penalty_factor = 0.5

# Logging
[logging]
level = "info"
format = "json"
output = "/var/log/kindly-guard/server.log"

# Performance
[performance]
event_processor_enabled = false  # Enable only if needed
thread_pool_size = 4
max_concurrent_requests = 100
```

### 3. Generate JWT Secret

```bash
# Generate secure secret
openssl rand -base64 32

# Or using Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Security Hardening

### 1. File Permissions

```bash
# Set correct ownership
sudo chown -R kindly-guard:kindly-guard /etc/kindly-guard
sudo chown -R kindly-guard:kindly-guard /var/log/kindly-guard

# Restrict permissions
sudo chmod 750 /etc/kindly-guard
sudo chmod 640 /etc/kindly-guard/config.toml
sudo chmod 750 /var/log/kindly-guard
```

### 2. Systemd Security

The provided systemd service includes security hardening:

```ini
# Security settings in kindly-guard.service
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/kindly-guard
MemoryLimit=512M
TasksMax=100
```

### 3. Firewall Rules

```bash
# If using HTTP mode, restrict access
sudo ufw allow from 10.0.0.0/8 to any port 8080
sudo ufw deny 8080

# Or with iptables
sudo iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 8080 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP
```

### 4. TLS Configuration

If using HTTP transport:

```toml
[server.tls]
enabled = true
cert_file = "/etc/kindly-guard/tls/cert.pem"
key_file = "/etc/kindly-guard/tls/key.pem"
min_version = "1.2"
```

## Monitoring

### 1. Health Checks

```bash
# Check service status
systemctl is-active kindly-guard

# Check logs for errors
journalctl -u kindly-guard -p err -n 50

# Monitor resource usage
systemctl status kindly-guard
```

### 2. Log Monitoring

```bash
# Watch for threats
tail -f /var/log/kindly-guard/server.log | jq 'select(.threat_detected == true)'

# Monitor rate limiting
tail -f /var/log/kindly-guard/server.log | jq 'select(.rate_limit_exceeded == true)'

# Track authentication failures
tail -f /var/log/kindly-guard/server.log | jq 'select(.auth_failed == true)'
```

### 3. Metrics Collection

```bash
# Export metrics for Prometheus (coming soon)
curl http://localhost:9090/metrics

# Or use built-in stats
echo '{"jsonrpc":"2.0","method":"security/status","params":{},"id":1}' | kindly-guard --stdio
```

## Performance Tuning

### 1. System Limits

```bash
# Increase file descriptors
echo "kindly-guard soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "kindly-guard hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Apply sysctl settings
sudo tee /etc/sysctl.d/99-kindly-guard.conf <<EOF
net.core.somaxconn = 1024
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.ip_local_port_range = 10000 65535
EOF
sudo sysctl -p /etc/sysctl.d/99-kindly-guard.conf
```

### 2. Memory Configuration

```toml
[performance]
# Adjust based on available memory
event_buffer_size_mb = 100  # If using enhanced mode
pattern_cache_size = 10000
max_request_size_mb = 10
```

### 3. CPU Optimization

```bash
# Pin to specific CPUs
sudo systemctl set-property kindly-guard.service CPUAffinity=0-3

# Set CPU quota (percentage)
sudo systemctl set-property kindly-guard.service CPUQuota=200%
```

## High Availability

### 1. Load Balancing

Use HAProxy or nginx for load balancing:

```nginx
upstream kindly_guard {
    least_conn;
    server 10.0.1.10:8080 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8080 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:8080 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl;
    location /mcp {
        proxy_pass http://kindly_guard;
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### 2. Health Check Endpoint

Configure health checks in your load balancer:

```bash
# Health check command
echo '{"jsonrpc":"2.0","method":"ping","params":{},"id":1}' | nc localhost 8080
```

## Backup and Recovery

### 1. Configuration Backup

```bash
# Backup configuration
sudo tar czf /backup/kindly-guard-config-$(date +%Y%m%d).tar.gz /etc/kindly-guard/

# Restore configuration
sudo tar xzf /backup/kindly-guard-config-20240101.tar.gz -C /
```

### 2. Log Rotation

```bash
# Create logrotate config
sudo tee /etc/logrotate.d/kindly-guard <<EOF
/var/log/kindly-guard/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 kindly-guard kindly-guard
    postrotate
        systemctl reload kindly-guard
    endscript
}
EOF
```

## Troubleshooting

### Common Issues

1. **Service won't start**
   ```bash
   # Check logs
   journalctl -xeu kindly-guard
   
   # Verify configuration
   kindly-guard --config /etc/kindly-guard/config.toml --check
   ```

2. **High memory usage**
   ```bash
   # Check for memory leaks
   systemctl show kindly-guard | grep Memory
   
   # Restart if needed
   sudo systemctl restart kindly-guard
   ```

3. **Performance issues**
   ```bash
   # Check CPU usage
   top -p $(pgrep kindly-guard)
   
   # Profile with perf
   sudo perf top -p $(pgrep kindly-guard)
   ```

### Debug Mode

Enable debug logging temporarily:

```bash
# Set debug level
sudo systemctl edit kindly-guard

# Add environment override
[Service]
Environment="RUST_LOG=kindly_guard=debug"

# Restart
sudo systemctl restart kindly-guard
```

## Maintenance

### Regular Tasks

1. **Weekly**
   - Review security logs
   - Check for updates
   - Monitor resource usage

2. **Monthly**
   - Update threat patterns
   - Review rate limit settings
   - Audit authentication logs

3. **Quarterly**
   - Security audit
   - Performance review
   - Disaster recovery test

### Updates

```bash
# Check for updates
curl -s https://api.github.com/repos/yourusername/kindly-guard/releases/latest | jq -r .tag_name

# Update binary
wget https://github.com/yourusername/kindly-guard/releases/latest/download/kindly-guard-linux-x86_64.tar.gz
tar xzf kindly-guard-linux-x86_64.tar.gz
sudo systemctl stop kindly-guard
sudo install -m 755 kindly-guard /usr/local/bin/
sudo systemctl start kindly-guard
```

## Security Checklist

- [ ] JWT secret configured and secure
- [ ] Authentication enabled
- [ ] Rate limiting configured
- [ ] File permissions restricted
- [ ] systemd hardening enabled
- [ ] Firewall rules in place
- [ ] TLS enabled (if using HTTP)
- [ ] Logs being monitored
- [ ] Backups configured
- [ ] Update process documented

## Support

For production support:
- Documentation: https://docs.kindlyguard.dev
- Issues: https://github.com/yourusername/kindly-guard/issues
- Security: security@kindlyguard.dev