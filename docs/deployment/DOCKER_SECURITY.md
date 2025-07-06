# Docker Security Guide for KindlyGuard

## Table of Contents
- [Overview](#overview)
- [Security Principles](#security-principles)
- [Container Hardening](#container-hardening)
- [Secret Management](#secret-management)
- [Network Security](#network-security)
- [Runtime Security](#runtime-security)
- [Image Security](#image-security)
- [Compliance Checklist](#compliance-checklist)
- [Security Monitoring](#security-monitoring)
- [Incident Response](#incident-response)

## Overview

This guide provides comprehensive security recommendations for deploying KindlyGuard in Docker environments. Following these practices ensures defense-in-depth and minimizes attack surface.

## Security Principles

### Defense in Depth
1. **Least Privilege**: Containers run with minimal permissions
2. **Isolation**: Network and process isolation between containers
3. **Immutability**: Read-only filesystems where possible
4. **Auditability**: Comprehensive logging and monitoring
5. **Zero Trust**: Assume breach and verify everything

## Container Hardening

### 1. Non-Root User

**Always run KindlyGuard as non-root:**

```dockerfile
# Official image already configured
USER 10001:10001
```

```yaml
# docker-compose.yml
services:
  kindlyguard:
    user: "10001:10001"
```

### 2. Read-Only Root Filesystem

**Enforce read-only root filesystem:**

```yaml
services:
  kindlyguard:
    read_only: true
    tmpfs:
      - /tmp/kindlyguard:noexec,nosuid,size=100M
    volumes:
      - kindly-data:/var/lib/kindlyguard
      - kindly-logs:/var/log/kindlyguard
```

### 3. Drop Capabilities

**Remove all unnecessary Linux capabilities:**

```yaml
services:
  kindlyguard:
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Only if binding to port < 1024
```

### 4. Security Options

**Apply security profiles:**

```yaml
services:
  kindlyguard:
    security_opt:
      - no-new-privileges:true
      - seccomp:seccomp-profile.json
      - apparmor:docker-kindlyguard
```

**Seccomp Profile Example:**

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {"names": ["accept", "accept4"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["bind"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["clone"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 0, "value": 2080505856, "op": "SCMP_CMP_MASKED_EQ"}]},
    {"names": ["close"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["connect"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["exit", "exit_group"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["fcntl"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["fstat", "fstatat64", "fstatfs"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["futex"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["getpid", "getppid", "gettid"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["getrandom"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["ioctl"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["listen"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["mmap", "munmap", "mprotect"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["nanosleep"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["open", "openat"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["poll"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["read", "readv", "pread64"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["recvfrom", "recvmsg"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["rt_sigaction", "rt_sigprocmask", "rt_sigreturn"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["sendto", "sendmsg"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["setsockopt", "getsockopt", "getsockname"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["sigaltstack"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["socket"], "action": "SCMP_ACT_ALLOW"},
    {"names": ["write", "writev", "pwrite64"], "action": "SCMP_ACT_ALLOW"}
  ]
}
```

### 5. Resource Limits

**Prevent resource exhaustion:**

```yaml
services:
  kindlyguard:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 128M
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
      nproc:
        soft: 4096
        hard: 4096
```

### 6. Health Checks

**Implement proper health checks:**

```yaml
services:
  kindlyguard:
    healthcheck:
      test: ["CMD", "/usr/local/bin/kindlyguard", "health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
      disable: false  # Never disable in production
```

## Secret Management

### 1. Docker Secrets (Swarm Mode)

```bash
# Create secrets
echo -n "your-auth-secret" | docker secret create kindly-auth-secret -
echo -n "your-db-password" | docker secret create kindly-db-password -

# Use in service
docker service create \
  --name kindlyguard \
  --secret kindly-auth-secret \
  --secret kindly-db-password \
  kindlysoftware/kindlyguard:latest
```

```yaml
# docker-compose.yml (Swarm mode)
version: '3.8'

services:
  kindlyguard:
    image: kindlysoftware/kindlyguard:latest
    secrets:
      - kindly-auth-secret
      - kindly-db-password
    environment:
      - KINDLY_AUTH_SECRET_FILE=/run/secrets/kindly-auth-secret
      - KINDLY_DB_PASSWORD_FILE=/run/secrets/kindly-db-password

secrets:
  kindly-auth-secret:
    external: true
  kindly-db-password:
    external: true
```

### 2. Environment Variable Security

**Never hardcode secrets:**

```bash
# BAD - Visible in docker inspect
docker run -e AUTH_SECRET="my-secret" kindlyguard

# GOOD - Use files
docker run -v /secure/secrets:/secrets:ro \
  -e KINDLY_AUTH_SECRET_FILE=/secrets/auth-secret \
  kindlyguard
```

### 3. BuildKit Secrets (Build Time)

```dockerfile
# syntax=docker/dockerfile:1
FROM rust:1.76-alpine AS builder

# Mount secret during build only
RUN --mount=type=secret,id=cargo-token \
    CARGO_REGISTRIES_CRATES_IO_TOKEN=$(cat /run/secrets/cargo-token) \
    cargo build --release
```

```bash
# Build with secret
DOCKER_BUILDKIT=1 docker build \
  --secret id=cargo-token,src=$HOME/.cargo/credentials \
  -t kindlyguard .
```

### 4. Vault Integration

```yaml
# Using HashiCorp Vault
services:
  vault-agent:
    image: vault:latest
    command: ["vault", "agent", "-config=/vault/config/agent.hcl"]
    volumes:
      - ./vault-config:/vault/config:ro
      - vault-secrets:/vault/secrets
  
  kindlyguard:
    depends_on:
      - vault-agent
    volumes:
      - vault-secrets:/secrets:ro
    environment:
      - KINDLY_AUTH_SECRET_FILE=/secrets/auth-secret
```

### 5. AWS Secrets Manager

```yaml
# Using AWS Secrets Manager
services:
  secrets-provider:
    image: aws/secrets-manager-provider:latest
    environment:
      - AWS_REGION=us-east-1
    volumes:
      - aws-secrets:/mnt/secrets
  
  kindlyguard:
    depends_on:
      - secrets-provider
    volumes:
      - aws-secrets:/secrets:ro
```

## Network Security

### 1. Network Isolation

```yaml
version: '3.8'

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge
    internal: true  # No external access
  monitoring:
    driver: bridge
    internal: true

services:
  nginx:
    networks:
      - frontend
      - backend

  kindlyguard:
    networks:
      - backend
      - monitoring
    # No frontend access

  prometheus:
    networks:
      - monitoring
```

### 2. Firewall Rules

```yaml
services:
  kindlyguard:
    ports:
      - "127.0.0.1:8080:8080"  # Only localhost
    # Or use iptables
    labels:
      - "com.kindlyguard.firewall.rules=ACCEPT tcp -- 10.0.0.0/8"
```

### 3. TLS Configuration

```yaml
services:
  kindlyguard:
    environment:
      - KINDLY_TLS_ENABLED=true
      - KINDLY_TLS_CERT_FILE=/certs/server.crt
      - KINDLY_TLS_KEY_FILE=/certs/server.key
      - KINDLY_TLS_MIN_VERSION=1.2
      - KINDLY_TLS_CIPHERS=TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
    volumes:
      - ./certs:/certs:ro
```

### 4. Service Mesh Security

```yaml
# Istio sidecar injection
metadata:
  annotations:
    sidecar.istio.io/inject: "true"
spec:
  containers:
  - name: kindlyguard
    image: kindlysoftware/kindlyguard:latest
```

## Runtime Security

### 1. Runtime Protection

```yaml
# Falco runtime security
services:
  falco:
    image: falcosecurity/falco:latest
    privileged: true
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock:ro
      - /dev:/host/dev:ro
      - /proc:/host/proc:ro
```

### 2. File Integrity Monitoring

```bash
# Create baseline
docker run --rm -v kindly-data:/data alpine \
  find /data -type f -exec sha256sum {} \; > baseline.txt

# Verify integrity
docker run --rm -v kindly-data:/data -v $(pwd):/check alpine \
  sh -c 'cd /data && sha256sum -c /check/baseline.txt'
```

### 3. Process Monitoring

```yaml
services:
  kindlyguard:
    labels:
      - "com.kindlyguard.monitoring.processes=kindlyguard"
    environment:
      - KINDLY_ALLOWED_PROCESSES=/usr/local/bin/kindlyguard
```

### 4. Syscall Monitoring

```bash
# Monitor syscalls with strace
docker run --cap-add SYS_PTRACE \
  --pid container:kindlyguard \
  alpine strace -p 1 -f -e trace=network
```

## Image Security

### 1. Image Scanning

```bash
# Scan with Trivy
trivy image kindlysoftware/kindlyguard:latest

# Scan with Grype
grype kindlysoftware/kindlyguard:latest

# Scan with Docker Scout
docker scout cves kindlysoftware/kindlyguard:latest
```

### 2. Image Signing

```bash
# Sign with Cosign
cosign sign kindlysoftware/kindlyguard:latest

# Verify signature
cosign verify kindlysoftware/kindlyguard:latest \
  --certificate-identity=samuel@kindly.software \
  --certificate-oidc-issuer=https://github.com/login/oauth
```

### 3. SBOM Generation

```bash
# Generate Software Bill of Materials
syft kindlysoftware/kindlyguard:latest -o spdx-json > sbom.json

# Scan SBOM for vulnerabilities
grype sbom:./sbom.json
```

### 4. Distroless Images

```dockerfile
# Multi-stage build with distroless
FROM rust:1.76-alpine AS builder
# Build steps...

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/kindlyguard /usr/local/bin/
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/kindlyguard"]
```

## Compliance Checklist

### CIS Docker Benchmark

- [ ] Host Configuration
  - [ ] Audit Docker daemon
  - [ ] Audit Docker files and directories
  - [ ] Configure appropriate logging
- [ ] Docker Daemon Configuration
  - [ ] Restrict network traffic between containers
  - [ ] Enable content trust
  - [ ] Enable live restore
- [ ] Container Images
  - [ ] Create a user for containers
  - [ ] Use trusted base images
  - [ ] Scan images for vulnerabilities
- [ ] Container Runtime
  - [ ] Restrict container capabilities
  - [ ] Use read-only root filesystem
  - [ ] Limit memory usage

### NIST Guidelines

- [ ] Access Control (AC)
  - [ ] Least privilege enforcement
  - [ ] Role-based access control
- [ ] Audit and Accountability (AU)
  - [ ] Comprehensive logging
  - [ ] Log retention policies
- [ ] Configuration Management (CM)
  - [ ] Baseline configurations
  - [ ] Change control process
- [ ] System and Information Integrity (SI)
  - [ ] Flaw remediation
  - [ ] Malicious code protection

### PCI DSS Requirements

- [ ] Build and maintain secure systems
  - [ ] Use vendor security patches
  - [ ] Develop secure systems
- [ ] Implement strong access controls
  - [ ] Restrict access to need-to-know
  - [ ] Assign unique ID to each user
- [ ] Regularly monitor and test
  - [ ] Track all access to resources
  - [ ] Test security systems regularly

## Security Monitoring

### 1. Container Logging

```yaml
services:
  kindlyguard:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "security,production"
        env: "KINDLY_VERSION,DEPLOYMENT_ENV"
```

### 2. Security Events

```yaml
# Fluentd configuration for security events
<source>
  @type forward
  port 24224
</source>

<filter docker.**>
  @type grep
  <regexp>
    key log
    pattern /(SECURITY|THREAT|AUTH_FAIL|INJECTION)/
  </regexp>
</filter>

<match docker.**>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name security-events
</match>
```

### 3. Metrics Collection

```yaml
# Prometheus configuration
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'kindlyguard'
    static_configs:
      - targets: ['kindlyguard:9090']
    metric_relabel_configs:
      - source_labels: [__name__]
        regex: 'kindly_security_.*'
        action: keep
```

### 4. Alerting Rules

```yaml
# Prometheus alerting rules
groups:
  - name: security
    rules:
      - alert: HighThreatRate
        expr: rate(kindly_threats_detected[5m]) > 10
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "High threat detection rate"
          
      - alert: AuthenticationFailures
        expr: rate(kindly_auth_failures[5m]) > 5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Multiple authentication failures"
```

## Incident Response

### 1. Container Forensics

```bash
# Preserve evidence
docker commit kindlyguard kindlyguard-incident-$(date +%s)
docker save kindlyguard-incident-* | gzip > incident.tar.gz

# Export logs
docker logs kindlyguard > incident-logs.txt
docker inspect kindlyguard > incident-inspect.json
```

### 2. Runtime Analysis

```bash
# Capture running processes
docker exec kindlyguard ps auxf > processes.txt

# Capture network connections
docker exec kindlyguard netstat -tuln > connections.txt

# Capture file system changes
docker diff kindlyguard > filesystem-changes.txt
```

### 3. Automated Response

```yaml
# Kubernetes NetworkPolicy for isolation
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-compromised
spec:
  podSelector:
    matchLabels:
      quarantine: "true"
  policyTypes:
  - Ingress
  - Egress
```

### 4. Recovery Procedures

```bash
#!/bin/bash
# incident-recovery.sh

# 1. Stop compromised container
docker stop kindlyguard

# 2. Backup data
docker run --rm -v kindly-data:/data -v $(pwd):/backup \
  alpine tar czf /backup/pre-recovery-backup.tar.gz /data

# 3. Deploy clean image
docker pull kindlysoftware/kindlyguard:latest
docker run -d --name kindlyguard-new \
  -v kindly-data:/var/lib/kindlyguard \
  kindlysoftware/kindlyguard:latest

# 4. Verify health
docker exec kindlyguard-new kindlyguard health
```

## Best Practices Summary

### Do's
- ✅ Always run as non-root user
- ✅ Use read-only root filesystem
- ✅ Implement proper secret management
- ✅ Enable comprehensive logging
- ✅ Scan images regularly
- ✅ Use network isolation
- ✅ Set resource limits
- ✅ Implement health checks
- ✅ Sign and verify images
- ✅ Monitor security events

### Don'ts
- ❌ Never run privileged containers
- ❌ Don't expose Docker socket
- ❌ Avoid using latest tag in production
- ❌ Don't store secrets in images
- ❌ Never disable security features
- ❌ Don't use --net=host
- ❌ Avoid running as root
- ❌ Don't ignore CVE warnings
- ❌ Never skip health checks
- ❌ Don't use outdated base images

## Security Tools Reference

### Image Scanning
- **Trivy**: `aquasec/trivy`
- **Grype**: `anchore/grype`
- **Clair**: `quay.io/coreos/clair`
- **Snyk**: `snyk/snyk`

### Runtime Security
- **Falco**: `falcosecurity/falco`
- **Sysdig**: `sysdig/sysdig`
- **Tracee**: `aquasec/tracee`

### Compliance
- **Docker Bench**: `docker/docker-bench-security`
- **InSpec**: `chef/inspec`
- **Open Policy Agent**: `openpolicyagent/opa`

### Secret Management
- **Vault**: `hashicorp/vault`
- **Sealed Secrets**: `bitnami-labs/sealed-secrets`
- **SOPS**: `mozilla/sops`

---

**Remember**: Security is not a one-time setup but a continuous process. Regularly review and update your security measures, stay informed about new vulnerabilities, and always follow the principle of least privilege.