# KindlyGuard Security Best Practices

A comprehensive guide to deploying and operating KindlyGuard securely.

## Table of Contents

- [Deployment Security](#deployment-security)
- [Authentication Best Practices](#authentication-best-practices)
- [Network Security](#network-security)
- [Configuration Hardening](#configuration-hardening)
- [Operational Security](#operational-security)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Incident Response](#incident-response)
- [Security Checklist](#security-checklist)

## Deployment Security

### System Requirements

#### Minimum Security Requirements
- **OS**: Linux with SELinux/AppArmor
- **User**: Dedicated non-root user
- **Permissions**: Minimal file system access
- **Dependencies**: Verified checksums

#### Recommended Setup
```bash
# Create dedicated user
sudo useradd --system --shell /bin/false --home /var/lib/kindly-guard kindlyguard

# Set directory permissions
sudo mkdir -p /etc/kindly-guard /var/log/kindly-guard /var/lib/kindly-guard
sudo chown -R kindlyguard:kindlyguard /var/log/kindly-guard /var/lib/kindly-guard
sudo chmod 750 /var/log/kindly-guard /var/lib/kindly-guard
sudo chmod 755 /etc/kindly-guard
```

### Container Security

#### Docker Configuration
```dockerfile
FROM rust:1.70-alpine AS builder
# Build stage...

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
RUN adduser -D -s /bin/false kindlyguard

USER kindlyguard
EXPOSE 8080

# Security options
SECURITY_OPT --cap-drop=ALL
SECURITY_OPT --read-only
SECURITY_OPT --no-new-privileges
```

#### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kindly-guard
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: kindly-guard
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
          runAsNonRoot: true
          runAsUser: 1000
        resources:
          limits:
            memory: "512Mi"
            cpu: "1000m"
          requests:
            memory: "256Mi"
            cpu: "100m"
```

### Binary Verification

Always verify binary integrity:

```bash
# Download checksums
wget https://github.com/yourusername/kindly-guard/releases/download/v0.1.0/checksums.txt
wget https://github.com/yourusername/kindly-guard/releases/download/v0.1.0/checksums.txt.sig

# Verify signature
gpg --verify checksums.txt.sig checksums.txt

# Verify binary
sha256sum -c checksums.txt
```

## Authentication Best Practices

### Client Credentials

#### Strong Secret Generation
```bash
# Generate secure client secret (32 bytes)
openssl rand -base64 32

# Hash for storage (bcrypt)
htpasswd -bnBC 12 "" "your-secret-here" | tr -d ':\n' | sed 's/$2y/$2b/'
```

#### Credential Storage
- **Never** commit secrets to version control
- Use environment variables or secret management systems
- Rotate credentials regularly (90 days recommended)

#### Example Secure Configuration
```yaml
auth:
  enabled: true
  token_lifetime_secs: 900  # 15 minutes
  refresh_token_lifetime_secs: 3600  # 1 hour
  require_resource_indicators: true
  allowed_resources:
    - "kindlyguard:v0.1.0"
  allowed_clients:
    - client_id: "prod-app-${ENVIRONMENT}"
      secret: "${CLIENT_SECRET_HASH}"  # From environment
      allowed_scopes:
        - "tools:execute"
        - "resources:read"
      require_signing: true
```

### Token Management

#### Token Lifecycle
1. **Short-lived access tokens** (15-30 minutes)
2. **Refresh tokens** for extending sessions
3. **Token revocation** on suspicious activity
4. **Token binding** to client certificates (optional)

#### Secure Token Storage (Client-side)
```python
import keyring
import json

class SecureTokenStore:
    def __init__(self, service_name="kindlyguard"):
        self.service = service_name
    
    def store_token(self, client_id, token_data):
        keyring.set_password(
            self.service,
            client_id,
            json.dumps(token_data)
        )
    
    def get_token(self, client_id):
        data = keyring.get_password(self.service, client_id)
        return json.loads(data) if data else None
```

### OAuth 2.0 Hardening

#### Resource Indicators
Always specify the resource parameter:
```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=your-client&
client_secret=your-secret&
resource=kindlyguard:v0.1.0&  # Required
scope=tools:execute
```

#### PKCE for Public Clients
If implementing public clients:
```python
import hashlib
import base64
import secrets

# Generate code verifier
code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

# Generate code challenge
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode()).digest()
).decode('utf-8').rstrip('=')
```

## Network Security

### Transport Security

#### TLS Configuration (if using HTTPS endpoint)
```yaml
tls:
  min_version: "1.2"
  cipher_suites:
    - "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    - "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305"
    - "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"
  prefer_server_ciphers: true
  session_tickets: false
```

#### Unix Socket Security
For local communication:
```yaml
socket:
  path: "/var/run/kindly-guard/kindly-guard.sock"
  mode: 0660
  owner: kindlyguard
  group: kindlyguard-clients
```

### Firewall Rules

#### iptables Example
```bash
# Allow only specific clients
iptables -A INPUT -p tcp --dport 8080 -s 10.0.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP

# Rate limit connections
iptables -A INPUT -p tcp --dport 8080 -m state --state NEW -m limit --limit 10/min -j ACCEPT
```

#### nftables Example
```
table inet kindlyguard {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow established connections
        ct state established,related accept
        
        # Rate limit new connections
        tcp dport 8080 ct state new limit rate 10/minute accept
    }
}
```

## Configuration Hardening

### Secure Defaults

```yaml
# /etc/kindly-guard/config.yaml
scanner:
  unicode_detection: true
  injection_detection: true
  max_scan_depth: 5  # Limit recursion
  enable_event_buffer: true  # Enhanced detection

auth:
  enabled: true  # Never disable in production
  require_resource_indicators: true
  token_lifetime_secs: 900  # 15 minutes max

rate_limit:
  enabled: true
  default_rpm: 30  # Conservative default
  threat_penalty_multiplier: 5.0  # Heavy penalties

signing:
  enabled: true
  require_signed_requests: true
  timestamp_tolerance_secs: 60  # Strict timing

permissions:
  default_permissions:
    denied_tools: ["*"]  # Deny by default
    require_signing: true
    max_threat_level: "low"
```

### Environment Isolation

```bash
# /etc/systemd/system/kindly-guard.service
[Service]
# Process isolation
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Network isolation (if not needed)
PrivateNetwork=true

# Capability restrictions
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=true

# Syscall filtering
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
```

## Operational Security

### Logging Configuration

#### Structured Logging
```yaml
log_level: "info"
log_format: "json"  # Machine-readable

# Log sanitization
log_sanitization:
  enabled: true
  redact_patterns:
    - "password"
    - "secret"
    - "token"
    - "key"
```

#### Log Shipping
```yaml
logging:
  outputs:
    - type: file
      path: "/var/log/kindly-guard/app.log"
      rotation:
        max_size: "100MB"
        max_age: "7d"
        max_backups: 5
    
    - type: syslog
      address: "tcp://log-aggregator:514"
      format: "rfc5424"
      tls:
        enabled: true
        verify: true
```

### Secret Management

#### HashiCorp Vault Integration
```python
import hvac

class VaultSecretProvider:
    def __init__(self, vault_url, role_id, secret_id):
        self.client = hvac.Client(url=vault_url)
        self.client.auth.approle.login(
            role_id=role_id,
            secret_id=secret_id
        )
    
    def get_client_secret(self, client_id):
        response = self.client.secrets.kv.v2.read_secret_version(
            path=f"kindlyguard/clients/{client_id}"
        )
        return response['data']['data']['secret']
```

#### AWS Secrets Manager
```python
import boto3
import json

class AWSSecretProvider:
    def __init__(self):
        self.client = boto3.client('secretsmanager')
    
    def get_client_secret(self, client_id):
        response = self.client.get_secret_value(
            SecretId=f"kindlyguard/clients/{client_id}"
        )
        return json.loads(response['SecretString'])['secret']
```

### Update Management

#### Automated Updates
```yaml
# Update notification configuration
updates:
  check_enabled: true
  check_interval: "24h"
  notify_webhook: "https://ops.example.com/webhook"
  auto_download: false  # Manual verification required
```

#### Update Verification Process
1. Subscribe to security announcements
2. Verify changelog for security fixes
3. Test in staging environment
4. Gradual rollout with monitoring
5. Rollback plan ready

## Monitoring and Alerting

### Key Metrics

#### Security Metrics
```yaml
metrics:
  - name: "kindlyguard_threats_detected_total"
    type: counter
    labels: ["threat_type", "severity", "blocked"]
    
  - name: "kindlyguard_auth_attempts_total"
    type: counter
    labels: ["client_id", "success"]
    
  - name: "kindlyguard_rate_limit_hits_total"
    type: counter
    labels: ["client_id", "method"]
    
  - name: "kindlyguard_scan_duration_seconds"
    type: histogram
    buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
```

#### Alert Rules
```yaml
# Prometheus alert rules
groups:
  - name: kindlyguard_security
    rules:
      - alert: HighThreatRate
        expr: rate(kindlyguard_threats_detected_total[5m]) > 1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High rate of security threats detected"
          
      - alert: AuthenticationFailures
        expr: rate(kindlyguard_auth_attempts_total{success="false"}[5m]) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Elevated authentication failure rate"
          
      - alert: RateLimitBreaches
        expr: rate(kindlyguard_rate_limit_hits_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Multiple clients hitting rate limits"
```

### Security Dashboard

Essential dashboard panels:
1. **Threat Overview** - Real-time threat detection
2. **Authentication Status** - Success/failure rates
3. **Rate Limit Status** - Throttled clients
4. **Scanner Performance** - Response times
5. **Error Rates** - System health

## Incident Response

### Threat Detection Response

#### Automated Response
```yaml
incident_response:
  threat_detected:
    - action: "log"
      priority: "high"
    - action: "alert"
      channels: ["security-team", "ops"]
    - action: "block_client"
      conditions:
        severity: ["critical"]
        count: 3
        window: "5m"
```

#### Manual Investigation
```bash
# Recent threats
echo '{"jsonrpc":"2.0","method":"security/threats","params":{"limit":100},"id":1}' | \
  kindly-guard --stdio | jq '.result.threats'

# Client activity
echo '{"jsonrpc":"2.0","method":"security/client_activity","params":{"client_id":"suspicious-client"},"id":1}' | \
  kindly-guard --stdio

# Export threat data
kindly-guard export-threats --since "1 hour ago" --format json > threats.json
```

### Recovery Procedures

#### After Compromise
1. **Immediate Actions**
   - Revoke all client credentials
   - Rotate signing keys
   - Review audit logs
   - Update configurations

2. **Investigation**
   - Analyze threat patterns
   - Check for data exfiltration
   - Review client permissions
   - Audit configuration changes

3. **Remediation**
   - Patch vulnerabilities
   - Update threat patterns
   - Strengthen rate limits
   - Enhanced monitoring

## Security Checklist

### Pre-Deployment
- [ ] Binary integrity verified
- [ ] Dedicated user account created
- [ ] File permissions hardened
- [ ] Configuration reviewed
- [ ] Secrets properly managed
- [ ] TLS/Socket security configured
- [ ] Firewall rules implemented
- [ ] SELinux/AppArmor policies applied

### Authentication & Authorization
- [ ] Strong client secrets generated
- [ ] OAuth 2.0 properly configured
- [ ] Token lifetimes appropriately short
- [ ] Resource indicators required
- [ ] Scopes properly restricted
- [ ] Message signing enabled
- [ ] Permissions deny-by-default

### Operational
- [ ] Structured logging enabled
- [ ] Log shipping configured
- [ ] Monitoring dashboards created
- [ ] Alert rules implemented
- [ ] Backup procedures tested
- [ ] Update process documented
- [ ] Incident response plan ready
- [ ] Security contacts defined

### Regular Audits (Monthly)
- [ ] Review client permissions
- [ ] Analyze threat patterns
- [ ] Check for unusual activity
- [ ] Verify configurations
- [ ] Update threat definitions
- [ ] Rotate credentials
- [ ] Test incident response
- [ ] Review security patches

## Additional Resources

### Security Documentation
- [OWASP Security Practices](https://owasp.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Security Benchmarks](https://www.cisecurity.org/)

### Threat Intelligence
- [Unicode Security (TR36)](https://unicode.org/reports/tr36/)
- [CAPEC Attack Patterns](https://capec.mitre.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

### Compliance Frameworks
- SOC 2 Type II considerations
- GDPR data protection requirements
- HIPAA security requirements (if applicable)
- PCI DSS (if processing payment data)