# Security Policy

## Supported Versions

KindlyGuard is currently in beta. Security updates are provided for:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please follow these steps:

### 1. Do NOT Create a Public Issue

Security vulnerabilities should NOT be reported through public GitHub issues, as this could put users at risk.

### 2. Report Privately

Please report security vulnerabilities by emailing: security@kindlyguard.dev

Include the following information:
- Type of vulnerability
- Full paths of source file(s) related to the issue
- Location of affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue

### 3. Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Resolution Target**: 
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 60 days

### 4. Disclosure Process

1. Reporter submits vulnerability
2. KindlyGuard team acknowledges receipt
3. Team investigates and validates the issue
4. Fix is developed and tested
5. Security advisory is prepared
6. Fix is released
7. Public disclosure (coordinated with reporter)

## Security Best Practices

When using KindlyGuard:

### Configuration Security

- **Always use strong JWT secrets** (minimum 256 bits of entropy)
- **Enable signature verification** in production
- **Restrict trusted issuers** to known OAuth providers
- **Enable rate limiting** to prevent DoS attacks
- **Use TLS** for all network communications

### Deployment Security

- Run with minimal privileges
- Use systemd security features (if applicable):
  - `NoNewPrivileges=true`
  - `ProtectSystem=strict`
  - `PrivateTmp=true`
- Keep dependencies updated
- Monitor security advisories

### Operational Security

- **Log monitoring**: Watch for unusual patterns
- **Rate limit monitoring**: Track limit violations
- **Threat detection**: Monitor blocked threats
- **Update regularly**: Apply security patches promptly

## Security Features

KindlyGuard includes multiple security layers:

### 1. Input Validation
- All external input is validated
- Pattern-based threat detection
- Unicode normalization and validation

### 2. Authentication & Authorization
- OAuth 2.0 with Resource Indicators (RFC 8707)
- JWT token validation
- Scope-based permissions
- HMAC-SHA256 signature verification

### 3. Rate Limiting
- Token bucket algorithm
- Per-client and per-method limits
- Adaptive rate limiting
- DoS protection

### 4. Threat Detection
- Unicode attack detection (BiDi, homoglyphs, invisible chars)
- Injection detection (SQL, command, path traversal)
- Real-time threat correlation
- Pattern-based detection engine

### 5. Secure Coding
- No unsafe code (`#[forbid(unsafe_code)]`)
- Memory-safe Rust implementation
- Comprehensive error handling
- No panics in production code

## Security Checklist

Before deploying KindlyGuard:

- [ ] Configure strong JWT secret
- [ ] Enable signature verification
- [ ] Configure appropriate rate limits
- [ ] Set up log monitoring
- [ ] Review firewall rules
- [ ] Enable TLS if using HTTP transport
- [ ] Review and restrict permissions
- [ ] Set up security alerts
- [ ] Document incident response plan
- [ ] Test backup and recovery procedures

## Known Security Considerations

### 1. Token Storage
Tokens are cached in memory. Ensure:
- Memory is not swapped to disk
- Process memory is protected
- Tokens are cleared on shutdown

### 2. Log Sanitization
Sensitive data is sanitized from logs, but:
- Review log outputs regularly
- Ensure log storage is secure
- Implement log rotation

### 3. Resource Limits
Configure appropriate limits for:
- Maximum request size
- Connection limits
- Memory usage
- CPU usage

## Security Tools

### Vulnerability Scanning
```bash
# Check for known vulnerabilities
cargo audit

# Check for outdated dependencies
cargo outdated

# Static analysis
cargo clippy -- -D warnings
```

### Fuzzing
```bash
# Run fuzz tests
cd fuzz
cargo fuzz run fuzz_unicode_scanner
cargo fuzz run fuzz_injection_detector
cargo fuzz run fuzz_mcp_protocol
```

### Security Testing
```bash
# Run security-specific tests
cargo test --test security_tests

# Run property-based security tests
cargo test --test property_tests
```

## Responsible Disclosure

We support responsible disclosure and will:
- Work with security researchers
- Provide credit (if desired) 
- Not pursue legal action for good-faith research
- Coordinate disclosure timing

## Security Updates

Security updates are announced via:
- GitHub Security Advisories
- Release notes
- Mailing list (coming soon)

Subscribe to notifications to stay informed about security updates.

## Contact

For security-related questions or concerns:
- Email: security@kindlyguard.dev
- GPG Key: [Coming Soon]

Thank you for helping keep KindlyGuard secure!