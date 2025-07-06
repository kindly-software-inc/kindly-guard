# KindlyGuard Security Architecture

## Executive Summary

KindlyGuard implements a comprehensive, defense-in-depth security architecture for protecting Model Context Protocol (MCP) servers against a wide range of threats. The system employs multiple overlapping security layers, from input validation to output sanitization, with sophisticated threat detection and neutralization capabilities.

## Security Components Overview

### 1. Authentication & Authorization

#### 1.1 OAuth 2.0 Implementation (`src/auth.rs`)
- **Token Types**: Bearer and MAC tokens supported
- **Resource Indicators**: RFC 8707 compliance for token scope restriction
- **Validation Methods**:
  - Local JWT validation with HMAC-SHA256
  - Remote introspection endpoint support
  - Constant-time token comparison to prevent timing attacks
- **Security Features**:
  - Configurable token cache with TTL (default: 5 minutes)
  - Trusted issuer validation
  - Resource-specific token validation
  - Grace period for gradual rollout

#### 1.2 Digital Signatures (`src/signing.rs`)
- **Algorithms Supported**:
  - HMAC-SHA256 for symmetric signing
  - Ed25519 for asymmetric signing
- **Message Integrity**:
  - Timestamp inclusion for replay prevention
  - Canonical message representation
  - Maximum clock skew validation (default: 5 minutes)
- **Key Management**:
  - Base64-encoded key storage
  - Key rotation support via key IDs
  - Minimum key size enforcement (32 bytes)

#### 1.3 Permissions System (`src/permissions/`)
- **Tool-Level Access Control**:
  - Fine-grained permissions per tool
  - Category-based permission grouping
  - Threat-level based restrictions
- **Client Management**:
  - Per-client permission profiles
  - Rate limit overrides
  - Mandatory signing requirements
- **Dynamic Enforcement**:
  - Real-time permission checks
  - Context-aware decisions based on threat level
  - Audit trail of permission decisions

### 2. Threat Detection Components

#### 2.1 Unicode Security Scanner (`src/scanner/unicode.rs`)
Detects Unicode-based attacks with comprehensive coverage:

**Attack Vectors Detected**:
- **Invisible Characters**:
  - Zero-width spaces (U+200B, U+200C, U+200D)
  - Zero-width no-break space (U+FEFF)
  - Mongolian vowel separator (U+180E)
  - Detection accuracy: 100%
  
- **BiDi Spoofing**:
  - Right-to-left override (U+202E)
  - Left-to-right/right-to-left embeddings
  - Pop directional formatting detection
  - Used in file extension spoofing attacks
  
- **Homograph Attacks**:
  - Cyrillic/Latin lookalikes (е vs e)
  - Greek/Latin confusion
  - Mixed script detection
  - Punycode domain validation
  
- **Control Characters**:
  - Format control characters
  - Line/paragraph separators
  - Dangerous combining characters

#### 2.2 Injection Attack Scanner (`src/scanner/injection.rs`)
Multi-vector injection detection with context awareness:

**SQL Injection Detection**:
- Pattern matching for common SQL keywords
- UNION-based attack detection
- Blind SQL injection patterns
- Time-based injection detection
- Parameterized query recommendation

**Command Injection Detection**:
- Shell metacharacter detection
- Command chaining patterns (;, &&, ||)
- Backtick command substitution
- Pipe character abuse
- Path injection in commands

**Prompt Injection Detection** (LLM-specific):
- System prompt override attempts
- Context manipulation patterns
- Instruction injection detection
- Role confusion attacks
- Jailbreak attempt patterns

**Path Traversal Detection**:
- Directory traversal sequences (../, ..\\)
- Absolute path detection
- Null byte injection
- Unicode normalization bypasses
- Symbolic link attacks

**Additional Injection Types**:
- LDAP injection (DN manipulation, filter injection)
- XML injection/XXE (DTD declarations, entity expansion)
- NoSQL injection (MongoDB operators, JavaScript injection)

#### 2.3 XSS Scanner (`src/scanner/xss_scanner.rs`)
Context-aware cross-site scripting detection:

**HTML Context**:
- Script tag detection
- Event handler attributes
- JavaScript URL schemes
- Data URI attacks
- SVG-based XSS

**JavaScript Context**:
- String escape sequences
- Template literal injection
- Function constructor abuse
- Eval-like constructs

**CSS Context**:
- Expression() attacks
- @import abuse
- JavaScript in CSS
- Data URI embedding

**URL Context**:
- JavaScript: protocol
- Data: protocol abuse
- Malformed URL encoding
- IDN homograph attacks

#### 2.4 Pattern-Based Detection (`src/scanner/patterns.rs`)
Extensible pattern matching system:

**MCP-Specific Patterns**:
- Session ID exposure
- Authentication token leakage
- Tool poisoning attempts
- Resource exhaustion patterns

**Custom Patterns**:
- Regex-based matching with size limits
- Fuzzy pattern matching
- Machine learning pattern integration
- Performance-optimized matching

### 3. Threat Neutralization System

#### 3.1 Neutralization Strategies (`src/neutralizer/`)
Automated threat remediation with multiple strategies:

**Unicode Neutralization**:
- **BiDi Handling**:
  - Remove: Complete removal of BiDi characters
  - Marker: Replace with visible markers ([BIDI])
  - Escape: Convert to Unicode escape sequences
  
- **Zero-Width Handling**:
  - Automatic removal
  - Preservation with warning for legitimate uses
  
- **Homograph Handling**:
  - ASCII conversion (е → e)
  - Visual warning markers
  - Complete blocking option

**Injection Neutralization**:
- **SQL Injection**:
  - Parameterization (preferred)
  - Quote escaping
  - Query rejection
  
- **Command Injection**:
  - Shell metacharacter escaping
  - Command sandboxing
  - Execution blocking
  
- **Path Traversal**:
  - Path normalization
  - Jail directory enforcement
  - Symbolic link resolution
  
- **Prompt Injection**:
  - Safety context wrapping
  - Control sequence escaping
  - Instruction boundary enforcement

#### 3.2 Advanced Neutralization Features
- **Rollback Support**: Ability to undo neutralization
- **Batch Processing**: Multiple threat handling
- **Confidence Scoring**: Neutralization effectiveness metrics
- **Audit Trail**: Complete action history

### 4. Defense Mechanisms

#### 4.1 Rate Limiting (`src/rate_limit.rs`)
Token bucket algorithm implementation:

**Features**:
- Per-client rate limits
- Per-method rate limits
- Adaptive rate limiting under attack
- Threat penalty system (reduces limits for attackers)
- Priority-based client handling

**Configuration**:
- Default: 60 requests/minute
- Burst capacity: 10 requests
- Cleanup interval: 5 minutes
- Penalty multiplier: 0.5x for threats

#### 4.2 Circuit Breakers (`src/resilience/`)
Fault isolation and recovery:

**States**:
- Closed: Normal operation
- Open: Failure threshold exceeded
- Half-Open: Testing recovery

**Features**:
- Configurable failure thresholds
- Exponential backoff
- Health check integration
- Metric collection

#### 4.3 Resource Protection
- **Content Size Limits**: DoS prevention
- **Scan Depth Limits**: Stack exhaustion prevention
- **Timeout Protection**: Long-running operation limits
- **Memory Monitoring**: Resource exhaustion detection

### 5. Security Boundaries

#### 5.1 Trust Boundaries
```
External Clients
    ↓ [Authentication Layer]
MCP Transport Layer (HTTP/WebSocket/stdio)
    ↓ [Input Validation]
Request Handler
    ↓ [Authorization Check]
Business Logic
    ↓ [Output Sanitization]
Response Handler
    ↓ [Signing Layer]
External Clients
```

#### 5.2 Input Validation Points
1. **Transport Layer**: Protocol validation
2. **Authentication**: Token validation
3. **Request Parser**: JSON schema validation
4. **Scanner Layer**: Threat detection
5. **Business Logic**: Domain validation

#### 5.3 Output Sanitization Points
1. **Neutralizer**: Threat remediation
2. **Response Builder**: Safe encoding
3. **Transport Layer**: Protocol compliance
4. **Signing Layer**: Integrity protection

### 6. Cryptographic Operations

#### 6.1 Algorithms Used
- **Hashing**: SHA-256 (token hashing, HMAC)
- **Signing**: HMAC-SHA256, Ed25519
- **Random Generation**: OS entropy via rand::thread_rng()
- **Key Derivation**: PBKDF2 (future)

#### 6.2 Key Security Properties
- Constant-time comparisons for secrets
- Secure random token generation (min 128 bits)
- Key size enforcement
- No hardcoded secrets

### 7. Attack Surface Analysis

#### 7.1 External Attack Surface
- **MCP Endpoints**: Tools, resources, prompts
- **Transport Protocols**: HTTP, WebSocket, stdio
- **Authentication Endpoints**: Token validation
- **Configuration API**: Admin operations

#### 7.2 Internal Attack Surface
- **Plugin System**: Sandboxed execution
- **Storage Layer**: SQL injection prevention
- **Logging System**: Log injection prevention
- **Metrics Collection**: Resource exhaustion prevention

### 8. Threat Mitigation Matrix

| Threat Type | Detection Component | Neutralization Strategy | Defense Layer |
|------------|-------------------|------------------------|---------------|
| Unicode Invisible Chars | Unicode Scanner | Remove/Escape | Input Validation |
| BiDi Spoofing | Unicode Scanner | Marker Replacement | Input Validation |
| Homograph Attack | Unicode Scanner | ASCII Conversion | Input Validation |
| SQL Injection | Injection Scanner | Parameterization | Input Validation + WAF |
| Command Injection | Injection Scanner | Shell Escaping | Input Validation + Sandboxing |
| XSS | XSS Scanner | HTML Encoding | Output Sanitization |
| Prompt Injection | Injection Scanner | Context Wrapping | Input Validation |
| Path Traversal | Injection Scanner | Path Normalization | Input Validation |
| DoS | Size Limits | Request Rejection | Rate Limiting |
| Brute Force | Rate Limiter | Adaptive Limiting | Rate Limiting |
| Token Theft | Auth Manager | Token Rotation | Authentication |
| Session Hijacking | Pattern Scanner | Session Invalidation | Authentication |
| Resource Exhaustion | Resource Monitor | Circuit Breaking | Resilience |

### 9. Security Test Coverage

#### 9.1 Unit Test Coverage
- **Scanner Tests**: Individual threat detection validation
- **Neutralizer Tests**: Remediation effectiveness
- **Auth Tests**: Token validation, constant-time comparison
- **Crypto Tests**: Key generation, signing verification

#### 9.2 Integration Test Coverage
- **End-to-End Security**: Full request flow with threats
- **Multi-Protocol Tests**: Security across transports
- **Performance Tests**: Security under load
- **Chaos Tests**: Failure mode security

#### 9.3 Security-Specific Tests
- **OWASP ASVS Compliance**: Level 2 validation
- **Property-Based Testing**: Fuzzing with proptest
- **Penetration Testing**: Automated attack simulation
- **Unicode Security**: Comprehensive Unicode attack coverage

### 10. Defense in Depth Layers

#### Layer 1: Network Security
- TLS 1.2+ enforcement
- Certificate validation
- Network-level rate limiting

#### Layer 2: Authentication & Authorization  
- OAuth 2.0 with resource indicators
- Digital message signatures
- Fine-grained permissions

#### Layer 3: Input Validation
- Protocol validation
- Schema validation
- Threat scanning

#### Layer 4: Application Security
- Secure coding practices
- Memory safety (Rust)
- Error handling without info leakage

#### Layer 5: Output Security
- Context-aware encoding
- Threat neutralization
- Response signing

#### Layer 6: Monitoring & Response
- Security event logging
- Anomaly detection
- Incident response procedures

### 11. Compliance & Standards

#### 11.1 Standards Compliance
- **OAuth 2.0**: RFC 6749
- **Resource Indicators**: RFC 8707
- **JWT**: RFC 7519
- **Unicode Security**: UAX #31, UTR #36

#### 11.2 Security Frameworks
- **OWASP Top 10**: Full coverage
- **OWASP ASVS**: Level 2 compliance
- **NIST Cybersecurity**: Identify, Protect, Detect, Respond, Recover

### 12. Incident Response

#### 12.1 Detection
- Real-time threat detection
- Anomaly detection via metrics
- Security event correlation

#### 12.2 Response
- Automatic threat neutralization
- Adaptive rate limiting
- Circuit breaker activation
- Client penalty application

#### 12.3 Recovery
- Rollback capability
- Health monitoring
- Automatic recovery strategies
- Graceful degradation

### 13. Security Configuration

#### 13.1 Secure Defaults
- Authentication: Disabled (must enable)
- Rate limiting: Disabled (must enable)  
- Neutralization: Report-only mode
- All scanners: Enabled

#### 13.2 Production Hardening
```toml
[auth]
enabled = true
require_signature_verification = true
validate_resource_indicators = true

[rate_limit]
enabled = true
adaptive = true
threat_penalty_multiplier = 0.5

[scanner]
unicode_detection = true
injection_detection = true
xss_detection = true
enhanced_mode = true

[neutralization]
mode = "automatic"
backup_originals = true
audit_all_actions = true
```

### 14. Future Security Enhancements

#### 14.1 Planned Features
- Hardware security module (HSM) integration
- Advanced threat correlation with ML
- Zero-trust architecture implementation
- Quantum-resistant cryptography preparation

#### 14.2 Continuous Improvement
- Regular security audits
- Dependency vulnerability scanning
- Threat intelligence integration
- Security metrics dashboard

## STRIDE Analysis

### Spoofing
- **Threats**: Token forgery, identity spoofing
- **Mitigations**: Digital signatures, constant-time comparison, secure token generation

### Tampering
- **Threats**: Message modification, injection attacks
- **Mitigations**: Message signing, input validation, parameterization

### Repudiation
- **Threats**: Denial of actions
- **Mitigations**: Comprehensive audit logging, digital signatures

### Information Disclosure
- **Threats**: Token leakage, error info leakage
- **Mitigations**: Secure error handling, token hashing, TLS enforcement

### Denial of Service
- **Threats**: Resource exhaustion, amplification attacks
- **Mitigations**: Rate limiting, circuit breakers, resource monitoring

### Elevation of Privilege
- **Threats**: Permission bypass, tool poisoning
- **Mitigations**: Fine-grained permissions, tool validation, secure defaults

## Conclusion

KindlyGuard implements a comprehensive security architecture that addresses modern threats to MCP servers. The multi-layered approach ensures that even if one security control fails, others provide continued protection. The system is designed to be secure by default while remaining configurable for specific deployment needs.

The architecture emphasizes:
- **Prevention**: Strong input validation and authentication
- **Detection**: Comprehensive threat scanning
- **Response**: Automatic neutralization and adaptation
- **Recovery**: Resilience patterns and rollback capabilities

This defense-in-depth strategy provides robust protection against both known and emerging threats in the MCP ecosystem.