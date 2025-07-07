# KindlyGuard Protection Modes Guide

> *Kind to you, tough on threats™*

## Overview

KindlyGuard offers three distinct protection modes that balance security with usability. Each mode is designed for specific use cases, allowing you to choose the right level of protection for your environment while maintaining the user-friendly experience that makes KindlyGuard unique.

## Table of Contents

- [Protection Modes Overview](#protection-modes-overview)
- [Mode 1: Auto Protection Mode](#mode-1-auto-protection-mode)
- [Mode 2: Interactive Protection Mode](#mode-2-interactive-protection-mode)
- [Mode 3: Report-Only Mode](#mode-3-report-only-mode)
- [Configuration Guide](#configuration-guide)
- [CLI Usage Examples](#cli-usage-examples)
- [MCP Integration Examples](#mcp-integration-examples)
- [Best Practices](#best-practices)
- [Mode Selection Guide](#mode-selection-guide)
- [Troubleshooting](#troubleshooting)

## Protection Modes Overview

### Quick Comparison

| Mode | Threat Action | User Interaction | Use Case |
|------|--------------|------------------|----------|
| **Auto** | Automatically neutralizes | None required | Production systems |
| **Interactive** | Asks for confirmation | Required for each threat | Sensitive data handling |
| **Report-Only** | Logs but doesn't modify | None | Testing & monitoring |

### Visual Shield Indicators

- 🟢 **Green Shield**: Normal operation, no active threats
- 🟣 **Purple Shield**: Enhanced detection active (better protection)
- 🔴 **Red Shield**: Active threat detected and being handled
- ⚫ **Gray Shield**: Disabled or in report-only mode

## Mode 1: Auto Protection Mode

### Overview

Auto Protection Mode provides seamless, real-time threat neutralization without user intervention. It's the recommended mode for production environments where security and uptime are critical.

### How It Works

1. **Detection**: Continuously scans input for threats
2. **Analysis**: Evaluates threat severity and context
3. **Neutralization**: Automatically applies the safest remediation
4. **Logging**: Records all actions for audit purposes
5. **Recovery**: Maintains originals for rollback if needed

### Configuration

```toml
[neutralization]
# Enable automatic protection
mode = "automatic"

# Always backup original content
backup_originals = true

# Log all neutralization actions
audit_all_actions = true

# Specific threat handling
[neutralization.unicode]
bidi_replacement = "marker"      # Add visible markers for BiDi chars
zero_width_action = "remove"     # Remove zero-width characters
homograph_action = "ascii"       # Convert to ASCII equivalents

[neutralization.injection]
sql_action = "parameterize"      # Convert to parameterized queries
command_action = "escape"        # Escape shell metacharacters
path_action = "normalize"        # Normalize path traversal attempts
prompt_action = "wrap"           # Wrap AI prompts safely
```

### Use Case Examples

#### Example 1: API Server Protection

```bash
# Start KindlyGuard with auto protection
kindly-guard server --config production.toml

# Configuration excerpt
[neutralization]
mode = "automatic"

[scanner]
unicode_detection = true
injection_detection = true
xss_detection = true
```

**Result**: All incoming API requests are automatically sanitized before processing.

#### Example 2: CI/CD Pipeline Integration

```yaml
# GitHub Actions example
- name: Security Scan with Auto-Fix
  run: |
    kindly scan . --mode auto --fix
```

**Result**: Automatically fixes security issues in code before deployment.

#### Example 3: Database Query Protection

```rust
// Automatic SQL injection prevention
let user_input = "admin'; DROP TABLE users; --";
let safe_query = kindly_guard.neutralize_sql(user_input).await?;
// Result: "admin\'; DROP TABLE users; --"
```

### Benefits

- ✅ **Zero-touch security**: No manual intervention required
- ✅ **Minimal latency**: Optimized for performance
- ✅ **Audit trail**: Complete logging of all actions
- ✅ **Rollback capability**: Can undo changes if needed
- ✅ **Production-ready**: Battle-tested algorithms

### When to Use

- Production web applications
- API gateways and microservices
- Automated CI/CD pipelines
- High-traffic systems
- Unattended services

## Mode 2: Interactive Protection Mode

### Overview

Interactive Protection Mode requires user confirmation before neutralizing threats. It's ideal for environments where human judgment is valuable or when handling sensitive data that requires careful review.

### How It Works

1. **Detection**: Identifies potential threats
2. **Notification**: Alerts user with threat details
3. **Options**: Presents neutralization choices
4. **Confirmation**: Waits for user decision
5. **Action**: Applies chosen remediation
6. **Learning**: Can remember preferences

### Configuration

```toml
[neutralization]
# Enable interactive mode
mode = "interactive"

# Show detailed threat information
show_threat_details = true

# Remember user choices
remember_decisions = true
decision_cache_ttl = 3600  # 1 hour

# Interactive UI settings
[neutralization.interactive]
# Terminal UI settings
use_colors = true
show_examples = true
max_preview_length = 200

# Decision timeout (0 = no timeout)
timeout_seconds = 30
default_action = "ask"  # or "allow", "block"
```

### Use Case Examples

#### Example 1: Development Environment

```bash
# Scan with interactive mode
kindly scan suspicious_file.json --mode interactive

# Output:
🔍 Threat Detected: SQL Injection
   Location: Line 42, Column 15
   Content: "SELECT * FROM users WHERE id='$id'"
   
   What would you like to do?
   [1] Parameterize query (recommended)
   [2] Escape special characters
   [3] Block this content
   [4] Allow as-is (dangerous)
   [5] View more details
   
   Choice [1]: _
```

#### Example 2: Code Review Integration

```bash
# Git pre-commit hook with interactive mode
#!/bin/bash
kindly scan --staged --mode interactive

# Allows developers to review and fix issues before committing
```

#### Example 3: Data Import Validation

```python
# Python integration example
from kindly_guard import KindlyGuard

guard = KindlyGuard(mode="interactive")

# Import data with user review
for record in csv_reader:
    result = guard.scan(record)
    if result.has_threats:
        action = guard.prompt_user(result)
        if action == "fix":
            record = guard.neutralize(record)
```

### Interactive UI Features

- **Color-coded severity**: 🔴 Critical, 🟠 High, 🟡 Medium, 🔵 Low
- **Context preview**: Shows surrounding content
- **Suggested fixes**: Recommends safe alternatives
- **Batch operations**: Handle multiple similar threats at once
- **Undo/redo**: Change decisions before applying

### Benefits

- ✅ **Human oversight**: Combine AI detection with human judgment
- ✅ **Educational**: Learn about threats as you work
- ✅ **Flexible**: Different actions for different threats
- ✅ **Context-aware**: Make decisions based on full context
- ✅ **Selective protection**: Choose what to protect

### When to Use

- Development and testing environments
- Data migration and ETL processes
- Code review and auditing
- Educational settings
- Sensitive data handling
- Initial security assessments

## Mode 3: Report-Only Mode

### Overview

Report-Only Mode detects and logs threats without modifying content. It's perfect for monitoring, testing, and understanding your security landscape before enabling active protection.

### How It Works

1. **Detection**: Scans all content for threats
2. **Analysis**: Evaluates severity and impact
3. **Reporting**: Logs detailed findings
4. **Metrics**: Updates statistics and dashboards
5. **Alerts**: Can trigger notifications
6. **No modification**: Content passes through unchanged

### Configuration

```toml
[neutralization]
# Enable report-only mode
mode = "report_only"

# Enhanced reporting settings
generate_reports = true
report_format = "detailed"  # or "summary"
include_recommendations = true

# Report destinations
[neutralization.reporting]
# Console output
console_enabled = true
console_format = "human"  # or "json", "yaml"

# File output
file_enabled = true
file_path = "/var/log/kindly-guard/threats.log"
file_rotation = "daily"

# Metrics collection
metrics_enabled = true
metrics_endpoint = "http://prometheus:9090"

# Alert thresholds
[neutralization.reporting.alerts]
critical_threshold = 1      # Alert on any critical threat
high_threshold = 5          # Alert on 5+ high threats
total_threshold = 100       # Alert on 100+ total threats
```

### Use Case Examples

#### Example 1: Security Assessment

```bash
# Scan entire codebase in report-only mode
kindly scan /path/to/project --mode report-only -o security-report.json

# View summary
kindly report summary security-report.json

# Output:
📊 Security Report Summary
├── Total Files Scanned: 1,247
├── Threats Detected: 89
├── Critical: 3
├── High: 12
├── Medium: 31
└── Low: 43

Top Threat Types:
1. Unicode homoglyphs (23 instances)
2. Potential SQL injection (18 instances)
3. Path traversal attempts (15 instances)
```

#### Example 2: Production Monitoring

```yaml
# Kubernetes deployment with report-only mode
apiVersion: v1
kind: ConfigMap
metadata:
  name: kindly-guard-config
data:
  config.toml: |
    [neutralization]
    mode = "report_only"
    
    [neutralization.reporting]
    metrics_enabled = true
    metrics_endpoint = "http://prometheus:9090"
```

#### Example 3: A/B Testing Security Rules

```bash
# Run parallel instances with different configurations
# Instance A: Current rules (report-only)
kindly-guard server --config current-rules.toml --port 8080

# Instance B: New rules (report-only)  
kindly-guard server --config new-rules.toml --port 8081

# Compare detection rates and false positives
kindly compare-reports instance-a.log instance-b.log
```

### Report Types

#### 1. Summary Reports
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-01-20T10:30:00Z",
  "summary": {
    "files_scanned": 150,
    "threats_found": 23,
    "severity_breakdown": {
      "critical": 2,
      "high": 5,
      "medium": 10,
      "low": 6
    }
  }
}
```

#### 2. Detailed Reports
```json
{
  "threat_id": "threat-001",
  "type": "sql_injection",
  "severity": "high",
  "location": {
    "file": "api/users.rs",
    "line": 42,
    "column": 15
  },
  "content": "query = \"SELECT * FROM users WHERE id = '\" + user_id + \"'\"",
  "recommendation": "Use parameterized queries or prepared statements",
  "fix_example": "query = sqlx::query!(\"SELECT * FROM users WHERE id = $1\", user_id)"
}
```

#### 3. Metrics Dashboard
```
# Prometheus metrics exposed
kindly_guard_threats_detected_total{severity="critical"} 3
kindly_guard_threats_detected_total{severity="high"} 12
kindly_guard_scan_duration_seconds{quantile="0.99"} 0.125
kindly_guard_files_processed_total 1247
```

### Benefits

- ✅ **Zero impact**: No changes to your data or workflow
- ✅ **Visibility**: Understand your threat landscape
- ✅ **Testing**: Validate rules before enforcement
- ✅ **Compliance**: Generate audit reports
- ✅ **Baseline**: Establish security metrics

### When to Use

- Initial deployment and testing
- Security audits and assessments
- Compliance reporting
- Performance benchmarking
- Rule development and tuning
- Monitoring production systems

## Configuration Guide

### File-Based Configuration

Create a `kindly-guard.toml` file:

```toml
# Protection mode configuration
[neutralization]
mode = "automatic"  # or "interactive", "report_only"

# Mode-specific settings
[neutralization.automatic]
confidence_threshold = 0.8  # Min confidence for auto-action
prefer_safe_defaults = true

[neutralization.interactive]
timeout_seconds = 30
show_confidence_scores = true

[neutralization.report_only]
detailed_reports = true
include_fix_suggestions = true
```

### Environment Variables

Override configuration with environment variables:

```bash
# Set protection mode
export KINDLY_GUARD_NEUTRALIZATION_MODE=interactive

# Configure interactive timeout
export KINDLY_GUARD_NEUTRALIZATION_INTERACTIVE_TIMEOUT_SECONDS=60

# Enable detailed reporting
export KINDLY_GUARD_NEUTRALIZATION_REPORT_ONLY_DETAILED_REPORTS=true
```

### Runtime Configuration

Change modes dynamically via API:

```bash
# Switch to report-only mode
curl -X POST http://localhost:8080/api/config \
  -H "Content-Type: application/json" \
  -d '{"neutralization": {"mode": "report_only"}}'
```

## CLI Usage Examples

### Basic Commands

```bash
# Scan with specific mode
kindly scan file.txt --mode auto
kindly scan file.txt --mode interactive
kindly scan file.txt --mode report-only

# Server with protection mode
kindly-guard server --neutralization-mode automatic

# Wrap command with mode
kindly wrap --mode interactive -- claude "Write code"
```

### Advanced Usage

```bash
# Scan directory with auto-fix
kindly scan ./src --mode auto --fix --backup

# Interactive scan with preferences
kindly scan data.json --mode interactive --remember-choices

# Report-only with detailed output
kindly scan project/ --mode report-only --format detailed -o report.json

# Monitor with specific mode
kindly monitor --neutralization-mode report-only --dashboard
```

### Shell Integration

```bash
# Add to ~/.bashrc or ~/.zshrc
alias kindly-auto='kindly scan --mode auto'
alias kindly-check='kindly scan --mode report-only'
alias kindly-fix='kindly scan --mode interactive --fix'

# Protected command execution
alias safe-claude='kindly wrap --mode auto -- claude'
```

## MCP Integration Examples

### MCP Server Configuration

```toml
# MCP server with protection modes
[mcp]
enabled = true

[mcp.tools.security_scan]
default_mode = "automatic"
allow_mode_override = true

[mcp.tools.security_neutralize]
default_mode = "interactive"
require_confirmation = true
```

### Claude Desktop Integration

```json
// claude_desktop_config.json
{
  "mcpServers": {
    "kindly-guard": {
      "command": "kindly-guard",
      "args": ["mcp", "--mode", "automatic"],
      "env": {
        "KINDLY_GUARD_NEUTRALIZATION_MODE": "automatic"
      }
    }
  }
}
```

### Tool-Specific Modes

```javascript
// MCP tool registration with mode support
{
  "name": "security/scan",
  "description": "Scan content for security threats",
  "inputSchema": {
    "type": "object",
    "properties": {
      "content": { "type": "string" },
      "mode": {
        "type": "string",
        "enum": ["auto", "interactive", "report_only"],
        "default": "auto"
      }
    }
  }
}
```

### Usage in Claude

```
# Using KindlyGuard MCP tools with different modes

# Auto mode (default)
Use the security/scan tool to check this SQL query and fix any issues automatically.

# Interactive mode
Use security/scan with mode "interactive" to review this configuration file.

# Report-only mode  
Run security/scan in "report_only" mode to audit this codebase without changes.
```

## Best Practices

### Mode Selection Guidelines

1. **Start with Report-Only**
   - Begin with report-only mode to understand your threat landscape
   - Analyze reports to tune detection rules
   - Identify false positives before enabling protection

2. **Graduate to Interactive**
   - Move to interactive mode for controlled environments
   - Train team members on threat identification
   - Build confidence in the system

3. **Deploy Auto Mode**
   - Enable automatic mode in production
   - Monitor metrics and logs
   - Maintain audit trails

### Security Recommendations

#### For Auto Mode
- Enable comprehensive logging
- Set up alerting for critical threats
- Regularly review neutralization actions
- Maintain backup of originals
- Test rollback procedures

#### For Interactive Mode
- Set reasonable timeouts
- Provide clear threat descriptions
- Train users on threat types
- Log user decisions for audit
- Consider decision caching

#### For Report-Only Mode
- Automate report generation
- Set up dashboards for monitoring
- Alert on threshold breaches
- Regular security reviews
- Use for A/B testing rules

### Performance Optimization

```toml
# Optimize for each mode
[performance]
# Auto mode: Optimize for speed
[performance.auto]
use_simd = true
parallel_scanning = true
cache_size_mb = 256

# Interactive mode: Optimize for clarity
[performance.interactive]
detailed_analysis = true
include_context = true
syntax_highlighting = true

# Report-only: Optimize for completeness
[performance.report_only]
deep_scanning = true
collect_all_metrics = true
async_reporting = true
```

## Mode Selection Guide

### Decision Tree

```
Is this a production system?
├─ Yes
│  └─ Are you familiar with the threat patterns?
│     ├─ Yes → Use Auto Mode
│     └─ No → Start with Report-Only, then Auto
└─ No
   └─ Is this for testing/development?
      ├─ Yes → Use Interactive Mode
      └─ No → Is this for security audit?
         ├─ Yes → Use Report-Only Mode
         └─ No → Use Interactive Mode
```

### Comparison Matrix

| Factor | Auto | Interactive | Report-Only |
|--------|------|-------------|-------------|
| **User Intervention** | None | Required | None |
| **Performance Impact** | Minimal | Moderate | Minimal |
| **Security Level** | High | High | Monitoring |
| **False Positive Handling** | Automatic | Manual | Logged |
| **Learning Curve** | Low | Medium | Low |
| **Audit Trail** | Complete | Complete | Complete |
| **Rollback Support** | Yes | Yes | N/A |

### Environment Recommendations

| Environment | Recommended Mode | Reason |
|-------------|------------------|---------|
| Production API | Auto | Zero-touch security |
| Development | Interactive | Educational value |
| CI/CD Pipeline | Auto | Automated protection |
| Security Audit | Report-Only | Non-invasive |
| Data Migration | Interactive | Human oversight |
| Monitoring | Report-Only | Visibility |
| Customer Demo | Auto | Seamless experience |

## Troubleshooting

### Common Issues

#### Auto Mode Not Neutralizing
```bash
# Check configuration
kindly config validate

# Verify mode is set correctly
kindly config get neutralization.mode

# Check confidence thresholds
kindly config get neutralization.automatic.confidence_threshold
```

#### Interactive Mode Timeout
```toml
# Increase timeout in config
[neutralization.interactive]
timeout_seconds = 120  # 2 minutes

# Or disable timeout
timeout_seconds = 0
```

#### Report-Only Missing Threats
```bash
# Enable deep scanning
kindly scan --mode report-only --deep

# Check scanner configuration
kindly config get scanner

# Verify all scanners are enabled
kindly scanner list --enabled
```

### Debug Mode

```bash
# Enable debug logging for protection modes
export RUST_LOG=kindly_guard::neutralizer=debug

# Run with verbose output
kindly scan file.txt --mode auto -vvv

# Trace neutralization decisions
kindly scan --mode interactive --trace
```

### Getting Help

- 📚 Documentation: [docs.kindlyguard.com](https://docs.kindlyguard.com)
- 💬 Community: [GitHub Discussions](https://github.com/kindly-ai/kindly-guard/discussions)
- 🐛 Issues: [GitHub Issues](https://github.com/kindly-ai/kindly-guard/issues)
- 📧 Email: support@kindlyguard.com

---

Remember: KindlyGuard is **kind to you, tough on threats**. Choose the protection mode that best fits your needs, and rest assured that your security is in good hands. 🛡️