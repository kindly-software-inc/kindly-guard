# KindlyGuard Quarantine Management Guide

## Table of Contents
- [Overview](#overview)
- [How Quarantine Works](#how-quarantine-works)
- [Management Commands](#management-commands)
- [Security Features](#security-features)
- [Retention Policies](#retention-policies)
- [Best Practices](#best-practices)
- [Common Scenarios](#common-scenarios)
- [Troubleshooting](#troubleshooting)

## Overview

The KindlyGuard quarantine system provides a secure isolation mechanism for potentially malicious content detected during security scans. Rather than immediately deleting suspicious content, the system moves it to an encrypted quarantine storage where it can be safely reviewed, analyzed, and restored if determined to be a false positive.

### Key Benefits

1. **False Positive Protection**: Prevents accidental data loss from overzealous security scanning
2. **Forensic Analysis**: Allows security teams to study attack patterns and improve detection
3. **Audit Trail**: Maintains a complete record of all quarantined threats
4. **Secure Storage**: Military-grade encryption ensures quarantined threats cannot execute or spread
5. **Automated Lifecycle**: Intelligent retention policies manage storage automatically

## How Quarantine Works

### Automatic Quarantine Process

When KindlyGuard detects a threat, the following automated process occurs:

1. **Detection**: Scanner identifies potentially malicious content
2. **Isolation**: Content is immediately moved to quarantine storage
3. **Encryption**: Data is encrypted using ChaCha20Poly1305 with unique keys
4. **Metadata Recording**: Threat details, timestamps, and context are logged
5. **Notification**: Administrators receive alerts about new quarantine entries
6. **Original Replacement**: A safe placeholder is left at the original location

### Quarantine Storage Structure

```
~/.kindlyguard/quarantine/
├── active/           # Recently quarantined items (< 30 days)
│   └── {id}/        # Unique quarantine ID
│       ├── data     # Encrypted content
│       └── meta     # Metadata and threat info
├── compressed/      # Older items (30-90 days)
│   └── {year-month}.tar.zst
└── index.db        # SQLite database for quick lookups
```

## Management Commands

### List Quarantined Items

View all quarantined content with filtering options:

```bash
# List all quarantined items
kindly-guard quarantine list

# Filter by date range
kindly-guard quarantine list --since "7 days ago" --until "today"

# Filter by threat type
kindly-guard quarantine list --threat-type unicode-injection

# Filter by severity
kindly-guard quarantine list --severity critical

# Combine filters with output formatting
kindly-guard quarantine list --severity high --format json
```

### Show Quarantine Details

Examine specific quarantined items:

```bash
# Show detailed information about a quarantined item
kindly-guard quarantine show <quarantine-id>

# Show with decrypted content preview (requires admin privileges)
kindly-guard quarantine show <quarantine-id> --decrypt

# Export quarantine metadata
kindly-guard quarantine show <quarantine-id> --export metadata.json
```

### Restore Quarantined Content

Restore false positives back to their original location:

```bash
# Restore a single item
kindly-guard quarantine restore <quarantine-id>

# Restore with safety check
kindly-guard quarantine restore <quarantine-id> --verify

# Restore to alternative location
kindly-guard quarantine restore <quarantine-id> --to /safe/location/

# Batch restore with pattern
kindly-guard quarantine restore --pattern "*.txt" --threat-type low
```

### Clean Quarantine Storage

Remove quarantined items permanently:

```bash
# Remove specific item
kindly-guard quarantine clean <quarantine-id>

# Clean items older than retention policy
kindly-guard quarantine clean --expired

# Clean by severity (remove only low severity)
kindly-guard quarantine clean --severity low --older-than "60 days"

# Dry run to preview what would be cleaned
kindly-guard quarantine clean --dry-run --all
```

## Security Features

### ChaCha20Poly1305 Encryption

All quarantined content is encrypted using the ChaCha20Poly1305 authenticated encryption algorithm:

- **256-bit keys**: Unique key per quarantined item
- **96-bit nonces**: Prevents replay attacks
- **Authentication tags**: Ensures data integrity
- **Key derivation**: Uses Argon2id for master key protection

### Access Control

The quarantine system implements strict access controls:

```toml
# Example configuration in kindly-guard.toml
[quarantine.access]
# Require admin privileges for decrypt operations
require_admin_for_decrypt = true

# Require MFA for restore operations
require_mfa_for_restore = true

# Audit all quarantine access
audit_access = true
```

### Secure Deletion

When items are cleaned from quarantine:

1. Encryption keys are securely wiped from memory
2. File data is overwritten with random data (3 passes)
3. Metadata is purged from all indexes
4. Audit logs record the deletion event

## Retention Policies

### Default Lifecycle

The quarantine system follows a three-stage retention policy:

#### Stage 1: Active Storage (0-30 days)
- Items remain individually encrypted
- Full metadata available for quick access
- Instant restore capability
- No compression applied

#### Stage 2: Compressed Archive (30-90 days)
- Items are bundled into monthly archives
- Compression reduces storage by ~70%
- Restore requires archive extraction
- Metadata remains searchable

#### Stage 3: Automatic Deletion (90+ days)
- Items are permanently deleted
- Deletion logs retained for compliance
- Statistics preserved in summary reports
- Keys securely destroyed

### Custom Retention Policies

Configure custom retention in `kindly-guard.toml`:

```toml
[quarantine.retention]
# Days before compression
compress_after_days = 30

# Days before deletion
delete_after_days = 90

# Special retention for critical threats
[quarantine.retention.overrides]
critical_severity_days = 365
legal_hold_pattern = "evidence-*"
```

## Best Practices

### Regular Review Schedule

1. **Daily**: Review critical and high severity quarantines
2. **Weekly**: Analyze patterns in medium severity items
3. **Monthly**: Clean up verified threats and false positives
4. **Quarterly**: Update detection rules based on quarantine analysis

### False Positive Management

When reviewing potential false positives:

```bash
# 1. Examine the threat details
kindly-guard quarantine show <id> --verbose

# 2. Check similar patterns
kindly-guard quarantine list --similar-to <id>

# 3. Test with updated rules
kindly-guard scan --test-rules /tmp/test-content

# 4. Restore if confirmed safe
kindly-guard quarantine restore <id> --log-reason "False positive: internal tool"

# 5. Update exclusion rules
echo "exclude_pattern = 'internal-tool-*'" >> .kindlyguard/config.toml
```

### Quarantine Analysis Workflow

```bash
# Generate quarantine statistics
kindly-guard quarantine stats --last-month

# Export for threat intelligence
kindly-guard quarantine export --format=stix2 --output=threats.json

# Identify patterns
kindly-guard quarantine analyze --find-patterns --min-occurrences=5

# Create detection rule updates
kindly-guard quarantine suggest-rules --based-on-fps
```

## Common Scenarios

### Scenario 1: Accidental Quarantine of Development Files

Your build artifacts were quarantined due to obfuscated code detection:

```bash
# Find all quarantined build files
kindly-guard quarantine list --path-pattern "**/build/**"

# Review one to confirm
kindly-guard quarantine show <id> --decrypt | less

# Restore all build artifacts
kindly-guard quarantine restore --path-pattern "**/build/**" \
  --log-reason "Build artifacts false positive"

# Add exclusion
echo 'exclude_paths = ["**/build/**", "**/dist/**"]' >> .kindlyguard/config.toml
```

### Scenario 2: Investigating a Targeted Attack

Multiple related threats detected across the system:

```bash
# Find all threats from the same time window
kindly-guard quarantine list --since "2024-01-20 14:00" \
  --until "2024-01-20 15:00" --format json > attack-window.json

# Analyze relationships
kindly-guard quarantine analyze --input attack-window.json \
  --find-relationships

# Export for incident response
kindly-guard quarantine export --ids-from attack-window.json \
  --include-samples --password-protect
```

### Scenario 3: Compliance Audit

Preparing quarantine data for audit:

```bash
# Generate compliance report
kindly-guard quarantine report --compliance --format pdf \
  --period "last-quarter" --output Q1-quarantine-report.pdf

# Export audit logs
kindly-guard quarantine audit-log --export --sign

# Verify retention compliance
kindly-guard quarantine verify-retention --policy company-policy.yaml
```

### Scenario 4: Storage Management

Quarantine storage growing too large:

```bash
# Check storage usage
kindly-guard quarantine storage --usage

# Find large items
kindly-guard quarantine list --sort-by size --limit 20

# Archive old items manually
kindly-guard quarantine archive --older-than "45 days" \
  --to /backup/quarantine/

# Clean up low-risk items
kindly-guard quarantine clean --severity info \
  --older-than "14 days" --confirm
```

## Troubleshooting

### Common Issues

#### Cannot Decrypt Quarantine Item
```bash
# Check permissions
kindly-guard auth status

# Verify key availability
kindly-guard quarantine verify-keys

# Try with elevated privileges
sudo kindly-guard quarantine show <id> --decrypt
```

#### Restore Fails
```bash
# Check original path still exists
kindly-guard quarantine show <id> | grep original_path

# Restore to alternative location
kindly-guard quarantine restore <id> --to /tmp/restored/

# Force restore with new permissions
kindly-guard quarantine restore <id> --force --fix-permissions
```

#### Quarantine Database Corruption
```bash
# Run integrity check
kindly-guard quarantine verify --deep

# Rebuild index from files
kindly-guard quarantine rebuild-index

# Export and reimport
kindly-guard quarantine export --all --format sqlite
kindly-guard quarantine import --from backup.db
```

### Performance Optimization

For large quarantine stores:

```toml
# Optimize in kindly-guard.toml
[quarantine.performance]
# Use parallel processing
parallel_operations = true

# Increase cache size
metadata_cache_mb = 512

# Enable bloom filters
use_bloom_filters = true

# Compression settings
[quarantine.compression]
algorithm = "zstd"
level = 3  # Balance speed/size
threads = 4
```

### Getting Help

```bash
# Built-in help
kindly-guard quarantine --help
kindly-guard quarantine <command> --help

# Check system status
kindly-guard doctor --quarantine

# View recent operations
kindly-guard quarantine log --tail 50

# Generate debug bundle
kindly-guard debug --quarantine --output debug-bundle.tar.gz
```

---

Remember: The quarantine system is your safety net. When in doubt, quarantine first and analyze later. It's always better to temporarily isolate suspicious content than to risk system compromise.