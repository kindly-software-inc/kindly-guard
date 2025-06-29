# KindlyGuard CLI

Command-line interface for KindlyGuard security operations. Provides utilities for threat scanning, monitoring, and security analysis.

## Features

- **🔍 File Scanning** - Scan files and directories for security threats
- **📊 Real-time Monitoring** - Live threat detection dashboard
- **🛡️ Security Status** - View current security status and statistics
- **⚙️ Configuration Management** - Validate and test configurations

## Installation

### From crates.io
```bash
cargo install kindly-guard-cli
```

### From source
```bash
git clone https://github.com/kindlyguard/kindly-guard
cd kindly-guard
cargo build --release --bin kindly-guard-cli
```

## Usage

### Scan Files
```bash
# Scan a single file
kindly-guard-cli scan file.txt

# Scan with JSON output
kindly-guard-cli scan file.txt --output json

# Scan directory recursively
kindly-guard-cli scan /path/to/dir --recursive

# Scan with specific threat types
kindly-guard-cli scan file.txt --types unicode,injection
```

### Monitor Mode
```bash
# Start monitoring dashboard
kindly-guard-cli monitor

# Monitor with custom update interval
kindly-guard-cli monitor --interval 500

# Monitor specific server
kindly-guard-cli monitor --server http://localhost:8080
```

### Security Status
```bash
# Get current status
kindly-guard-cli status

# Get status in JSON format
kindly-guard-cli status --output json

# Get detailed status
kindly-guard-cli status --detailed
```

### Configuration
```bash
# Validate configuration
kindly-guard-cli validate-config config.yaml

# Generate example config
kindly-guard-cli generate-config > config.yaml

# Test configuration
kindly-guard-cli test-config config.yaml
```

## Output Formats

### Human-Readable (Default)
```
🛡️ KindlyGuard Security Scan
━━━━━━━━━━━━━━━━━━━━━━━━━

📄 File: example.txt
⚠️  2 threats detected

[HIGH] Unicode BiDi Override at position 42
  Hidden text reversal detected
  → Remove BiDi control characters

[CRITICAL] SQL Injection at line 5
  Pattern: '; DROP TABLE users; --
  → Use parameterized queries
```

### JSON Format
```json
{
  "scan_results": {
    "file": "example.txt",
    "threats": [
      {
        "type": "unicode_bidi",
        "severity": "high",
        "location": {"offset": 42},
        "description": "Hidden text reversal detected"
      }
    ],
    "summary": {
      "total_threats": 2,
      "critical": 1,
      "high": 1
    }
  }
}
```

### CSV Format
```csv
file,threat_type,severity,location,description
example.txt,unicode_bidi,high,42,"Hidden text reversal detected"
example.txt,sql_injection,critical,line:5,"SQL injection pattern detected"
```

## Configuration

### Environment Variables
- `KINDLY_GUARD_CONFIG` - Path to configuration file
- `RUST_LOG` - Logging level (trace, debug, info, warn, error)

### CLI Configuration File
```yaml
# ~/.config/kindly-guard/cli.yaml
default_output: human
colors: true
scanner:
  types: [unicode, injection]
  max_file_size: 10MB
monitor:
  update_interval: 1000
  show_stats: true
```

## Examples

### Batch Scanning
```bash
# Scan multiple files
kindly-guard-cli scan *.json

# Scan with pattern
find . -name "*.py" | xargs kindly-guard-cli scan

# Scan and save report
kindly-guard-cli scan src/ --recursive --output json > report.json
```

### Integration with CI/CD
```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    kindly-guard-cli scan . --recursive --output json > scan-results.json
    if [ -s scan-results.json ]; then
      echo "Security threats detected!"
      cat scan-results.json
      exit 1
    fi
```

### Monitoring Script
```bash
#!/bin/bash
# monitor.sh - Monitor and alert on threats

kindly-guard-cli monitor --output json | while read -r line; do
  threat_count=$(echo "$line" | jq -r '.threats_detected // 0')
  if [ "$threat_count" -gt 0 ]; then
    echo "ALERT: $threat_count threats detected!"
    # Send notification
    notify-send "KindlyGuard Alert" "$threat_count threats detected"
  fi
done
```

## Exit Codes

- `0` - Success, no threats found
- `1` - Threats detected
- `2` - Configuration error
- `3` - File not found
- `4` - Permission denied
- `5` - Network error
- `10` - Unknown error

## Performance

- Scans ~1GB/sec on modern hardware
- Low memory footprint (<50MB for most operations)
- Parallel scanning for directories
- Streaming mode for large files

## License

Licensed under either of:
- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## See Also

- [kindly-guard-server](https://crates.io/crates/kindly-guard-server) - MCP server
- [kindly-guard-client](https://crates.io/crates/kindly-guard-client) - Client library
- [Documentation](https://docs.kindlyguard.dev)