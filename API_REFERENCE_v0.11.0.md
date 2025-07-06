# KindlyGuard API Reference v0.11.0

## Table of Contents

1. [Overview](#overview)
2. [Public Traits](#public-traits)
3. [CLI Commands](#cli-commands)
4. [New Features in v0.11.0](#new-features-in-v0110)
5. [Usage Examples](#usage-examples)
6. [Shield Auto-Wrap Configuration](#shield-auto-wrap-configuration)

## Overview

KindlyGuard v0.11.0 introduces powerful new features including the wrap command with colored output, shield auto-wrap configuration, and enhanced trait-based architecture. This document provides comprehensive API documentation for all public interfaces.

## Public Traits

### Core Security Traits

#### `SecurityScannerTrait`

The primary trait for security scanning operations.

```rust
pub trait SecurityScannerTrait: Send + Sync {
    /// Scan text for security threats
    fn scan_text(&self, text: &str) -> Vec<Threat>;
    
    /// Scan JSON value for threats
    fn scan_json(&self, value: &serde_json::Value) -> Vec<Threat>;
    
    /// Scan with depth limit for nested content
    fn scan_with_depth(&self, text: &str, max_depth: usize) -> Vec<Threat>;
    
    /// Get scanner statistics
    fn get_stats(&self) -> ScannerStats;
    
    /// Reset scanner statistics
    fn reset_stats(&self);
}
```

**Example Usage:**
```rust
use kindly_guard_server::{SecurityScanner, Config};

let config = Config::default();
let scanner = SecurityScanner::new(config.scanner)?;

// Scan text for threats
let threats = scanner.scan_text("DROP TABLE users; --");
for threat in threats {
    println!("Threat detected: {}", threat);
}

// Get statistics
let stats = scanner.get_stats();
println!("Texts scanned: {}", stats.texts_scanned);
```

### Resilience Traits

#### `CircuitBreakerTrait`

Provides fault tolerance through circuit breaker pattern.

```rust
pub trait CircuitBreakerTrait: Send + Sync {
    /// Execute a function with circuit protection
    async fn call<F, T, Fut>(&self, name: &str, f: F) -> Result<T, CircuitBreakerError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<T>> + Send,
        T: Send;
    
    /// Get circuit state
    fn state(&self, name: &str) -> CircuitState;
    
    /// Get statistics
    fn stats(&self, name: &str) -> CircuitStats;
    
    /// Manual circuit control
    async fn trip(&self, name: &str, reason: &str);
    async fn reset(&self, name: &str);
}
```

#### `RetryStrategyTrait`

Handles retry logic with exponential backoff.

```rust
pub trait RetryStrategyTrait: Send + Sync {
    /// Execute with retry logic
    async fn execute<F, T, Fut>(&self, operation: &str, f: F) -> Result<T>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: Future<Output = Result<T>> + Send,
        T: Send;
    
    /// Analyze error for retry decision
    fn should_retry(&self, error: &anyhow::Error, context: &RetryContext) -> RetryDecision;
    
    /// Get retry statistics
    fn stats(&self) -> RetryStats;
}
```

### Enhanced Security Traits

#### `EnhancedScanner`

Advanced threat detection capabilities.

```rust
pub trait EnhancedScanner: Send + Sync {
    /// Scan with enhanced capabilities
    fn enhanced_scan(&self, data: &[u8]) -> Result<Vec<Threat>>;
    
    /// Get scanner performance metrics
    fn get_metrics(&self) -> ScannerMetrics;
    
    /// Preload patterns for optimization
    fn preload_patterns(&self, patterns: &[String]) -> Result<()>;
}
```

#### `SecurityEventProcessor`

Process and correlate security events.

```rust
pub trait SecurityEventProcessor: Send + Sync {
    /// Process a security event
    async fn process_event(&self, event: SecurityEvent) -> Result<EventHandle>;
    
    /// Get processor statistics
    fn get_stats(&self) -> ProcessorStats;
    
    /// Check if an endpoint is under monitoring
    fn is_monitored(&self, endpoint: &str) -> bool;
    
    /// Get correlation insights for a client
    async fn get_insights(&self, client_id: &str) -> Result<SecurityInsights>;
    
    /// Perform cleanup of old events
    async fn cleanup(&self) -> Result<()>;
}
```

## CLI Commands

### kindly-tools

The main development and utility CLI for KindlyGuard ecosystem.

#### Main Commands

```bash
# Scan files or directories for security threats
kindly-tools scan <PATH> [OPTIONS]

# Install tools and dependencies
kindly-tools install [SUBCOMMAND]

# Manage MCP servers
kindly-tools mcp [SUBCOMMAND]

# Development utilities
kindly-tools dev [SUBCOMMAND]

# Wrap AI CLI commands with protection (NEW in v0.11.0)
kindly-tools wrap [COMMAND] [OPTIONS]

# Monitor KindlyGuard server status
kindly-tools monitor [OPTIONS]

# Security shield commands (NEW in v0.11.0)
kindly-tools shield [SUBCOMMAND]
```

### Scan Command

Comprehensive security scanning for files and directories.

```bash
# Basic scan
kindly-tools scan /path/to/file.json

# Recursive directory scan
kindly-tools scan /path/to/dir --recursive

# Scan with specific format output
kindly-tools scan file.txt --format json

# Filter by extensions
kindly-tools scan . --recursive --extensions json,txt,md

# Limit file size
kindly-tools scan large_dir/ --max-size-mb 5
```

**Options:**
- `--format`: Output format (json, table, brief) - default: table
- `--recursive`: Recursively scan directories
- `--extensions`: Comma-separated list of file extensions
- `--max-size-mb`: Maximum file size in MB - default: 10
- `--config`: Custom configuration file path

### Wrap Command (NEW in v0.11.0)

Real-time protection for any AI CLI command with colored output indicating threat levels.

```bash
# Wrap a single command
kindly-tools wrap claude "Help me write a SQL query"

# Use blocking mode (prevents threats from executing)
kindly-tools wrap --block openai "Generate a bash script"

# Use custom server
kindly-tools wrap --server http://security.local:8080 gemini "Create code"

# Configure auto-wrap
kindly-tools wrap config init
kindly-tools wrap config show
kindly-tools wrap config add mycli
kindly-tools wrap config remove oldcli
```

**Colored Output:**
- 🟢 **Green**: Safe input, no threats detected
- 🟡 **Yellow**: Low/Medium severity threats detected (warning mode)
- 🔴 **Red**: High/Critical threats detected

**Example Session:**
```bash
$ kindly-tools wrap claude "Tell me about SQL injection"
🛡️ KindlyGuard Protection: Active
Server: http://localhost:8080
Mode: Warning

▶ Tell me about SQL injection  # Green - safe educational query
[Claude responds normally...]

$ kindly-tools wrap claude "'; DROP TABLE users; --"
🛡️ KindlyGuard Protection: Active
Server: http://localhost:8080
Mode: Warning

▶ '; DROP TABLE users; --  # Red - SQL injection detected
⚠️  THREAT DETECTED
  • SQL injection attempt detected at position 0
⚠️  Proceeding with caution...
[Claude responds with warning about the malicious input...]

🛡️ KindlyGuard Protection: Session ended
```

### Shield Command (NEW in v0.11.0)

Generate shell functions for automatic AI CLI protection.

```bash
# Generate shield wrapper functions
kindly-tools shield auto-wrap -o ~/.kindly-shield.sh

# Specify shell type
kindly-tools shield auto-wrap --shell zsh -o ~/.kindly-shield.zsh

# Add custom commands
kindly-tools shield auto-wrap -c mycli -c aichat -o ~/.kindly-shield.sh

# Skip default commands
kindly-tools shield auto-wrap --no-defaults -c mycli -o ~/.custom-shield.sh
```

**Generated Functions:**
- Wrapper functions for each AI command
- `kindly-shield-status`: Check protection status
- `kindly-shield-disable`: Temporarily disable protection
- `kindly-shield-enable`: Re-enable protection

### Monitor Command

Real-time monitoring of KindlyGuard server status.

```bash
# Basic monitoring
kindly-tools monitor

# Connect to specific server
kindly-tools monitor --server http://localhost:8080

# Set refresh interval
kindly-tools monitor --interval 1000  # milliseconds

# Show detailed metrics
kindly-tools monitor --detailed
```

## New Features in v0.11.0

### 1. Wrap Command with Colored Output

The wrap command now provides visual feedback through colored prompts:

```rust
// Color coding logic
let colored_input = match (threats.is_empty(), max_severity) {
    (true, _) => {
        // Green for safe input
        format!("▶ {}", stdin_buf.trim()).green().to_string()
    }
    (false, Severity::Low | Severity::Medium) => {
        // Yellow for warnings
        format!("▶ {}", stdin_buf.trim()).yellow().to_string()
    }
    (false, Severity::High | Severity::Critical) => {
        // Red for critical threats
        format!("▶ {}", stdin_buf.trim()).red().to_string()
    }
};
```

### 2. Shield Auto-Wrap Configuration

Automatic protection for AI CLI tools through shell function wrappers:

```bash
# Installation
kindly-tools shield auto-wrap -o ~/.kindly-shield.sh
echo "source ~/.kindly-shield.sh" >> ~/.bashrc

# Usage
claude "Help me with coding"  # Automatically scanned
openai "Generate a script"    # Protected by default

# Management
kindly-shield-status          # Check status
kindly-shield-disable         # Temporary bypass
kindly-shield-enable          # Re-enable
```

### 3. Wrap Configuration Management

Persistent configuration for wrap behavior:

```toml
# ~/.config/kindly/wrap.toml
enabled = true
mode = "warning"  # or "blocking"
server = "http://localhost:8080"
verbose = false
log_sessions = true
log_directory = "~/.local/share/kindly/logs"

# Commands to wrap
commands = ["claude", "openai", "gemini", "gpt", "ai"]

# Custom commands added by user
custom_commands = ["mycli", "company-ai"]
```

### 4. Enhanced Threat Visualization

The wrap command provides detailed threat information:

```
⚠️  THREAT DETECTED
  • SQL injection attempt at position 15
  • Severity: Critical
  • Pattern: DROP TABLE statement
  • Recommended action: Block execution
```

## Usage Examples

### Example 1: Basic Security Scanning

```rust
use kindly_guard_server::{SecurityScanner, Config, Threat};

#[tokio::main]
async fn main() -> Result<()> {
    // Create scanner with default config
    let config = Config::default();
    let scanner = SecurityScanner::new(config.scanner)?;
    
    // Scan user input
    let user_input = "SELECT * FROM users WHERE id = '1' OR '1'='1'";
    let threats = scanner.scan_text(user_input);
    
    if !threats.is_empty() {
        println!("Security threats detected:");
        for threat in threats {
            println!("  - {}: {}", threat.threat_type, threat.description);
        }
    }
    
    Ok(())
}
```

### Example 2: Using Circuit Breaker

```rust
use kindly_guard_server::{Config, create_circuit_breaker};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::default();
    let circuit_breaker = create_circuit_breaker(&config)?;
    
    // Protected API call
    let result = circuit_breaker.call("api-endpoint", || async {
        // Your API call here
        external_api_call().await
    }).await;
    
    match result {
        Ok(data) => println!("Success: {:?}", data),
        Err(CircuitBreakerError::CircuitOpen) => {
            println!("Circuit is open - service unavailable");
        }
        Err(e) => println!("Error: {}", e),
    }
    
    // Check circuit state
    let state = circuit_breaker.state("api-endpoint");
    println!("Circuit state: {:?}", state);
    
    Ok(())
}
```

### Example 3: Wrap Command Integration

```bash
#!/bin/bash
# Script that uses wrapped AI commands

# The command is automatically protected
claude "Help me optimize this SQL query: SELECT * FROM large_table"

# Check if protection is active
if kindly-shield-status | grep -q "ACTIVE"; then
    echo "Protection is active"
fi

# Temporarily disable for trusted operations
kindly-shield-disable
claude "$(cat trusted_prompt.txt)"
kindly-shield-enable
```

### Example 4: Programmatic Wrap Usage

```rust
use kindly_tools::wrap::{wrap_command, WrapConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = WrapConfig::load()?;
    
    // Wrap a command programmatically
    let command = vec![
        "claude".to_string(),
        "Analyze this code for vulnerabilities".to_string()
    ];
    
    // Execute with protection
    wrap_command_with_config(command, Some(config)).await?;
    
    Ok(())
}
```

### Example 5: Custom Shield Configuration

```bash
# Create custom shield for specific tools
cat > ~/.custom-ai-shield.sh << 'EOF'
#!/bin/bash

# Custom protection for company AI tools
__protect_ai() {
    local cmd="$1"
    shift
    
    # Custom validation logic
    if [[ "$*" =~ (password|secret|key) ]]; then
        echo "⚠️  Sensitive data detected! Blocking for security." >&2
        return 1
    fi
    
    # Use KindlyGuard scanner
    if kindly-tools scan --brief <(echo "$*") 2>/dev/null | grep -q "THREAT"; then
        echo "🛡️ KindlyGuard: Threats detected" >&2
        return 1
    fi
    
    # Execute if safe
    command "$cmd" "$@"
}

# Wrap company tools
company_ai() { __protect_ai "company-ai" "$@"; }
internal_llm() { __protect_ai "internal-llm" "$@"; }
EOF

source ~/.custom-ai-shield.sh
```

## Shield Auto-Wrap Configuration

### Default Protected Commands

The shield auto-wrap feature protects these AI CLI tools by default:

- `claude` - Anthropic's Claude CLI
- `openai` - OpenAI CLI
- `gemini` - Google Gemini CLI
- `gpt` - Generic GPT interfaces
- `chatgpt` - ChatGPT CLI
- `llm` - Generic LLM tools
- `ai` - Generic AI tools
- `ollama` - Local LLM runner
- `anthropic` - Anthropic tools
- `bard` - Google Bard CLI

### Configuration Options

```toml
# ~/.config/kindly/wrap.toml

# Global settings
enabled = true              # Enable/disable wrapping
mode = "warning"           # "warning" or "blocking"
server = "http://localhost:8080"  # KindlyGuard server URL
verbose = true             # Show detailed threat info
log_sessions = true        # Log all wrapped sessions
log_directory = "~/.local/share/kindly/logs"

# Commands to wrap (merged with defaults)
commands = [
    "claude",
    "openai", 
    "custom-ai-tool"
]

# Additional custom commands (tracked separately)
custom_commands = [
    "company-llm",
    "research-ai"
]
```

### Environment Variables

Control wrap behavior through environment variables:

```bash
# Disable protection temporarily
KINDLY_SHIELD_DISABLED=1 claude "unsafe prompt"

# Use different server
KINDLY_WRAP_SERVER="http://security:8080" openai "query"

# Enable verbose mode
KINDLY_WRAP_VERBOSE=1 gemini "analyze this"

# Force blocking mode
KINDLY_WRAP_MODE=blocking ai "generate code"
```

### Integration Examples

#### VS Code Integration

```json
// .vscode/settings.json
{
    "terminal.integrated.env.linux": {
        "KINDLY_SHIELD_CONFIG": "${workspaceFolder}/.kindly/wrap.toml"
    },
    "terminal.integrated.shellArgs.linux": [
        "-c",
        "source ~/.kindly-shield.sh && exec bash"
    ]
}
```

#### Docker Integration

```dockerfile
# Add KindlyGuard protection to containers
FROM ubuntu:latest

# Install KindlyGuard
RUN cargo install kindly-tools

# Generate shield
RUN kindly-tools shield auto-wrap -o /etc/profile.d/kindly-shield.sh

# Ensure it's sourced
ENV BASH_ENV=/etc/profile.d/kindly-shield.sh
```

#### CI/CD Integration

```yaml
# GitHub Actions
- name: Setup KindlyGuard Shield
  run: |
    cargo install kindly-tools
    kindly-tools shield auto-wrap -o $HOME/.kindly-shield.sh
    echo "source $HOME/.kindly-shield.sh" >> $GITHUB_ENV

# GitLab CI
before_script:
  - cargo install kindly-tools
  - kindly-tools shield auto-wrap -o ~/.kindly-shield.sh
  - source ~/.kindly-shield.sh
```

### Troubleshooting

#### Common Issues

1. **"kindly command not found"**
   ```bash
   # Ensure kindly-tools is in PATH
   export PATH="$HOME/.cargo/bin:$PATH"
   cargo install kindly-tools
   ```

2. **Commands not being wrapped**
   ```bash
   # Check if functions are loaded
   type claude  # Should show the wrapper function
   kindly-shield-status
   ```

3. **Performance concerns**
   - Scanner only activates for args >10 characters
   - Temporary files are immediately cleaned up
   - Adds <100ms latency typically

4. **Bypass protection (use with caution)**
   ```bash
   # Method 1: Environment variable
   KINDLY_SHIELD_DISABLED=1 claude "prompt"
   
   # Method 2: Direct command
   command claude "prompt"
   
   # Method 3: Full path
   /usr/local/bin/claude "prompt"
   ```

## Security Best Practices

1. **Always use blocking mode in production**
   ```toml
   mode = "blocking"
   ```

2. **Monitor wrapped sessions**
   ```toml
   log_sessions = true
   log_directory = "/var/log/kindly"
   ```

3. **Regularly update threat patterns**
   ```bash
   kindly-tools mcp update-patterns
   ```

4. **Use local KindlyGuard server for sensitive environments**
   ```toml
   server = "http://127.0.0.1:8080"
   ```

5. **Implement defense in depth**
   - Use wrap for real-time protection
   - Scan files before processing
   - Monitor with shield dashboard
   - Enable audit logging

## Migration Guide from v0.10.x

### Breaking Changes

None - v0.11.0 maintains backward compatibility.

### New Features to Adopt

1. **Enable wrap protection**:
   ```bash
   kindly-tools wrap config init
   ```

2. **Install shield wrappers**:
   ```bash
   kindly-tools shield auto-wrap -o ~/.kindly-shield.sh
   source ~/.kindly-shield.sh
   ```

3. **Update configuration for colored output**:
   ```toml
   # Enable colored output in terminals
   [output]
   colored = true
   unicode_symbols = true
   ```

## Performance Considerations

### Wrap Command Performance

- **Overhead**: <100ms per command typically
- **Memory**: Minimal - uses streaming for large inputs
- **CPU**: Negligible for normal usage

### Optimization Tips

1. **Use allow-lists for trusted commands**:
   ```toml
   [wrap.whitelist]
   patterns = ["test_*", "demo_*"]
   ```

2. **Configure scan depth**:
   ```toml
   [scanner]
   max_depth = 3  # Limit recursion
   ```

3. **Enable pattern caching**:
   ```toml
   [performance]
   pattern_cache_size = 1000
   ```

## Support and Resources

- **Documentation**: https://docs.kindlyguard.com
- **GitHub**: https://github.com/kindlyguard/kindly-guard
- **Discord**: https://discord.gg/kindlyguard
- **Security Issues**: security@kindlyguard.com

## License

KindlyGuard is licensed under the Apache License 2.0. See LICENSE file for details.