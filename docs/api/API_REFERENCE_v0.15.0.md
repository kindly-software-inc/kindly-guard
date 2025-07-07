# KindlyGuard API Reference v0.15.0

## Table of Contents

1. [Overview](#overview)
2. [New Features in v0.15.0](#new-features-in-v0150)
3. [Quarantine API](#quarantine-api)
4. [Enhanced Scan Tool](#enhanced-scan-tool)
5. [Protection Mode APIs](#protection-mode-apis)
6. [Message Service APIs](#message-service-apis)
7. [MCP Tool Definitions](#mcp-tool-definitions)
8. [Response Format Changes](#response-format-changes)
9. [Configuration Options](#configuration-options)
10. [Migration Guide](#migration-guide)

## Overview

KindlyGuard v0.15.0 introduces groundbreaking features that enhance the "Kind to you, tough on threats" philosophy. Major additions include:

- **Quarantine System**: Safe isolation of threats with encryption and retention policies
- **Enhanced Scan Tool**: Multi-mode protection with automatic neutralization
- **Friendly Messaging**: Positive, encouraging UI while maintaining security
- **Protection Modes**: Auto-protect, interactive, and report-only modes
- **Advanced Message Service**: Context-aware messaging with personality adaptation

## New Features in v0.15.0

### 1. Quarantine System
- Encrypted threat storage using ChaCha20Poly1305
- Automatic compression after 30 days
- Automatic deletion after 90 days
- Full audit trail with metadata tracking

### 2. Enhanced Protection Modes
- **Auto-Protect**: Automatic threat neutralization
- **Interactive**: User confirmation for each action
- **Report-Only**: Analysis without modification

### 3. Friendly Messaging System
- Context-aware message generation
- Personality adaptation based on threat levels
- Color-coded output for clarity
- Positive reinforcement for security actions

### 4. Advanced Neutralization
- Quarantine-aware neutralization
- Recovery capabilities
- Multi-strategy threat handling

## Quarantine API

### Core Trait: `Quarantine`

The quarantine system provides safe storage for threats before neutralization.

```rust
#[async_trait::async_trait]
pub trait Quarantine: Send + Sync {
    /// Store content in quarantine
    async fn quarantine(
        &self,
        content: &str,
        threat_info: ThreatInfo,
        source: Option<String>,
    ) -> Result<String>; // Returns quarantine ID
    
    /// Retrieve quarantined content
    async fn retrieve(&self, id: &str) -> Result<Option<QuarantineEntry>>;
    
    /// List quarantined items
    async fn list(&self, filter: QuarantineFilter) -> Result<Vec<QuarantineEntry>>;
    
    /// Delete quarantined item
    async fn delete(&self, id: &str) -> Result<bool>;
    
    /// Apply retention policy
    async fn apply_retention(&self) -> Result<RetentionStats>;
}
```

### Types

#### `ThreatInfo`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub threat_type: String,
    pub severity: String,
    pub description: String,
    pub location: Option<String>,
    pub timestamp: SystemTime,
}
```

#### `QuarantineEntry`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_content: String,
    pub threat_info: ThreatInfo,
    pub source: Option<String>,
    pub created_at: SystemTime,
    pub compressed: bool,
    pub metadata: HashMap<String, String>,
}
```

#### `QuarantineFilter`

```rust
#[derive(Debug, Default)]
pub struct QuarantineFilter {
    pub start_time: Option<SystemTime>,
    pub end_time: Option<SystemTime>,
    pub threat_type: Option<String>,
    pub severity: Option<String>,
    pub source: Option<String>,
}
```

#### `RetentionStats`

```rust
#[derive(Debug, Serialize)]
pub struct RetentionStats {
    pub compressed: usize,
    pub deleted: usize,
    pub errors: usize,
}
```

### Example Usage

```rust
use kindly_guard_server::{
    quarantine::{create_quarantine, QuarantineConfig, ThreatInfo},
    scanner::Threat,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Create quarantine manager
    let config = QuarantineConfig {
        base_path: PathBuf::from("/var/lib/kindlyguard/quarantine"),
        encrypt: true,
        compress_after_days: 30,
        delete_after_days: 90,
        max_size_mb: 1000,
    };
    let quarantine = create_quarantine(&config);
    
    // Quarantine a threat
    let threat_info = ThreatInfo {
        threat_type: "sql_injection".to_string(),
        severity: "critical".to_string(),
        description: "SQL injection attempt detected".to_string(),
        location: Some("user_input:42".to_string()),
        timestamp: SystemTime::now(),
    };
    
    let quarantine_id = quarantine.quarantine(
        "SELECT * FROM users WHERE id='1' OR '1'='1'",
        threat_info,
        Some("api_endpoint".to_string()),
    ).await?;
    
    println!("Threat quarantined with ID: {}", quarantine_id);
    
    // List quarantined items
    let filter = QuarantineFilter {
        severity: Some("critical".to_string()),
        ..Default::default()
    };
    
    let entries = quarantine.list(filter).await?;
    for entry in entries {
        println!("Quarantine {}: {} threat from {}", 
            entry.id, 
            entry.threat_info.threat_type,
            entry.source.unwrap_or_else(|| "unknown".to_string())
        );
    }
    
    Ok(())
}
```

## Enhanced Scan Tool

### Scan Options

```rust
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub neutralize: bool,
    pub quarantine: bool,
    pub interactive: bool,
    pub backup_original: bool,
    pub output_path: Option<String>,
    pub format: String,
    pub mode: ProtectionMode,
}
```

### Protection Modes

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum ProtectionMode {
    /// Automatically protect against threats
    AutoProtect,
    
    /// Ask user for each action
    Interactive,
    
    /// Report threats without taking action
    ReportOnly,
}
```

### Scan Results

```rust
#[derive(Debug, Serialize)]
pub enum ScanResult {
    /// No threats detected
    Clean,
    
    /// Threats were neutralized
    Protected {
        original_threats: Vec<Threat>,
        neutralized_content: String,
        quarantine_id: Option<String>,
        actions_taken: Vec<(ThreatType, String)>,
    },
    
    /// Threats reported but not acted upon
    ReportOnly {
        threats: Vec<Threat>,
    },
}
```

### CLI Usage

```bash
# Auto-protect mode (default)
kindly-tools scan file.txt --mode auto-protect

# Interactive mode - asks for confirmation
kindly-tools scan sensitive.json --mode interactive

# Report-only mode - no modifications
kindly-tools scan analyze.sql --mode report-only

# With quarantine enabled (default)
kindly-tools scan malicious.js --quarantine

# Save neutralized output
kindly-tools scan input.txt --output clean.txt

# Scan from stdin
echo "DROP TABLE users;" | kindly-tools scan -

# Scan with all protections
kindly-tools scan dangerous.sql \
    --mode auto-protect \
    --quarantine \
    --backup-original \
    --output safe.sql
```

### Programmatic Usage

```rust
use kindly_guard::tools::scan::{
    run_scan_enhanced, 
    ScanOptions, 
    ProtectionMode,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Configure scan options
    let options = ScanOptions {
        mode: ProtectionMode::AutoProtect,
        neutralize: true,
        quarantine: true,
        interactive: false,
        backup_original: true,
        output_path: Some("cleaned.txt".to_string()),
        format: "json".to_string(),
    };
    
    // Run enhanced scan
    run_scan_enhanced("suspicious_file.txt", options).await?;
    
    Ok(())
}
```

## Protection Mode APIs

### Mode Selection

Protection modes determine how KindlyGuard responds to detected threats:

```rust
impl ProtectionMode {
    /// Get mode from string
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "auto" | "auto-protect" => Ok(Self::AutoProtect),
            "interactive" | "ask" => Ok(Self::Interactive),
            "report" | "report-only" => Ok(Self::ReportOnly),
            _ => Err(anyhow!("Invalid protection mode: {}", s)),
        }
    }
    
    /// Get description
    pub fn description(&self) -> &'static str {
        match self {
            Self::AutoProtect => "Automatically neutralize all threats",
            Self::Interactive => "Ask before neutralizing each threat",
            Self::ReportOnly => "Report threats without taking action",
        }
    }
}
```

### Interactive Mode Prompts

In interactive mode, users are prompted for each threat:

```rust
pub struct InteractivePrompt {
    pub threat: Threat,
    pub options: Vec<InteractiveOption>,
}

pub enum InteractiveOption {
    Neutralize,
    Skip,
    ViewDetails,
    Quarantine,
    Abort,
}

impl InteractivePrompt {
    pub async fn display(&self) -> Result<InteractiveOption> {
        // Display threat information
        println!("🔍 Threat Detected: {}", self.threat.threat_type);
        println!("   Severity: {}", self.threat.severity);
        println!("   Location: {}", self.threat.location);
        
        // Show options
        println!("\nWhat would you like to do?");
        println!("  [N]eutralize - Remove the threat");
        println!("  [S]kip - Leave as is");
        println!("  [D]etails - View more information");
        println!("  [Q]uarantine - Save to quarantine only");
        println!("  [A]bort - Stop scanning");
        
        // Get user input
        let choice = read_user_input().await?;
        
        match choice.to_lowercase().as_str() {
            "n" => Ok(InteractiveOption::Neutralize),
            "s" => Ok(InteractiveOption::Skip),
            "d" => Ok(InteractiveOption::ViewDetails),
            "q" => Ok(InteractiveOption::Quarantine),
            "a" => Ok(InteractiveOption::Abort),
            _ => Err(anyhow!("Invalid choice")),
        }
    }
}
```

## Message Service APIs

### Core Types

#### `MessageService`

```rust
pub struct MessageService {
    formatter: Arc<MessageFormatter>,
    templates: Arc<MessageTemplates>,
    personality: Arc<MessagePersonality>,
}

impl MessageService {
    /// Generate a welcome message
    pub fn welcome(&self, user_name: Option<&str>) -> FriendlyMessage;
    
    /// Generate a threat neutralized message
    pub fn threat_neutralized(&self, threat_type: &str, count: usize) -> FriendlyMessage;
    
    /// Generate a success celebration
    pub fn celebrate_success(&self, achievement: &str) -> FriendlyMessage;
    
    /// Generate a quarantine notification
    pub fn quarantine_notification(&self, file_path: &str, reason: &str) -> FriendlyMessage;
    
    /// Generate an interactive prompt
    pub fn prompt(&self, question: &str, options: &[&str]) -> FriendlyMessage;
    
    /// Generate a positive reinforcement message
    pub fn encourage(&self) -> FriendlyMessage;
    
    /// Generate a security tip
    pub fn security_tip(&self) -> FriendlyMessage;
    
    /// Set the mood of the message personality
    pub fn set_mood(&self, mood: Mood);
    
    /// Adapt personality to context
    pub fn adapt_to_context(&self, context: PersonalityContext);
}
```

#### `FriendlyMessage`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendlyMessage {
    pub id: String,
    pub message_type: MessageType,
    pub priority: MessagePriority,
    pub content: String,
    pub icon: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub context: Option<MessageContext>,
}

impl FriendlyMessage {
    /// Format the message with optional color and emoji
    pub fn format(&self, color: bool, emoji: bool) -> String;
}
```

#### `MessageType`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    PositiveReinforcement,
    ThreatNeutralized,
    InteractivePrompt,
    SuccessCelebration,
    QuarantineNotification,
    Welcome,
    StatusUpdate,
    SecurityTip,
}
```

### Example Usage

```rust
use kindly_guard_server::messages::{MessageService, Mood, PersonalityContext};

fn main() {
    let message_service = MessageService::new();
    
    // Welcome message
    let welcome = message_service.welcome(Some("Alice"));
    println!("{}", welcome.format(true, true));
    // Output: 👋 Welcome back, Alice! Ready to keep your system safe and sound!
    
    // Threat neutralized
    let threat_msg = message_service.threat_neutralized("SQL Injection", 3);
    println!("{}", threat_msg.format(true, true));
    // Output: 🛡️ Successfully neutralized 3 SQL Injection threats! Your data is safe!
    
    // Success celebration
    let celebrate = message_service.celebrate_success("100% threat prevention rate");
    println!("{}", celebrate.format(true, true));
    // Output: 🎉 Amazing! You've achieved 100% threat prevention rate!
    
    // Adapt personality to high-threat environment
    message_service.adapt_to_context(PersonalityContext {
        threat_level: ThreatLevel::High,
        user_experience: UserExperience::Advanced,
        time_of_day: TimeOfDay::Evening,
    });
    
    // Messages will now be more serious but still encouraging
    let alert = message_service.threat_neutralized("XSS", 1);
    println!("{}", alert); 
    // Output: 🛡️ Critical XSS threat neutralized. Excellent security posture maintained.
}
```

## MCP Tool Definitions

### Enhanced Scan Tool

```json
{
  "name": "scan",
  "description": "Scan content for security threats with protection options",
  "inputSchema": {
    "type": "object",
    "properties": {
      "content": {
        "type": "string",
        "description": "Content to scan (file path, URL, or direct text)"
      },
      "mode": {
        "type": "string",
        "enum": ["auto-protect", "interactive", "report-only"],
        "default": "auto-protect",
        "description": "Protection mode"
      },
      "options": {
        "type": "object",
        "properties": {
          "neutralize": {
            "type": "boolean",
            "default": true,
            "description": "Neutralize detected threats"
          },
          "quarantine": {
            "type": "boolean",
            "default": true,
            "description": "Quarantine threats before neutralization"
          },
          "backup_original": {
            "type": "boolean",
            "default": true,
            "description": "Create backup of original content"
          },
          "output_path": {
            "type": "string",
            "description": "Path to save neutralized content"
          }
        }
      }
    },
    "required": ["content"]
  }
}
```

### Quarantine Management Tool

```json
{
  "name": "quarantine",
  "description": "Manage quarantined threats",
  "inputSchema": {
    "type": "object",
    "properties": {
      "action": {
        "type": "string",
        "enum": ["list", "retrieve", "delete", "stats"],
        "description": "Quarantine action to perform"
      },
      "id": {
        "type": "string",
        "description": "Quarantine entry ID (for retrieve/delete)"
      },
      "filter": {
        "type": "object",
        "properties": {
          "severity": {
            "type": "string",
            "enum": ["low", "medium", "high", "critical"]
          },
          "threat_type": {
            "type": "string"
          },
          "start_date": {
            "type": "string",
            "format": "date-time"
          },
          "end_date": {
            "type": "string",
            "format": "date-time"
          }
        }
      }
    },
    "required": ["action"]
  }
}
```

### Neutralize Tool

```json
{
  "name": "neutralize",
  "description": "Neutralize threats in content",
  "inputSchema": {
    "type": "object",
    "properties": {
      "content": {
        "type": "string",
        "description": "Content containing threats"
      },
      "threats": {
        "type": "array",
        "items": {
          "type": "object",
          "properties": {
            "type": { "type": "string" },
            "severity": { "type": "string" },
            "location": { "type": "string" }
          }
        },
        "description": "Detected threats to neutralize"
      },
      "strategy": {
        "type": "string",
        "enum": ["remove", "escape", "sanitize", "replace"],
        "default": "sanitize",
        "description": "Neutralization strategy"
      },
      "create_quarantine": {
        "type": "boolean",
        "default": true,
        "description": "Create quarantine entry before neutralization"
      }
    },
    "required": ["content", "threats"]
  }
}
```

### Protection Status Tool

```json
{
  "name": "protection_status",
  "description": "Get current protection status and statistics",
  "inputSchema": {
    "type": "object",
    "properties": {
      "include_stats": {
        "type": "boolean",
        "default": true,
        "description": "Include detailed statistics"
      },
      "time_range": {
        "type": "string",
        "enum": ["hour", "day", "week", "month", "all"],
        "default": "day",
        "description": "Time range for statistics"
      }
    }
  }
}
```

## Response Format Changes

### Enhanced Scan Response

```json
{
  "result": {
    "status": "protected",
    "summary": {
      "threats_found": 3,
      "threats_neutralized": 3,
      "quarantine_id": "q-2025-01-20-xyz123",
      "processing_time_ms": 45
    },
    "threats": [
      {
        "id": "t-001",
        "type": "sql_injection",
        "severity": "critical",
        "location": "line 42, column 15",
        "description": "SQL injection attempt detected",
        "neutralized": true,
        "action_taken": "Escaped SQL metacharacters"
      }
    ],
    "message": {
      "type": "ThreatNeutralized",
      "content": "Successfully protected your content from 3 threats! 🛡️",
      "icon": "🛡️",
      "priority": "high"
    },
    "neutralized_content": "SELECT * FROM users WHERE id = ?",
    "original_backup_path": "/tmp/backup-2025-01-20-xyz123.txt"
  }
}
```

### Quarantine List Response

```json
{
  "result": {
    "entries": [
      {
        "id": "q-2025-01-20-abc456",
        "threat_info": {
          "type": "xss",
          "severity": "high",
          "description": "Cross-site scripting attempt"
        },
        "source": "user_comment.html",
        "created_at": "2025-01-20T10:30:00Z",
        "size_bytes": 1024,
        "compressed": false,
        "expires_at": "2025-04-20T10:30:00Z"
      }
    ],
    "total": 15,
    "page": 1,
    "per_page": 10,
    "retention_status": {
      "total_size_mb": 45.2,
      "items_pending_compression": 5,
      "items_pending_deletion": 2
    }
  }
}
```

### Protection Status Response

```json
{
  "result": {
    "protection_enabled": true,
    "mode": "auto-protect",
    "statistics": {
      "time_range": "day",
      "threats_detected": 42,
      "threats_neutralized": 40,
      "threats_quarantined": 38,
      "false_positives_reported": 2,
      "uptime_hours": 168,
      "last_threat": "2025-01-20T09:45:00Z"
    },
    "quarantine_status": {
      "total_entries": 156,
      "total_size_mb": 89.3,
      "oldest_entry": "2024-10-22T14:20:00Z"
    },
    "system_health": {
      "scanner_status": "healthy",
      "neutralizer_status": "healthy",
      "quarantine_status": "healthy",
      "message_service_status": "healthy"
    }
  }
}
```

## Configuration Options

### Quarantine Configuration

```toml
[quarantine]
# Base directory for quarantine storage
base_path = "/var/lib/kindlyguard/quarantine"

# Enable encryption for quarantined content
encrypt = true

# Compress entries after this many days
compress_after_days = 30

# Delete entries after this many days
delete_after_days = 90

# Maximum total size for quarantine storage (MB)
max_size_mb = 1000

# Retention check interval (seconds)
retention_check_interval = 3600
```

### Protection Mode Configuration

```toml
[protection]
# Default protection mode
default_mode = "auto-protect"

# Enable interactive prompts
allow_interactive = true

# Automatic backup of original content
auto_backup = true

# Backup directory
backup_dir = "/var/lib/kindlyguard/backups"

# Maximum backup retention (days)
backup_retention_days = 7
```

### Message Service Configuration

```toml
[messages]
# Enable friendly messages
enabled = true

# Message personality
personality = "encouraging"  # encouraging, professional, minimal

# Color output
use_color = true

# Emoji in messages
use_emoji = true

# Adapt personality to threat levels
adaptive_personality = true

# Message templates directory
templates_dir = "/etc/kindlyguard/messages"
```

### Enhanced Scanner Configuration

```toml
[scanner.enhanced]
# Enable enhanced scanning features
enabled = true

# Maximum scan depth for nested content
max_scan_depth = 10

# Pattern caching
enable_pattern_cache = true
pattern_cache_size = 1000

# Parallel scanning
parallel_scan = true
max_scan_threads = 4

# Scan timeout (seconds)
scan_timeout = 30
```

## Migration Guide

### From v0.11.x to v0.15.0

#### 1. Update Dependencies

```toml
[dependencies]
kindly-guard-server = "0.15.0"
kindly-tools = "0.15.0"
```

#### 2. Enable New Features

```rust
// Old scan API
let threats = scanner.scan_text(content);

// New enhanced scan API
let options = ScanOptions {
    mode: ProtectionMode::AutoProtect,
    quarantine: true,
    ..Default::default()
};
let result = run_scan_enhanced(content, options).await?;
```

#### 3. Configure Quarantine

```rust
// Add quarantine configuration
let config = Config {
    quarantine: Some(QuarantineConfig {
        base_path: PathBuf::from("/var/lib/kindlyguard/quarantine"),
        encrypt: true,
        compress_after_days: 30,
        delete_after_days: 90,
        max_size_mb: 1000,
    }),
    ..existing_config
};
```

#### 4. Integrate Message Service

```rust
// Create message service
let message_service = MessageService::new();

// Use friendly messages
let msg = message_service.threat_neutralized("XSS", 1);
println!("{}", msg.format(true, true));
```

#### 5. Update MCP Tool Registrations

```rust
// Register enhanced tools
server.register_tool("scan", enhanced_scan_tool());
server.register_tool("quarantine", quarantine_management_tool());
server.register_tool("protection_status", protection_status_tool());
```

### Breaking Changes

- The `scan` tool now returns `ScanResult` instead of `Vec<Threat>`
- Default protection mode is now `AutoProtect` instead of report-only
- Quarantine is enabled by default for all threat detections
- Message formatting now includes color and emoji by default

### Compatibility Notes

- Old scan API is maintained for backward compatibility but deprecated
- Configuration files from v0.11.x will work but should be updated
- MCP protocol remains compatible with existing clients

## Performance Considerations

### Quarantine Performance

- Encryption adds ~2ms per KB of content
- Compression reduces storage by 60-80% for text content
- Retention checks run asynchronously every hour
- Maximum quarantine size prevents disk exhaustion

### Scanner Performance

- Enhanced scanning adds <5% overhead
- Pattern caching improves performance by 40%
- Parallel scanning utilizes all CPU cores
- Memory usage scales with content size

### Message Service Performance

- Message generation adds <1ms overhead
- Template caching eliminates repeated parsing
- Personality adaptation is instantaneous
- No performance impact on core security operations

## Security Considerations

### Quarantine Security

- All quarantined content is encrypted at rest
- Encryption keys are rotated monthly
- Access requires explicit permissions
- Audit trail for all quarantine operations

### Protection Modes

- Auto-protect mode is recommended for production
- Interactive mode requires TTY for prompts
- Report-only mode allows security analysis
- All modes maintain full audit trails

## Best Practices

### 1. Quarantine Management

```rust
// Regularly apply retention policies
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(3600));
    loop {
        interval.tick().await;
        if let Err(e) = quarantine.apply_retention().await {
            error!("Retention policy failed: {}", e);
        }
    }
});
```

### 2. Protection Mode Selection

```rust
// Choose mode based on context
let mode = match environment {
    Environment::Production => ProtectionMode::AutoProtect,
    Environment::Development => ProtectionMode::Interactive,
    Environment::Testing => ProtectionMode::ReportOnly,
};
```

### 3. Message Personalization

```rust
// Adapt messages to user context
let context = PersonalityContext {
    threat_level: current_threat_level(),
    user_experience: detect_user_experience(),
    time_of_day: current_time_of_day(),
};
message_service.adapt_to_context(context);
```

## Troubleshooting

### Common Issues

1. **Quarantine storage full**
   - Check `max_size_mb` configuration
   - Run manual retention: `kindly-tools quarantine cleanup`
   - Review retention policies

2. **Interactive mode not working**
   - Ensure TTY is available
   - Check `allow_interactive` configuration
   - Use `--mode report-only` as fallback

3. **Messages not displaying colors**
   - Check terminal color support
   - Verify `use_color` configuration
   - Set `COLORTERM=truecolor` environment variable

4. **Performance degradation**
   - Review scanner timeout settings
   - Check pattern cache hit rate
   - Monitor quarantine size

## Support and Resources

- **Documentation**: https://docs.kindlyguard.com/v0.15.0
- **API Reference**: https://api.kindlyguard.com/v0.15.0
- **GitHub**: https://github.com/kindlyguard/kindly-guard
- **Discord**: https://discord.gg/kindlyguard
- **Security Issues**: security@kindlyguard.com

## License

KindlyGuard is licensed under the Apache License 2.0. See LICENSE file for details.