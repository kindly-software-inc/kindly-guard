# KindlyGuard Screenshots Guide

## Required Screenshots

### 1. Shield States

#### Standard Shield (Blue)
**Filename**: `screenshots/shield-standard.png`
- System tray with blue shield icon
- Tooltip showing "KindlyGuard - Protected (Standard)"
- Clean, professional appearance

#### Enhanced Shield (Purple) 
**Filename**: `screenshots/shield-enhanced.png`
- System tray with purple glowing shield
- Tooltip showing "KindlyGuard - Protected (Enhanced)"
- Subtle glow/pulse effect visible

#### Threat Detected Shield (Red)
**Filename**: `screenshots/shield-threat.png`
- Shield turns red during active threat
- Warning badge or exclamation mark
- Captures the moment of detection

### 2. Threat Notifications

#### Unicode Attack Notification
**Filename**: `screenshots/notif-unicode.png`
- Popup notification with threat details
- Shows: "Unicode Attack Blocked"
- Displays cleaned text
- Timestamp and severity

#### SQL Injection Notification
**Filename**: `screenshots/notif-sql.png`
- SQL injection attempt blocked
- Shows pattern that was detected
- Action taken (blocked/neutralized)

#### XSS Attack Notification
**Filename**: `screenshots/notif-xss.png`
- XSS attempt notification
- Shows sanitized output
- Protection status

### 3. Dashboard Views

#### Main Dashboard
**Filename**: `screenshots/dashboard-main.png`
- Overview of protection status
- Threat statistics
- Performance metrics
- Recent threats list

#### Threat Details View
**Filename**: `screenshots/dashboard-threat-detail.png`
- Detailed view of a specific threat
- Pattern analysis
- Timestamp and context
- Remediation action

#### Performance Analytics
**Filename**: `screenshots/dashboard-performance.png`
- Real-time performance graphs
- Scan speed metrics
- Memory usage
- Comparison between modes

### 4. Claude Integration

#### Claude Configuration
**Filename**: `screenshots/claude-config.png`
- claude_mcp_config.json file
- KindlyGuard server entry highlighted
- Clean JSON formatting

#### Protected Conversation
**Filename**: `screenshots/claude-protected.png`
- Claude interface with KindlyGuard active
- Small shield indicator
- Clean conversation flow

#### Threat Blocked in Claude
**Filename**: `screenshots/claude-threat-blocked.png`
- Attempted prompt injection
- KindlyGuard blocking message
- Safe response generated

### 5. Terminal/CLI

#### Installation Process
**Filename**: `screenshots/cli-install.png`
```bash
$ cargo install kindly-guard
   Compiling kindly-guard v0.2.0
   ...
   Installed kindly-guard
```

#### Server Running
**Filename**: `screenshots/cli-running.png`
```bash
$ kindly-guard serve
[INFO] KindlyGuard v0.2.0 starting...
[INFO] Security scanner initialized
[INFO] Shield UI connected
[INFO] MCP server listening on stdio
```

#### Threat Detection Log
**Filename**: `screenshots/cli-threat-log.png`
```bash
[WARN] Threat detected: Unicode bidirectional override at position 9
[INFO] Threat neutralized: Removed U+202E character
[INFO] Request processed safely
```

### 6. Configuration Examples

#### Standard Configuration
**Filename**: `screenshots/config-standard.png`
- TOML configuration file
- Standard mode settings
- Syntax highlighted

#### Enhanced Configuration
**Filename**: `screenshots/config-enhanced.png`
- Enhanced mode enabled
- Advanced features configured
- Performance optimizations

### 7. Feature Comparisons

#### Mode Comparison Table
**Filename**: `screenshots/comparison-modes.png`
| Feature | Standard | Enhanced |
|---------|----------|----------|
| Unicode Detection | ✓ | ✓ |
| SQL Injection | ✓ | ✓ |
| XSS Protection | ✓ | ✓ |
| Performance | Good | Excellent |
| Advanced Patterns | Basic | Full |
| Resource Usage | Low | Optimized |

#### Performance Benchmark
**Filename**: `screenshots/benchmark-results.png`
- Bar chart showing scan speeds
- Standard vs Enhanced mode
- Different file sizes

## Screenshot Tips

1. **Consistency**:
   - Use same OS/theme for all screenshots
   - Consistent window sizes
   - Clean desktop background

2. **Highlighting**:
   - Red boxes for important areas
   - Arrows to point out features
   - Blur sensitive information

3. **Quality**:
   - PNG format for clarity
   - Minimum 1280x720 resolution
   - Retina/HiDPI if possible

4. **Annotations**:
   - Add callouts for key features
   - Use consistent font/colors
   - Keep text minimal and clear

## Tools Recommended

- **macOS**: CleanShot X, Xnapper
- **Windows**: ShareX, Greenshot  
- **Linux**: Flameshot, Spectacle
- **Cross-platform**: Snagit

## File Organization

```
demo/screenshots/
├── shield/
│   ├── shield-standard.png
│   ├── shield-enhanced.png
│   └── shield-threat.png
├── notifications/
│   ├── notif-unicode.png
│   ├── notif-sql.png
│   └── notif-xss.png
├── dashboard/
│   ├── dashboard-main.png
│   ├── dashboard-threat-detail.png
│   └── dashboard-performance.png
├── claude/
│   ├── claude-config.png
│   ├── claude-protected.png
│   └── claude-threat-blocked.png
├── cli/
│   ├── cli-install.png
│   ├── cli-running.png
│   └── cli-threat-log.png
└── features/
    ├── comparison-modes.png
    └── benchmark-results.png
```