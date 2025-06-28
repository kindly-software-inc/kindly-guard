# KindlyGuard Development Plan

## Current Status
We've created the initial structure for KindlyGuard, a focused MCP security server that protects against unicode attacks, injection attempts, and other threats.

### ✅ Completed
1. Created workspace structure with proper naming
2. Set up Cargo.toml with 2025 Rust security best practices
3. Created main.rs entry point
4. Implemented configuration system (config.rs)

### 🚧 In Progress
- Building the scanner module for threat detection
- Implementing the MCP server protocol handler
- Creating the shield UI display

### 📋 Todo List
1. **Scanner Module** (scanner/mod.rs, unicode.rs, injection.rs, patterns.rs)
   - Unicode threat detection (invisible chars, BiDi, homoglyphs)
   - Injection pattern detection (prompt, command, SQL)
   - Path traversal detection
   - Integration with core patented tech

2. **Server Implementation** (server.rs)
   - MCP protocol handling with jsonrpc
   - Request/response security middleware
   - Threat logging and metrics
   - Session protection

3. **Shield Display** (shield/mod.rs, display.rs)
   - Terminal-based real-time display
   - Show protection status, threats blocked, uptime
   - Use ratatui for nice TUI

4. **CLI Tool** (kindly-guard-cli/)
   - Standalone scanner for files/directories
   - Integration with server for monitoring
   - Report generation

5. **Core Integration**
   - Set up private repo for patented tech
   - Link as git dependency
   - Use atomic event buffer for high-performance scanning

## Architecture Notes

### Security Scanner Design
```rust
pub trait ThreatScanner {
    fn scan_text(&self, text: &str) -> Vec<Threat>;
    fn scan_json(&self, json: &Value) -> Vec<Threat>;
    fn scan_bytes(&self, data: &[u8]) -> Vec<Threat>;
}

pub struct Threat {
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub location: Location,
    pub description: String,
}
```

### MCP Server Flow
1. Receive request via stdio/HTTP
2. Parse JSON-RPC request
3. **Security scan all inputs**
4. If threats detected → block & log
5. If clean → process request
6. Return response with security headers

### Shield UI Mock
```
╭──────────────────────────────────────╮
│ 🛡️  KindlyGuard Security Shield      │
├──────────────────────────────────────┤
│ Status: ● Protected                  │
│ Uptime: 2h 15m 42s                  │
│                                      │
│ Threats Blocked                      │
│ ├─ Unicode Attacks:     23           │
│ ├─ Injection Attempts:  15           │
│ ├─ Path Traversal:      4            │
│ └─ Total:              42            │
│                                      │
│ Performance                          │
│ ├─ Scan Rate: 125k req/s            │
│ ├─ Avg Latency: 0.8ms               │
│ └─ Memory: 42 MB                    │
╰──────────────────────────────────────╯
```

## Key Security Patterns (2025 Best Practices)

1. **Zero Unsafe Blocks** in public code
2. **Type-Safe Threat Modeling** - use enums not strings
3. **SIMD Scanning** where possible for performance
4. **Constant-Time Comparisons** for security checks
5. **No Panics in Production** - all Results handled
6. **Minimal Dependencies** - audit everything

## Next Steps
1. Complete scanner module with unicode detection
2. Implement basic MCP server protocol
3. Create minimal shield display
4. Test with real MCP clients
5. Add CLI tool for standalone scanning

## Private Core Features
The `kindly-guard-core` private repo will contain:
- Atomic Event Buffer for high-performance scanning
- Patented circuit breaker implementation
- Advanced pattern matching algorithms
- Zero-copy scanning techniques

This keeps the valuable IP separate while providing a useful open-source tool.