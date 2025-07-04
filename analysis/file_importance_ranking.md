# KindlyGuard File Importance Ranking

## Critical Files (Importance: 9-10)

### 1. **kindly-guard-server/src/main.rs** (10/10)
- Entry point for the main MCP server
- Handles all protocol initialization and server startup
- Critical for the entire system's operation

### 2. **kindly-guard-server/src/lib.rs** (10/10)
- Core library exports and module organization
- Defines the public API surface for the server
- Central to all server functionality

### 3. **kindly-guard-server/src/traits.rs** (9/10)
- Defines core traits for scanner, neutralizer, and other components
- Essential for the plugin architecture and extensibility
- All security components implement these traits

### 4. **kindly-guard-server/src/scanner/mod.rs** (9/10)
- Core threat detection logic
- Implements Unicode, XSS, and injection attack detection
- Critical security component

### 5. **kindly-guard-core/src/atomic_event_buffer.rs** (9/10)
- Patent-pending atomic event buffer implementation
- Core performance optimization for high-throughput scenarios
- Part of the enhanced/proprietary features

## High Importance Files (7-8)

### 6. **kindly-guard-server/src/neutralizer/mod.rs** (8/10)
- Threat neutralization and mitigation logic
- Works in tandem with the scanner
- Critical for security response

### 7. **kindly-guard-server/src/protocol/mod.rs** (8/10)
- MCP protocol implementation
- Handles Claude Code integration
- Essential for AI assistant communication

### 8. **kindly-guard-shield/src-tauri/src/main.rs** (8/10)
- Tauri application entry point
- System tray integration
- Visual feedback system

### 9. **kindly-guard-server/src/transport/websocket.rs** (7/10)
- WebSocket transport for real-time communication
- Essential for Claude Code extension integration
- Enables live threat monitoring

### 10. **kindly-guard-server/src/auth.rs** (7/10)
- Authentication and authorization logic
- Security-critical component
- Protects server endpoints

## Medium Importance Files (5-6)

### 11. **kindly-guard-cli/src/main.rs** (6/10)
- CLI tool entry point
- User-facing interface for scanning
- Important for standalone usage

### 12. **kindly-guard-server/src/config.rs** (6/10)
- Configuration management
- Runtime behavior customization
- Essential for deployment flexibility

### 13. **claude-code-kindlyguard/src/extension.ts** (6/10)
- VS Code extension integration
- Provides IDE-level security scanning
- Important for developer experience

### 14. **npm-package/lib/main.js** (5/10)
- NPM package entry point
- JavaScript/Node.js integration
- Important for cross-platform support

### 15. **kindly-guard-server/src/metrics.rs** (5/10)
- Performance metrics and monitoring
- Important for production deployments
- Helps identify bottlenecks

## Module Relationships

### Core Dependencies Flow:
1. **kindly-guard-cli** → **kindly-guard-server**
   - CLI depends on server for scanning functionality
   
2. **kindly-guard-server** ⇢ **kindly-guard-core** (optional)
   - Server can use enhanced features from core
   
3. **kindly-guard-shield** ⇢ **kindly-guard-core** (optional)
   - Shield app can use enhanced features
   
4. **External Integrations** → **kindly-guard-server**
   - All integrations communicate with the main server

### Critical Paths:
1. **Security Path**: scanner → neutralizer → audit
2. **Protocol Path**: transport → protocol → server
3. **Enhancement Path**: standard_impl ⇢ enhanced_impl (when core enabled)