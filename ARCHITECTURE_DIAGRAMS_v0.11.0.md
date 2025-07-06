# KindlyGuard Architecture Diagrams v0.11.0

This document provides comprehensive architecture diagrams for the KindlyGuard system, illustrating the component structure, data flows, and integration patterns.

## Table of Contents

1. [System Overview](#system-overview)
2. [Component Interaction](#component-interaction)
3. [Data Flow - Wrap Command](#data-flow-wrap-command)
4. [Shield Auto-Wrap Sequence](#shield-auto-wrap-sequence)
5. [Threat Detection Pipeline](#threat-detection-pipeline)
6. [Binary Structure](#binary-structure)
7. [MCP Protocol Flow](#mcp-protocol-flow)

## System Overview

```mermaid
graph TB
    subgraph "User Space"
        CLI[AI CLI Tools<br/>claude, openai, etc.]
        User[User Input]
        Shield[Shell Functions<br/>Auto-wrap]
    end
    
    subgraph "KindlyGuard Ecosystem"
        subgraph "kindly-tools Binary"
            Wrap[wrap command]
            ScanCmd[scan command]
            MonitorCmd[monitor command]
            ShieldCmd[shield command]
        end
        
        subgraph "kindly-guard-server Binary"
            Server[MCP Server]
            Scanner[Security Scanner]
            Storage[(Threat Storage)]
            Dashboard[TUI Dashboard]
        end
        
        subgraph "kindly-guard-shield Binary"
            Desktop[Tauri Desktop App]
            WebUI[Web Interface]
        end
    end
    
    subgraph "AI Systems"
        Claude[Claude Code]
        OpenAI[OpenAI CLI]
        Other[Other AI CLIs]
    end
    
    User -->|types| Shield
    Shield -->|intercepts| CLI
    CLI -->|wrapped by| Wrap
    Wrap -->|scans with| Scanner
    Scanner -->|logs to| Storage
    Scanner -->|displays in| Dashboard
    
    Claude -->|MCP Protocol| Server
    OpenAI -->|wrapped| Wrap
    Other -->|wrapped| Wrap
    
    Desktop -->|monitors| Server
    WebUI -->|displays| Storage
    
    style Scanner fill:#ff6b6b,stroke:#c92a2a,color:#fff
    style Server fill:#51cf66,stroke:#2f9e44,color:#fff
    style Wrap fill:#339af0,stroke:#1864ab,color:#fff
```

## Component Interaction

```mermaid
graph LR
    subgraph "Security Core"
        Scanner[SecurityScanner]
        Unicode[Unicode Scanner]
        Injection[Injection Scanner]
        XSS[XSS Scanner]
        Crypto[Crypto Scanner]
        Patterns[Pattern Scanner]
    end
    
    subgraph "Resilience Layer"
        CB[Circuit Breaker]
        Retry[Retry Handler]
        Bulkhead[Bulkhead Isolation]
    end
    
    subgraph "Protocol Layer"
        MCP[MCP Handler]
        Claude[Claude Code Extensions]
        Types[Protocol Types]
    end
    
    subgraph "Storage Layer"
        SQLite[(SQLite DB)]
        Cache[LRU Cache]
        EventBuffer[Event Buffer]
    end
    
    subgraph "UI Layer"
        TUI[Terminal UI]
        Shield[Shield Dashboard]
        Stats[Statistics View]
    end
    
    Scanner --> Unicode
    Scanner --> Injection
    Scanner --> XSS
    Scanner --> Crypto
    Scanner --> Patterns
    
    MCP -->|uses| Scanner
    MCP -->|protected by| CB
    MCP -->|retries with| Retry
    MCP -->|isolated by| Bulkhead
    
    Scanner -->|stores threats| SQLite
    Scanner -->|caches results| Cache
    Scanner -->|buffers events| EventBuffer
    
    SQLite -->|displays in| TUI
    Cache -->|shows stats| Stats
    EventBuffer -->|feeds| Shield
    
    style Scanner fill:#ff6b6b,stroke:#c92a2a,color:#fff
    style MCP fill:#51cf66,stroke:#2f9e44,color:#fff
    style TUI fill:#339af0,stroke:#1864ab,color:#fff
```

## Data Flow - Wrap Command

```mermaid
sequenceDiagram
    participant User
    participant Shell
    participant KindlyTools as kindly-tools
    participant Scanner
    participant AITool as AI CLI
    participant Output
    
    User->>Shell: Types AI command
    Shell->>KindlyTools: kindly wrap [ai-tool] [args]
    KindlyTools->>KindlyTools: Load wrap config
    
    Note over KindlyTools: Check if command should be wrapped
    
    KindlyTools->>AITool: Spawn process with pipes
    
    loop User Input
        User->>KindlyTools: Input text
        KindlyTools->>Scanner: Scan for threats
        Scanner->>Scanner: Unicode detection
        Scanner->>Scanner: Injection detection
        Scanner->>Scanner: XSS detection
        Scanner->>Scanner: Pattern matching
        
        alt Threats Detected
            Scanner-->>KindlyTools: Threat list
            KindlyTools->>Output: Display colored warning
            
            alt Blocking Mode
                KindlyTools->>Output: ❌ Input blocked
                KindlyTools->>User: Request new input
            else Warning Mode
                KindlyTools->>Output: ⚠️ Proceeding with caution
                KindlyTools->>AITool: Forward input
            end
        else No Threats
            Scanner-->>KindlyTools: Empty threat list
            KindlyTools->>Output: ▶ Safe input (green)
            KindlyTools->>AITool: Forward input
        end
        
        AITool-->>Output: Response
    end
    
    AITool-->>KindlyTools: Exit code
    KindlyTools->>Output: 🛡️ Session ended
```

## Shield Auto-Wrap Sequence

```mermaid
sequenceDiagram
    participant User
    participant Shell as Shell Config
    participant Shield as kindly shield
    participant FS as File System
    participant Runtime as Shell Runtime
    
    User->>Shield: kindly shield auto-wrap
    Shield->>Shield: Gather AI commands list
    
    Note over Shield: Default commands:<br/>claude, openai, gemini,<br/>gpt, chatgpt, llm, ai,<br/>ollama, anthropic, bard
    
    Shield->>Shield: Generate shell functions
    
    alt Output to File
        Shield->>FS: Write wrapper script
        Shield->>User: Display activation instructions
        User->>Shell: source wrapper.sh
    else Output to Stdout
        Shield->>User: Print wrapper functions
        User->>Shell: Paste into .bashrc/.zshrc
    end
    
    Shell->>Runtime: Load wrapper functions
    
    Note over Runtime: Functions now override<br/>original commands
    
    loop Each AI Command Call
        User->>Runtime: ai-command [args]
        Runtime->>Runtime: __kindly_shield_wrap()
        
        alt Kindly Not Installed
            Runtime->>User: Warning: Shield disabled
            Runtime->>Runtime: Run original command
        else Text Content Detected
            Runtime->>FS: Create temp file
            Runtime->>Runtime: kindly scan temp.txt
            
            alt Threats Found
                Runtime->>User: ⚠️ THREAT DETECTED
                Runtime->>User: Show threat details
                
                alt KINDLY_SHIELD_BLOCK=1
                    Runtime->>User: ❌ Command blocked
                else
                    Runtime->>User: ⚠️ Proceed? [y/N]
                    User->>Runtime: Decision
                end
            else No Threats
                Runtime->>Runtime: Execute command
            end
        else No Text Content
            Runtime->>Runtime: Execute command directly
        end
    end
```

## Threat Detection Pipeline

```mermaid
graph TD
    Input[Input Text/JSON]
    
    subgraph "Pre-processing"
        Normalize[Unicode Normalization]
        Depth[Depth Check]
    end
    
    subgraph "Detection Modules"
        subgraph "Unicode Scanner"
            Invisible[Invisible Chars]
            BiDi[BiDi Override]
            Homograph[Homograph Attack]
            Control[Control Chars]
        end
        
        subgraph "Injection Scanner"
            SQL[SQL Injection]
            Command[Command Injection]
            Prompt[Prompt Injection]
            Path[Path Traversal]
            LDAP[LDAP Injection]
        end
        
        subgraph "XSS Scanner"
            Script[Script Tags]
            Event[Event Handlers]
            DataURI[Data URIs]
            Entity[HTML Entities]
        end
        
        subgraph "Crypto Scanner"
            Weak[Weak Algorithms]
            Insecure[Insecure Modes]
            BadRandom[Bad RNG]
            SmallKey[Small Key Size]
        end
        
        subgraph "Pattern Scanner"
            MCP[MCP Patterns]
            Tool[Tool Poisoning]
            Custom[Custom Patterns]
        end
    end
    
    subgraph "Post-processing"
        Merge[Merge Results]
        Dedupe[Deduplicate]
        Severity[Assign Severity]
        Context[Add Context]
    end
    
    subgraph "Output"
        Threats[Threat List]
        Stats[Statistics]
        Logs[Audit Logs]
    end
    
    Input --> Normalize
    Normalize --> Depth
    
    Depth --> Invisible
    Depth --> SQL
    Depth --> Script
    Depth --> Weak
    Depth --> MCP
    
    Invisible --> Merge
    BiDi --> Merge
    Homograph --> Merge
    Control --> Merge
    
    SQL --> Merge
    Command --> Merge
    Prompt --> Merge
    Path --> Merge
    LDAP --> Merge
    
    Script --> Merge
    Event --> Merge
    DataURI --> Merge
    Entity --> Merge
    
    Weak --> Merge
    Insecure --> Merge
    BadRandom --> Merge
    SmallKey --> Merge
    
    MCP --> Merge
    Tool --> Merge
    Custom --> Merge
    
    Merge --> Dedupe
    Dedupe --> Severity
    Severity --> Context
    
    Context --> Threats
    Context --> Stats
    Context --> Logs
    
    style Merge fill:#ff6b6b,stroke:#c92a2a,color:#fff
    style Severity fill:#51cf66,stroke:#2f9e44,color:#fff
```

## Binary Structure

```mermaid
graph TB
    subgraph "Workspace Root"
        Cargo[Cargo.toml<br/>Workspace Definition]
    end
    
    subgraph "Binary Crates"
        subgraph "kindly-tools"
            ToolsMain[main.rs]
            ToolsCmds[Commands]
            ToolsWrap[wrap.rs]
            ToolsScan[scan.rs]
            ToolsShield[shield.rs]
            ToolsMonitor[monitor.rs]
        end
        
        subgraph "kindly-guard-server"
            ServerMain[main.rs]
            Protocol[protocol/]
            Scanner[scanner/]
            Storage[storage/]
            Shield[shield/]
        end
        
        subgraph "kindly-guard-shield"
            ShieldMain[main.rs]
            Tauri[src-tauri/]
            WebUI[Web UI]
        end
    end
    
    subgraph "Published to crates.io"
        Crate[kindlyguard<br/>All-in-one Package]
    end
    
    Cargo --> ToolsMain
    Cargo --> ServerMain
    Cargo --> ShieldMain
    
    ToolsMain --> ToolsCmds
    ToolsCmds --> ToolsWrap
    ToolsCmds --> ToolsScan
    ToolsCmds --> ToolsShield
    ToolsCmds --> ToolsMonitor
    
    ServerMain --> Protocol
    ServerMain --> Scanner
    ServerMain --> Storage
    ServerMain --> Shield
    
    ShieldMain --> Tauri
    ShieldMain --> WebUI
    
    ToolsMain -.->|uses| Scanner
    ToolsWrap -.->|communicates| ServerMain
    
    Crate -.->|includes| ToolsMain
    Crate -.->|includes| ServerMain
    Crate -.->|optional| ShieldMain
    
    style ToolsMain fill:#339af0,stroke:#1864ab,color:#fff
    style ServerMain fill:#51cf66,stroke:#2f9e44,color:#fff
    style ShieldMain fill:#ffd43b,stroke:#fab005,color:#000
    style Crate fill:#ff6b6b,stroke:#c92a2a,color:#fff
```

## MCP Protocol Flow

```mermaid
sequenceDiagram
    participant Claude as Claude Code
    participant Server as kindly-guard-server
    participant Handler as MCP Handler
    participant Scanner as Security Scanner
    participant Storage as Storage Layer
    participant Shield as Shield Status
    
    Claude->>Server: MCP Connection (stdio/TCP)
    Server->>Handler: Initialize protocol
    
    Claude->>Handler: initialize request
    Handler->>Handler: Register tools
    Handler->>Handler: Setup capabilities
    Handler-->>Claude: InitializeResult
    
    Note over Claude,Shield: Tool Registration Phase
    
    Claude->>Handler: tools/list
    Handler-->>Claude: Available tools:<br/>- scan_text<br/>- scan_json<br/>- shield_status<br/>- shield_control
    
    Note over Claude,Shield: Normal Operation
    
    loop Tool Calls
        Claude->>Handler: tools/call
        Handler->>Scanner: Validate request
        
        alt scan_text Tool
            Claude->>Handler: {tool: "scan_text", text: "..."}
            Handler->>Scanner: scan_text(input)
            Scanner->>Scanner: Run detection pipeline
            Scanner-->>Handler: Threat list
            Handler->>Storage: Log threats
            Handler->>Shield: Update statistics
            Handler-->>Claude: ScanResult
        else scan_json Tool
            Claude->>Handler: {tool: "scan_json", json: {...}}
            Handler->>Scanner: scan_json(input)
            Scanner->>Scanner: Recursive scan
            Scanner-->>Handler: Threat list
            Handler->>Storage: Log threats
            Handler-->>Claude: ScanResult
        else shield_status Tool
            Claude->>Handler: {tool: "shield_status"}
            Handler->>Shield: Get current status
            Shield-->>Handler: Statistics & state
            Handler-->>Claude: ShieldStatus
        else shield_control Tool
            Claude->>Handler: {tool: "shield_control", action: "..."}
            Handler->>Shield: Execute action
            Shield-->>Handler: Action result
            Handler-->>Claude: ControlResult
        end
        
        Note over Handler,Shield: Async notifications
        
        Shield-->>Handler: Status change
        Handler-->>Claude: notifications/shield_status
    end
    
    Claude->>Handler: shutdown
    Handler->>Storage: Flush pending
    Handler->>Shield: Save state
    Handler-->>Claude: Acknowledged
    
    style Scanner fill:#ff6b6b,stroke:#c92a2a,color:#fff
    style Handler fill:#51cf66,stroke:#2f9e44,color:#fff
    style Shield fill:#339af0,stroke:#1864ab,color:#fff
```

## Integration Points

### 1. kindly-tools Integration with kindly-guard-server

The `kindly-tools` binary provides user-facing commands that integrate with the core `kindly-guard-server`:

- **Direct Library Usage**: The `scan` command uses the `SecurityScanner` from `kindly-guard-server` as a library dependency
- **Process Communication**: The `wrap` command spawns AI tools as child processes and intercepts I/O
- **File System**: Commands share configuration files and threat pattern definitions
- **Network (Future)**: Plans for `kindly-tools` to connect to remote `kindly-guard-server` instances

### 2. MCP Protocol Extensions

KindlyGuard extends the standard MCP protocol with Claude Code specific features:

- **Shield Status Notifications**: Real-time threat alerts pushed to Claude Code
- **Binary Protocol (Enhanced Mode)**: High-performance binary encoding for large payloads
- **Custom Error Codes**: Security-specific error types for better handling

### 3. Security Boundaries

```mermaid
graph LR
    subgraph "Untrusted Zone"
        UserInput[User Input]
        AIOutput[AI Output]
    end
    
    subgraph "Security Perimeter"
        Scanner[Scanner]
        Neutralizer[Neutralizer]
    end
    
    subgraph "Trusted Zone"
        Storage[Storage]
        Config[Config]
        Logs[Audit Logs]
    end
    
    UserInput -->|scan| Scanner
    Scanner -->|threats| Neutralizer
    Neutralizer -->|safe| AIOutput
    
    Scanner -->|log| Logs
    Config -->|rules| Scanner
    Scanner -->|store| Storage
    
    style Scanner fill:#ff6b6b,stroke:#c92a2a,color:#fff
    style Neutralizer fill:#51cf66,stroke:#2f9e44,color:#fff
```

## Performance Optimizations

### 1. Zero-Copy Scanning
- Text is scanned in-place without allocation
- SIMD instructions for Unicode detection (x86_64)
- Memory-mapped files for large inputs

### 2. Caching Strategy
- LRU cache for repeated scans
- Pattern compilation cache
- Threat deduplication cache

### 3. Async Architecture
- Non-blocking I/O throughout
- Parallel scanner execution
- Event-driven notifications

## Configuration Flow

```mermaid
graph TD
    Default[Default Config]
    System[/etc/kindly-guard/config.toml]
    User[~/.config/kindly-guard/config.toml]
    Env[Environment Variables]
    Runtime[Runtime Config]
    
    Default --> Runtime
    System --> Runtime
    User --> Runtime
    Env --> Runtime
    
    Runtime --> Scanner[Scanner Config]
    Runtime --> Server[Server Config]
    Runtime --> UI[UI Config]
    
    Scanner --> Patterns[Pattern Files]
    Scanner --> Rules[Security Rules]
    
    style Runtime fill:#51cf66,stroke:#2f9e44,color:#fff
```

## Deployment Scenarios

### 1. Local Development
- Single binary: `kindly-tools` for all CLI operations
- MCP server runs embedded within Claude Code
- Shield provides real-time monitoring

### 2. Team Environment
- Central `kindly-guard-server` instance
- Team members use `kindly-tools` to connect
- Shared threat intelligence database

### 3. CI/CD Integration
- `kindly scan` in pre-commit hooks
- `kindly-guard-server` as security gate
- Automated threat reporting

## Future Architecture Considerations

1. **Plugin System**: Dynamic loading of custom scanners
2. **Distributed Mode**: Multiple scanner nodes with load balancing
3. **ML Integration**: Anomaly detection using learned patterns
4. **Cloud Native**: Kubernetes operators and service mesh integration
5. **Language SDKs**: Native bindings for Python, Go, TypeScript

---

*Generated for KindlyGuard v0.11.0 - Architecture subject to enhancement in future releases*