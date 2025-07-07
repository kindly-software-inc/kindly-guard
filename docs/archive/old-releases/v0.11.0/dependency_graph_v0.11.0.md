# KindlyGuard v0.11.0 Dependency Graph

Generated: 2025-07-06

## Overview

This document visualizes the dependency structure of KindlyGuard v0.11.0 after the binary consolidation that merged `kindly-guard-cli` into `kindly-guard-server`.

## High-Level Crate Dependencies

```mermaid
graph TD
    %% Workspace Crates
    KGS[kindly-guard-server<br/>v0.11.0]
    KT[kindly-tools<br/>v0.11.0]
    KGShield[kindly-guard-shield<br/>v0.11.0]
    KGCIO[crates-io-package/kindlyguard<br/>v0.11.0]
    XT[xtask<br/>v0.11.0]
    
    %% Dependencies between workspace crates
    KT --> KGS
    
    %% External Dependencies
    subgraph "Core Dependencies"
        Tokio[tokio 1.42]
        Serde[serde 1.0]
        SerdeJson[serde_json 1.0]
        Tracing[tracing 0.1]
        Clap[clap 4.5]
    end
    
    subgraph "Security Dependencies"
        UnicodeSec[unicode-security 0.1]
        Regex[regex 1.11]
        SHA2[sha2 0.10]
        Base64[base64 0.22]
        HMAC[hmac 0.12]
        Ed25519[ed25519-dalek 2.1]
    end
    
    subgraph "MCP Protocol"
        JsonRPC[jsonrpc-core 18.0]
        JsonRPCStdio[jsonrpc-stdio-server 18.0]
    end
    
    %% Connect dependencies
    KGS --> Tokio
    KGS --> Serde
    KGS --> UnicodeSec
    KGS --> JsonRPC
    KT --> Tokio
    KT --> Clap
    KGShield --> Tokio
    KGShield --> Serde
```

## Internal Module Structure - kindly-guard-server

```mermaid
graph TD
    subgraph "kindly-guard-server modules"
        Main[main.rs<br/>Binary Entry Point]
        Lib[lib.rs<br/>Library Root]
        
        subgraph "Core Modules"
            Config[config/]
            Traits[traits.rs]
            Error[error/]
            Logging[logging.rs]
        end
        
        subgraph "Security Modules"
            Scanner[scanner/]
            ScannerMod[scanner/mod.rs]
            Unicode[scanner/unicode.rs]
            Injection[scanner/injection.rs]
            XSS[scanner/xss_scanner.rs]
            Patterns[scanner/patterns.rs]
            Crypto[scanner/crypto.rs]
            
            Neutralizer[neutralizer/]
            NeutMod[neutralizer/mod.rs]
            NeutStd[neutralizer/standard.rs]
            NeutEnh[neutralizer/enhanced.rs]
        end
        
        subgraph "Protocol & Transport"
            Protocol[protocol/]
            ProtoTypes[protocol/types.rs]
            ClaudeCode[protocol/claude_code.rs]
            
            Transport[transport/]
            Stdio[transport/stdio.rs]
            HTTP[transport/http.rs]
            WebSocket[transport/websocket.rs]
        end
        
        subgraph "UI & Display"
            Shield[shield/]
            CLI[shield/cli.rs]
            Display[shield/display.rs]
            Universal[shield/universal_display.rs]
        end
        
        subgraph "Storage & Persistence"
            Storage[storage/]
            Memory[storage/memory.rs]
            Enhanced[storage/enhanced.rs]
        end
        
        subgraph "Resilience & Monitoring"
            Resilience[resilience/]
            CircuitBreaker[resilience/circuit_breaker.rs]
            Retry[resilience/retry.rs]
            Bulkhead[resilience/bulkhead.rs]
            
            Metrics[metrics/]
            Audit[audit/]
        end
        
        subgraph "CLI Integration"
            CLIMod[cli/]
            Commands[cli/commands.rs]
            Validation[cli/validation.rs]
        end
    end
    
    %% Main dependencies
    Main --> Lib
    Main --> CLIMod
    Main --> Config
    Main --> Transport
    
    %% Library dependencies
    Lib --> Traits
    Lib --> Error
    Lib --> Scanner
    Lib --> Neutralizer
    Lib --> Protocol
    
    %% Scanner dependencies
    ScannerMod --> Unicode
    ScannerMod --> Injection
    ScannerMod --> XSS
    ScannerMod --> Patterns
    ScannerMod --> Crypto
    
    %% Neutralizer dependencies
    NeutMod --> NeutStd
    NeutMod --> NeutEnh
    Neutralizer --> Scanner
    
    %% Protocol dependencies
    Protocol --> Transport
    Protocol --> Shield
    
    %% Storage dependencies
    Storage --> Metrics
    Storage --> Audit
    
    %% Resilience patterns
    Resilience --> CircuitBreaker
    Resilience --> Retry
    Resilience --> Bulkhead
```

## Detailed Module Interactions

```mermaid
graph LR
    subgraph "Request Flow"
        Input[External Input]
        MCP[MCP Request Handler]
        Scan[Security Scanner]
        Neut[Neutralizer]
        Store[Storage]
        Response[MCP Response]
    end
    
    Input --> MCP
    MCP --> Scan
    Scan --> Neut
    Neut --> Store
    Store --> Response
    
    subgraph "Cross-Cutting Concerns"
        Metrics[Metrics Collection]
        Audit[Audit Logging]
        Resilience[Resilience Patterns]
    end
    
    MCP -.-> Metrics
    Scan -.-> Audit
    Neut -.-> Resilience
```

## kindly-tools Dependencies

```mermaid
graph TD
    subgraph "kindly-tools"
        KTMain[main.rs]
        
        subgraph "Commands"
            Monitor[commands/monitor.rs]
            Scan[commands/scan.rs]
            Shield[commands/shield.rs]
            Wrap[commands/wrap.rs]
        end
        
        subgraph "Configuration"
            WrapConfig[config/wrap.rs]
        end
        
        Platform[platform.rs]
        Output[output.rs]
    end
    
    %% Internal dependencies
    KTMain --> Monitor
    KTMain --> Scan
    KTMain --> Shield
    KTMain --> Wrap
    Wrap --> WrapConfig
    
    %% External dependency on kindly-guard-server
    KGSLib[kindly-guard-server lib]
    Monitor --> KGSLib
    Scan --> KGSLib
```

## kindly-guard-shield (Tauri App) Dependencies

```mermaid
graph TD
    subgraph "kindly-guard-shield"
        TauriMain[src-tauri/main.rs]
        TauriLib[src-tauri/lib.rs]
        
        subgraph "Frontend"
            MainTS[src/main.ts]
            ShieldTS[src/shield.ts]
            StylesCSS[src/styles.css]
        end
        
        subgraph "Binary Protocol"
            BinaryProto[Binary Protocol Handler]
            SHM[Shared Memory IPC]
        end
    end
    
    %% Tauri dependencies
    TauriMain --> TauriLib
    TauriLib --> BinaryProto
    TauriLib --> SHM
    
    %% Frontend to backend
    MainTS -.-> TauriLib
    ShieldTS -.-> BinaryProto
```

## External Crate Dependencies Tree

```mermaid
graph TD
    subgraph "Async Runtime"
        Tokio[tokio 1.42]
        Futures[futures 0.3]
        AsyncTrait[async-trait 0.1]
    end
    
    subgraph "Serialization"
        Serde[serde 1.0]
        SerdeJson[serde_json 1.0]
        TOML[toml 0.8]
    end
    
    subgraph "Security"
        UnicodeSec[unicode-security 0.1]
        Regex[regex 1.11]
        SHA2[sha2 0.10]
        Base64[base64 0.22]
        HMAC[hmac 0.12]
        Ed25519[ed25519-dalek 2.1]
        Rand[rand 0.8]
        Subtle[subtle 2.6]
    end
    
    subgraph "UI/TUI"
        Crossterm[crossterm 0.28]
        Ratatui[ratatui 0.29]
        Tauri[tauri 2.0]
    end
    
    subgraph "Networking"
        Axum[axum 0.7]
        Tower[tower 0.4]
        Hyper[hyper 1.5]
        TokioTungstenite[tokio-tungstenite 0.24]
    end
    
    subgraph "Development"
        Clap[clap 4.5]
        Tracing[tracing 0.1]
        TracingSub[tracing-subscriber 0.3]
        Anyhow[anyhow 1.0]
        ThisError[thiserror 2.0]
    end
```

## Binary Outputs After Consolidation

```mermaid
graph TD
    subgraph "v0.11.0 Binaries"
        KG[kindlyguard<br/>Main server binary<br/>includes CLI commands]
        KT[kindly-tools<br/>Development tools]
        KGS[kindly-guard-shield<br/>Desktop UI]
    end
    
    subgraph "Functionality"
        Server[MCP Server Mode]
        CLI[CLI Commands]
        Monitor[Monitoring]
        DevTools[Dev Tools]
        Desktop[Desktop App]
    end
    
    KG --> Server
    KG --> CLI
    KT --> Monitor
    KT --> DevTools
    KGS --> Desktop
```

## Key Changes in v0.11.0

1. **Binary Consolidation**: `kindly-guard-cli` merged into `kindly-guard-server`, creating a single `kindlyguard` binary
2. **Module Reorganization**: CLI functionality moved to `cli/` module within server
3. **Simplified Distribution**: Fewer binaries to manage and distribute
4. **Shared Code**: Better code reuse between server and CLI functionality
5. **Enhanced Integration**: Direct access to server internals from CLI commands

## Module Importance Ranking

Based on the dependency analysis:

1. **Critical Path Modules**:
   - `scanner/` - Core security functionality
   - `protocol/` - MCP communication
   - `traits.rs` - Core trait definitions
   - `config/` - Configuration management

2. **High Priority Modules**:
   - `neutralizer/` - Threat mitigation
   - `transport/` - Communication layer
   - `resilience/` - Fault tolerance
   - `error/` - Error handling

3. **Support Modules**:
   - `shield/` - UI components
   - `storage/` - Persistence
   - `metrics/` - Monitoring
   - `audit/` - Logging

4. **Extension Modules**:
   - `cli/` - Command-line interface
   - `permissions/` - Access control
   - `plugins/` - Plugin system