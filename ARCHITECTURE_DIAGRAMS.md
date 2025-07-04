# KindlyGuard Architecture Diagrams

This document contains comprehensive visual diagrams of the KindlyGuard security-focused MCP server architecture using Mermaid syntax.

## 1. High-Level System Architecture

```mermaid
graph TB
    subgraph "External Interfaces"
        MCP[MCP Protocol]
        HTTP[HTTP API]
        WS[WebSocket]
        STDIO[STDIO]
        CLI[CLI Interface]
    end
    
    subgraph "Core Components"
        Server[MCP Server]
        Scanner[Security Scanner]
        Neutralizer[Threat Neutralizer]
        Shield[Shield UI]
        Auth[Auth Manager]
        RateLimit[Rate Limiter]
    end
    
    subgraph "Storage Layer"
        Storage[Storage Provider]
        Memory[In-Memory Store]
        SQLite[SQLite DB]
        EventStore[Event Store]
    end
    
    subgraph "Transport Layer"
        TransportMgr[Transport Manager]
        StdioTrans[STDIO Transport]
        HttpTrans[HTTP Transport]
        WsTrans[WebSocket Transport]
        ProxyTrans[Proxy Transport]
    end
    
    subgraph "Support Services"
        Telemetry[Telemetry]
        Metrics[Metrics Registry]
        Audit[Audit Logger]
        Signing[Signing Manager]
    end
    
    %% External to Transport connections
    MCP --> TransportMgr
    HTTP --> HttpTrans
    WS --> WsTrans
    STDIO --> StdioTrans
    CLI --> Server
    
    %% Transport to Core connections
    TransportMgr --> Server
    StdioTrans --> TransportMgr
    HttpTrans --> TransportMgr
    WsTrans --> TransportMgr
    ProxyTrans --> TransportMgr
    
    %% Core component interactions
    Server --> Scanner
    Server --> Neutralizer
    Server --> Auth
    Server --> RateLimit
    Server --> Shield
    
    Scanner --> Storage
    Neutralizer --> Storage
    Auth --> Storage
    RateLimit --> Storage
    
    %% Storage implementations
    Storage --> Memory
    Storage --> SQLite
    Storage --> EventStore
    
    %% Support service connections
    Server --> Telemetry
    Server --> Metrics
    Server --> Audit
    Server --> Signing
    Scanner --> Metrics
    Neutralizer --> Metrics
    
    style Scanner fill:#ff9999
    style Neutralizer fill:#ff9999
    style Auth fill:#ffcc99
    style RateLimit fill:#ffcc99
```

## 2. Detailed Component Interaction Diagram

```mermaid
sequenceDiagram
    participant Client
    participant Transport
    participant Server
    participant Auth
    participant RateLimit
    participant Scanner
    participant Neutralizer
    participant Storage
    participant Shield
    participant Audit
    
    Client->>Transport: JSON-RPC Request
    Transport->>Server: Parse & Route Request
    
    %% Authentication
    Server->>Auth: Verify Credentials
    Auth->>Storage: Check Auth State
    Storage-->>Auth: Auth Context
    Auth-->>Server: Authorization Result
    
    alt Unauthorized
        Server-->>Transport: Error Response
        Transport-->>Client: 401 Unauthorized
    end
    
    %% Rate Limiting
    Server->>RateLimit: Check Rate Limit
    RateLimit->>Storage: Get Token Bucket
    Storage-->>RateLimit: Current State
    
    alt Rate Limited
        Server-->>Transport: Error Response
        Transport-->>Client: 429 Too Many Requests
    end
    
    %% Security Scanning
    Server->>Scanner: Scan Request Content
    
    Note over Scanner: Unicode Detection<br/>Injection Detection<br/>XSS Detection<br/>Pattern Matching
    
    Scanner->>Storage: Log Scan Event
    Scanner-->>Server: Threat List
    
    alt Threats Detected
        Server->>Shield: Update Dashboard
        Server->>Neutralizer: Neutralize Threats
        Neutralizer-->>Server: Sanitized Content
        Server->>Audit: Log Security Event
        Server-->>Transport: Error/Sanitized Response
        Transport-->>Client: Security Response
    end
    
    %% Normal Processing
    Server->>Server: Process Request
    Server->>Storage: Update State
    Server->>Metrics: Record Metrics
    Server->>Audit: Log Request
    Server-->>Transport: Success Response
    Transport-->>Client: JSON-RPC Response
```

## 3. Trait Hierarchy Diagram

```mermaid
classDiagram
    %% Core Traits
    class SecurityScanner {
        <<trait>>
        +scan_text(text: &str) Vec~Threat~
        +scan_json(json: &Value) Vec~Threat~
    }
    
    class EnhancedScanner {
        <<trait>>
        +enhanced_scan(data: &[u8]) Vec~Threat~
        +get_metrics() ScannerMetrics
        +preload_patterns(patterns: &[String])
    }
    
    class ThreatNeutralizer {
        <<trait>>
        +neutralize(input: &str, threats: &[Threat]) NeutralizeResult
        +get_capabilities() Vec~NeutralizationCapability~
    }
    
    class StorageProvider {
        <<trait>>
        +store_event(event: &SecurityEvent) EventId
        +get_event(id: &EventId) Option~SecurityEvent~
        +query_events(filter: &EventFilter) Vec~SecurityEvent~
    }
    
    class RateLimiter {
        <<trait>>
        +check_rate_limit(key: &RateLimitKey) RateLimitDecision
        +record_request(key: &RateLimitKey)
        +apply_penalty(client_id: &str, factor: f32)
    }
    
    class SecurityEventProcessor {
        <<trait>>
        +process_event(event: SecurityEvent) EventHandle
        +get_stats() ProcessorStats
        +get_insights(client_id: &str) SecurityInsights
    }
    
    class EventBufferTrait {
        <<trait>>
        +enqueue_event(endpoint_id: u32, data: &[u8], priority: Priority) u64
        +get_endpoint_stats(endpoint_id: u32) EndpointStats
    }
    
    %% Standard Implementations
    class StandardScanner {
        +unicode_scanner: UnicodeScanner
        +injection_scanner: InjectionScanner
        +xss_scanner: XssScanner
    }
    
    class StandardNeutralizer {
        +html_encoder: HtmlEncoder
        +url_encoder: UrlEncoder
        +unicode_normalizer: UnicodeNormalizer
    }
    
    class InMemoryStorage {
        +events: HashMap
        +rate_limits: HashMap
        +snapshots: HashMap
    }
    
    class StandardRateLimiter {
        +buckets: HashMap
        +config: RateLimitConfig
    }
    
    class SimpleEventProcessor {
        +events: Vec~SecurityEvent~
        +max_events: usize
    }
    
    %% Enhanced Implementations (Feature-gated)
    class EnhancedScannerImpl {
        <<feature=enhanced>>
        +pattern_cache: PatternCache
        +simd_scanner: SimdScanner
        +ml_detector: MlDetector
    }
    
    class EnhancedNeutralizer {
        <<feature=enhanced>>
        +context_aware: ContextEngine
        +adaptive_rules: AdaptiveRules
    }
    
    class EnhancedStorage {
        <<feature=enhanced>>
        +write_ahead_log: WAL
        +compression: Compressor
        +encryption: Encryptor
    }
    
    class HierarchicalRateLimiter {
        <<feature=enhanced>>
        +global_limiter: GlobalLimiter
        +per_client_limiter: ClientLimiter
        +adaptive_limits: AdaptiveLimits
    }
    
    class AtomicEventProcessor {
        <<feature=enhanced>>
        +event_buffer: AtomicEventBuffer
        +correlation_engine: CorrelationEngine
    }
    
    %% Relationships
    StandardScanner ..|> SecurityScanner
    StandardScanner ..|> EnhancedScanner
    EnhancedScannerImpl ..|> EnhancedScanner
    
    StandardNeutralizer ..|> ThreatNeutralizer
    EnhancedNeutralizer ..|> ThreatNeutralizer
    
    InMemoryStorage ..|> StorageProvider
    EnhancedStorage ..|> StorageProvider
    
    StandardRateLimiter ..|> RateLimiter
    HierarchicalRateLimiter ..|> RateLimiter
    
    SimpleEventProcessor ..|> SecurityEventProcessor
    AtomicEventProcessor ..|> SecurityEventProcessor
    AtomicEventProcessor --> EventBufferTrait
```

## 4. Security Flow Diagram

```mermaid
flowchart TD
    Start([Request Received]) --> Transport{Transport Type?}
    
    Transport -->|STDIO| StdioAuth[STDIO Authentication]
    Transport -->|HTTP| HttpAuth[HTTP Auth Headers]
    Transport -->|WebSocket| WsAuth[WebSocket Auth]
    
    StdioAuth --> AuthCheck{Authorized?}
    HttpAuth --> AuthCheck
    WsAuth --> AuthCheck
    
    AuthCheck -->|No| AuthReject[Return 401]
    AuthCheck -->|Yes| RateCheck{Rate Limit OK?}
    
    RateCheck -->|No| RateReject[Return 429]
    RateCheck -->|Yes| ParseRequest[Parse JSON-RPC]
    
    ParseRequest --> ScanRequest[Security Scan Request]
    
    subgraph "Threat Detection Pipeline"
        ScanRequest --> UnicodeCheck[Unicode Scanner]
        UnicodeCheck --> InjectionCheck[Injection Scanner]
        InjectionCheck --> XssCheck[XSS Scanner]
        XssCheck --> PatternCheck[Pattern Matcher]
        PatternCheck --> PluginCheck[Plugin Scanners]
    end
    
    PluginCheck --> ThreatFound{Threats Found?}
    
    ThreatFound -->|No| ProcessRequest[Process Request]
    ThreatFound -->|Yes| ThreatSeverity{Critical Threat?}
    
    ThreatSeverity -->|Yes| BlockRequest[Block Request]
    ThreatSeverity -->|No| NeutralizeThreats[Neutralize Threats]
    
    BlockRequest --> AuditLog1[Audit: Blocked]
    NeutralizeThreats --> AuditLog2[Audit: Neutralized]
    
    subgraph "Neutralization Strategies"
        NeutralizeThreats --> HtmlEncode[HTML Entity Encoding]
        NeutralizeThreats --> UrlEncode[URL Encoding]
        NeutralizeThreats --> UnicodeNorm[Unicode Normalization]
        NeutralizeThreats --> RemovePatterns[Pattern Removal]
    end
    
    HtmlEncode --> ContinueProcessing[Continue with Sanitized]
    UrlEncode --> ContinueProcessing
    UnicodeNorm --> ContinueProcessing
    RemovePatterns --> ContinueProcessing
    
    ProcessRequest --> ExecuteRequest[Execute MCP Method]
    ContinueProcessing --> ExecuteRequest
    
    ExecuteRequest --> ResponseCheck{Response OK?}
    
    ResponseCheck -->|Yes| SignResponse[Sign Response]
    ResponseCheck -->|No| ErrorResponse[Generate Error]
    
    SignResponse --> SendResponse[Send to Client]
    ErrorResponse --> SendResponse
    
    subgraph "Audit Points"
        AuditLog1 --> EventStore[Event Storage]
        AuditLog2 --> EventStore
        SendResponse --> AuditLog3[Audit: Response]
        AuditLog3 --> EventStore
    end
    
    SendResponse --> UpdateMetrics[Update Metrics]
    UpdateMetrics --> End([Complete])
    
    style BlockRequest fill:#ff0000,color:#fff
    style ThreatSeverity fill:#ff9900
    style NeutralizeThreats fill:#ffcc00
    style ProcessRequest fill:#00ff00
```

## 5. Component Factory Pattern

```mermaid
classDiagram
    class ComponentSelector {
        -factory: SecurityComponentFactory
        +new(config: &Config) Self
        +create_event_processor() Arc~SecurityEventProcessor~
        +create_scanner() Arc~EnhancedScanner~
        +create_rate_limiter() Arc~RateLimiter~
        +is_enhanced_mode() bool
    }
    
    class SecurityComponentFactory {
        <<trait>>
        +create_event_processor() Arc~SecurityEventProcessor~
        +create_scanner() Arc~EnhancedScanner~
        +create_correlation_engine() Arc~CorrelationEngine~
        +create_rate_limiter() Arc~RateLimiter~
    }
    
    class StandardComponentFactory {
        +create_event_processor() SimpleEventProcessor
        +create_scanner() StandardScanner
        +create_rate_limiter() StandardRateLimiter
    }
    
    class EnhancedComponentFactory {
        <<feature=enhanced>>
        +create_event_processor() AtomicEventProcessor
        +create_scanner() EnhancedScannerImpl
        +create_rate_limiter() HierarchicalRateLimiter
    }
    
    ComponentSelector --> SecurityComponentFactory
    StandardComponentFactory ..|> SecurityComponentFactory
    EnhancedComponentFactory ..|> SecurityComponentFactory
    
    ComponentSelector ..> Config : uses
```

## 6. Data Flow Through Security Layers

```mermaid
graph LR
    subgraph "Input Layer"
        Raw[Raw Input]
        JSON[JSON Data]
        Text[Text Data]
    end
    
    subgraph "Transport Security"
        TLS[TLS Encryption]
        Auth[Authentication]
        Sign[Signature Verification]
    end
    
    subgraph "Application Security"
        Rate[Rate Limiting]
        Scan[Threat Scanning]
        Neutral[Neutralization]
    end
    
    subgraph "Processing"
        MCP[MCP Handler]
        Tools[Tool Execution]
        Response[Response Generation]
    end
    
    subgraph "Output Security"
        Sanitize[Output Sanitization]
        SignOut[Response Signing]
        Encrypt[Encryption]
    end
    
    Raw --> TLS
    JSON --> TLS
    Text --> TLS
    
    TLS --> Auth
    Auth --> Sign
    Sign --> Rate
    
    Rate --> Scan
    Scan --> Neutral
    Neutral --> MCP
    
    MCP --> Tools
    Tools --> Response
    Response --> Sanitize
    
    Sanitize --> SignOut
    SignOut --> Encrypt
    Encrypt --> Client[Client]
    
    style Scan fill:#ff9999
    style Neutral fill:#ffcc99
    style Rate fill:#99ccff
```

## 7. Plugin Architecture

```mermaid
graph TD
    subgraph "Plugin System"
        PM[Plugin Manager]
        PL[Plugin Loader]
        PR[Plugin Registry]
        
        subgraph "Plugin Types"
            Native[Native Plugins]
            WASM[WASM Plugins]
            Script[Script Plugins]
        end
    end
    
    subgraph "Plugin Interfaces"
        ScanPlugin[Scanner Plugin Trait]
        NeutPlugin[Neutralizer Plugin Trait]
        AuthPlugin[Auth Plugin Trait]
    end
    
    subgraph "Security Sandbox"
        Sandbox[Plugin Sandbox]
        Limits[Resource Limits]
        Perms[Permission System]
    end
    
    PM --> PL
    PL --> PR
    
    PR --> Native
    PR --> WASM
    PR --> Script
    
    Native --> ScanPlugin
    WASM --> ScanPlugin
    Script --> ScanPlugin
    
    ScanPlugin --> Sandbox
    NeutPlugin --> Sandbox
    AuthPlugin --> Sandbox
    
    Sandbox --> Limits
    Sandbox --> Perms
```

## 8. Resilience Architecture

```mermaid
stateDiagram-v2
    [*] --> Closed: Initial State
    
    Closed --> Open: Failure Threshold Exceeded
    Closed --> Closed: Success
    
    Open --> HalfOpen: Recovery Timeout
    Open --> Open: Request Rejected
    
    HalfOpen --> Closed: Success
    HalfOpen --> Open: Failure
    
    note right of Open
        All requests fail fast
        No backend calls made
    end note
    
    note right of HalfOpen
        Limited requests allowed
        Testing if service recovered
    end note
    
    note right of Closed
        Normal operation
        Requests pass through
    end note
```

## Notes

- **Security First**: All data flows through multiple security checkpoints
- **Type Safety**: Threats are represented as typed enums, never strings
- **Trait-Based**: Clean separation between interfaces and implementations
- **Feature Gating**: Enhanced implementations are behind feature flags
- **Plugin Support**: Extensible architecture for custom security modules
- **Resilience**: Circuit breakers and retry logic for fault tolerance
- **Audit Trail**: All security events are logged for compliance

The architecture emphasizes defense-in-depth with multiple overlapping security layers, ensuring that even if one layer is compromised, others provide protection.