# KindlyGuard Threat Model Diagrams

## System Architecture Overview

```mermaid
graph TB
    subgraph "External Actors"
        Client[MCP Client]
        Attacker[Malicious Actor]
        Admin[Administrator]
    end

    subgraph "KindlyGuard Security Layers"
        subgraph "Layer 1: Network Security"
            TLS[TLS 1.2+ Encryption]
            Firewall[Network Firewall]
        end

        subgraph "Layer 2: Authentication"
            OAuth[OAuth 2.0 Manager]
            Signing[Message Signing]
            TokenCache[Token Cache]
        end

        subgraph "Layer 3: Authorization"
            Permissions[Permission Manager]
            RateLimit[Rate Limiter]
            ClientAuth[Client Authentication]
        end

        subgraph "Layer 4: Input Validation"
            Scanner[Security Scanner]
            Unicode[Unicode Scanner]
            Injection[Injection Scanner]
            XSS[XSS Scanner]
            Pattern[Pattern Scanner]
        end

        subgraph "Layer 5: Business Logic"
            MCPHandler[MCP Request Handler]
            ToolExec[Tool Executor]
            ResourceMgr[Resource Manager]
        end

        subgraph "Layer 6: Output Security"
            Neutralizer[Threat Neutralizer]
            Encoder[Output Encoder]
            ResponseSign[Response Signing]
        end

        subgraph "Layer 7: Resilience"
            CircuitBreaker[Circuit Breaker]
            Retry[Retry Handler]
            HealthCheck[Health Monitor]
        end

        subgraph "Layer 8: Monitoring"
            Audit[Audit Logger]
            Metrics[Metrics Collector]
            Alerts[Alert System]
        end
    end

    subgraph "Data Storage"
        DB[(Database)]
        Cache[(Cache)]
        FileSystem[File System]
    end

    %% Client flow
    Client -->|HTTPS/WSS| TLS
    TLS --> OAuth
    OAuth --> Permissions
    Permissions --> RateLimit
    RateLimit --> Scanner
    Scanner --> MCPHandler
    MCPHandler --> Neutralizer
    Neutralizer --> ResponseSign
    ResponseSign -->|Signed Response| Client

    %% Attack vectors
    Attacker -.->|DoS Attack| RateLimit
    Attacker -.->|Injection Attack| Scanner
    Attacker -.->|Token Theft| OAuth
    Attacker -.->|Spoofing| Signing
    Attacker -.->|Unicode Attack| Unicode
    
    %% Admin flow
    Admin -->|Secure Channel| ClientAuth
    ClientAuth --> MCPHandler

    %% Internal connections
    MCPHandler --> ToolExec
    MCPHandler --> ResourceMgr
    ToolExec --> CircuitBreaker
    ResourceMgr --> DB
    TokenCache --> Cache
    
    %% Monitoring
    Scanner --> Audit
    Neutralizer --> Audit
    CircuitBreaker --> Metrics
    RateLimit --> Alerts
```

## Threat Detection Flow

```mermaid
sequenceDiagram
    participant Client
    participant Transport
    participant Auth
    participant Scanner
    participant Neutralizer
    participant Handler
    participant Audit

    Client->>Transport: MCP Request
    Transport->>Auth: Validate Token
    Auth-->>Transport: Auth Result
    
    alt Authentication Failed
        Transport-->>Client: 401 Unauthorized
        Transport->>Audit: Log Auth Failure
    else Authentication Success
        Transport->>Scanner: Scan Request
        Scanner->>Scanner: Unicode Detection
        Scanner->>Scanner: Injection Detection
        Scanner->>Scanner: XSS Detection
        
        alt Threats Detected
            Scanner->>Neutralizer: Neutralize Threats
            Neutralizer->>Neutralizer: Apply Strategy
            Neutralizer-->>Scanner: Sanitized Content
            Scanner->>Audit: Log Threats
        end
        
        Scanner->>Handler: Process Request
        Handler->>Handler: Execute Business Logic
        Handler->>Scanner: Scan Response
        Scanner->>Neutralizer: Neutralize Response
        Neutralizer-->>Handler: Safe Response
        Handler-->>Client: Signed Response
        Handler->>Audit: Log Transaction
    end
```

## Attack Surface Model

```mermaid
graph LR
    subgraph "External Attack Surface"
        API[MCP API Endpoints]
        WebUI[Web Dashboard]
        Config[Configuration API]
        Plugins[Plugin Interface]
    end

    subgraph "Attack Vectors"
        Unicode_Attacks[Unicode Attacks]
        Injection_Attacks[Injection Attacks]
        XSS_Attacks[XSS Attacks]
        DoS_Attacks[DoS Attacks]
        Auth_Attacks[Auth Attacks]
        MITM[Man-in-the-Middle]
    end

    subgraph "Protection Mechanisms"
        TLS_Protection[TLS Encryption]
        Input_Val[Input Validation]
        Output_San[Output Sanitization]
        Rate_Limiting[Rate Limiting]
        Auth_System[Authentication]
        Monitoring[Monitoring]
    end

    %% Attack paths
    Unicode_Attacks -->|Targets| API
    Injection_Attacks -->|Targets| API
    XSS_Attacks -->|Targets| WebUI
    DoS_Attacks -->|Targets| API
    Auth_Attacks -->|Targets| Config
    MITM -->|Intercepts| API

    %% Protection coverage
    API -->|Protected by| Input_Val
    API -->|Protected by| Rate_Limiting
    WebUI -->|Protected by| Output_San
    Config -->|Protected by| Auth_System
    API -->|Encrypted by| TLS_Protection
    Plugins -->|Monitored by| Monitoring
```

## Threat Neutralization Decision Tree

```mermaid
graph TD
    Start[Threat Detected]
    
    Start --> TypeCheck{Threat Type?}
    
    TypeCheck -->|Unicode| Unicode_Handler[Unicode Neutralization]
    TypeCheck -->|Injection| Injection_Handler[Injection Neutralization]
    TypeCheck -->|XSS| XSS_Handler[XSS Neutralization]
    TypeCheck -->|DoS| DoS_Handler[DoS Mitigation]
    
    Unicode_Handler --> BiDi_Check{BiDi Attack?}
    BiDi_Check -->|Yes| BiDi_Action[Replace with Marker]
    BiDi_Check -->|No| Homograph_Check{Homograph?}
    Homograph_Check -->|Yes| ASCII_Convert[Convert to ASCII]
    Homograph_Check -->|No| Remove_Invisible[Remove Invisible Chars]
    
    Injection_Handler --> SQL_Check{SQL Injection?}
    SQL_Check -->|Yes| Parameterize[Parameterize Query]
    SQL_Check -->|No| Command_Check{Command Injection?}
    Command_Check -->|Yes| Escape_Shell[Escape Metacharacters]
    Command_Check -->|No| Path_Check{Path Traversal?}
    Path_Check -->|Yes| Normalize_Path[Normalize Path]
    Path_Check -->|No| Prompt_Wrap[Wrap in Safety Context]
    
    XSS_Handler --> Context_Check{Output Context?}
    Context_Check -->|HTML| HTML_Encode[HTML Entity Encoding]
    Context_Check -->|JavaScript| JS_Escape[JavaScript Escaping]
    Context_Check -->|URL| URL_Encode[URL Encoding]
    Context_Check -->|CSS| CSS_Escape[CSS Escaping]
    
    DoS_Handler --> Size_Check{Content Size?}
    Size_Check -->|Oversized| Reject_Request[Reject Request]
    Size_Check -->|Normal| Apply_Rate_Limit[Apply Rate Limit]
    
    %% All paths lead to audit
    BiDi_Action --> Audit_Log[Audit Log]
    ASCII_Convert --> Audit_Log
    Remove_Invisible --> Audit_Log
    Parameterize --> Audit_Log
    Escape_Shell --> Audit_Log
    Normalize_Path --> Audit_Log
    Prompt_Wrap --> Audit_Log
    HTML_Encode --> Audit_Log
    JS_Escape --> Audit_Log
    URL_Encode --> Audit_Log
    CSS_Escape --> Audit_Log
    Reject_Request --> Audit_Log
    Apply_Rate_Limit --> Audit_Log
    
    Audit_Log --> Complete[Neutralization Complete]
```

## Security State Machine

```mermaid
stateDiagram-v2
    [*] --> Initializing
    Initializing --> Ready: Config Loaded
    
    Ready --> Authenticating: Request Received
    Authenticating --> Authorized: Valid Token
    Authenticating --> Rejected: Invalid Token
    
    Authorized --> Scanning: Begin Scan
    Scanning --> ThreatDetected: Threats Found
    Scanning --> Safe: No Threats
    
    ThreatDetected --> Neutralizing: Auto Mode
    ThreatDetected --> Quarantined: Manual Mode
    ThreatDetected --> Alerting: Report Mode
    
    Neutralizing --> Safe: Neutralized
    Neutralizing --> Failed: Error
    
    Safe --> Processing: Execute Request
    Processing --> Responding: Complete
    Processing --> CircuitOpen: Failure
    
    CircuitOpen --> HalfOpen: Timeout
    HalfOpen --> Processing: Test Request
    HalfOpen --> CircuitOpen: Still Failing
    
    Responding --> Monitoring: Log & Metrics
    Failed --> Monitoring: Log Error
    Rejected --> Monitoring: Log Rejection
    
    Monitoring --> Ready: Complete
    
    Quarantined --> [*]: Manual Review
    Alerting --> Ready: Logged
```

## Data Flow Security

```mermaid
graph LR
    subgraph "Input Stage"
        Raw[Raw Input]
        Validated[Validated Input]
        Scanned[Scanned Input]
    end
    
    subgraph "Processing Stage"
        Business[Business Logic]
        Storage[Data Storage]
    end
    
    subgraph "Output Stage"
        Response[Raw Response]
        Sanitized[Sanitized Output]
        Signed[Signed Response]
    end
    
    subgraph "Security Controls"
        Val[Schema Validation]
        Scan[Security Scanner]
        Neut[Neutralizer]
        Enc[Encoder]
        Sign[Digital Signature]
    end
    
    Raw -->|Validate| Val
    Val -->|Valid| Validated
    Val -.->|Invalid| Reject[Reject]
    
    Validated -->|Scan| Scan
    Scan -->|Clean| Scanned
    Scan -.->|Threats| Neut
    Neut -->|Sanitized| Scanned
    
    Scanned --> Business
    Business --> Storage
    Business --> Response
    
    Response -->|Encode| Enc
    Enc --> Sanitized
    Sanitized -->|Sign| Sign
    Sign --> Signed
    
    %% Threat indicators
    style Scan fill:#f9f,stroke:#333,stroke-width:4px
    style Neut fill:#f9f,stroke:#333,stroke-width:4px
    style Val fill:#9f9,stroke:#333,stroke-width:2px
    style Enc fill:#9f9,stroke:#333,stroke-width:2px
    style Sign fill:#9f9,stroke:#333,stroke-width:2px
```

## Threat Correlation Engine

```mermaid
graph TD
    subgraph "Event Sources"
        Auth_Events[Auth Events]
        Scan_Events[Scanner Events]
        Neutral_Events[Neutralizer Events]
        Rate_Events[Rate Limit Events]
    end
    
    subgraph "Correlation Engine"
        Collector[Event Collector]
        Analyzer[Pattern Analyzer]
        Predictor[Threat Predictor]
        Classifier[Attack Classifier]
    end
    
    subgraph "Attack Patterns"
        Recon[Reconnaissance]
        Campaign[Attack Campaign]
        Escalation[Privilege Escalation]
        APT[Advanced Persistent Threat]
    end
    
    subgraph "Response Actions"
        Alert[Security Alert]
        Block[Block Client]
        Tighten[Tighten Limits]
        Isolate[Isolate System]
    end
    
    %% Event flow
    Auth_Events --> Collector
    Scan_Events --> Collector
    Neutral_Events --> Collector
    Rate_Events --> Collector
    
    Collector --> Analyzer
    Analyzer --> Classifier
    Analyzer --> Predictor
    
    Classifier --> Recon
    Classifier --> Campaign
    Classifier --> Escalation
    Classifier --> APT
    
    Recon --> Alert
    Campaign --> Block
    Escalation --> Tighten
    APT --> Isolate
```

## Security Zones

```mermaid
graph TB
    subgraph "Untrusted Zone"
        Internet[Internet]
        Unknown[Unknown Clients]
    end
    
    subgraph "DMZ"
        LoadBalancer[Load Balancer]
        WAF[Web Application Firewall]
        ReverseProxy[Reverse Proxy]
    end
    
    subgraph "Trusted Zone"
        MCPServer[MCP Server]
        AuthService[Auth Service]
        Scanner[Security Scanner]
    end
    
    subgraph "Restricted Zone"
        Database[Database]
        SecretStore[Secret Store]
        AuditLog[Audit Logs]
    end
    
    Internet --> LoadBalancer
    LoadBalancer --> WAF
    WAF --> ReverseProxy
    ReverseProxy --> MCPServer
    
    MCPServer --> AuthService
    MCPServer --> Scanner
    AuthService --> SecretStore
    Scanner --> Database
    MCPServer --> AuditLog
    
    %% Zone boundaries
    style DMZ fill:#ffcccc
    style Trusted_Zone fill:#ccffcc
    style Restricted_Zone fill:#ccccff
```

## Incident Response Flow

```mermaid
sequenceDiagram
    participant Detector as Threat Detector
    participant Analyzer as Threat Analyzer
    participant Responder as Auto Responder
    participant Logger as Audit Logger
    participant Alerter as Alert System
    participant Human as Security Team

    Detector->>Analyzer: Threat Detected
    Analyzer->>Analyzer: Classify Threat
    
    alt Critical Threat
        Analyzer->>Responder: Immediate Response
        Responder->>Responder: Block Source
        Responder->>Responder: Neutralize Threat
        Responder->>Alerter: Critical Alert
        Alerter->>Human: Page On-Call
    else High Threat
        Analyzer->>Responder: Auto Mitigate
        Responder->>Responder: Apply Penalties
        Responder->>Logger: Log Incident
        Logger->>Alerter: High Priority Alert
        Alerter->>Human: Email Alert
    else Medium/Low Threat
        Analyzer->>Responder: Standard Response
        Responder->>Logger: Log Event
        Logger->>Logger: Update Metrics
    end
    
    Responder->>Analyzer: Response Complete
    Analyzer->>Detector: Update Patterns
    
    Human->>Logger: Review Logs
    Human->>Responder: Adjust Response
```

These diagrams provide a comprehensive visual representation of:

1. **System Architecture**: Shows all security layers and data flow
2. **Threat Detection Flow**: Details the request lifecycle with security checks
3. **Attack Surface Model**: Maps attack vectors to protection mechanisms
4. **Neutralization Decision Tree**: Shows how different threats are handled
5. **Security State Machine**: Represents system security states
6. **Data Flow Security**: Tracks security controls at each stage
7. **Threat Correlation Engine**: Shows how events are correlated
8. **Security Zones**: Illustrates network segmentation
9. **Incident Response Flow**: Details automated and manual response procedures

Each diagram highlights the defense-in-depth approach and shows how multiple security controls work together to protect the system.