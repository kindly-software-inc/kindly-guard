# KindlyGuard Client

Rust client library for interacting with KindlyGuard MCP security servers. Provides a safe, async API for security scanning and threat detection.

## Features

- **🔒 Type-Safe API** - Strongly typed requests and responses
- **⚡ Async/Await** - Built on Tokio for high-performance async operations
- **🔄 Automatic Retries** - Configurable retry logic with exponential backoff
- **📊 Connection Pooling** - Efficient connection management
- **🛡️ Built-in Security** - Automatic threat detection on responses

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
kindly-guard-client = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use kindly_guard_client::{Client, Config};
use kindly_guard_client::tools::ScanTextArgs;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client with default config
    let client = Client::new(Config::default()).await?;
    
    // Connect to server
    client.connect("stdio://kindly-guard").await?;
    
    // Scan text for threats
    let result = client.scan_text(ScanTextArgs {
        text: "Check this content".to_string(),
        context: Some("user_input".to_string()),
        deep_scan: false,
    }).await?;
    
    if result.threats.is_empty() {
        println!("✅ No threats detected");
    } else {
        println!("⚠️ {} threats found!", result.threats.len());
    }
    
    Ok(())
}
```

## Configuration

### Client Configuration

```rust
use kindly_guard_client::{Config, AuthConfig};
use std::time::Duration;

let config = Config {
    // Authentication
    auth: Some(AuthConfig {
        client_id: "my-app".to_string(),
        client_secret: "secret".to_string(),
        scopes: vec!["tools:execute".to_string()],
    }),
    
    // Connection settings
    timeout: Duration::from_secs(30),
    retry_attempts: 3,
    retry_delay: Duration::from_millis(100),
    
    // Security settings
    verify_signatures: true,
    require_secure_transport: true,
};

let client = Client::new(config).await?;
```

### Connection Types

```rust
// Standard I/O (recommended for local MCP)
client.connect("stdio://kindly-guard").await?;

// Unix socket
client.connect("unix:///var/run/kindly-guard.sock").await?;

// TCP (if supported by server)
client.connect("tcp://localhost:8080").await?;
```

## API Usage

### Scanning Text

```rust
use kindly_guard_client::tools::{ScanTextArgs, ScanTextResult};

// Basic scan
let result = client.scan_text(ScanTextArgs {
    text: user_input.clone(),
    context: None,
    deep_scan: false,
}).await?;

// Deep scan with context
let result = client.scan_text(ScanTextArgs {
    text: user_input.clone(),
    context: Some("form_submission".to_string()),
    deep_scan: true,
}).await?;

// Handle results
for threat in &result.threats {
    eprintln!("Threat: {} ({})", threat.description, threat.severity);
    if let Some(remediation) = &threat.remediation {
        eprintln!("  Fix: {}", remediation);
    }
}
```

### Verifying Signatures

```rust
use kindly_guard_client::tools::{VerifySignatureArgs, VerifySignatureResult};

let result = client.verify_signature(VerifySignatureArgs {
    message: "Important message".to_string(),
    signature: signature_base64,
    public_key: None, // Use server's key
}).await?;

if result.valid {
    println!("✅ Valid signature from {}", result.signer.unwrap_or_default());
} else {
    println!("❌ Invalid signature!");
}
```

### Getting Security Information

```rust
use kindly_guard_client::tools::{GetSecurityInfoArgs, SecurityInfoTopic};

let info = client.get_security_info(GetSecurityInfoArgs {
    topic: SecurityInfoTopic::Unicode,
    format: Some("markdown".to_string()),
}).await?;

println!("{}", info.content);
```

### Reading Resources

```rust
// Get current security status
let status = client.read_resource("kindlyguard://security/status").await?;
let status_data: SecurityStatus = serde_json::from_str(&status.text)?;

// Get recent threats
let threats = client.read_resource("kindlyguard://threats/recent").await?;
```

## Trait-Based Architecture

The client uses a trait-based architecture for flexibility:

```rust
use kindly_guard_client::traits::{McpClient, McpTransport};

// Custom transport implementation
struct MyTransport;

#[async_trait]
impl McpTransport for MyTransport {
    async fn send_request(&self, request: &str) -> Result<String> {
        // Custom transport logic
    }
    
    fn is_connected(&self) -> bool {
        true
    }
    
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

// Use custom transport
let transport = Arc::new(MyTransport);
let client = Client::with_transport(transport).await?;
```

## Error Handling

```rust
use kindly_guard_client::{ClientError, ErrorCode};

match client.scan_text(args).await {
    Ok(result) => handle_result(result),
    Err(ClientError::Server { code, message, .. }) => {
        match code {
            ErrorCode::ThreatDetected => {
                eprintln!("Threat in request: {}", message);
            }
            ErrorCode::RateLimited => {
                eprintln!("Rate limited, retry later");
            }
            _ => eprintln!("Server error: {}", message),
        }
    }
    Err(e) => eprintln!("Client error: {}", e),
}
```

## Testing

The client includes testing utilities:

```rust
#[cfg(test)]
mod tests {
    use kindly_guard_client::testing::{MockServer, MockResponse};
    
    #[tokio::test]
    async fn test_scan_text() {
        let server = MockServer::new();
        server.expect_scan_text()
            .returning(|_| Ok(MockResponse::no_threats()));
        
        let client = server.create_client().await;
        let result = client.scan_text(/* ... */).await.unwrap();
        assert!(result.threats.is_empty());
    }
}
```

## Performance Considerations

- **Connection Pooling** - Reuse clients when possible
- **Batch Operations** - Group multiple scans
- **Streaming** - Use streaming for large content
- **Caching** - Cache security info and status

## Examples

### Web Service Integration

```rust
use axum::{Router, Json, extract::State};
use kindly_guard_client::Client;

async fn validate_input(
    State(client): State<Arc<Client>>,
    Json(input): Json<UserInput>,
) -> Result<Json<Response>, StatusCode> {
    let result = client.scan_text(ScanTextArgs {
        text: input.content,
        context: Some("api_input".to_string()),
        deep_scan: false,
    }).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if !result.threats.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    Ok(Json(Response { status: "clean" }))
}
```

### CLI Tool

```rust
use clap::Parser;
use kindly_guard_client::{Client, Config};

#[derive(Parser)]
struct Args {
    /// Text to scan
    text: String,
    
    /// Enable deep scanning
    #[arg(long)]
    deep: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let client = Client::new(Config::default()).await?;
    
    client.connect("stdio://kindly-guard").await?;
    
    let result = client.scan_text(/* ... */).await?;
    // Handle result...
    
    Ok(())
}
```

## License

Licensed under either of:
- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Contributing

See the [main repository](https://github.com/kindlyguard/kindly-guard) for contribution guidelines.