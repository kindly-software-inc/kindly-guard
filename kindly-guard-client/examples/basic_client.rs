//! Basic client example showing standard MCP operations

use anyhow::Result;
use kindly_guard_client::{ClientConfiguration, TestClient};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("🚀 Starting KindlyGuard basic client example");

    // Create client configuration
    let config = ClientConfiguration {
        endpoint: "stdio".to_string(),
        auth_token: std::env::var("KINDLY_GUARD_TOKEN").ok(),
        enable_signing: false,
        client_id: "example-client".to_string(),
        signing_key: None,
    };

    // Path to the server binary
    let server_path = std::env::var("KINDLY_GUARD_SERVER")
        .unwrap_or_else(|_| "../target/release/kindly-guard".to_string());

    // Create and connect client
    let mut client = TestClient::stdio(&server_path, config).await?;
    client.connect().await?;

    // Get server capabilities
    let capabilities = client.get_capabilities().await?;
    info!("Server capabilities: {:?}", capabilities);

    // List available tools
    let tools = client.list_tools().await?;
    info!("Available tools:");
    for tool in &tools {
        info!("  - {}: {}", tool.name, tool.description);
    }

    // Call a tool - scan some text
    info!("\n📝 Testing text scanning...");
    let scan_result = client.call_tool(
        "scan_text",
        serde_json::json!({
            "text": "This is a safe text without any threats."
        })
    ).await?;
    info!("Scan result: {:?}", scan_result);

    // Test with a potential threat
    info!("\n⚠️ Testing threat detection...");
    match client.call_tool(
        "scan_text",
        serde_json::json!({
            "text": "'; DROP TABLE users; --"
        })
    ).await {
        Ok(result) => info!("Threat scan result: {:?}", result),
        Err(e) => info!("Threat detected and blocked: {}", e),
    }

    // Get security info
    info!("\n🔒 Getting security information...");
    let security_info = client.call_tool(
        "get_security_info",
        serde_json::json!({})
    ).await?;
    info!("Security info: {:?}", security_info);

    // Disconnect
    client.disconnect().await?;
    info!("✅ Client example completed successfully");

    Ok(())
}