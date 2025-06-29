//! KindlyGuard MCP Client Test Harness
//! 
//! A comprehensive testing client for the KindlyGuard security server
//! with trait-based architecture for flexible testing scenarios.

pub mod traits;
pub mod transport;
pub mod client;
pub mod security_tester;
pub mod metrics;

pub use traits::*;
pub use client::TestClient;
pub use transport::stdio::StdioTransport;
pub use security_tester::SecurityTestRunner;
pub use metrics::MetricsCollectorImpl;

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfiguration {
    /// Server endpoint (e.g., "stdio" or "http://localhost:8080")
    pub endpoint: String,
    
    /// OAuth2 token for authentication
    pub auth_token: Option<String>,
    
    /// Enable message signing
    pub enable_signing: bool,
    
    /// Client identifier
    pub client_id: String,
    
    /// Signing key (if signing enabled)
    pub signing_key: Option<String>,
}

impl Default for ClientConfiguration {
    fn default() -> Self {
        Self {
            endpoint: "stdio".to_string(),
            auth_token: None,
            enable_signing: false,
            client_id: "test-client".to_string(),
            signing_key: None,
        }
    }
}

impl ClientConfig for ClientConfiguration {
    fn server_endpoint(&self) -> &str {
        &self.endpoint
    }
    
    fn auth_token(&self) -> Option<&str> {
        self.auth_token.as_deref()
    }
    
    fn signing_enabled(&self) -> bool {
        self.enable_signing
    }
    
    fn client_id(&self) -> &str {
        &self.client_id
    }
}