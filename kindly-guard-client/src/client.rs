//! MCP test client implementation

use async_trait::async_trait;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::traits::{McpTransport, McpClient, ToolInfo, ServerCapabilities, SecurityFeatures};
use crate::ClientConfiguration;

/// JSON-RPC request structure
#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<Value>,
    id: u64,
}

/// JSON-RPC response structure
#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: u64,
}

/// JSON-RPC error
#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

/// Test client implementation
pub struct TestClient {
    transport: Arc<dyn McpTransport>,
    config: ClientConfiguration,
    request_id: AtomicU64,
    initialized: Arc<Mutex<bool>>,
    capabilities: Arc<Mutex<Option<ServerCapabilities>>>,
}

impl TestClient {
    /// Create a new test client
    pub fn new(transport: Arc<dyn McpTransport>, config: ClientConfiguration) -> Self {
        Self {
            transport,
            config,
            request_id: AtomicU64::new(1),
            initialized: Arc::new(Mutex::new(false)),
            capabilities: Arc::new(Mutex::new(None)),
        }
    }
    
    /// Get next request ID
    fn next_id(&self) -> u64 {
        self.request_id.fetch_add(1, Ordering::SeqCst)
    }
    
    /// Build authorization header if needed
    fn build_auth_header(&self) -> Option<String> {
        self.config.auth_token.as_ref().map(|token| {
            format!("Bearer {}", token)
        })
    }
    
    /// Send a raw request
    async fn send_raw_request(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse> {
        // Add authorization if configured
        let mut request_value = serde_json::to_value(&request)?;
        if let Some(auth) = self.build_auth_header() {
            request_value["authorization"] = json!(auth);
        }
        
        let request_str = serde_json::to_string(&request_value)?;
        let response_str = self.transport.send_request(&request_str).await?;
        
        let response: JsonRpcResponse = serde_json::from_str(&response_str)
            .map_err(|e| anyhow!("Failed to parse response: {} - Response: {}", e, response_str))?;
        
        if let Some(error) = &response.error {
            return Err(anyhow!("Server error: {} (code: {})", error.message, error.code));
        }
        
        Ok(response)
    }
}

#[async_trait]
impl McpClient for TestClient {
    async fn connect(&mut self) -> Result<()> {
        info!("Connecting to MCP server...");
        
        // Send initialize request
        let init_params = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "kindly-guard-test-client",
                "version": "0.1.0"
            }
        });
        
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "initialize".to_string(),
            params: Some(init_params),
            id: self.next_id(),
        };
        
        let response = self.send_raw_request(request).await?;
        
        if let Some(result) = response.result {
            // Parse server capabilities
            let capabilities = self.parse_capabilities(&result)?;
            *self.capabilities.lock().await = Some(capabilities);
            *self.initialized.lock().await = true;
            
            info!("Connected to MCP server successfully");
            
            // Send initialized notification
            let notification = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "notifications/initialized".to_string(),
                params: Some(json!({})),
                id: self.next_id(),
            };
            
            let _ = self.send_raw_request(notification).await;
            
            Ok(())
        } else {
            Err(anyhow!("No result in initialize response"))
        }
    }
    
    async fn send_request(&self, method: &str, params: Option<Value>) -> Result<Value> {
        // Check if initialized
        if !*self.initialized.lock().await {
            return Err(anyhow!("Client not initialized"));
        }
        
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: self.next_id(),
        };
        
        let response = self.send_raw_request(request).await?;
        
        response.result.ok_or_else(|| anyhow!("No result in response"))
    }
    
    async fn call_tool(&self, tool_name: &str, arguments: Value) -> Result<Value> {
        let params = json!({
            "name": tool_name,
            "arguments": arguments
        });
        
        self.send_request("tools/call", Some(params)).await
    }
    
    async fn list_tools(&self) -> Result<Vec<ToolInfo>> {
        let result = self.send_request("tools/list", None).await?;
        
        let tools = result["tools"].as_array()
            .ok_or_else(|| anyhow!("No tools array in response"))?;
        
        let mut tool_infos = Vec::new();
        for tool in tools {
            let name = tool["name"].as_str()
                .ok_or_else(|| anyhow!("Tool missing name"))?
                .to_string();
            let description = tool["description"].as_str()
                .unwrap_or("")
                .to_string();
            let input_schema = tool["inputSchema"].clone();
            
            tool_infos.push(ToolInfo {
                name,
                description,
                input_schema,
            });
        }
        
        Ok(tool_infos)
    }
    
    async fn get_capabilities(&self) -> Result<ServerCapabilities> {
        let capabilities = self.capabilities.lock().await;
        capabilities.clone().ok_or_else(|| anyhow!("Not connected"))
    }
    
    async fn disconnect(&mut self) -> Result<()> {
        *self.initialized.lock().await = false;
        self.transport.close().await?;
        info!("Disconnected from MCP server");
        Ok(())
    }
}

impl TestClient {
    /// Parse server capabilities from initialize response
    fn parse_capabilities(&self, result: &Value) -> Result<ServerCapabilities> {
        let server_info = &result["serverInfo"];
        debug!("Server info: {:?}", server_info);
        
        let capabilities = &result["capabilities"];
        let tools = capabilities["tools"].as_object().is_some();
        
        // Check for security features
        let oauth2 = result["securityFeatures"]["oauth2"]
            .as_bool()
            .unwrap_or(false);
        let message_signing = result["securityFeatures"]["messageSigning"]
            .as_bool()
            .unwrap_or(false);
        let rate_limiting = result["securityFeatures"]["rateLimiting"]
            .as_bool()
            .unwrap_or(false);
        let threat_detection = result["securityFeatures"]["threatDetection"]
            .as_bool()
            .unwrap_or(false);
        let enhanced_mode = result["securityFeatures"]["enhancedMode"]
            .as_bool()
            .unwrap_or(false);
        
        Ok(ServerCapabilities {
            tools,
            security_features: SecurityFeatures {
                oauth2,
                message_signing,
                rate_limiting,
                threat_detection,
                enhanced_mode,
            },
        })
    }
    
    /// Create a test client for stdio communication
    pub async fn stdio(server_path: &str, config: ClientConfiguration) -> Result<Self> {
        use crate::transport::stdio::StdioTransportBuilder;
        
        let mut builder = StdioTransportBuilder::new(server_path);
        
        // Add config file if specified
        if let Some(config_file) = std::env::var("KINDLY_GUARD_CONFIG").ok() {
            builder = builder.with_config(config_file);
        }
        
        let transport = builder.build();
        transport.start().await?;
        
        Ok(Self::new(Arc::new(transport), config))
    }
}