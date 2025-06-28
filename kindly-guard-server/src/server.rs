//! MCP (Model Context Protocol) server implementation
//! 
//! Provides security middleware for MCP requests/responses

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tracing::{debug, error, info};
use anyhow::Result;

use crate::scanner::{SecurityScanner, Threat, Severity};
use crate::shield::Shield;
use crate::config::Config;

/// MCP server that provides security scanning
pub struct McpServer {
    scanner: Arc<SecurityScanner>,
    pub shield: Arc<Shield>,
    config: Arc<Config>,
    session_store: Arc<Mutex<SessionStore>>,
}

/// Session storage for tracking connections
struct SessionStore {
    sessions: std::collections::HashMap<String, SessionInfo>,
}

/// Information about an active session
struct SessionInfo {
    id: String,
    created_at: std::time::Instant,
    threats_blocked: u64,
    last_activity: std::time::Instant,
}

/// JSON-RPC request structure
#[derive(Debug, Deserialize, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<Value>,
    id: Option<Value>,
}

/// JSON-RPC response structure
#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    result: Option<Value>,
    error: Option<JsonRpcError>,
    id: Option<Value>,
}

/// JSON-RPC error structure
#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    data: Option<Value>,
}

/// Server errors
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Security threat detected: {0:?}")]
    ThreatDetected(Vec<Threat>),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Method not found: {0}")]
    MethodNotFound(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
    
    #[error("Timeout")]
    Timeout,
}

impl McpServer {
    /// Create a new MCP server
    pub fn new(config: Config) -> Result<Self> {
        let scanner = Arc::new(SecurityScanner::new(config.scanner.clone())?);
        let shield = Arc::new(Shield::new(config.shield.clone()));
        
        Ok(Self {
            scanner,
            shield,
            config: Arc::new(config),
            session_store: Arc::new(Mutex::new(SessionStore {
                sessions: std::collections::HashMap::new(),
            })),
        })
    }
    
    /// Handle JSON-RPC request with security scanning
    pub async fn handle_request(&self, request_str: &str) -> Result<String, ServerError> {
        // Parse JSON-RPC request
        let request: JsonRpcRequest = serde_json::from_str(request_str)
            .map_err(|e| ServerError::InvalidRequest(e.to_string()))?;
            
        debug!("Handling request: method={}", request.method);
        
        // Validate JSON-RPC version
        if request.jsonrpc != "2.0" {
            return Err(ServerError::InvalidRequest("Invalid JSON-RPC version".to_string()));
        }
        
        // Scan the entire request for threats
        let threats = self.scan_request(&request).await?;
        if !threats.is_empty() {
            self.shield.record_threats(&threats);
            error!("Threats detected: {:?}", threats);
            return Err(ServerError::ThreatDetected(threats));
        }
        
        // Process the request with timeout
        let result = tokio::time::timeout(
            Duration::from_secs(self.config.server.request_timeout_secs),
            self.process_method(&request.method, request.params)
        ).await
        .map_err(|_| ServerError::Timeout)??;
        
        // Build response
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id: request.id,
        };
        
        // Serialize response
        serde_json::to_string(&response)
            .map_err(|e| ServerError::InternalError(e.to_string()))
    }
    
    /// Scan request for security threats
    async fn scan_request(&self, request: &JsonRpcRequest) -> Result<Vec<Threat>, ServerError> {
        let mut all_threats = Vec::new();
        
        // Scan method name
        match self.scanner.scan_text(&request.method) {
            Ok(threats) => all_threats.extend(threats),
            Err(e) => {
                error!("Failed to scan method: {}", e);
                return Err(ServerError::InternalError(e.to_string()));
            }
        }
        
        // Scan parameters if present
        if let Some(params) = &request.params {
            match self.scanner.scan_json(params) {
                Ok(threats) => all_threats.extend(threats),
                Err(e) => {
                    error!("Failed to scan params: {}", e);
                    return Err(ServerError::InternalError(e.to_string()));
                }
            }
        }
        
        // Filter by severity threshold
        all_threats.retain(|t| t.severity >= Severity::Medium);
        
        Ok(all_threats)
    }
    
    /// Process MCP method
    async fn process_method(&self, method: &str, params: Option<Value>) -> Result<Value, ServerError> {
        match method {
            // MCP standard methods
            "initialize" => self.handle_initialize(params).await,
            "initialized" => self.handle_initialized(params).await,
            "shutdown" => self.handle_shutdown(params).await,
            
            // Tool-related methods
            "tools/list" => self.handle_tools_list(params).await,
            "tools/call" => self.handle_tools_call(params).await,
            
            // Resource-related methods
            "resources/list" => self.handle_resources_list(params).await,
            "resources/read" => self.handle_resources_read(params).await,
            
            // Security monitoring methods (custom)
            "security/status" => self.handle_security_status(params).await,
            "security/threats" => self.handle_security_threats(params).await,
            
            _ => Err(ServerError::MethodNotFound(method.to_string())),
        }
    }
    
    /// Handle initialize request
    async fn handle_initialize(&self, _params: Option<Value>) -> Result<Value, ServerError> {
        info!("MCP server initializing");
        
        Ok(serde_json::json!({
            "protocolVersion": "0.1.0",
            "serverInfo": {
                "name": "KindlyGuard",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Security-focused MCP server"
            },
            "capabilities": {
                "tools": true,
                "resources": true,
                "security": true
            }
        }))
    }
    
    /// Handle initialized notification
    async fn handle_initialized(&self, _params: Option<Value>) -> Result<Value, ServerError> {
        info!("MCP server initialized");
        self.shield.set_active(true);
        Ok(Value::Null)
    }
    
    /// Handle shutdown request
    async fn handle_shutdown(&self, _params: Option<Value>) -> Result<Value, ServerError> {
        info!("MCP server shutting down");
        self.shield.set_active(false);
        Ok(Value::Null)
    }
    
    /// Handle tools/list request
    async fn handle_tools_list(&self, _params: Option<Value>) -> Result<Value, ServerError> {
        Ok(serde_json::json!({
            "tools": [
                {
                    "name": "scan_text",
                    "description": "Scan text for security threats",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "text": {
                                "type": "string",
                                "description": "Text to scan"
                            }
                        },
                        "required": ["text"]
                    }
                },
                {
                    "name": "scan_file",
                    "description": "Scan a file for security threats",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "File path to scan"
                            }
                        },
                        "required": ["path"]
                    }
                }
            ]
        }))
    }
    
    /// Handle tools/call request
    async fn handle_tools_call(&self, params: Option<Value>) -> Result<Value, ServerError> {
        let params = params.ok_or_else(|| ServerError::InvalidRequest("Missing params".to_string()))?;
        
        let tool_name = params["name"].as_str()
            .ok_or_else(|| ServerError::InvalidRequest("Missing tool name".to_string()))?;
            
        let args = params.get("arguments")
            .ok_or_else(|| ServerError::InvalidRequest("Missing tool arguments".to_string()))?;
            
        match tool_name {
            "scan_text" => {
                let text = args["text"].as_str()
                    .ok_or_else(|| ServerError::InvalidRequest("Missing text argument".to_string()))?;
                    
                let threats = self.scanner.scan_text(text)
                    .map_err(|e| ServerError::InternalError(e.to_string()))?;
                    
                Ok(serde_json::json!({
                    "threats": threats,
                    "safe": threats.is_empty()
                }))
            }
            
            "scan_file" => {
                let path = args["path"].as_str()
                    .ok_or_else(|| ServerError::InvalidRequest("Missing path argument".to_string()))?;
                    
                // Read file content
                let content = tokio::fs::read_to_string(path).await
                    .map_err(|e| ServerError::InternalError(format!("Failed to read file: {}", e)))?;
                    
                let threats = self.scanner.scan_text(&content)
                    .map_err(|e| ServerError::InternalError(e.to_string()))?;
                    
                Ok(serde_json::json!({
                    "threats": threats,
                    "safe": threats.is_empty(),
                    "file": path
                }))
            }
            
            _ => Err(ServerError::MethodNotFound(format!("Unknown tool: {}", tool_name))),
        }
    }
    
    /// Handle resources/list request
    async fn handle_resources_list(&self, _params: Option<Value>) -> Result<Value, ServerError> {
        Ok(serde_json::json!({
            "resources": [
                {
                    "uri": "security://status",
                    "name": "Security Status",
                    "description": "Current security status and statistics",
                    "mimeType": "application/json"
                },
                {
                    "uri": "security://threats",
                    "name": "Threat Log",
                    "description": "Recent threats detected and blocked",
                    "mimeType": "application/json"
                }
            ]
        }))
    }
    
    /// Handle resources/read request
    async fn handle_resources_read(&self, params: Option<Value>) -> Result<Value, ServerError> {
        let params = params.ok_or_else(|| ServerError::InvalidRequest("Missing params".to_string()))?;
        let uri = params["uri"].as_str()
            .ok_or_else(|| ServerError::InvalidRequest("Missing uri".to_string()))?;
            
        match uri {
            "security://status" => self.handle_security_status(None).await,
            "security://threats" => self.handle_security_threats(None).await,
            _ => Err(ServerError::MethodNotFound(format!("Unknown resource: {}", uri))),
        }
    }
    
    /// Handle security/status request
    async fn handle_security_status(&self, _params: Option<Value>) -> Result<Value, ServerError> {
        let stats = self.scanner.stats();
        let shield_info = self.shield.get_info();
        
        Ok(serde_json::json!({
            "active": shield_info.active,
            "uptime_seconds": shield_info.uptime.as_secs(),
            "threats_blocked": shield_info.threats_blocked,
            "scanner_stats": {
                "unicode_threats": stats.unicode_threats_detected,
                "injection_threats": stats.injection_threats_detected,
                "total_scans": stats.total_scans,
            }
        }))
    }
    
    /// Handle security/threats request
    async fn handle_security_threats(&self, _params: Option<Value>) -> Result<Value, ServerError> {
        let recent_threats = self.shield.get_recent_threats(100);
        
        Ok(serde_json::json!({
            "threats": recent_threats,
            "count": recent_threats.len(),
        }))
    }
    
    /// Start the server (stdio mode)
    pub async fn run_stdio(self: Arc<Self>) -> Result<()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        
        info!("Starting KindlyGuard MCP server in stdio mode");
        self.shield.set_active(true);
        
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();
        
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    
                    match self.handle_request(line).await {
                        Ok(response) => {
                            stdout.write_all(response.as_bytes()).await?;
                            stdout.write_all(b"\n").await?;
                            stdout.flush().await?;
                        }
                        Err(e) => {
                            let error_response = JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                result: None,
                                error: Some(JsonRpcError {
                                    code: -32000,
                                    message: e.to_string(),
                                    data: None,
                                }),
                                id: None,
                            };
                            
                            let response = serde_json::to_string(&error_response)?;
                            stdout.write_all(response.as_bytes()).await?;
                            stdout.write_all(b"\n").await?;
                            stdout.flush().await?;
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to read from stdin: {}", e);
                    break;
                }
            }
        }
        
        self.shield.set_active(false);
        info!("KindlyGuard MCP server stopped");
        Ok(())
    }
}