//! MCP Server implementation with full protocol compliance

use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{debug, info, warn, error};

use crate::config::Config;
use crate::protocol::*;
use crate::scanner::{SecurityScanner, Threat};
use crate::shield::Shield;

/// Session information
struct SessionInfo {
    id: String,
    client_info: Option<ClientInfo>,
    created_at: std::time::Instant,
    threats_blocked: u64,
    last_activity: std::time::Instant,
}

/// Session store
struct SessionStore {
    sessions: std::collections::HashMap<String, SessionInfo>,
}

/// MCP Server with security features
pub struct McpServer {
    scanner: Arc<SecurityScanner>,
    pub shield: Arc<Shield>,
    config: Arc<Config>,
    session_store: Arc<Mutex<SessionStore>>,
    server_info: ServerInfo,
    capabilities: ServerCapabilities,
}

/// Server error types
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Method not found: {0}")]
    MethodNotFound(String),
    
    #[error("Invalid parameters: {0}")]
    InvalidParams(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
    
    #[error("Threat detected: {threats:?}")]
    ThreatDetected { threats: Vec<Threat> },
    
    #[error("Unauthorized")]
    Unauthorized,
    
    #[error("Rate limited")]
    RateLimited,
    
    #[error("Timeout")]
    Timeout,
}

impl ServerError {
    /// Convert to JSON-RPC error
    fn to_json_rpc_error(&self) -> JsonRpcError {
        match self {
            ServerError::InvalidRequest(msg) => JsonRpcError {
                code: error_codes::INVALID_REQUEST,
                message: msg.clone(),
                data: None,
            },
            ServerError::MethodNotFound(method) => JsonRpcError {
                code: error_codes::METHOD_NOT_FOUND,
                message: format!("Method not found: {}", method),
                data: None,
            },
            ServerError::InvalidParams(msg) => JsonRpcError {
                code: error_codes::INVALID_PARAMS,
                message: msg.clone(),
                data: None,
            },
            ServerError::InternalError(msg) => JsonRpcError {
                code: error_codes::INTERNAL_ERROR,
                message: msg.clone(),
                data: None,
            },
            ServerError::ThreatDetected { threats } => JsonRpcError {
                code: error_codes::THREAT_DETECTED,
                message: "Security threat detected".to_string(),
                data: Some(serde_json::to_value(threats).unwrap_or(Value::Null)),
            },
            ServerError::Unauthorized => JsonRpcError {
                code: error_codes::UNAUTHORIZED,
                message: "Unauthorized".to_string(),
                data: None,
            },
            ServerError::RateLimited => JsonRpcError {
                code: error_codes::RATE_LIMITED,
                message: "Rate limit exceeded".to_string(),
                data: None,
            },
            ServerError::Timeout => JsonRpcError {
                code: error_codes::INTERNAL_ERROR,
                message: "Request timeout".to_string(),
                data: None,
            },
        }
    }
}

impl McpServer {
    /// Create a new MCP server
    pub fn new(config: Config) -> Result<Self> {
        let scanner = Arc::new(SecurityScanner::new(config.scanner.clone())?);
        let shield = Arc::new(Shield::with_config(config.shield.clone()));
        
        let server_info = ServerInfo {
            name: "KindlyGuard".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            description: Some("Security-focused MCP server protecting against unicode attacks and injection threats".to_string()),
        };
        
        let capabilities = ServerCapabilities {
            tools: Some(ToolsCapability {}),
            resources: Some(ResourcesCapability { subscribe: Some(false) }),
            prompts: None,
            logging: Some(LoggingCapability {}),
        };
        
        Ok(Self {
            scanner,
            shield,
            config: Arc::new(config),
            session_store: Arc::new(Mutex::new(SessionStore {
                sessions: std::collections::HashMap::new(),
            })),
            server_info,
            capabilities,
        })
    }
    
    /// Handle incoming JSON-RPC message
    pub async fn handle_message(&self, message: &str) -> Option<String> {
        // Try to parse as request
        if let Ok(request) = serde_json::from_str::<JsonRpcRequest>(message) {
            let response = self.handle_request(request).await;
            return Some(serde_json::to_string(&response).unwrap_or_else(|e| {
                error!("Failed to serialize response: {}", e);
                r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"},"id":null}"#.to_string()
            }));
        }
        
        // Try to parse as notification
        if let Ok(notification) = serde_json::from_str::<JsonRpcNotification>(message) {
            self.handle_notification(notification).await;
            return None; // Notifications don't get responses
        }
        
        // Invalid JSON-RPC
        let error_response = error_response(
            error_codes::PARSE_ERROR,
            "Parse error".to_string(),
            ResponseId::Null { id: None },
            None,
        );
        
        Some(serde_json::to_string(&error_response).unwrap())
    }
    
    /// Handle JSON-RPC request
    async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        // Validate JSON-RPC version
        if request.jsonrpc != "2.0" {
            return error_response(
                error_codes::INVALID_REQUEST,
                "Invalid JSON-RPC version".to_string(),
                request.id.into(),
                None,
            );
        }
        
        // Security scan the request
        match self.scan_request(&request).await {
            Ok(threats) if !threats.is_empty() => {
                self.shield.record_threats(&threats);
                error!("Threats detected in request: {:?}", threats);
                return error_response(
                    error_codes::THREAT_DETECTED,
                    "Security threat detected".to_string(),
                    request.id.into(),
                    Some(serde_json::to_value(&threats).unwrap_or(Value::Null)),
                );
            }
            Err(e) => {
                error!("Failed to scan request: {}", e);
                // Continue processing but log the error
            }
            _ => {}
        }
        
        // Process the method
        let result = match request.method.as_str() {
            "initialize" => self.handle_initialize(request.params).await,
            "initialized" => self.handle_initialized(request.params).await,
            "shutdown" => self.handle_shutdown(request.params).await,
            
            "tools/list" => self.handle_tools_list(request.params).await,
            "tools/call" => self.handle_tools_call(request.params).await,
            
            "resources/list" => self.handle_resources_list(request.params).await,
            "resources/read" => self.handle_resources_read(request.params).await,
            
            "logging/setLevel" => self.handle_logging_set_level(request.params).await,
            
            // KindlyGuard custom methods
            "security/status" => self.handle_security_status(request.params).await,
            "security/threats" => self.handle_security_threats(request.params).await,
            
            // Cancel request
            "$/cancelRequest" => self.handle_cancel_request(request.params).await,
            
            method => Err(ServerError::MethodNotFound(method.to_string())),
        };
        
        match result {
            Ok(value) => success_response(value, request.id.into()),
            Err(error) => error_response(
                error.to_json_rpc_error().code,
                error.to_json_rpc_error().message,
                request.id.into(),
                error.to_json_rpc_error().data,
            ),
        }
    }
    
    /// Handle JSON-RPC notification
    async fn handle_notification(&self, notification: JsonRpcNotification) {
        debug!("Received notification: {}", notification.method);
        
        match notification.method.as_str() {
            "initialized" => {
                info!("Client sent initialized notification");
                self.shield.set_active(true);
            }
            "$/cancelRequest" => {
                if let Some(params) = notification.params {
                    if let Some(id) = params.get("id") {
                        debug!("Cancel request for id: {:?}", id);
                        // TODO: Implement request cancellation
                    }
                }
            }
            _ => {
                debug!("Unknown notification: {}", notification.method);
            }
        }
    }
    
    /// Scan request for security threats
    async fn scan_request(&self, request: &JsonRpcRequest) -> Result<Vec<Threat>, ServerError> {
        let mut all_threats = Vec::new();
        
        // Scan method name
        match self.scanner.scan_text(&request.method) {
            Ok(threats) => all_threats.extend(threats),
            Err(e) => {
                error!("Failed to scan method: {}", e);
            }
        }
        
        // Scan parameters if present
        if let Some(params) = &request.params {
            match self.scanner.scan_json(params) {
                Ok(threats) => all_threats.extend(threats),
                Err(e) => {
                    error!("Failed to scan params: {}", e);
                }
            }
        }
        
        Ok(all_threats)
    }
    
    /// Handle initialize request
    async fn handle_initialize(&self, params: Option<Value>) -> Result<Value, ServerError> {
        let params: InitializeParams = if let Some(p) = params {
            serde_json::from_value(p)
                .map_err(|e| ServerError::InvalidParams(format!("Invalid initialize params: {}", e)))?
        } else {
            return Err(ServerError::InvalidParams("Missing initialize params".to_string()));
        };
        
        info!("Initialize request from {} v{}", 
            params.client_info.name, 
            params.client_info.version
        );
        
        // Store client info
        let session_id = uuid::Uuid::new_v4().to_string();
        let mut store = self.session_store.lock().await;
        store.sessions.insert(session_id.clone(), SessionInfo {
            id: session_id,
            client_info: Some(params.client_info),
            created_at: std::time::Instant::now(),
            threats_blocked: 0,
            last_activity: std::time::Instant::now(),
        });
        
        // Version negotiation - we support 2024-11-05
        let protocol_version = if params.protocol_version == PROTOCOL_VERSION {
            PROTOCOL_VERSION.to_string()
        } else {
            warn!("Client requested protocol version {}, we support {}", 
                params.protocol_version, PROTOCOL_VERSION);
            PROTOCOL_VERSION.to_string()
        };
        
        let result = InitializeResult {
            protocol_version,
            capabilities: self.capabilities.clone(),
            server_info: self.server_info.clone(),
            instructions: Some(
                "KindlyGuard protects your MCP session against unicode attacks and injection threats. \
                All requests are scanned for security threats before processing.".to_string()
            ),
        };
        
        Ok(serde_json::to_value(result).map_err(|e| ServerError::InternalError(e.to_string()))?)
    }
    
    /// Handle initialized notification (as request)
    async fn handle_initialized(&self, _params: Option<Value>) -> Result<Value, ServerError> {
        // This is usually a notification, but handle as request too
        Ok(Value::Null)
    }
    
    /// Handle shutdown request
    async fn handle_shutdown(&self, _params: Option<Value>) -> Result<Value, ServerError> {
        info!("Shutdown requested");
        self.shield.set_active(false);
        Ok(Value::Null)
    }
    
    /// Handle tools/list request
    async fn handle_tools_list(&self, _params: Option<Value>) -> Result<Value, ServerError> {
        let tools = vec![
            Tool {
                name: "scan_text".to_string(),
                description: "Scan text for security threats including unicode attacks and injection attempts".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "Text to scan for threats"
                        }
                    },
                    "required": ["text"]
                }),
            },
            Tool {
                name: "scan_file".to_string(),
                description: "Scan a file for security threats".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "File path to scan"
                        }
                    },
                    "required": ["path"]
                }),
            },
            Tool {
                name: "scan_json".to_string(),
                description: "Scan JSON data for security threats".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "data": {
                            "type": "object",
                            "description": "JSON data to scan"
                        }
                    },
                    "required": ["data"]
                }),
            },
        ];
        
        let result = ToolsListResult { tools };
        Ok(serde_json::to_value(result).map_err(|e| ServerError::InternalError(e.to_string()))?)
    }
    
    /// Handle tools/call request
    async fn handle_tools_call(&self, params: Option<Value>) -> Result<Value, ServerError> {
        let params: ToolCallParams = if let Some(p) = params {
            serde_json::from_value(p)
                .map_err(|e| ServerError::InvalidParams(format!("Invalid tool call params: {}", e)))?
        } else {
            return Err(ServerError::InvalidParams("Missing tool call params".to_string()));
        };
        
        // Apply timeout to tool execution
        let result = tokio::time::timeout(
            Duration::from_secs(self.config.server.request_timeout_secs),
            self.execute_tool(&params.name, params.arguments)
        ).await
        .map_err(|_| ServerError::Timeout)??;
        
        Ok(result)
    }
    
    /// Execute a tool
    async fn execute_tool(&self, name: &str, arguments: Value) -> Result<Value, ServerError> {
        match name {
            "scan_text" => {
                let text = arguments.get("text")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ServerError::InvalidParams("Missing 'text' argument".to_string()))?;
                
                let threats = self.scanner.scan_text(text)
                    .map_err(|e| ServerError::InternalError(e.to_string()))?;
                
                if !threats.is_empty() {
                    self.shield.record_threats(&threats);
                }
                
                Ok(serde_json::json!({
                    "threats": threats,
                    "safe": threats.is_empty(),
                    "scanned_length": text.len(),
                }))
            }
            
            "scan_file" => {
                let path = arguments.get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ServerError::InvalidParams("Missing 'path' argument".to_string()))?;
                
                // Security check: prevent path traversal
                if path.contains("..") || path.starts_with('/') {
                    return Err(ServerError::InvalidParams("Invalid file path".to_string()));
                }
                
                let content = tokio::fs::read_to_string(path).await
                    .map_err(|e| ServerError::InternalError(format!("Failed to read file: {}", e)))?;
                
                let threats = self.scanner.scan_text(&content)
                    .map_err(|e| ServerError::InternalError(e.to_string()))?;
                
                if !threats.is_empty() {
                    self.shield.record_threats(&threats);
                }
                
                Ok(serde_json::json!({
                    "threats": threats,
                    "safe": threats.is_empty(),
                    "file_path": path,
                    "file_size": content.len(),
                }))
            }
            
            "scan_json" => {
                let data = arguments.get("data")
                    .ok_or_else(|| ServerError::InvalidParams("Missing 'data' argument".to_string()))?;
                
                let threats = self.scanner.scan_json(data)
                    .map_err(|e| ServerError::InternalError(e.to_string()))?;
                
                if !threats.is_empty() {
                    self.shield.record_threats(&threats);
                }
                
                Ok(serde_json::json!({
                    "threats": threats,
                    "safe": threats.is_empty(),
                }))
            }
            
            _ => Err(ServerError::MethodNotFound(format!("Unknown tool: {}", name))),
        }
    }
    
    /// Handle resources/list request
    async fn handle_resources_list(&self, _params: Option<Value>) -> Result<Value, ServerError> {
        let resources = vec![
            Resource {
                uri: "threat-patterns://default".to_string(),
                name: "Default Threat Patterns".to_string(),
                description: Some("Built-in threat detection patterns".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            Resource {
                uri: "security-report://latest".to_string(),
                name: "Latest Security Report".to_string(),
                description: Some("Current security status and recent threats".to_string()),
                mime_type: Some("application/json".to_string()),
            },
        ];
        
        let result = ResourcesListResult { resources };
        Ok(serde_json::to_value(result).map_err(|e| ServerError::InternalError(e.to_string()))?)
    }
    
    /// Handle resources/read request
    async fn handle_resources_read(&self, params: Option<Value>) -> Result<Value, ServerError> {
        let params: ResourceReadParams = if let Some(p) = params {
            serde_json::from_value(p)
                .map_err(|e| ServerError::InvalidParams(format!("Invalid resource read params: {}", e)))?
        } else {
            return Err(ServerError::InvalidParams("Missing resource read params".to_string()));
        };
        
        match params.uri.as_str() {
            "threat-patterns://default" => {
                let patterns = self.scanner.patterns.get_all_patterns();
                let content = ResourceContent {
                    uri: params.uri,
                    mime_type: Some("application/json".to_string()),
                    content: ResourceContentType::Text { 
                        text: serde_json::to_string_pretty(&patterns)
                            .unwrap_or_else(|_| "{}".to_string())
                    },
                };
                Ok(serde_json::to_value(content).map_err(|e| ServerError::InternalError(e.to_string()))?)
            }
            
            "security-report://latest" => {
                let shield_info = self.shield.get_info();
                let stats = self.scanner.stats();
                let recent_threats = self.shield.get_recent_threats(10);
                
                let report = serde_json::json!({
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "status": {
                        "active": shield_info.active,
                        "uptime_seconds": shield_info.uptime.as_secs(),
                        "threats_blocked": shield_info.threats_blocked,
                        "threat_rate_per_minute": shield_info.recent_threat_rate,
                    },
                    "scanner_stats": {
                        "unicode_threats_detected": stats.unicode_threats_detected,
                        "injection_threats_detected": stats.injection_threats_detected,
                        "total_scans": stats.total_scans,
                    },
                    "recent_threats": recent_threats,
                });
                
                let content = ResourceContent {
                    uri: params.uri,
                    mime_type: Some("application/json".to_string()),
                    content: ResourceContentType::Text { 
                        text: serde_json::to_string_pretty(&report)
                            .unwrap_or_else(|_| "{}".to_string())
                    },
                };
                Ok(serde_json::to_value(content).map_err(|e| ServerError::InternalError(e.to_string()))?)
            }
            
            _ => Err(ServerError::InvalidParams(format!("Unknown resource URI: {}", params.uri))),
        }
    }
    
    /// Handle logging/setLevel request
    async fn handle_logging_set_level(&self, params: Option<Value>) -> Result<Value, ServerError> {
        if let Some(params) = params {
            if let Some(level) = params.get("level").and_then(|v| v.as_str()) {
                info!("Setting log level to: {}", level);
                // TODO: Actually implement log level changes
                Ok(Value::Null)
            } else {
                Err(ServerError::InvalidParams("Missing 'level' parameter".to_string()))
            }
        } else {
            Err(ServerError::InvalidParams("Missing parameters".to_string()))
        }
    }
    
    /// Handle security/status request
    async fn handle_security_status(&self, _params: Option<Value>) -> Result<Value, ServerError> {
        let shield_info = self.shield.get_info();
        let stats = self.scanner.stats();
        
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
    async fn handle_security_threats(&self, params: Option<Value>) -> Result<Value, ServerError> {
        let limit = params
            .as_ref()
            .and_then(|p| p.get("limit"))
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;
            
        let recent_threats = self.shield.get_recent_threats(limit);
        
        Ok(serde_json::json!({
            "threats": recent_threats,
            "count": recent_threats.len(),
        }))
    }
    
    /// Handle cancel request
    async fn handle_cancel_request(&self, params: Option<Value>) -> Result<Value, ServerError> {
        if let Some(params) = params {
            if let Some(id) = params.get("id") {
                debug!("Cancel request for id: {:?}", id);
                // TODO: Implement actual request cancellation
                Ok(Value::Null)
            } else {
                Err(ServerError::InvalidParams("Missing 'id' parameter".to_string()))
            }
        } else {
            Err(ServerError::InvalidParams("Missing parameters".to_string()))
        }
    }
    
    /// Run the server in stdio mode
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
                    
                    debug!("Received: {}", line);
                    
                    if let Some(response) = self.handle_message(line).await {
                        stdout.write_all(response.as_bytes()).await?;
                        stdout.write_all(b"\n").await?;
                        stdout.flush().await?;
                        debug!("Sent: {}", response);
                    }
                }
                Err(e) => {
                    error!("Error reading from stdin: {}", e);
                    break;
                }
            }
        }
        
        info!("MCP server shutting down");
        self.shield.set_active(false);
        Ok(())
    }
    
    /// Handle JSON-RPC batch request
    pub async fn handle_json_rpc(&self, value: Value) -> Value {
        // Check if it's a batch request
        if let Some(array) = value.as_array() {
            let mut responses = Vec::new();
            
            for item in array {
                if let Ok(request) = serde_json::from_value::<JsonRpcRequest>(item.clone()) {
                    let response = self.handle_request(request).await;
                    responses.push(serde_json::to_value(response).unwrap_or(Value::Null));
                } else if let Ok(notification) = serde_json::from_value::<JsonRpcNotification>(item.clone()) {
                    self.handle_notification(notification).await;
                    // Notifications don't get responses in batch
                } else {
                    // Invalid request in batch
                    let error = error_response(
                        error_codes::INVALID_REQUEST,
                        "Invalid request in batch".to_string(),
                        ResponseId::Null { id: None },
                        None,
                    );
                    responses.push(serde_json::to_value(error).unwrap_or(Value::Null));
                }
            }
            
            Value::Array(responses)
        } else if let Ok(request) = serde_json::from_value::<JsonRpcRequest>(value.clone()) {
            // Single request
            serde_json::to_value(self.handle_request(request).await).unwrap_or(Value::Null)
        } else if let Ok(notification) = serde_json::from_value::<JsonRpcNotification>(value.clone()) {
            // Single notification
            self.handle_notification(notification).await;
            Value::Null
        } else {
            // Invalid JSON-RPC
            serde_json::to_value(error_response(
                error_codes::INVALID_REQUEST,
                "Invalid JSON-RPC".to_string(),
                ResponseId::Null { id: None },
                None,
            )).unwrap_or(Value::Null)
        }
    }
}