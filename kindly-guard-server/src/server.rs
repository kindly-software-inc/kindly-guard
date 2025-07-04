// Copyright 2025 Kindly Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! MCP Server implementation with full protocol compliance

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::auth::{AuthContext, AuthManager};
use crate::component_selector::ComponentManager;
use crate::config::Config;
use crate::protocol::{
    error_codes, error_response, success_response, ClientInfo, InitializeParams, InitializeResult,
    JsonRpcError, JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, LoggingCapability, Prompt,
    PromptArgument, PromptsCapability, PromptsListResult, Resource, ResourceContent,
    ResourceContentType, ResourceReadParams, ResourcesCapability, ResourcesListResult,
    ServerCapabilities, ServerInfo, Tool, ToolCallParams, ToolsCapability, ToolsListResult,
    PROTOCOL_VERSION,
};
use crate::scanner::{SecurityScanner, Threat};
use crate::shield::Shield;
use crate::signing::{MessageSignature, SignedMessage, SigningManager};
use crate::telemetry::{MetricValue, TelemetryMetric};
use crate::traits::{RateLimitKey, RateLimiter, SecurityEvent, SecurityEventProcessor};
use crate::transport::{
    DefaultTransportFactory, MessageHandler, TransportConnection, TransportFactory,
    TransportManager, TransportMessage,
};
use crate::versioning::{add_version_metadata, ApiRegistry};

/// Session information
struct SessionInfo {
    #[allow(dead_code)]
    id: String,
    client_info: Option<ClientInfo>,
    #[allow(dead_code)]
    created_at: std::time::Instant,
    #[allow(dead_code)]
    threats_blocked: u64,
    #[allow(dead_code)]
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
    auth_manager: Arc<AuthManager>,
    signing_manager: Arc<SigningManager>,
    rate_limiter: Arc<dyn RateLimiter>,
    event_processor: Arc<dyn SecurityEventProcessor>,
    session_store: Arc<Mutex<SessionStore>>,
    server_info: ServerInfo,
    capabilities: ServerCapabilities,
    pub component_manager: Arc<ComponentManager>,
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
            Self::InvalidRequest(msg) => JsonRpcError {
                code: error_codes::INVALID_REQUEST,
                message: msg.clone(),
                data: None,
            },
            Self::MethodNotFound(method) => JsonRpcError {
                code: error_codes::METHOD_NOT_FOUND,
                message: format!("Method not found: {method}"),
                data: None,
            },
            Self::InvalidParams(msg) => JsonRpcError {
                code: error_codes::INVALID_PARAMS,
                message: msg.clone(),
                data: None,
            },
            Self::InternalError(msg) => JsonRpcError {
                code: error_codes::INTERNAL_ERROR,
                message: msg.clone(),
                data: None,
            },
            Self::ThreatDetected { threats } => JsonRpcError {
                code: error_codes::THREAT_DETECTED,
                message: "Security threat detected".to_string(),
                data: Some(serde_json::to_value(threats).unwrap_or(Value::Null)),
            },
            Self::Unauthorized => JsonRpcError {
                code: error_codes::UNAUTHORIZED,
                message: "Unauthorized".to_string(),
                data: None,
            },
            Self::RateLimited => JsonRpcError {
                code: error_codes::RATE_LIMITED,
                message: "Rate limit exceeded".to_string(),
                data: None,
            },
            Self::Timeout => JsonRpcError {
                code: error_codes::INTERNAL_ERROR,
                message: "Request timeout".to_string(),
                data: None,
            },
        }
    }
}

impl McpServer {
    /// Helper to track security events
    async fn track_security_event(
        &self,
        event_type: &str,
        client_id: &str,
        metadata: serde_json::Value,
    ) {
        // Log to audit system
        if self.config.audit.enabled {
            use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};

            let audit_event_type = match event_type {
                "auth.success" => AuditEventType::AuthSuccess {
                    user_id: client_id.to_string(),
                },
                "auth.failure" => AuditEventType::AuthFailure {
                    user_id: Some(client_id.to_string()),
                    reason: metadata
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string(),
                },
                "threat.detected" => AuditEventType::ThreatDetected {
                    client_id: client_id.to_string(),
                    threat_count: 1,
                },
                "rate_limit.exceeded" => AuditEventType::RateLimitTriggered {
                    client_id: client_id.to_string(),
                    limit_type: "request".to_string(),
                },
                _ => AuditEventType::Custom {
                    event_type: event_type.to_string(),
                    data: metadata.clone(),
                },
            };

            let severity = match event_type {
                "auth.failure" | "threat.detected" => AuditSeverity::Warning,
                "rate_limit.exceeded" => AuditSeverity::Warning,
                "auth.success" => AuditSeverity::Info,
                _ => AuditSeverity::Info,
            };

            let audit_event =
                AuditEvent::new(audit_event_type, severity).with_client_id(client_id.to_string());

            let audit_logger = self.component_manager.audit_logger();
            let retry_strategy = self.component_manager.retry_strategy();
            
            // Wrap audit logging with retry logic
            let audit_event_json = serde_json::to_value(&audit_event).unwrap_or(Value::Null);
            match retry_strategy
                .execute_json("audit.log", audit_event_json.clone())
                .await
            {
                Ok(_) => {
                    // Perform actual audit logging
                    if let Err(e) = audit_logger.log(audit_event).await {
                        warn!("Failed to log audit event: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to log audit event after retries: {}", e);
                }
            }
        }

        // Track in event processor if enabled
        if self.config.is_event_processor_enabled() {
            let event = SecurityEvent {
                event_type: event_type.to_string(),
                client_id: client_id.to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                metadata,
            };
            let _ = self.event_processor.process_event(event).await;
        }
    }
    /// Create a new MCP server
    pub fn new(config: Config) -> Result<Self> {
        // Create component manager to handle standard vs enhanced implementations
        let component_manager = Arc::new(ComponentManager::new(&config)?);

        let mut scanner = SecurityScanner::new(config.scanner.clone())?;

        // Set plugin manager on scanner if plugins are enabled
        if config.plugins.enabled {
            scanner.set_plugin_manager(component_manager.plugin_manager().clone());
        }

        let scanner = Arc::new(scanner);
        let shield = Arc::new(Shield::with_config(config.shield.clone()));

        // Set event processor state in shield for purple mode
        shield.set_event_processor_enabled(config.is_event_processor_enabled());

        // Create auth manager with server resource ID
        let server_resource_id = format!("kindlyguard:{}", env!("CARGO_PKG_VERSION"));
        let auth_manager = Arc::new(AuthManager::new(config.auth.clone(), server_resource_id));

        // Create signing manager
        let signing_manager = Arc::new(SigningManager::new(config.signing.clone())?);

        // Get components from manager (automatically selects standard vs enhanced)
        let rate_limiter = component_manager.rate_limiter().clone();
        let event_processor = component_manager.event_processor().clone();

        // Link event processor to shield for correlation data
        if config.is_event_processor_enabled() {
            shield.set_event_processor(&event_processor);
        }

        let server_info = ServerInfo {
            name: "kindly-guard".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };

        let capabilities = ServerCapabilities {
            tools: Some(ToolsCapability {}),
            resources: Some(ResourcesCapability {}),
            prompts: Some(PromptsCapability {}),
            logging: Some(LoggingCapability {}),
        };

        Ok(Self {
            scanner,
            shield,
            config: Arc::new(config),
            auth_manager,
            signing_manager,
            rate_limiter,
            event_processor,
            session_store: Arc::new(Mutex::new(SessionStore {
                sessions: std::collections::HashMap::new(),
            })),
            server_info,
            capabilities,
            component_manager,
        })
    }

    /// Handle incoming JSON-RPC message
    /// Get the security scanner
    pub fn scanner(&self) -> &Arc<SecurityScanner> {
        &self.scanner
    }

    pub async fn handle_message(&self, message: &str) -> Option<String> {
        // Try to parse as Value first to handle batch requests
        match serde_json::from_str::<Value>(message) {
            Ok(Value::Array(requests)) => {
                // Handle batch request
                let mut responses = Vec::new();
                for req in requests {
                    if let Some(response) = self.handle_value(req).await {
                        if let Ok(resp_value) = serde_json::from_str::<Value>(&response) {
                            responses.push(resp_value);
                        }
                    }
                }

                if responses.is_empty() {
                    None
                } else {
                    match serde_json::to_string(&responses) {
                        Ok(json) => Some(json),
                        Err(e) => {
                            error!("Failed to serialize batch response: {}", e);
                            None
                        }
                    }
                }
            }
            Ok(value) => self.handle_value(value).await,
            Err(_) => {
                // Invalid JSON
                let error_response = error_response(
                    Value::Null,
                    error_codes::PARSE_ERROR,
                    "Parse error".to_string(),
                    None,
                );
                match serde_json::to_string(&error_response) {
                    Ok(json) => Some(json),
                    Err(e) => {
                        error!("Failed to serialize error response: {}", e);
                        None
                    }
                }
            }
        }
    }

    /// Handle a parsed JSON value
    async fn handle_value(&self, mut value: Value) -> Option<String> {
        // Check if this is a signed message and unwrap it
        if let Ok(signed) = serde_json::from_value::<SignedMessage>(value.clone()) {
            // Verify signature if signing is enabled
            if self.config.signing.enabled {
                let verification_result = self.signing_manager.verify_message(&signed);

                // Track signature verification event
                if self.config.is_event_processor_enabled() {
                    let client_id = "anonymous"; // Could extract from signed message metadata
                    let event = SecurityEvent {
                        event_type: if verification_result.is_ok() {
                            "signature.verified".to_string()
                        } else {
                            "signature.failed".to_string()
                        },
                        client_id: client_id.to_string(),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                        metadata: serde_json::json!({
                            "signature": &signed.signature.signature,
                        }),
                    };
                    let _ = self.event_processor.process_event(event).await;
                }

                if let Err(e) = verification_result {
                    error!("Message signature verification failed: {}", e);
                    let error_response = error_response(
                        Value::Null,
                        error_codes::UNAUTHORIZED,
                        "Invalid message signature".to_string(),
                        None,
                    );
                    return match serde_json::to_string(&error_response) {
                        Ok(json) => Some(json),
                        Err(e) => {
                            error!("Failed to serialize error response: {}", e);
                            None
                        }
                    };
                }
            }

            // Process the inner message by extracting it
            value = signed.message;
        }

        // Check if it has an id field to distinguish request from notification
        let has_id = value.get("id").is_some();

        if has_id {
            // Try to parse as request (has id field)
            if let Ok(request) = serde_json::from_value::<JsonRpcRequest>(value.clone()) {
                let response = self.handle_request(request).await;
                return self.maybe_sign_response(response).await;
            }
        } else {
            // Try to parse as notification (no id field)
            if let Ok(notification) = serde_json::from_value::<JsonRpcNotification>(value.clone()) {
                self.handle_notification(notification).await;
                return None; // Notifications don't get responses
            }
        }

        // Check if it's missing required fields
        if let Some(obj) = value.as_object() {
            if !obj.contains_key("method") {
                // Missing method field
                let id = obj.get("id").cloned().unwrap_or(Value::Null);
                let response_id = id;

                let error_response = error_response(
                    response_id,
                    error_codes::INVALID_REQUEST,
                    "Missing method field".to_string(),
                    None,
                );
                match serde_json::to_string(&error_response) {
                    Ok(json) => return Some(json),
                    Err(e) => {
                        error!("Failed to serialize error response: {}", e);
                        return None;
                    }
                }
            }
        }

        // Invalid JSON-RPC format
        let error_response = error_response(
            Value::Null,
            error_codes::INVALID_REQUEST,
            "Invalid request".to_string(),
            None,
        );

        match serde_json::to_string(&error_response) {
            Ok(json) => Some(json),
            Err(e) => {
                error!("Failed to serialize error response: {}", e);
                None
            }
        }
    }

    /// Handle JSON-RPC request
    /// 
    /// This is public for testing purposes only.
    /// In production, use the transport layer methods.
    pub async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        // Start telemetry span for request handling
        let telemetry = self.component_manager.telemetry_provider();
        let request_span = telemetry.start_span(&format!("mcp.request.{}", request.method));

        // Validate JSON-RPC version
        if request.jsonrpc != "2.0" {
            telemetry.set_status(&request_span, true, Some("Invalid JSON-RPC version"));
            telemetry.end_span(request_span);
            return error_response(
                request.id.clone(),
                error_codes::INVALID_REQUEST,
                "Invalid JSON-RPC version".to_string(),
                None,
            );
        }

        // Extract authorization from params._meta.authToken
        let mut authorization: Option<String> = None;

        // Check if authToken is in params._meta
        let params = &request.params;
        if let Some(meta) = params.get("_meta") {
            if let Some(auth_token) = meta.get("authToken").and_then(|v| v.as_str()) {
                authorization = Some(format!("Bearer {auth_token}"));
            }
        } else if let Some(arguments) = params.get("arguments") {
            // For tools/call, check in arguments._meta
            if let Some(meta) = arguments.get("_meta") {
                if let Some(auth_token) = meta.get("authToken").and_then(|v| v.as_str()) {
                    authorization = Some(format!("Bearer {auth_token}"));
                }
            }
        }

        // Authenticate the request
        let auth_context = match self
            .auth_manager
            .authenticate(authorization.as_deref())
            .await
        {
            Ok(ctx) => {
                // Track successful auth event
                let client_id = ctx.client_id.as_deref().unwrap_or("anonymous");
                self.track_security_event("auth.success", client_id, serde_json::json!({}))
                    .await;

                // Record auth metric
                telemetry.record_metric(TelemetryMetric {
                    name: "auth.attempts".to_string(),
                    value: MetricValue::Counter(1),
                    labels: vec![
                        ("status".to_string(), "success".to_string()),
                        ("client_id".to_string(), client_id.to_string()),
                    ],
                });
                ctx
            }
            Err(e) => {
                warn!("Authentication failed: {}", e);

                // Track failed auth event
                self.track_security_event(
                    "auth.failure",
                    "anonymous",
                    serde_json::json!({
                        "reason": e.to_string()
                    }),
                )
                .await;

                // Record auth metric
                telemetry.record_metric(TelemetryMetric {
                    name: "auth.attempts".to_string(),
                    value: MetricValue::Counter(1),
                    labels: vec![
                        ("status".to_string(), "failure".to_string()),
                        ("reason".to_string(), e.to_string()),
                    ],
                });

                telemetry.set_status(&request_span, true, Some("Authentication failed"));
                telemetry.end_span(request_span);
                return error_response(
                    request.id.clone(),
                    error_codes::UNAUTHORIZED,
                    "Authentication required".to_string(),
                    None,
                );
            }
        };

        // Check rate limit
        let client_id = auth_context.client_id.as_deref().unwrap_or("anonymous");
        let rate_limit_key = RateLimitKey {
            client_id: client_id.to_string(),
            method: Some(request.method.clone()),
        };
        let rate_limit_decision = match self.rate_limiter.check_rate_limit(&rate_limit_key).await {
            Ok(decision) => decision,
            Err(e) => {
                error!("Rate limiter error: {}", e);
                // On error, allow the request but log it
                crate::traits::RateLimitDecision {
                    allowed: true,
                    tokens_remaining: 0.0,
                    reset_after: Duration::ZERO,
                }
            }
        };

        // Track rate limit event
        self.track_security_event(
            if rate_limit_decision.allowed {
                "rate_limit.allowed"
            } else {
                "rate_limit.exceeded"
            },
            client_id,
            serde_json::json!({
                "method": &request.method,
                "tokens_remaining": rate_limit_decision.tokens_remaining,
            }),
        )
        .await;

        if !rate_limit_decision.allowed {
            warn!(
                "Rate limit exceeded for client {} on method {}",
                client_id, request.method
            );

            // Record rate limit metric
            telemetry.record_metric(TelemetryMetric {
                name: "rate_limit.exceeded".to_string(),
                value: MetricValue::Counter(1),
                labels: vec![
                    ("client_id".to_string(), client_id.to_string()),
                    ("method".to_string(), request.method.clone()),
                ],
            });

            // Check if client is under attack monitoring
            if self.event_processor.is_monitored(client_id) {
                error!(
                    "Client {} is under attack monitoring - circuit breaker may activate",
                    client_id
                );
            }

            telemetry.set_status(&request_span, true, Some("Rate limit exceeded"));
            telemetry.end_span(request_span);
            return error_response(
                request.id.clone(),
                error_codes::RATE_LIMITED,
                format!(
                    "Rate limit exceeded. Try again in {} seconds",
                    rate_limit_decision.reset_after.as_secs()
                ),
                Some(serde_json::json!({
                    "retry_after": rate_limit_decision.reset_after.as_secs(),
                    "tokens_remaining": rate_limit_decision.tokens_remaining,
                })),
            );
        }

        // Security scan the request (skip for security scanning tools)
        let should_scan_request = match request.method.as_str() {
            "tools/call" => {
                // Check if it's a security scanning tool
                let params = &request.params;
                if let Some(tool_name) = params.get("name").and_then(|n| n.as_str()) {
                    !matches!(tool_name, "scan_text" | "scan_file" | "scan_json")
                } else {
                    true
                }
            }
            _ => true,
        };

        if should_scan_request {
            match self.scan_request(&request).await {
                Ok(threats) if !threats.is_empty() => {
                    self.shield.record_threats(&threats);
                    error!("Threats detected in request: {:?}", threats);

                    // Track threat detection event
                    for threat in &threats {
                        self.track_security_event(
                            "threat.detected",
                            client_id,
                            serde_json::json!({
                                "threat_type": format!("{:?}", threat.threat_type),
                                "severity": format!("{:?}", threat.severity),
                                "threat": threat,
                            }),
                        )
                        .await;

                        // Record threat metric
                        telemetry.record_metric(TelemetryMetric {
                            name: "threats.detected".to_string(),
                            value: MetricValue::Counter(1),
                            labels: vec![
                                (
                                    "threat_type".to_string(),
                                    format!("{:?}", threat.threat_type),
                                ),
                                ("severity".to_string(), format!("{:?}", threat.severity)),
                                ("client_id".to_string(), client_id.to_string()),
                            ],
                        });
                    }

                    // Apply rate limit penalty for security threats
                    if let Err(e) = self
                        .rate_limiter
                        .apply_penalty(client_id, self.config.rate_limit.threat_penalty_multiplier)
                        .await
                    {
                        error!("Failed to apply rate limit penalty: {}", e);
                    }

                    telemetry.set_status(&request_span, true, Some("Threat detected"));
                    telemetry.end_span(request_span);
                    return error_response(
                        request.id.clone(),
                        error_codes::THREAT_DETECTED,
                        "Security threat detected".to_string(),
                        Some(serde_json::to_value(&threats).unwrap_or(Value::Null)),
                    );
                }
                Err(e) => {
                    error!("Failed to scan request: {}", e);
                    // Continue processing but log the error
                }
                _ => {}
            }
        }

        // Track MCP request event
        let request_id = match &request.id {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Null => "null".to_string(),
            _ => serde_json::to_string(&request.id).unwrap_or_else(|_| "unknown".to_string()),
        };

        self.track_security_event(
            "request.received",
            client_id,
            serde_json::json!({
                "method": &request.method,
                "request_id": &request_id,
            }),
        )
        .await;

        let start_time = std::time::Instant::now();

        // Check if method requires experimental features
        if let Some(stability) = ApiRegistry::get_stability(&request.method) {
            use crate::versioning::ApiStability;
            if stability == ApiStability::Experimental && !ApiRegistry::experimental_enabled() {
                return error_response(
                    request.id.clone(),
                    -32601,
                    format!(
                        "Method '{}' is experimental and not enabled",
                        request.method
                    ),
                    None,
                );
            }
        }

        // Process the method
        let result = match request.method.as_str() {
            "initialize" => self.handle_initialize(Some(request.params)).await,
            "initialized" => self.handle_initialized(Some(request.params)).await,
            "shutdown" => self.handle_shutdown(Some(request.params)).await,

            "tools/list" => {
                self.handle_tools_list(Some(request.params), &auth_context)
                    .await
            }
            "tools/call" => {
                self.handle_tools_call(Some(request.params), &auth_context)
                    .await
            }

            "resources/list" => self.handle_resources_list(Some(request.params)).await,
            "resources/read" => {
                self.handle_resources_read(Some(request.params), &auth_context)
                    .await
            }

            "prompts/list" => self.handle_prompts_list(Some(request.params)).await,
            "prompts/get" => self.handle_prompts_get(Some(request.params)).await,

            "logging/setLevel" => self.handle_logging_set_level(Some(request.params)).await,

            // KindlyGuard custom methods
            "security/status" => self.handle_security_status(Some(request.params)).await,
            "security/threats" => self.handle_security_threats(Some(request.params)).await,
            "security/rate_limit_status" => {
                self.handle_rate_limit_status(Some(request.params), &auth_context)
                    .await
            }

            // Cancel request
            "$/cancelRequest" => self.handle_cancel_request(Some(request.params)).await,

            method => Err(ServerError::MethodNotFound(method.to_string())),
        };

        let success = result.is_ok();
        let mut response = match result {
            Ok(value) => success_response(request.id.clone(), value),
            Err(error) => {
                telemetry.set_status(&request_span, true, Some(&error.to_string()));
                error_response(
                    request.id.clone(),
                    error.to_json_rpc_error().code,
                    error.to_json_rpc_error().message,
                    error.to_json_rpc_error().data,
                )
            }
        };

        // Add version metadata to successful responses
        if success {
            if let Some(ref mut result_value) = response.result {
                add_version_metadata(result_value);
            }
        }

        // Track MCP response event
        let duration_ms = start_time.elapsed().as_millis() as u64;
        self.track_security_event(
            "response.sent",
            client_id,
            serde_json::json!({
                "method": &request.method,
                "request_id": &request_id,
                "duration_ms": duration_ms,
                "success": success,
            }),
        )
        .await;

        // Record telemetry metrics
        telemetry.record_metric(TelemetryMetric {
            name: "mcp.request.duration".to_string(),
            value: MetricValue::Histogram(duration_ms as f64),
            labels: vec![
                ("method".to_string(), request.method.clone()),
                ("success".to_string(), success.to_string()),
            ],
        });

        telemetry.record_metric(TelemetryMetric {
            name: "mcp.request.count".to_string(),
            value: MetricValue::Counter(1),
            labels: vec![
                ("method".to_string(), request.method.clone()),
                (
                    "status".to_string(),
                    if success { "success" } else { "error" }.to_string(),
                ),
            ],
        });

        // End span
        telemetry.end_span(request_span);

        response
    }

    /// Handle JSON-RPC notification
    /// 
    /// This is public for testing purposes only.
    /// In production, use the transport layer methods.
    pub async fn handle_notification(&self, notification: JsonRpcNotification) {
        debug!("Received notification: {}", notification.method);

        match notification.method.as_str() {
            "initialized" => {
                info!("Client sent initialized notification");
                self.shield.set_active(true);
            }
            "$/cancelRequest" => {
                if !notification.params.is_null() {
                    if let Some(id) = notification.params.get("id") {
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
        let circuit_breaker = self.component_manager.circuit_breaker();

        // Scan method name with circuit breaker protection
        match circuit_breaker
            .call_json(
                "scanner.scan_text",
                serde_json::json!({
                    "text": &request.method
                }),
            )
            .await
        {
            Ok(_) => {
                // Perform actual scan
                match self.scanner.scan_text(&request.method) {
                    Ok(threats) => all_threats.extend(threats),
                    Err(e) => {
                        error!("Failed to scan method: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Circuit breaker open for scanner.scan_text: {}", e);
                // Continue without scanning if circuit is open
            }
        }

        // Scan parameters if present with circuit breaker protection
        let params = &request.params;
        match circuit_breaker
            .call_json(
                "scanner.scan_json",
                serde_json::json!({
                    "params": params
                }),
            )
            .await
        {
            Ok(_) => {
                // Perform actual scan
                match self.scanner.scan_json(params) {
                    Ok(threats) => all_threats.extend(threats),
                    Err(e) => {
                        error!("Failed to scan params: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Circuit breaker open for scanner.scan_json: {}", e);
                // Continue without scanning if circuit is open
            }
        }

        Ok(all_threats)
    }

    /// Handle initialize request
    async fn handle_initialize(&self, params: Option<Value>) -> Result<Value, ServerError> {
        let params: InitializeParams = if let Some(p) = params {
            serde_json::from_value(p).map_err(|e| {
                ServerError::InvalidParams(format!("Invalid initialize params: {e}"))
            })?
        } else {
            return Err(ServerError::InvalidParams(
                "Missing initialize params".to_string(),
            ));
        };

        info!(
            "Initialize request from {} v{}",
            params.client_info.name, params.client_info.version
        );

        // Store client info
        let session_id = uuid::Uuid::new_v4().to_string();
        let mut store = self.session_store.lock().await;
        store.sessions.insert(
            session_id.clone(),
            SessionInfo {
                id: session_id,
                client_info: Some(params.client_info),
                created_at: std::time::Instant::now(),
                threats_blocked: 0,
                last_activity: std::time::Instant::now(),
            },
        );

        // Version negotiation - we support 2024-11-05
        if params.protocol_version != PROTOCOL_VERSION {
            warn!(
                "Client requested protocol version {}, we support {}",
                params.protocol_version, PROTOCOL_VERSION
            );
            return Err(ServerError::InvalidParams(format!(
                "Unsupported protocol version: {}. Supported version: {}",
                params.protocol_version, PROTOCOL_VERSION
            )));
        }

        let protocol_version = PROTOCOL_VERSION.to_string();

        let result = InitializeResult {
            protocol_version,
            capabilities: self.capabilities.clone(),
            server_info: self.server_info.clone(),
        };

        serde_json::to_value(result).map_err(|e| ServerError::InternalError(e.to_string()))
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
    async fn handle_tools_list(
        &self,
        _params: Option<Value>,
        auth: &AuthContext,
    ) -> Result<Value, ServerError> {
        // Get all available tools
        let all_tools = vec![
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
            Tool {
                name: "get_security_info".to_string(),
                description: "Get current security information and statistics".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {},
                }),
            },
            Tool {
                name: "verify_signature".to_string(),
                description: "Verify message signature".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "message": {
                            "type": "string",
                            "description": "Message to verify"
                        },
                        "signature": {
                            "type": "string",
                            "description": "Signature to verify"
                        }
                    },
                    "required": ["message", "signature"]
                }),
            },
            Tool {
                name: "get_shield_status".to_string(),
                description: "Get current shield status and protection level".to_string(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {},
                }),
            },
        ];

        // Get allowed tools for this client
        let client_id = auth.client_id.as_deref().unwrap_or("anonymous");
        let tools = if self.config.auth.enabled {
            let allowed_tools = self
                .component_manager
                .permission_manager()
                .get_allowed_tools(client_id)
                .await
                .map_err(|e| {
                    ServerError::InternalError(format!("Failed to get allowed tools: {e}"))
                })?;

            // Filter tools based on permissions
            all_tools
                .into_iter()
                .filter(|tool| allowed_tools.contains(&tool.name))
                .collect()
        } else {
            // When auth is disabled, allow all tools
            all_tools
        };

        info!("Client {} has access to {} tools", client_id, tools.len());

        let result = ToolsListResult { tools };
        serde_json::to_value(result).map_err(|e| ServerError::InternalError(e.to_string()))
    }

    /// Handle tools/call request
    async fn handle_tools_call(
        &self,
        params: Option<Value>,
        auth: &AuthContext,
    ) -> Result<Value, ServerError> {
        let params: ToolCallParams = if let Some(p) = params {
            serde_json::from_value(p)
                .map_err(|e| ServerError::InvalidParams(format!("Invalid tool call params: {e}")))?
        } else {
            return Err(ServerError::InvalidParams(
                "Missing tool call params".to_string(),
            ));
        };

        // Check OAuth2 authorization for tool (only if auth is enabled)
        if self.config.auth.enabled {
            self.auth_manager
                .authorize_tool(auth, &params.name)
                .map_err(|_e| ServerError::Unauthorized)?;
        }

        // Check fine-grained permissions (only if auth is enabled)
        if self.config.auth.enabled {
            let permission_context = crate::permissions::PermissionContext {
                auth_token: None, // Auth token is internal to auth manager
                scopes: auth.scopes.clone(),
                threat_level: self.get_current_threat_level(),
                request_metadata: std::collections::HashMap::new(),
            };

            let client_id = auth.client_id.as_deref().unwrap_or("anonymous");
            let permission = self
                .component_manager
                .permission_manager()
                .check_permission(client_id, &params.name, &permission_context)
                .await
                .map_err(|e| ServerError::InternalError(format!("Permission check failed: {e}")))?;

            if let crate::permissions::Permission::Deny(reason) = permission {
                warn!("Tool access denied for {}: {}", client_id, reason);
                return Err(ServerError::Unauthorized);
            }
        }

        // Apply bulkhead protection and timeout to tool execution
        let bulkhead = self.component_manager.bulkhead();
        let tool_name = params.name.clone();
        let arguments = params.arguments;
        
        let _bulkhead_result = bulkhead
            .execute_json(
                &format!("tool.{}", tool_name),
                serde_json::json!({
                    "tool": &tool_name,
                    "arguments": &arguments
                }),
            )
            .await
            .map_err(|e| {
                warn!("Bulkhead rejected tool execution for {}: {}", tool_name, e);
                ServerError::InternalError(format!("Tool execution rejected: {}", e))
            })?;
        
        // Now execute with timeout
        let result = tokio::time::timeout(
            Duration::from_secs(self.config.server.request_timeout_secs),
            self.execute_tool(&tool_name, arguments),
        )
        .await
        .map_err(|_| ServerError::Timeout)??;

        Ok(result)
    }

    /// Execute a tool
    async fn execute_tool(&self, name: &str, arguments: Value) -> Result<Value, ServerError> {
        match name {
            "scan_text" => {
                let text = arguments
                    .get("text")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ServerError::InvalidParams("Missing 'text' argument".to_string())
                    })?;

                let threats = self
                    .scanner
                    .scan_text(text)
                    .map_err(|e| ServerError::InternalError(e.to_string()))?;

                if !threats.is_empty() {
                    self.shield.record_threats(&threats);
                }

                // Neutralize threats if configured
                let neutralizer = self.component_manager.threat_neutralizer();
                let neutralization_mode = self.config.neutralization.mode;

                let (neutralization_results, final_content) = if !threats.is_empty()
                    && neutralization_mode != crate::neutralizer::NeutralizationMode::ReportOnly
                {
                    let mut results = Vec::new();
                    let mut current_content = text.to_string();

                    // Get client ID for audit logging from current session
                    let client_id = {
                        let store = self.session_store.lock().await;
                        store
                            .sessions
                            .values()
                            .next()
                            .and_then(|s| s.client_info.as_ref())
                            .map_or_else(|| "anonymous".to_string(), |ci| ci.name.clone())
                    };

                    // Create audit context
                    let audit_logger = if self.config.audit.enabled {
                        Some(self.component_manager.audit_logger().clone())
                    } else {
                        None
                    };

                    // Create telemetry helper if enabled
                    let telemetry = if self.config.telemetry.enabled {
                        Some(crate::telemetry::SecureTelemetry::new(
                            self.component_manager.telemetry_provider().clone(),
                        ))
                    } else {
                        None
                    };

                    // Create metrics tracker
                    let neutralization_metrics =
                        crate::neutralizer::metrics::NeutralizationMetrics::new(Arc::new(
                            crate::telemetry::metrics::MetricsCollector::new(),
                        ));

                    // Create validator with config
                    let validator = crate::neutralizer::validation::NeutralizationValidator::new(
                        crate::neutralizer::validation::ValidationConfig::default(),
                    );

                    for threat in &threats {
                        // Log neutralization start
                        if let Some(ref logger) = audit_logger {
                            let event = crate::audit::AuditEvent::new(
                                crate::audit::AuditEventType::NeutralizationStarted {
                                    client_id: client_id.clone(),
                                    threat_id: format!(
                                        "threat-{:?}-{}",
                                        threat.threat_type,
                                        match &threat.location {
                                            crate::scanner::Location::Text { offset, .. } =>
                                                *offset,
                                            crate::scanner::Location::Json { path } => path.len(),
                                            crate::scanner::Location::Binary { offset } => *offset,
                                        }
                                    ),
                                    threat_type: format!("{:?}", threat.threat_type),
                                },
                                crate::audit::AuditSeverity::Info,
                            )
                            .with_client_id(client_id.clone())
                            .with_tags(vec!["neutralization".to_string(), "security".to_string()]);

                            if let Err(e) = logger.log(event).await {
                                tracing::warn!("Failed to log neutralization start: {}", e);
                            }
                        }

                        // Validate input before neutralization
                        if let Err(e) = validator.validate_input(threat, &current_content) {
                            tracing::warn!("Input validation failed: {}", e);
                            neutralization_metrics.record_validation_failure(&e.to_string());
                            continue; // Skip this threat
                        }

                        // Record content size metric
                        neutralization_metrics
                            .record_content_size(current_content.len(), &threat.threat_type);

                        let start_time = std::time::Instant::now();

                        match neutralizer.neutralize(threat, &current_content).await {
                            Ok(result) => {
                                // Validate output
                                if let Err(e) =
                                    validator.validate_output(threat, &current_content, &result)
                                {
                                    tracing::error!("Output validation failed: {}", e);
                                    neutralization_metrics
                                        .record_validation_failure(&e.to_string());
                                    continue; // Skip this result
                                }
                                // Log neutralization completion
                                let duration = start_time.elapsed();
                                let action_str = match result.action_taken {
                                    crate::neutralizer::NeutralizeAction::Sanitized => "sanitized",
                                    crate::neutralizer::NeutralizeAction::Parameterized => {
                                        "parameterized"
                                    }
                                    crate::neutralizer::NeutralizeAction::Normalized => {
                                        "normalized"
                                    }
                                    crate::neutralizer::NeutralizeAction::Escaped => "escaped",
                                    crate::neutralizer::NeutralizeAction::Removed => "removed",
                                    crate::neutralizer::NeutralizeAction::Quarantined => {
                                        "quarantined"
                                    }
                                    crate::neutralizer::NeutralizeAction::NoAction => "no_action",
                                };

                                if let Some(ref logger) = audit_logger {
                                    let event = crate::audit::AuditEvent::new(
                                        crate::audit::AuditEventType::NeutralizationCompleted {
                                            client_id: client_id.clone(),
                                            threat_id: format!(
                                                "threat-{:?}-{}",
                                                threat.threat_type,
                                                match &threat.location {
                                                    crate::scanner::Location::Text {
                                                        offset,
                                                        ..
                                                    } => *offset,
                                                    crate::scanner::Location::Json { path } =>
                                                        path.len(),
                                                    crate::scanner::Location::Binary { offset } =>
                                                        *offset,
                                                }
                                            ),
                                            action: action_str.to_string(),
                                            duration_ms: duration.as_millis() as u64,
                                        },
                                        crate::audit::AuditSeverity::Info,
                                    )
                                    .with_client_id(client_id.clone())
                                    .with_context(
                                        "confidence".to_string(),
                                        serde_json::to_value(result.confidence_score)
                                            .unwrap_or(serde_json::Value::Null),
                                    )
                                    .with_tags(vec![
                                        "neutralization".to_string(),
                                        "security".to_string(),
                                        "success".to_string(),
                                    ]);

                                    if let Err(e) = logger.log(event).await {
                                        tracing::warn!(
                                            "Failed to log neutralization completion: {}",
                                            e
                                        );
                                    }
                                }

                                // Record telemetry
                                if let Some(ref telemetry) = telemetry {
                                    telemetry.record_neutralization(
                                        &format!("{:?}", threat.threat_type),
                                        action_str,
                                        duration.as_millis() as f64,
                                        true,
                                    );
                                }

                                // Record neutralization metrics
                                neutralization_metrics.record_neutralization(
                                    &threat.threat_type,
                                    &result.action_taken,
                                    true,
                                    duration,
                                    neutralization_mode,
                                );

                                if let Some(ref sanitized) = result.sanitized_content {
                                    current_content = sanitized.clone();
                                }
                                results.push(serde_json::json!({
                                    "threat_type": format!("{:?}", threat.threat_type),
                                    "action": format!("{}", result.action_taken),
                                    "confidence": result.confidence_score,
                                    "time_us": duration.as_micros() as u64,
                                }));
                            }
                            Err(e) => {
                                // Log neutralization failure
                                if let Some(ref logger) = audit_logger {
                                    let event = crate::audit::AuditEvent::new(
                                        crate::audit::AuditEventType::NeutralizationFailed {
                                            client_id: client_id.clone(),
                                            threat_id: format!(
                                                "threat-{:?}-{}",
                                                threat.threat_type,
                                                match &threat.location {
                                                    crate::scanner::Location::Text {
                                                        offset,
                                                        ..
                                                    } => *offset,
                                                    crate::scanner::Location::Json { path } =>
                                                        path.len(),
                                                    crate::scanner::Location::Binary { offset } =>
                                                        *offset,
                                                }
                                            ),
                                            error: e.to_string(),
                                        },
                                        crate::audit::AuditSeverity::Error,
                                    )
                                    .with_client_id(client_id.clone())
                                    .with_tags(vec![
                                        "neutralization".to_string(),
                                        "security".to_string(),
                                        "failure".to_string(),
                                    ]);

                                    if let Err(e) = logger.log(event).await {
                                        tracing::warn!(
                                            "Failed to log neutralization failure: {}",
                                            e
                                        );
                                    }
                                }

                                // Record telemetry for failure
                                if let Some(ref telemetry) = telemetry {
                                    telemetry.record_neutralization(
                                        &format!("{:?}", threat.threat_type),
                                        "failed",
                                        start_time.elapsed().as_millis() as f64,
                                        false,
                                    );
                                }

                                // Record failure metrics
                                neutralization_metrics.record_neutralization(
                                    &threat.threat_type,
                                    &crate::neutralizer::NeutralizeAction::NoAction,
                                    false,
                                    start_time.elapsed(),
                                    neutralization_mode,
                                );

                                tracing::warn!("Neutralization failed for threat: {}", e);
                            }
                        }
                    }

                    // Record batch telemetry and metrics
                    if let Some(ref telemetry) = telemetry {
                        let batch_start = std::time::Instant::now();
                        let neutralized_count = results.len();
                        telemetry.record_neutralization_batch(
                            threats.len(),
                            neutralized_count,
                            batch_start.elapsed().as_millis() as f64,
                        );
                    }

                    // Record batch metrics
                    let neutralized_count = results.len();
                    let failed_count = threats.len().saturating_sub(neutralized_count);
                    neutralization_metrics.record_batch_neutralization(
                        threats.len(),
                        neutralized_count,
                        failed_count,
                        std::time::Duration::from_millis(100), // Approximate batch time
                    );

                    (Some(results), Some(current_content))
                } else {
                    (None, None)
                };

                // Format response according to MCP protocol
                let threat_data = threats.iter().map(|t| {
                    serde_json::json!({
                        "type": match &t.threat_type {
                            crate::scanner::ThreatType::UnicodeInvisible => "unicode_invisible".to_string(),
                            crate::scanner::ThreatType::UnicodeBiDi => "unicode_bidi".to_string(),
                            crate::scanner::ThreatType::UnicodeHomograph => "unicode_homograph".to_string(),
                            crate::scanner::ThreatType::UnicodeControl => "unicode_control".to_string(),
                            crate::scanner::ThreatType::PromptInjection => "prompt_injection".to_string(),
                            crate::scanner::ThreatType::CommandInjection => "command_injection".to_string(),
                            crate::scanner::ThreatType::PathTraversal => "path_traversal".to_string(),
                            crate::scanner::ThreatType::SqlInjection => "sql_injection".to_string(),
                            crate::scanner::ThreatType::CrossSiteScripting => "cross_site_scripting".to_string(),
                            crate::scanner::ThreatType::LdapInjection => "ldap_injection".to_string(),
                            crate::scanner::ThreatType::XmlInjection => "xml_injection".to_string(),
                            crate::scanner::ThreatType::NoSqlInjection => "nosql_injection".to_string(),
                            crate::scanner::ThreatType::SessionIdExposure => "session_id_exposure".to_string(),
                            crate::scanner::ThreatType::ToolPoisoning => "tool_poisoning".to_string(),
                            crate::scanner::ThreatType::TokenTheft => "token_theft".to_string(),
                            crate::scanner::ThreatType::DosPotential => "dos_potential".to_string(),
                            crate::scanner::ThreatType::Custom(s) => s.to_lowercase().replace(' ', "_"),
                        },
                        "severity": format!("{:?}", t.severity).to_lowercase(),
                        "description": &t.description,
                        "location": t.location,
                    })
                }).collect::<Vec<_>>();

                let mut response_json = serde_json::json!({
                    "safe": threats.is_empty(),
                    "threats": threat_data,
                    "scan_info": {
                        "text_length": text.len(),
                        "threats_found": threats.len(),
                    }
                });

                // Add neutralization results if available
                if let Some(neutralization) = neutralization_results {
                    response_json["neutralization"] = serde_json::json!({
                        "mode": format!("{:?}", neutralization_mode),
                        "results": neutralization,
                        "neutralized": true,
                    });
                }

                if let Some(sanitized) = final_content {
                    response_json["sanitized_text"] = serde_json::Value::String(sanitized);
                }

                Ok(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string(&response_json)
                            .unwrap_or_else(|_| r#"{"error": "Failed to serialize response"}"#.to_string())
                    }]
                }))
            }

            "scan_file" => {
                let path = arguments
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ServerError::InvalidParams("Missing 'path' argument".to_string())
                    })?;

                // Security check: prevent path traversal
                if path.contains("..") || path.starts_with('/') {
                    return Err(ServerError::InvalidParams("Invalid file path".to_string()));
                }

                let content = tokio::fs::read_to_string(path)
                    .await
                    .map_err(|e| ServerError::InternalError(format!("Failed to read file: {e}")))?;

                let threats = self
                    .scanner
                    .scan_text(&content)
                    .map_err(|e| ServerError::InternalError(e.to_string()))?;

                if !threats.is_empty() {
                    self.shield.record_threats(&threats);
                }

                // Format response according to MCP protocol
                let threat_data = threats.iter().map(|t| {
                    serde_json::json!({
                        "type": match &t.threat_type {
                            crate::scanner::ThreatType::UnicodeInvisible => "unicode_invisible".to_string(),
                            crate::scanner::ThreatType::UnicodeBiDi => "unicode_bidi".to_string(),
                            crate::scanner::ThreatType::UnicodeHomograph => "unicode_homograph".to_string(),
                            crate::scanner::ThreatType::UnicodeControl => "unicode_control".to_string(),
                            crate::scanner::ThreatType::PromptInjection => "prompt_injection".to_string(),
                            crate::scanner::ThreatType::CommandInjection => "command_injection".to_string(),
                            crate::scanner::ThreatType::PathTraversal => "path_traversal".to_string(),
                            crate::scanner::ThreatType::SqlInjection => "sql_injection".to_string(),
                            crate::scanner::ThreatType::CrossSiteScripting => "cross_site_scripting".to_string(),
                            crate::scanner::ThreatType::LdapInjection => "ldap_injection".to_string(),
                            crate::scanner::ThreatType::XmlInjection => "xml_injection".to_string(),
                            crate::scanner::ThreatType::NoSqlInjection => "nosql_injection".to_string(),
                            crate::scanner::ThreatType::SessionIdExposure => "session_id_exposure".to_string(),
                            crate::scanner::ThreatType::ToolPoisoning => "tool_poisoning".to_string(),
                            crate::scanner::ThreatType::TokenTheft => "token_theft".to_string(),
                            crate::scanner::ThreatType::DosPotential => "dos_potential".to_string(),
                            crate::scanner::ThreatType::Custom(s) => s.to_lowercase().replace(' ', "_"),
                        },
                        "severity": format!("{:?}", t.severity).to_lowercase(),
                        "description": &t.description,
                        "location": t.location,
                    })
                }).collect::<Vec<_>>();

                let response_json = serde_json::json!({
                    "safe": threats.is_empty(),
                    "threats": threat_data,
                    "scan_info": {
                        "file_path": path,
                        "file_size": content.len(),
                        "threats_found": threats.len(),
                    }
                });

                Ok(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string(&response_json)
                            .unwrap_or_else(|_| r#"{"error": "Failed to serialize response"}"#.to_string())
                    }]
                }))
            }

            "scan_json" => {
                let data = arguments.get("data").ok_or_else(|| {
                    ServerError::InvalidParams("Missing 'data' argument".to_string())
                })?;

                let threats = self
                    .scanner
                    .scan_json(data)
                    .map_err(|e| ServerError::InternalError(e.to_string()))?;

                if !threats.is_empty() {
                    self.shield.record_threats(&threats);
                }

                // Format response according to MCP protocol
                let threat_data = threats.iter().map(|t| {
                    serde_json::json!({
                        "type": match &t.threat_type {
                            crate::scanner::ThreatType::UnicodeInvisible => "unicode_invisible".to_string(),
                            crate::scanner::ThreatType::UnicodeBiDi => "unicode_bidi".to_string(),
                            crate::scanner::ThreatType::UnicodeHomograph => "unicode_homograph".to_string(),
                            crate::scanner::ThreatType::UnicodeControl => "unicode_control".to_string(),
                            crate::scanner::ThreatType::PromptInjection => "prompt_injection".to_string(),
                            crate::scanner::ThreatType::CommandInjection => "command_injection".to_string(),
                            crate::scanner::ThreatType::PathTraversal => "path_traversal".to_string(),
                            crate::scanner::ThreatType::SqlInjection => "sql_injection".to_string(),
                            crate::scanner::ThreatType::CrossSiteScripting => "cross_site_scripting".to_string(),
                            crate::scanner::ThreatType::LdapInjection => "ldap_injection".to_string(),
                            crate::scanner::ThreatType::XmlInjection => "xml_injection".to_string(),
                            crate::scanner::ThreatType::NoSqlInjection => "nosql_injection".to_string(),
                            crate::scanner::ThreatType::SessionIdExposure => "session_id_exposure".to_string(),
                            crate::scanner::ThreatType::ToolPoisoning => "tool_poisoning".to_string(),
                            crate::scanner::ThreatType::TokenTheft => "token_theft".to_string(),
                            crate::scanner::ThreatType::DosPotential => "dos_potential".to_string(),
                            crate::scanner::ThreatType::Custom(s) => s.to_lowercase().replace(' ', "_"),
                        },
                        "severity": format!("{:?}", t.severity).to_lowercase(),
                        "description": &t.description,
                        "location": t.location,
                    })
                }).collect::<Vec<_>>();

                let response_json = serde_json::json!({
                    "safe": threats.is_empty(),
                    "threats": threat_data,
                    "scan_info": {
                        "data_type": "json",
                        "threats_found": threats.len(),
                    }
                });

                Ok(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string(&response_json)
                            .unwrap_or_else(|_| r#"{"error": "Failed to serialize response"}"#.to_string())
                    }]
                }))
            }

            "get_security_info" => {
                // Get current security statistics
                let shield_stats = self.shield.stats();
                let event_stats = self.event_processor.get_stats();
                let rate_limiter_stats = self.rate_limiter.get_stats();
                let permission_stats = self.component_manager.permission_manager().get_stats();

                let security_info = serde_json::json!({
                    "status": "active",
                    "enhanced_mode": self.component_manager.is_enhanced_mode(),
                    "shield": {
                        "threats_blocked": shield_stats.threats_blocked,
                        "active": shield_stats.active,
                    },
                    "event_processor": {
                        "events_processed": event_stats.events_processed,
                        "events_per_second": event_stats.events_per_second,
                        "buffer_utilization": event_stats.buffer_utilization,
                    },
                    "rate_limiter": {
                        "requests_allowed": rate_limiter_stats.requests_allowed,
                        "requests_denied": rate_limiter_stats.requests_denied,
                    },
                    "permissions": {
                        "total_checks": permission_stats.total_checks,
                        "allowed": permission_stats.allowed,
                        "denied": permission_stats.denied,
                    }
                });

                // Format response according to MCP protocol
                Ok(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&security_info)
                            .unwrap_or_else(|_| "Failed to serialize security info".to_string())
                    }]
                }))
            }

            "verify_signature" => {
                let message = arguments
                    .get("message")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ServerError::InvalidParams("Missing 'message' argument".to_string())
                    })?;

                let signature = arguments
                    .get("signature")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ServerError::InvalidParams("Missing 'signature' argument".to_string())
                    })?;

                // Parse the message JSON
                let message_value = serde_json::from_str(message)
                    .unwrap_or_else(|_| serde_json::json!({"raw": message}));

                // Create a signed message for verification
                let signed_message = SignedMessage {
                    message: message_value,
                    signature: MessageSignature {
                        algorithm: self.config.signing.algorithm.clone(),
                        signature: signature.to_string(),
                        timestamp: None,
                        key_id: None,
                    },
                };

                // Verify the signature using the signing manager
                let verification_result = match self.signing_manager.verify_message(&signed_message)
                {
                    Ok(()) => serde_json::json!({
                        "valid": true,
                        "algorithm": self.config.signing.algorithm.to_string(),
                        "message": message,
                        "error": null
                    }),
                    Err(e) => serde_json::json!({
                        "valid": false,
                        "algorithm": self.config.signing.algorithm.to_string(),
                        "message": message,
                        "error": e.to_string()
                    }),
                };

                // Format response according to MCP protocol
                Ok(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&verification_result)
                            .unwrap_or_else(|_| "Failed to serialize verification result".to_string())
                    }]
                }))
            }

            "get_shield_status" => {
                let shield_info = self.shield.get_info();

                let shield_status = serde_json::json!({
                    "active": shield_info.active,
                    "protection_level": if shield_info.threats_blocked > 100 { "high" } else if shield_info.threats_blocked > 10 { "medium" } else { "low" },
                    "threats_blocked": shield_info.threats_blocked,
                    "uptime_seconds": shield_info.uptime.as_secs(),
                    "recent_threat_rate": shield_info.recent_threat_rate,
                });

                // Format response according to MCP protocol
                Ok(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&shield_status)
                            .unwrap_or_else(|_| "Failed to serialize shield status".to_string())
                    }]
                }))
            }

            _ => Err(ServerError::InvalidParams(format!("Unknown tool: {name}"))),
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
            Resource {
                uri: "config://security".to_string(),
                name: "security-config".to_string(),
                description: Some("Security configuration and settings".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            Resource {
                uri: "threat-db://current".to_string(),
                name: "threat-database".to_string(),
                description: Some("Current threat database and patterns".to_string()),
                mime_type: Some("application/json".to_string()),
            },
        ];

        let result = ResourcesListResult { resources };
        serde_json::to_value(result).map_err(|e| ServerError::InternalError(e.to_string()))
    }

    /// Handle resources/read request
    async fn handle_resources_read(
        &self,
        params: Option<Value>,
        auth: &AuthContext,
    ) -> Result<Value, ServerError> {
        let params: ResourceReadParams = if let Some(p) = params {
            serde_json::from_value(p).map_err(|e| {
                ServerError::InvalidParams(format!("Invalid resource read params: {e}"))
            })?
        } else {
            return Err(ServerError::InvalidParams(
                "Missing resource read params".to_string(),
            ));
        };

        // Check authorization for resource
        self.auth_manager
            .authorize_resource(auth, &params.uri)
            .map_err(|_e| ServerError::Unauthorized)?;

        match params.uri.as_str() {
            "threat-patterns://default" => {
                let patterns = self.scanner.patterns.get_all_patterns();
                let content = ResourceContent {
                    uri: params.uri,
                    mime_type: Some("application/json".to_string()),
                    content: ResourceContentType::Text {
                        text: serde_json::to_string_pretty(&patterns)
                            .unwrap_or_else(|_| "{}".to_string()),
                    },
                };
                Ok(serde_json::to_value(content)
                    .map_err(|e| ServerError::InternalError(e.to_string()))?)
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
                            .unwrap_or_else(|_| "{}".to_string()),
                    },
                };
                Ok(serde_json::to_value(content)
                    .map_err(|e| ServerError::InternalError(e.to_string()))?)
            }

            _ => Err(ServerError::InvalidParams(format!(
                "Unknown resource URI: {}",
                params.uri
            ))),
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
                Err(ServerError::InvalidParams(
                    "Missing 'level' parameter".to_string(),
                ))
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
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(100) as usize;

        let recent_threats = self.shield.get_recent_threats(limit);

        Ok(serde_json::json!({
            "threats": recent_threats,
            "count": recent_threats.len(),
        }))
    }

    /// Handle `security/rate_limit_status` request
    async fn handle_rate_limit_status(
        &self,
        _params: Option<Value>,
        auth: &AuthContext,
    ) -> Result<Value, ServerError> {
        let client_id = auth.client_id.as_deref().unwrap_or("anonymous");

        // Get rate limiter stats
        let stats = self.rate_limiter.get_stats();

        Ok(serde_json::json!({
            "client_id": client_id,
            "requests_allowed": stats.requests_allowed,
            "requests_denied": stats.requests_denied,
            "active_buckets": stats.active_buckets,
            "enabled": self.config.rate_limit.enabled,
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
                Err(ServerError::InvalidParams(
                    "Missing 'id' parameter".to_string(),
                ))
            }
        } else {
            Err(ServerError::InvalidParams("Missing parameters".to_string()))
        }
    }

    /// Handle prompts/list request
    async fn handle_prompts_list(&self, _params: Option<Value>) -> Result<Value, ServerError> {
        let prompts = vec![
            Prompt {
                name: "analyze-security".to_string(),
                description: "Analyze security implications of the given input".to_string(),
                arguments: vec![PromptArgument {
                    name: "target".to_string(),
                    description: "The target to analyze (code, text, or data)".to_string(),
                    required: true,
                }],
            },
            Prompt {
                name: "threat-report".to_string(),
                description: "Generate a detailed threat report".to_string(),
                arguments: vec![PromptArgument {
                    name: "scope".to_string(),
                    description: "The scope of the report (recent, all, specific-type)".to_string(),
                    required: false,
                }],
            },
            Prompt {
                name: "security-best-practices".to_string(),
                description: "Provide security best practices for a given context".to_string(),
                arguments: vec![PromptArgument {
                    name: "context".to_string(),
                    description: "The context (web, api, database, etc.)".to_string(),
                    required: true,
                }],
            },
        ];

        let result = PromptsListResult { prompts };
        serde_json::to_value(result).map_err(|e| ServerError::InternalError(e.to_string()))
    }

    /// Handle prompts/get request
    async fn handle_prompts_get(&self, params: Option<Value>) -> Result<Value, ServerError> {
        let name = params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServerError::InvalidParams("Missing 'name' parameter".to_string()))?;

        let arguments = params
            .as_ref()
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        match name {
            "analyze-security" => {
                let target = arguments
                    .get("target")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ServerError::InvalidParams("Missing 'target' argument".to_string())
                    })?;

                let messages = vec![serde_json::json!({
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("Please analyze the security implications of the following:\n\n{}", target)
                    }
                })];

                Ok(serde_json::json!({
                    "messages": messages
                }))
            }

            "threat-report" => {
                let scope = arguments
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .unwrap_or("recent");

                let messages = vec![serde_json::json!({
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("Generate a threat report with scope: {}", scope)
                    }
                })];

                Ok(serde_json::json!({
                    "messages": messages
                }))
            }

            "security-best-practices" => {
                let context = arguments
                    .get("context")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        ServerError::InvalidParams("Missing 'context' argument".to_string())
                    })?;

                let messages = vec![serde_json::json!({
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("What are the security best practices for {}?", context)
                    }
                })];

                Ok(serde_json::json!({
                    "messages": messages
                }))
            }

            _ => Err(ServerError::InvalidParams(format!(
                "Unknown prompt: {name}"
            ))),
        }
    }

    /// Run the server with transport manager
    pub async fn run_with_transport(self: Arc<Self>) -> Result<()> {
        info!("Starting KindlyGuard with transport layer");
        self.shield.set_active(true);

        // Create message handler
        let handler = Arc::new(ServerMessageHandler {
            server: self.clone(),
        });

        // Create transport manager
        let mut transport_manager = TransportManager::new(self.config.transport.clone(), handler)?;

        // Add configured transports
        let factory = DefaultTransportFactory;
        for transport_config in &self.config.transport.transports {
            if transport_config.enabled {
                match factory.create(transport_config) {
                    Ok(transport) => {
                        info!("Adding transport: {:?}", transport_config.transport_type);
                        transport_manager.add_transport(transport)?;
                    }
                    Err(e) => {
                        warn!(
                            "Failed to create transport {:?}: {}",
                            transport_config.transport_type, e
                        );
                    }
                }
            }
        }

        // Start all transports
        transport_manager.start().await?;

        // Set up config hot-reload if config file exists
        let mut config_watcher = None;
        if let Ok(config_path) = std::env::var("KINDLY_GUARD_CONFIG") {
            let path = std::path::PathBuf::from(&config_path);
            if path.exists() {
                info!("Setting up config hot-reload for {:?}", path);

                let mut watcher =
                    crate::config::reload::ConfigWatcher::new(path, (*self.config).clone())?;

                // Add reload handler
                let reload_handler = Arc::new(ServerConfigReloadHandler {
                    server: self.clone(),
                });
                watcher.add_handler(reload_handler).await;

                watcher.start().await?;
                config_watcher = Some(watcher);
            }
        }

        // Log server startup
        if self.config.audit.enabled {
            use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};
            let audit_event = AuditEvent::new(
                AuditEventType::ServerStarted {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                AuditSeverity::Info,
            );
            let _ = self.component_manager.audit_logger().log(audit_event).await;
        }

        // Wait for shutdown signal
        tokio::signal::ctrl_c().await?;

        // Stop config watcher
        if let Some(mut watcher) = config_watcher {
            watcher.stop().await?;
        }

        info!("Shutting down transport layer");
        transport_manager.stop().await?;

        // Log server shutdown
        if self.config.audit.enabled {
            use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};
            let audit_event = AuditEvent::new(
                AuditEventType::ServerStopped {
                    reason: "Signal received".to_string(),
                },
                AuditSeverity::Info,
            );
            let _ = self.component_manager.audit_logger().log(audit_event).await;
        }

        self.shield.set_active(false);
        Ok(())
    }

    /// Run the server in HTTP mode
    pub async fn run_http(self: Arc<Self>, bind_addr: &str) -> Result<()> {
        use crate::transport::{HttpTransport, Transport};

        info!(
            "Starting KindlyGuard MCP server in HTTP mode at {}",
            bind_addr
        );
        self.shield.set_active(true);

        // Log server startup to audit
        if self.config.audit.enabled {
            use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};

            let audit_event = AuditEvent::new(
                AuditEventType::ServerStarted {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                AuditSeverity::Info,
            );

            let audit_logger = self.component_manager.audit_logger();
            if let Err(e) = audit_logger.log(audit_event).await {
                warn!("Failed to log server startup audit event: {}", e);
            }
        }

        // Create HTTP transport config
        let http_config = serde_json::json!({
            "bind_addr": bind_addr,
            "tls": false,
            "max_body_size": 10 * 1024 * 1024,
            "request_timeout_ms": 30000
        });

        // Create and start HTTP transport
        let mut transport = HttpTransport::new(http_config)?;
        transport.start().await?;

        info!("HTTP server started on {}", bind_addr);

        // Keep server running until shutdown
        tokio::signal::ctrl_c().await?;

        // Stop transport
        transport.stop().await?;

        // Log server shutdown
        if self.config.audit.enabled {
            use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};

            let audit_event = AuditEvent::new(
                AuditEventType::ServerStopped {
                    reason: "Shutdown signal received".to_string(),
                },
                AuditSeverity::Info,
            );

            let audit_logger = self.component_manager.audit_logger();
            if let Err(e) = audit_logger.log(audit_event).await {
                warn!("Failed to log server shutdown audit event: {}", e);
            }
        }

        self.shield.set_active(false);
        Ok(())
    }

    /// Run the server as HTTPS proxy
    pub async fn run_proxy(self: Arc<Self>, bind_addr: &str) -> Result<()> {
        use crate::transport::ProxyTransport;

        info!("Starting KindlyGuard as HTTPS proxy at {}", bind_addr);
        self.shield.set_active(true);

        // Log server startup to audit
        if self.config.audit.enabled {
            use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};

            let audit_event = AuditEvent::new(
                AuditEventType::ServerStarted {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                AuditSeverity::Info,
            );

            let audit_logger = self.component_manager.audit_logger();
            if let Err(e) = audit_logger.log(audit_event).await {
                warn!("Failed to log server startup audit event: {}", e);
            }
        }

        // Create proxy transport config
        let proxy_config = serde_json::json!({
            "bind_addr": bind_addr,
            "intercept_https": true,
            "ai_services": [
                "api.anthropic.com",
                "api.openai.com",
                "generativelanguage.googleapis.com",
                "api.cohere.ai",
                "api.mistral.ai"
            ]
        });

        // Create and start proxy transport
        let transport = ProxyTransport::new(proxy_config)?;
        transport.serve(self.clone()).await?;

        // Log server shutdown
        if self.config.audit.enabled {
            use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};

            let audit_event = AuditEvent::new(
                AuditEventType::ServerStopped {
                    reason: "Normal shutdown".to_string(),
                },
                AuditSeverity::Info,
            );

            let audit_logger = self.component_manager.audit_logger();
            if let Err(e) = audit_logger.log(audit_event).await {
                warn!("Failed to log server shutdown audit event: {}", e);
            }
        }

        self.shield.set_active(false);
        Ok(())
    }

    /// Run the server in stdio mode
    pub async fn run_stdio(self: Arc<Self>) -> Result<()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        info!("Starting KindlyGuard MCP server in stdio mode");
        self.shield.set_active(true);

        // Log server startup to audit
        if self.config.audit.enabled {
            use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};

            let audit_event = AuditEvent::new(
                AuditEventType::ServerStarted {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                AuditSeverity::Info,
            );

            let audit_logger = self.component_manager.audit_logger();
            if let Err(e) = audit_logger.log(audit_event).await {
                warn!("Failed to log server startup audit event: {}", e);
            }
        }

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

        // Log server shutdown to audit
        if self.config.audit.enabled {
            use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};

            let audit_event = AuditEvent::new(
                AuditEventType::ServerStopped {
                    reason: "Normal shutdown".to_string(),
                },
                AuditSeverity::Info,
            );

            let audit_logger = self.component_manager.audit_logger();
            if let Err(e) = audit_logger.log(audit_event).await {
                warn!("Failed to log server shutdown audit event: {}", e);
            }
        }

        // Flush and shutdown telemetry
        let telemetry = self.component_manager.telemetry_provider();
        if let Err(e) = telemetry.flush().await {
            error!("Failed to flush telemetry: {}", e);
        }
        if let Err(e) = telemetry.shutdown().await {
            error!("Failed to shutdown telemetry: {}", e);
        }

        Ok(())
    }

    /// Maybe sign response if signing is enabled
    async fn maybe_sign_response(&self, response: JsonRpcResponse) -> Option<String> {
        if self.config.signing.enabled {
            // Convert response to value for signing
            let response_value = serde_json::to_value(&response).ok()?;

            match self.signing_manager.sign_message(&response_value) {
                Ok(signed) => {
                    Some(serde_json::to_string(&signed).unwrap_or_else(|e| {
                        error!("Failed to serialize signed response: {}", e);
                        // Fall back to unsigned response
                        serde_json::to_string(&response).unwrap_or_else(|_| {
                            r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"},"id":null}"#.to_string()
                        })
                    }))
                }
                Err(e) => {
                    error!("Failed to sign response: {}", e);
                    // Fall back to unsigned response
                    Some(serde_json::to_string(&response).unwrap_or_else(|_| {
                        r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"},"id":null}"#.to_string()
                    }))
                }
            }
        } else {
            Some(serde_json::to_string(&response).unwrap_or_else(|e| {
                error!("Failed to serialize response: {}", e);
                r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"},"id":null}"#
                    .to_string()
            }))
        }
    }

    /// Get current threat level based on recent activity
    fn get_current_threat_level(&self) -> crate::permissions::ThreatLevel {
        // Get shield stats
        let shield_stats = self.shield.stats();
        let threats_blocked = shield_stats.threats_blocked;

        // Determine threat level based on activity
        if threats_blocked == 0 {
            crate::permissions::ThreatLevel::Safe
        } else if threats_blocked < 5 {
            crate::permissions::ThreatLevel::Low
        } else if threats_blocked < 20 {
            crate::permissions::ThreatLevel::Medium
        } else if threats_blocked < 50 {
            crate::permissions::ThreatLevel::High
        } else {
            crate::permissions::ThreatLevel::Critical
        }
    }
}

/// Message handler for transport layer
struct ServerMessageHandler {
    server: Arc<McpServer>,
}

#[async_trait]
impl MessageHandler for ServerMessageHandler {
    async fn handle_message(
        &self,
        message: TransportMessage,
        connection: &dyn TransportConnection,
    ) -> Result<Option<TransportMessage>> {
        let conn_info = connection.connection_info();
        let client_id = conn_info.client_id.as_deref().unwrap_or("unknown");

        debug!("Handling message {} from client {}", message.id, client_id);

        // Extract JSON-RPC from transport message
        let json_str = serde_json::to_string(&message.payload)?;

        // Process through server
        if let Some(response_str) = self.server.handle_message(&json_str).await {
            // Parse response
            let response_value: Value = serde_json::from_str(&response_str)?;

            // Create response message
            let response = TransportMessage {
                id: uuid::Uuid::new_v4().to_string(),
                payload: response_value,
                metadata: crate::transport::TransportMetadata {
                    client_id: conn_info.client_id.clone(),
                    timestamp: Some(chrono::Utc::now()),
                    trace_id: message.metadata.trace_id.clone(),
                    ..Default::default()
                },
            };

            Ok(Some(response))
        } else {
            Ok(None)
        }
    }

    async fn on_connect(&self, connection: &dyn TransportConnection) -> Result<()> {
        let conn_info = connection.connection_info();
        info!(
            "Client connected: {:?} via {:?}",
            conn_info.client_id, conn_info.transport_type
        );

        // Log connection event
        if self.server.config.audit.enabled {
            use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};
            let event = AuditEvent::new(
                AuditEventType::Custom {
                    event_type: "transport.connect".to_string(),
                    data: serde_json::json!({
                        "transport": format!("{:?}", conn_info.transport_type),
                        "client_id": conn_info.client_id,
                        "remote_addr": conn_info.remote_addr,
                    }),
                },
                AuditSeverity::Info,
            );
            let _ = self
                .server
                .component_manager
                .audit_logger()
                .log(event)
                .await;
        }

        Ok(())
    }

    async fn on_disconnect(&self, connection: &dyn TransportConnection) -> Result<()> {
        let conn_info = connection.connection_info();
        info!("Client disconnected: {:?}", conn_info.client_id);

        // Log disconnection event
        if self.server.config.audit.enabled {
            use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};
            let event = AuditEvent::new(
                AuditEventType::Custom {
                    event_type: "transport.disconnect".to_string(),
                    data: serde_json::json!({
                        "transport": format!("{:?}", conn_info.transport_type),
                        "client_id": conn_info.client_id,
                    }),
                },
                AuditSeverity::Info,
            );
            let _ = self
                .server
                .component_manager
                .audit_logger()
                .log(event)
                .await;
        }

        Ok(())
    }
}

/// Config reload handler for the server
struct ServerConfigReloadHandler {
    server: Arc<McpServer>,
}

#[async_trait]
impl crate::config::reload::ConfigChangeHandler for ServerConfigReloadHandler {
    async fn handle_change(&self, event: crate::config::reload::ConfigReloadEvent) -> Result<()> {
        use crate::config::reload::ConfigReloadEvent;

        match event {
            ConfigReloadEvent::Reloaded {
                new_config,
                changed_fields,
                ..
            } => {
                info!("Applying configuration changes: {:?}", changed_fields);

                // Update components that support hot-reload
                for field in &changed_fields {
                    match field.as_str() {
                        "shield.enabled" => {
                            self.server.shield.set_enabled(new_config.shield.enabled);
                            info!(
                                "Shield display {}",
                                if new_config.shield.enabled {
                                    "enabled"
                                } else {
                                    "disabled"
                                }
                            );
                        }
                        "shield.update_interval_ms" => {
                            // Shield would need a method to update interval
                            debug!("Shield update interval changed");
                        }
                        "rate_limit.enabled" => {
                            // Rate limiter would need to support enable/disable
                            info!(
                                "Rate limiting {}",
                                if new_config.rate_limit.enabled {
                                    "enabled"
                                } else {
                                    "disabled"
                                }
                            );
                        }
                        "rate_limit.default_rpm" => {
                            // Rate limiter would need to support updating limits
                            info!(
                                "Rate limit updated to {} requests/minute",
                                new_config.rate_limit.default_rpm
                            );
                        }
                        field if field.starts_with("scanner.") => {
                            // Scanner config changes would require scanner rebuild
                            warn!(
                                "Scanner configuration changed ({}), restart required",
                                field
                            );
                        }
                        _ => {
                            debug!("Configuration field {} changed", field);
                        }
                    }
                }

                // Log successful reload
                if self.server.config.audit.enabled {
                    use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};
                    let audit_event = AuditEvent::new(
                        AuditEventType::ConfigReloaded {
                            success: true,
                            error: None,
                        },
                        AuditSeverity::Info,
                    );
                    let _ = self
                        .server
                        .component_manager
                        .audit_logger()
                        .log(audit_event)
                        .await;
                }
            }
            ConfigReloadEvent::Failed { error, .. } => {
                error!("Configuration reload failed: {}", error);

                // Log failed reload
                if self.server.config.audit.enabled {
                    use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};
                    let audit_event = AuditEvent::new(
                        AuditEventType::ConfigReloaded {
                            success: false,
                            error: Some(error),
                        },
                        AuditSeverity::Error,
                    );
                    let _ = self
                        .server
                        .component_manager
                        .audit_logger()
                        .log(audit_event)
                        .await;
                }
            }
            ConfigReloadEvent::ValidationFailed { errors, .. } => {
                error!(
                    "Configuration validation failed with {} errors",
                    errors.len()
                );
            }
        }

        Ok(())
    }

    async fn validate_config(
        &self,
        config: &Config,
    ) -> Result<Vec<crate::config::reload::ValidationError>> {
        use crate::config::reload::{ValidationError, ValidationSeverity};

        let mut errors = Vec::new();

        // Validate transport config
        if config.transport.transports.is_empty() {
            errors.push(ValidationError {
                field: "transport.transports".to_string(),
                message: "At least one transport must be configured".to_string(),
                severity: ValidationSeverity::Error,
            });
        }

        // Validate security settings
        if !config.auth.enabled && !config.rate_limit.enabled {
            errors.push(ValidationError {
                field: "security".to_string(),
                message: "Both authentication and rate limiting are disabled".to_string(),
                severity: ValidationSeverity::Warning,
            });
        }

        // Use default validation for other fields
        let default_handler = crate::config::reload::DefaultConfigChangeHandler::new();
        let default_errors = default_handler.validate_config(config).await?;
        errors.extend(default_errors);

        Ok(errors)
    }

    fn get_reloadable_fields(&self) -> Vec<String> {
        vec![
            "shield.*".to_string(),
            "rate_limit.enabled".to_string(),
            "rate_limit.default_rpm".to_string(),
            "audit.enabled".to_string(),
            "telemetry.export_interval_seconds".to_string(),
        ]
    }
}
