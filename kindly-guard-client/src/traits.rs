//! Trait abstractions for MCP client components
//! Enables testing with different security scenarios

use async_trait::async_trait;
use anyhow::Result;
use serde_json::Value;
use std::time::Duration;

/// MCP transport trait for different connection types
#[async_trait]
pub trait McpTransport: Send + Sync {
    /// Send a request and receive a response
    async fn send_request(&self, request: &str) -> Result<String>;
    
    /// Check if transport is connected
    fn is_connected(&self) -> bool;
    
    /// Close the transport
    async fn close(&self) -> Result<()>;
}

/// Security testing capabilities
#[async_trait]
pub trait SecurityTester: Send + Sync {
    /// Inject a specific threat pattern
    async fn inject_threat(&self, threat_type: ThreatType, payload: &str) -> Result<TestResult>;
    
    /// Test rate limiting behavior
    async fn test_rate_limits(&self, requests_per_second: u32) -> Result<RateLimitTestResult>;
    
    /// Test authentication flows
    async fn test_auth(&self, scenario: AuthScenario) -> Result<AuthTestResult>;
    
    /// Test message signing
    async fn test_signing(&self, tamper: bool) -> Result<SigningTestResult>;
}

/// Client metrics collector
pub trait MetricsCollector: Send + Sync {
    /// Record request latency
    fn record_latency(&self, method: &str, duration: Duration);
    
    /// Record error
    fn record_error(&self, method: &str, error: &str);
    
    /// Get metrics summary
    fn get_summary(&self) -> MetricsSummary;
}

/// Types of threats to test
#[derive(Debug, Clone)]
pub enum ThreatType {
    SqlInjection,
    UnicodeAttack,
    PathTraversal,
    XssAttempt,
    CommandInjection,
    Custom(String),
}

/// Authentication test scenarios
#[derive(Debug, Clone)]
pub enum AuthScenario {
    ValidToken,
    ExpiredToken,
    InvalidToken,
    MissingToken,
    WrongResource,
    InsufficientScope,
}

/// Test result for threat injection
#[derive(Debug)]
pub struct TestResult {
    pub threat_detected: bool,
    pub response_code: i32,
    pub error_message: Option<String>,
    pub shield_color: Option<String>,
}

/// Rate limit test results
#[derive(Debug)]
pub struct RateLimitTestResult {
    pub requests_sent: u32,
    pub requests_allowed: u32,
    pub requests_blocked: u32,
    pub rate_limit_headers: Vec<(String, String)>,
}

/// Authentication test results
#[derive(Debug)]
pub struct AuthTestResult {
    pub authenticated: bool,
    pub error_code: Option<String>,
    pub required_scopes: Option<Vec<String>>,
}

/// Signing test results
#[derive(Debug)]
pub struct SigningTestResult {
    pub signature_valid: bool,
    pub tampering_detected: bool,
    pub signature_algorithm: Option<String>,
}

/// Metrics summary
#[derive(Debug, Clone)]
pub struct MetricsSummary {
    pub total_requests: u64,
    pub total_errors: u64,
    pub avg_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub errors_by_type: std::collections::HashMap<String, u64>,
}

/// Client configuration trait
pub trait ClientConfig {
    /// Get server URL or stdio indicator
    fn server_endpoint(&self) -> &str;
    
    /// Get authentication token if configured
    fn auth_token(&self) -> Option<&str>;
    
    /// Check if message signing is enabled
    fn signing_enabled(&self) -> bool;
    
    /// Get client identifier
    fn client_id(&self) -> &str;
}

/// MCP client trait combining all capabilities
#[async_trait]
pub trait McpClient: Send + Sync {
    /// Initialize the client connection
    async fn connect(&mut self) -> Result<()>;
    
    /// Send a raw JSON-RPC request
    async fn send_request(&self, method: &str, params: Option<Value>) -> Result<Value>;
    
    /// Call an MCP tool
    async fn call_tool(&self, tool_name: &str, arguments: Value) -> Result<Value>;
    
    /// List available tools
    async fn list_tools(&self) -> Result<Vec<ToolInfo>>;
    
    /// Get server capabilities
    async fn get_capabilities(&self) -> Result<ServerCapabilities>;
    
    /// Disconnect from server
    async fn disconnect(&mut self) -> Result<()>;
}

/// Tool information
#[derive(Debug, Clone)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Server capabilities
#[derive(Debug, Clone)]
pub struct ServerCapabilities {
    pub tools: bool,
    pub security_features: SecurityFeatures,
}

/// Security features advertised by server
#[derive(Debug, Clone)]
pub struct SecurityFeatures {
    pub oauth2: bool,
    pub message_signing: bool,
    pub rate_limiting: bool,
    pub threat_detection: bool,
    pub enhanced_mode: bool,
}