//! Audit logging system for compliance and security monitoring
//! 
//! This module provides a trait-based audit architecture that allows
//! different audit backends while maintaining compliance requirements.

use std::sync::Arc;
use std::collections::HashMap;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

pub mod memory;
pub mod file;
#[cfg(feature = "enhanced")]
pub mod enhanced;

// Re-exports
pub use memory::InMemoryAuditLogger;
pub use file::FileAuditLogger;

/// Audit event identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditEventId(pub String);

impl AuditEventId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

/// Audit event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Audit event types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Authentication events
    AuthSuccess { user_id: String },
    AuthFailure { user_id: Option<String>, reason: String },
    
    /// Authorization events
    AccessGranted { user_id: String, resource: String },
    AccessDenied { user_id: String, resource: String, reason: String },
    
    /// Security events
    ThreatDetected { client_id: String, threat_count: u32 },
    ThreatBlocked { client_id: String, threat_type: String },
    
    /// Rate limiting events
    RateLimitTriggered { client_id: String, limit_type: String },
    
    /// Configuration events
    ConfigChanged { changed_by: String, changes: HashMap<String, String> },
    ConfigReloaded { success: bool, error: Option<String> },
    
    /// Plugin events
    PluginLoaded { plugin_id: String, plugin_name: String },
    PluginUnloaded { plugin_id: String, reason: String },
    PluginError { plugin_id: String, error: String },
    
    /// System events
    ServerStarted { version: String },
    ServerStopped { reason: String },
    SystemError { component: String, error: String },
    
    /// Custom events
    Custom { event_type: String, data: serde_json::Value },
}

/// Audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub id: AuditEventId,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: AuditEventType,
    /// Event severity
    pub severity: AuditSeverity,
    /// Client/session ID if applicable
    pub client_id: Option<String>,
    /// IP address if applicable
    pub ip_address: Option<String>,
    /// User agent if applicable
    pub user_agent: Option<String>,
    /// Additional context
    pub context: HashMap<String, serde_json::Value>,
    /// Event tags for filtering
    pub tags: Vec<String>,
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(event_type: AuditEventType, severity: AuditSeverity) -> Self {
        Self {
            id: AuditEventId::new(),
            timestamp: Utc::now(),
            event_type,
            severity,
            client_id: None,
            ip_address: None,
            user_agent: None,
            context: HashMap::new(),
            tags: Vec::new(),
        }
    }
    
    /// Set client ID
    pub fn with_client_id(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }
    
    /// Set IP address
    pub fn with_ip_address(mut self, ip: String) -> Self {
        self.ip_address = Some(ip);
        self
    }
    
    /// Add context data
    pub fn with_context(mut self, key: String, value: serde_json::Value) -> Self {
        self.context.insert(key, value);
        self
    }
    
    /// Add tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// Audit query filter
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Filter by severity (minimum level)
    pub min_severity: Option<AuditSeverity>,
    /// Filter by event type pattern
    pub event_type_pattern: Option<String>,
    /// Filter by client ID
    pub client_id: Option<String>,
    /// Filter by IP address
    pub ip_address: Option<String>,
    /// Filter by time range (start)
    pub start_time: Option<DateTime<Utc>>,
    /// Filter by time range (end)
    pub end_time: Option<DateTime<Utc>>,
    /// Filter by tags (any match)
    pub tags: Vec<String>,
    /// Maximum results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Audit statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditStats {
    /// Total events logged
    pub total_events: u64,
    /// Events by severity
    pub events_by_severity: HashMap<String, u64>,
    /// Events by type
    pub events_by_type: HashMap<String, u64>,
    /// Storage size in bytes
    pub storage_size_bytes: u64,
    /// Oldest event timestamp
    pub oldest_event: Option<DateTime<Utc>>,
    /// Newest event timestamp
    pub newest_event: Option<DateTime<Utc>>,
}

/// Audit logger trait
#[async_trait]
pub trait AuditLogger: Send + Sync {
    /// Log an audit event
    async fn log(&self, event: AuditEvent) -> Result<AuditEventId>;
    
    /// Log multiple events in batch
    async fn log_batch(&self, events: Vec<AuditEvent>) -> Result<Vec<AuditEventId>>;
    
    /// Query audit events
    async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>>;
    
    /// Get a specific event by ID
    async fn get_event(&self, id: &AuditEventId) -> Result<Option<AuditEvent>>;
    
    /// Delete old events (for compliance with retention policies)
    async fn delete_before(&self, timestamp: DateTime<Utc>) -> Result<u64>;
    
    /// Get audit statistics
    async fn get_stats(&self) -> Result<AuditStats>;
    
    /// Export events to a specific format
    async fn export(&self, filter: AuditFilter, format: ExportFormat) -> Result<Vec<u8>>;
    
    /// Verify audit log integrity (for compliance)
    async fn verify_integrity(&self) -> Result<IntegrityReport>;
}

/// Export formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
    Csv,
    Syslog,
    Cef, // Common Event Format
}

/// Integrity verification report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    /// Is integrity intact
    pub intact: bool,
    /// Total events checked
    pub events_checked: u64,
    /// Any issues found
    pub issues: Vec<String>,
    /// Verification timestamp
    pub verified_at: DateTime<Utc>,
}

/// Audit logger configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,
    /// Audit backend type
    pub backend: AuditBackend,
    /// Retention period in days
    pub retention_days: u32,
    /// Maximum events to keep
    pub max_events: Option<u64>,
    /// Buffer size for batch operations
    pub buffer_size: usize,
    /// File path (for file backend)
    pub file_path: Option<String>,
    /// Rotation settings (for file backend)
    pub rotation: Option<RotationConfig>,
    /// Enable compression
    pub compress: bool,
    /// Enable encryption
    pub encrypt: bool,
    /// Custom backend configuration
    pub custom_config: HashMap<String, serde_json::Value>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: AuditBackend::Memory,
            retention_days: 90,
            max_events: Some(1_000_000),
            buffer_size: 1000,
            file_path: Some("./audit.log".to_string()),
            rotation: Some(RotationConfig::default()),
            compress: false,
            encrypt: false,
            custom_config: HashMap::new(),
        }
    }
}

/// Audit backend types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditBackend {
    Memory,
    File,
    #[cfg(feature = "enhanced")]
    Enhanced,
    Custom(String),
}

/// Log rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    /// Rotation strategy
    pub strategy: RotationStrategy,
    /// Maximum file size (for size-based rotation)
    pub max_size_mb: u64,
    /// Maximum file age (for time-based rotation)
    pub max_age_hours: u64,
    /// Maximum number of backups to keep
    pub max_backups: u32,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            strategy: RotationStrategy::Size,
            max_size_mb: 100,
            max_age_hours: 24,
            max_backups: 10,
        }
    }
}

/// Rotation strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationStrategy {
    Size,
    Time,
    Both,
}

/// Factory for creating audit loggers
pub trait AuditLoggerFactory: Send + Sync {
    /// Create an audit logger
    fn create(&self, config: &AuditConfig) -> Result<Arc<dyn AuditLogger>>;
}

/// Default audit logger factory
pub struct DefaultAuditLoggerFactory;

impl AuditLoggerFactory for DefaultAuditLoggerFactory {
    fn create(&self, config: &AuditConfig) -> Result<Arc<dyn AuditLogger>> {
        if !config.enabled {
            // Return a no-op logger when disabled
            return Ok(Arc::new(NoOpAuditLogger));
        }
        
        match &config.backend {
            AuditBackend::Memory => {
                Ok(Arc::new(InMemoryAuditLogger::new(config.clone())?))
            }
            AuditBackend::File => {
                Ok(Arc::new(FileAuditLogger::new(config.clone())?))
            }
            #[cfg(feature = "enhanced")]
            AuditBackend::Enhanced => {
                Ok(Arc::new(enhanced::EnhancedAuditLogger::new(config.clone())?))
            }
            AuditBackend::Custom(name) => {
                Err(anyhow::anyhow!("Custom audit backend '{}' not implemented", name))
            }
        }
    }
}

/// No-op audit logger for when auditing is disabled
struct NoOpAuditLogger;

#[async_trait]
impl AuditLogger for NoOpAuditLogger {
    async fn log(&self, _event: AuditEvent) -> Result<AuditEventId> {
        Ok(AuditEventId::new())
    }
    
    async fn log_batch(&self, events: Vec<AuditEvent>) -> Result<Vec<AuditEventId>> {
        Ok(events.into_iter().map(|_| AuditEventId::new()).collect())
    }
    
    async fn query(&self, _filter: AuditFilter) -> Result<Vec<AuditEvent>> {
        Ok(Vec::new())
    }
    
    async fn get_event(&self, _id: &AuditEventId) -> Result<Option<AuditEvent>> {
        Ok(None)
    }
    
    async fn delete_before(&self, _timestamp: DateTime<Utc>) -> Result<u64> {
        Ok(0)
    }
    
    async fn get_stats(&self) -> Result<AuditStats> {
        Ok(AuditStats::default())
    }
    
    async fn export(&self, _filter: AuditFilter, _format: ExportFormat) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
    
    async fn verify_integrity(&self) -> Result<IntegrityReport> {
        Ok(IntegrityReport {
            intact: true,
            events_checked: 0,
            issues: Vec::new(),
            verified_at: Utc::now(),
        })
    }
}

/// Helper for creating audit events
pub struct AuditEventBuilder {
    event: AuditEvent,
}

impl AuditEventBuilder {
    pub fn new(event_type: AuditEventType, severity: AuditSeverity) -> Self {
        Self {
            event: AuditEvent::new(event_type, severity),
        }
    }
    
    pub fn client_id(mut self, id: String) -> Self {
        self.event.client_id = Some(id);
        self
    }
    
    pub fn ip_address(mut self, ip: String) -> Self {
        self.event.ip_address = Some(ip);
        self
    }
    
    pub fn user_agent(mut self, ua: String) -> Self {
        self.event.user_agent = Some(ua);
        self
    }
    
    pub fn context(mut self, key: String, value: serde_json::Value) -> Self {
        self.event.context.insert(key, value);
        self
    }
    
    pub fn tag(mut self, tag: String) -> Self {
        self.event.tags.push(tag);
        self
    }
    
    pub fn build(self) -> AuditEvent {
        self.event
    }
}