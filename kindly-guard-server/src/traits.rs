//! Core trait abstractions for security components
//! Enables clean separation between standard and enhanced implementations

use async_trait::async_trait;
use std::sync::Arc;
use anyhow::Result;
use serde::{Serialize, Deserialize};
use crate::scanner::Threat;

#[cfg(any(test, feature = "test-utils"))]
use mockall::{automock, predicate::*};

/// Security event processor trait for handling and correlating events
#[async_trait]
#[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait SecurityEventProcessor: Send + Sync {
    /// Process a security event
    async fn process_event(&self, event: SecurityEvent) -> Result<EventHandle>;
    
    /// Get processor statistics
    fn get_stats(&self) -> ProcessorStats;
    
    /// Check if an endpoint is under monitoring
    fn is_monitored(&self, endpoint: &str) -> bool;
    
    /// Get correlation insights for a client
    async fn get_insights(&self, client_id: &str) -> Result<SecurityInsights>;
    
    /// Perform cleanup of old events
    async fn cleanup(&self) -> Result<()>;
}

/// Enhanced scanner trait for advanced threat detection
#[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait EnhancedScanner: Send + Sync {
    /// Scan with enhanced capabilities
    fn enhanced_scan(&self, data: &[u8]) -> Result<Vec<Threat>>;
    
    /// Get scanner performance metrics
    fn get_metrics(&self) -> ScannerMetrics;
    
    /// Preload patterns for optimization
    fn preload_patterns(&self, patterns: &[String]) -> Result<()>;
}

/// Correlation engine trait for pattern detection
#[async_trait]
#[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait CorrelationEngine: Send + Sync {
    /// Correlate events to detect patterns
    async fn correlate(&self, events: &[SecurityEvent]) -> Result<Vec<ThreatPattern>>;
    
    /// Update correlation rules
    async fn update_rules(&self, rules: CorrelationRules) -> Result<()>;
    
    /// Get correlation statistics
    fn get_correlation_stats(&self) -> CorrelationStats;
}

/// Rate limiter trait for flexible implementations
#[async_trait]
#[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait RateLimiter: Send + Sync {
    /// Check if request is allowed
    async fn check_rate_limit(&self, key: &RateLimitKey) -> Result<RateLimitDecision>;
    
    /// Record request for rate limiting
    async fn record_request(&self, key: &RateLimitKey) -> Result<()>;
    
    /// Apply penalty for threats
    async fn apply_penalty(&self, client_id: &str, factor: f32) -> Result<()>;
    
    /// Get rate limit stats
    fn get_stats(&self) -> RateLimiterStats;
}

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: String,
    pub client_id: String,
    pub timestamp: u64,
    pub metadata: serde_json::Value,
}

/// Event processing handle
#[derive(Debug, Clone)]
pub struct EventHandle {
    pub event_id: u64,
    pub processed: bool,
}

/// Processor statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessorStats {
    pub events_processed: u64,
    pub events_per_second: f64,
    pub buffer_utilization: f64,
    pub correlation_hits: u64,
}

/// Security insights from correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityInsights {
    pub risk_score: f32,
    pub detected_patterns: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Scanner performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerMetrics {
    pub scans_performed: u64,
    pub threats_detected: u64,
    pub avg_scan_time_us: u64,
    pub pattern_cache_hits: u64,
}

/// Detected threat pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatPattern {
    pub pattern_type: String,
    pub confidence: f32,
    pub events: Vec<u64>,
    pub description: String,
}

/// Correlation rules configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRules {
    pub time_window: std::time::Duration,
    pub min_events: usize,
    pub patterns: Vec<PatternRule>,
}

/// Individual pattern rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRule {
    pub name: String,
    pub event_types: Vec<String>,
    pub threshold: u32,
}

/// Correlation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationStats {
    pub patterns_detected: u64,
    pub false_positives: u64,
    pub avg_correlation_time_ms: u64,
}

/// Rate limit key
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct RateLimitKey {
    pub client_id: String,
    pub method: Option<String>,
}

/// Rate limit decision
#[derive(Debug, Clone)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub tokens_remaining: f64,
    pub reset_after: std::time::Duration,
}

/// Rate limiter statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterStats {
    pub requests_allowed: u64,
    pub requests_denied: u64,
    pub active_buckets: usize,
}

/// Factory trait for creating security components
pub trait SecurityComponentFactory: Send + Sync {
    /// Create event processor
    fn create_event_processor(&self, config: &crate::config::Config, storage: Arc<dyn crate::storage::StorageProvider>) -> Result<Arc<dyn SecurityEventProcessor>>;
    
    /// Create enhanced scanner
    fn create_scanner(&self, config: &crate::config::Config) -> Result<Arc<dyn EnhancedScanner>>;
    
    /// Create correlation engine
    fn create_correlation_engine(&self, config: &crate::config::Config, storage: Arc<dyn crate::storage::StorageProvider>) -> Result<Arc<dyn CorrelationEngine>>;
    
    /// Create rate limiter
    fn create_rate_limiter(&self, config: &crate::config::Config, storage: Arc<dyn crate::storage::StorageProvider>) -> Result<Arc<dyn RateLimiter>>;
}

