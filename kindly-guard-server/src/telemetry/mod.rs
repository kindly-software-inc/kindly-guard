//! Telemetry module for KindlyGuard
//! Provides observability through OpenTelemetry with trait-based architecture

use std::sync::Arc;
use std::time::Duration;
use async_trait::async_trait;
use anyhow::Result;
use serde::{Serialize, Deserialize};

/// Telemetry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Enable telemetry collection
    pub enabled: bool,
    
    /// Service name for telemetry
    pub service_name: String,
    
    /// Service version
    pub service_version: String,
    
    /// Export endpoint (e.g., OTLP endpoint)
    pub export_endpoint: Option<String>,
    
    /// Export interval
    pub export_interval_seconds: u64,
    
    /// Enable tracing
    pub tracing_enabled: bool,
    
    /// Enable metrics
    pub metrics_enabled: bool,
    
    /// Sampling rate (0.0 to 1.0)
    pub sampling_rate: f64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            service_name: "kindly-guard".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            export_endpoint: None,
            export_interval_seconds: 60,
            tracing_enabled: true,
            metrics_enabled: true,
            sampling_rate: 0.1,
        }
    }
}

/// Telemetry span for tracing
#[derive(Debug, Clone)]
pub struct TelemetrySpan {
    pub name: String,
    pub start_time: std::time::Instant,
    pub attributes: Vec<(String, String)>,
}

/// Metric types
#[derive(Debug, Clone)]
pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram(f64),
}

/// Telemetry metric
#[derive(Debug, Clone)]
pub struct TelemetryMetric {
    pub name: String,
    pub value: MetricValue,
    pub labels: Vec<(String, String)>,
}

/// Telemetry provider trait - implementations can use OpenTelemetry or custom solutions
#[async_trait]
pub trait TelemetryProvider: Send + Sync {
    /// Start a new span
    fn start_span(&self, name: &str) -> TelemetrySpan;
    
    /// End a span
    fn end_span(&self, span: TelemetrySpan);
    
    /// Record a metric
    fn record_metric(&self, metric: TelemetryMetric);
    
    /// Add event to current span
    fn add_event(&self, name: &str, attributes: Vec<(&str, &str)>);
    
    /// Set span status
    fn set_status(&self, span: &TelemetrySpan, is_error: bool, message: Option<&str>);
    
    /// Flush telemetry data
    async fn flush(&self) -> Result<()>;
    
    /// Shutdown telemetry
    async fn shutdown(&self) -> Result<()>;
}

/// Context for telemetry operations
#[derive(Debug, Clone)]
pub struct TelemetryContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub baggage: Vec<(String, String)>,
}

impl TelemetryContext {
    /// Create a new root context
    pub fn new() -> Self {
        Self {
            trace_id: uuid::Uuid::new_v4().to_string(),
            span_id: uuid::Uuid::new_v4().to_string(),
            parent_span_id: None,
            baggage: vec![],
        }
    }
    
    /// Create a child context
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            span_id: uuid::Uuid::new_v4().to_string(),
            parent_span_id: Some(self.span_id.clone()),
            baggage: self.baggage.clone(),
        }
    }
}

/// Factory for creating telemetry providers
pub trait TelemetryProviderFactory: Send + Sync {
    /// Create a telemetry provider based on configuration
    fn create(&self, config: &TelemetryConfig) -> Result<Arc<dyn TelemetryProvider>>;
}

/// Security-aware telemetry helper
pub struct SecureTelemetry {
    provider: Arc<dyn TelemetryProvider>,
}

impl SecureTelemetry {
    pub fn new(provider: Arc<dyn TelemetryProvider>) -> Self {
        Self { provider }
    }
    
    /// Record a security event with sanitized data
    pub fn record_security_event(&self, event_type: &str, client_id: &str, threat_level: &str) {
        // Sanitize client_id to prevent information leakage
        let sanitized_client = if client_id.len() > 8 {
            format!("{}...", &client_id[..8])
        } else {
            "anonymous".to_string()
        };
        
        self.provider.add_event("security.event", vec![
            ("event.type", event_type),
            ("client.id", &sanitized_client),
            ("threat.level", threat_level),
        ]);
    }
    
    /// Record performance metrics
    pub fn record_performance(&self, operation: &str, duration_ms: f64) {
        self.provider.record_metric(TelemetryMetric {
            name: format!("kindly_guard.{}.duration", operation),
            value: MetricValue::Histogram(duration_ms),
            labels: vec![
                ("operation".to_string(), operation.to_string()),
            ],
        });
    }
    
    /// Record rate limit metrics
    pub fn record_rate_limit(&self, client_id: &str, allowed: bool) {
        let sanitized_client = if client_id.len() > 8 {
            format!("{}...", &client_id[..8])
        } else {
            "anonymous".to_string()
        };
        
        self.provider.record_metric(TelemetryMetric {
            name: "kindly_guard.rate_limit.decisions".to_string(),
            value: MetricValue::Counter(1),
            labels: vec![
                ("client.id".to_string(), sanitized_client),
                ("decision".to_string(), if allowed { "allow" } else { "deny" }.to_string()),
            ],
        });
    }
}

// Re-export implementations
pub mod standard;
#[cfg(feature = "enhanced")]
pub mod enhanced;
pub mod metrics;

pub use standard::StandardTelemetryProvider;
pub use metrics::{MetricsCollector, CommandMetrics, MetricsSnapshot};