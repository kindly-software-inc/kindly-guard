// Copyright 2025 Kindly-Software
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
//! Core trait abstractions for security components
//! Enables clean separation between standard and enhanced implementations

use crate::scanner::Threat;
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[cfg(any(test, feature = "test-utils"))]
use mockall::{automock, predicate::*};

// Re-export event buffer types from kindly-guard-core when enhanced feature is enabled
#[cfg(feature = "enhanced")]
pub use kindly_guard_core::{EndpointStats, EventBufferTrait, Priority};

// For standard mode, define types locally
#[cfg(not(feature = "enhanced"))]
/// Priority levels for events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Normal,
    Urgent,
}

#[cfg(not(feature = "enhanced"))]
/// Statistics for an endpoint
#[derive(Debug, Clone)]
pub struct EndpointStats {
    pub success_count: u64,
    pub failure_count: u64,
    pub circuit_state: CircuitState,
    pub available_tokens: u32,
}

#[cfg(not(feature = "enhanced"))]
/// Event buffer trait for security event storage and retrieval
pub trait EventBufferTrait: Send + Sync {
    /// Enqueue an event in the buffer
    fn enqueue_event(&self, endpoint_id: u32, data: &[u8], priority: Priority) -> Result<u64>;

    /// Get statistics for an endpoint
    fn get_endpoint_stats(&self, endpoint_id: u32) -> Result<EndpointStats>;
}

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
    fn create_event_processor(
        &self,
        config: &crate::config::Config,
        storage: Arc<dyn crate::storage::StorageProvider>,
    ) -> Result<Arc<dyn SecurityEventProcessor>>;

    /// Create enhanced scanner
    fn create_scanner(&self, config: &crate::config::Config) -> Result<Arc<dyn EnhancedScanner>>;

    /// Create correlation engine
    fn create_correlation_engine(
        &self,
        config: &crate::config::Config,
        storage: Arc<dyn crate::storage::StorageProvider>,
    ) -> Result<Arc<dyn CorrelationEngine>>;

    /// Create rate limiter
    fn create_rate_limiter(
        &self,
        config: &crate::config::Config,
        storage: Arc<dyn crate::storage::StorageProvider>,
    ) -> Result<Arc<dyn RateLimiter>>;

    /// Create security scanner
    fn create_security_scanner(
        &self,
        config: &crate::config::Config,
    ) -> Result<Arc<dyn SecurityScannerTrait>>;
}

/// Circuit breaker trait for failure protection
#[async_trait]
// NOTE: automock disabled due to compatibility issues with async_trait
// #[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait CircuitBreakerTrait: Send + Sync {
    /// Execute a function with circuit protection
    async fn call<F, T, Fut>(&self, name: &str, f: F) -> Result<T, CircuitBreakerError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send;

    /// Get circuit state
    fn state(&self, name: &str) -> CircuitState;

    /// Get statistics
    fn stats(&self, name: &str) -> CircuitStats;

    /// Manual circuit control
    async fn trip(&self, name: &str, reason: &str);
    async fn reset(&self, name: &str);
}

/// Retry strategy trait for resilient operations
#[async_trait]
// NOTE: automock disabled due to compatibility issues with async_trait
// #[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait RetryStrategyTrait: Send + Sync {
    /// Execute with retry logic
    async fn execute<F, T, Fut>(&self, operation: &str, f: F) -> Result<T>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send;

    /// Analyze error for retry decision
    fn should_retry(&self, error: &anyhow::Error, context: &RetryContext) -> RetryDecision;

    /// Get retry statistics
    fn stats(&self) -> RetryStats;
}

/// Factory trait for resilience components
pub trait ResilienceFactory: Send + Sync {
    /// Create circuit breaker (returns dyn-compatible wrapper)
    fn create_circuit_breaker(
        &self,
        config: &crate::config::Config,
    ) -> Result<Arc<dyn DynCircuitBreaker>>;

    /// Create retry strategy (returns dyn-compatible wrapper)
    fn create_retry_strategy(
        &self,
        config: &crate::config::Config,
    ) -> Result<Arc<dyn DynRetryStrategy>>;

    /// Create health checker
    fn create_health_checker(
        &self,
        config: &crate::config::Config,
    ) -> Result<Arc<dyn HealthCheckTrait>>;

    /// Create recovery strategy
    fn create_recovery_strategy(
        &self,
        config: &crate::config::Config,
    ) -> Result<Arc<dyn RecoveryStrategyTrait>>;
}

/// Circuit breaker error types
#[derive(Debug, thiserror::Error, Clone)]
pub enum CircuitBreakerError {
    #[error("Circuit breaker is open")]
    CircuitOpen,

    #[error("Circuit breaker is throttled")]
    Throttled,

    #[error("Service call failed: {0}")]
    ServiceError(String),

    #[error("Timeout after {0:?}")]
    Timeout(Duration),
}

/// Circuit breaker states
#[cfg(not(feature = "enhanced"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    /// Circuit is closed - normal operation
    Closed,
    /// Circuit is throttled - degraded operation
    Throttled,
    /// Circuit is half-open - testing recovery
    HalfOpen,
    /// Circuit is open - all requests blocked
    Open,
}

// When enhanced feature is enabled, use CircuitState from kindly-guard-core
#[cfg(feature = "enhanced")]
pub use kindly_guard_core::CircuitState;

/// Circuit breaker statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitStats {
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
    pub total_requests: u64,
    pub last_failure_time: Option<u64>,
    pub tokens_available: f64,
}

/// Retry context for decision making
#[derive(Debug, Clone)]
pub struct RetryContext {
    pub attempts: u32,
    pub error_category: ErrorCategory,
    pub total_elapsed: Duration,
}

/// Error categorization
#[derive(Debug, Clone, Copy)]
pub struct ErrorCategory {
    pub is_retryable: bool,
    pub error_type: ErrorType,
}

/// Error types for retry decisions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorType {
    Network,
    Timeout,
    RateLimit,
    Authentication,
    ServerError,
    ClientError,
    Unknown,
}

/// Retry decision
#[derive(Debug, Clone)]
pub struct RetryDecision {
    pub should_retry: bool,
    pub delay: Option<Duration>,
    pub reason: String,
}

/// Retry statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryStats {
    pub total_attempts: u64,
    pub successful_retries: u64,
    pub failed_retries: u64,
    pub retry_budget_remaining: u32,
}

/// Health check trait for monitoring service health
#[async_trait]
// NOTE: automock disabled due to compatibility issues with async_trait
// #[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait HealthCheckTrait: Send + Sync {
    /// Perform health check
    async fn check(&self) -> Result<HealthStatus>;

    /// Get detailed health report
    async fn detailed_check(&self) -> Result<HealthReport>;

    /// Register dependency health check
    fn register_dependency(&self, name: String, checker: Arc<dyn HealthCheckTrait>);

    /// Get health check metadata
    fn metadata(&self) -> HealthCheckMetadata;
}

/// Recovery strategy trait for failure recovery
#[async_trait]
// NOTE: automock disabled due to compatibility issues with async_trait
// #[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait RecoveryStrategyTrait: Send + Sync {
    /// Execute recovery strategy with a JSON value result
    async fn recover(
        &self,
        context: &RecoveryContext,
        operation_name: &str,
    ) -> Result<serde_json::Value>;

    /// Check if recovery is possible
    fn can_recover(&self, error: &anyhow::Error) -> bool;

    /// Get recovery statistics
    fn stats(&self) -> RecoveryStats;

    /// Update recovery state
    async fn update_state(&self, state: RecoveryState);
}

/// Health status levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Service is healthy
    Healthy,
    /// Service is degraded but operational
    Degraded,
    /// Service is unhealthy
    Unhealthy,
}

/// Detailed health report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub checks: Vec<HealthCheckResult>,
    pub timestamp: u64,
    pub latency_ms: u64,
}

/// Individual health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub metadata: serde_json::Value,
}

/// Health check metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckMetadata {
    pub name: String,
    pub check_type: HealthCheckType,
    pub timeout: Duration,
    pub critical: bool,
}

/// Metrics provider trait for different implementations
#[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait MetricsProvider: Send + Sync {
    /// Get or create a counter metric
    fn counter(&self, name: &str, help: &str) -> Arc<dyn CounterTrait>;

    /// Get or create a gauge metric
    fn gauge(&self, name: &str, help: &str) -> Arc<dyn GaugeTrait>;

    /// Get or create a histogram metric
    fn histogram(&self, name: &str, help: &str, buckets: Vec<f64>) -> Arc<dyn HistogramTrait>;

    /// Export metrics in Prometheus format
    fn export_prometheus(&self) -> String;

    /// Export metrics as JSON
    fn export_json(&self) -> serde_json::Value;

    /// Get uptime in seconds
    fn uptime_seconds(&self) -> u64;
}

/// Counter metric trait
pub trait CounterTrait: Send + Sync {
    /// Increment the counter by 1
    fn inc(&self);

    /// Increment the counter by a specific amount
    fn inc_by(&self, amount: u64);

    /// Get current value
    fn value(&self) -> u64;
}

/// Gauge metric trait
pub trait GaugeTrait: Send + Sync {
    /// Set the gauge value
    fn set(&self, value: i64);

    /// Increment the gauge
    fn inc(&self);

    /// Decrement the gauge
    fn dec(&self);

    /// Get current value
    fn value(&self) -> i64;
}

/// Histogram metric trait
pub trait HistogramTrait: Send + Sync {
    /// Record an observation
    fn observe(&self, value: f64);

    /// Get histogram statistics
    fn stats(&self) -> HistogramStats;
}

/// Histogram statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramStats {
    pub count: u64,
    pub sum: f64,
    pub average: f64,
}

/// Types of health checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthCheckType {
    Liveness,
    Readiness,
    Startup,
    Dependency,
}

/// Recovery context
#[derive(Debug, Clone)]
pub struct RecoveryContext {
    pub failure_count: u32,
    pub last_error: String,
    pub recovery_attempts: u32,
    pub service_name: String,
}

/// Recovery state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryState {
    /// Normal operation
    Normal,
    /// Recovering from failure
    Recovering,
    /// Using fallback
    Fallback,
    /// Recovery failed
    Failed,
}

/// Recovery statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStats {
    pub recoveries_attempted: u64,
    pub recoveries_succeeded: u64,
    pub fallbacks_used: u64,
    pub current_state: RecoveryState,
}

/// Security scanner trait for threat detection
#[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait SecurityScannerTrait: Send + Sync {
    /// Scan text for threats
    fn scan_text(&self, text: &str) -> Vec<crate::scanner::Threat>;

    /// Scan JSON value for threats
    fn scan_json(&self, value: &serde_json::Value) -> Vec<crate::scanner::Threat>;

    /// Scan with depth limit
    fn scan_with_depth(&self, text: &str, max_depth: usize) -> Vec<crate::scanner::Threat>;

    /// Get scanner statistics
    fn get_stats(&self) -> ScannerStats;

    /// Reset scanner statistics
    fn reset_stats(&self);
}

/// Scanner statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerStats {
    pub texts_scanned: u64,
    pub threats_found: u64,
    pub unicode_threats: u64,
    pub injection_threats: u64,
    pub pattern_threats: u64,
    pub avg_scan_time_us: u64,
}

/// Type-erased circuit breaker for dyn compatibility
#[async_trait]
pub trait DynCircuitBreaker: Send + Sync {
    /// Execute a JSON-RPC call with circuit protection
    async fn call_json(
        &self,
        name: &str,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, CircuitBreakerError>;

    /// Get circuit state
    fn state(&self, name: &str) -> CircuitState;

    /// Get statistics
    fn stats(&self, name: &str) -> CircuitStats;

    /// Manual circuit control
    async fn trip(&self, name: &str, reason: &str);
    async fn reset(&self, name: &str);
}

/// Type-erased retry strategy for dyn compatibility
#[async_trait]
pub trait DynRetryStrategy: Send + Sync {
    /// Execute a JSON-RPC operation with retry logic
    async fn execute_json(
        &self,
        operation: &str,
        request: serde_json::Value,
    ) -> Result<serde_json::Value>;

    /// Analyze error for retry decision
    fn should_retry(&self, error: &anyhow::Error, context: &RetryContext) -> RetryDecision;

    /// Get retry statistics
    fn stats(&self) -> RetryStats;
}

/// Wrapper to adapt `CircuitBreakerTrait` to `DynCircuitBreaker`
pub struct CircuitBreakerWrapper<T: CircuitBreakerTrait> {
    inner: T,
}

impl<T: CircuitBreakerTrait> CircuitBreakerWrapper<T> {
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<T: CircuitBreakerTrait> DynCircuitBreaker for CircuitBreakerWrapper<T> {
    async fn call_json(
        &self,
        name: &str,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, CircuitBreakerError> {
        self.inner
            .call(name, || async {
                // Simulate JSON-RPC processing
                Ok(serde_json::json!({
                    "result": "processed",
                    "request": request
                }))
            })
            .await
    }

    fn state(&self, name: &str) -> CircuitState {
        self.inner.state(name)
    }

    fn stats(&self, name: &str) -> CircuitStats {
        self.inner.stats(name)
    }

    async fn trip(&self, name: &str, reason: &str) {
        self.inner.trip(name, reason).await;
    }

    async fn reset(&self, name: &str) {
        self.inner.reset(name).await;
    }
}

/// Wrapper to adapt `RetryStrategyTrait` to `DynRetryStrategy`
pub struct RetryStrategyWrapper<T: RetryStrategyTrait> {
    inner: T,
}

impl<T: RetryStrategyTrait> RetryStrategyWrapper<T> {
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<T: RetryStrategyTrait> DynRetryStrategy for RetryStrategyWrapper<T> {
    async fn execute_json(
        &self,
        operation: &str,
        request: serde_json::Value,
    ) -> Result<serde_json::Value> {
        self.inner
            .execute(operation, || async {
                // Simulate JSON-RPC processing
                Ok(serde_json::json!({
                    "result": "processed",
                    "request": request
                }))
            })
            .await
    }

    fn should_retry(&self, error: &anyhow::Error, context: &RetryContext) -> RetryDecision {
        self.inner.should_retry(error, context)
    }

    fn stats(&self) -> RetryStats {
        self.inner.stats()
    }
}
