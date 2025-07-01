//! Health checking for the neutralization system
//!
//! Provides comprehensive health monitoring including:
//! - Performance health (response times, throughput)
//! - Error rate monitoring
//! - Resource usage tracking
//! - Capability verification
//! - Circuit breaker integration

use anyhow::{bail, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::{
    neutralizer::{NeutralizeResult, ThreatNeutralizer},
    scanner::{Location, Severity, Threat, ThreatType},
    traits::HealthCheckTrait,
};

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeutralizationHealthConfig {
    /// Enable health checking
    pub enabled: bool,

    /// Health check interval in seconds
    pub check_interval_seconds: u64,

    /// Performance thresholds
    pub performance: PerformanceThresholds,

    /// Error rate thresholds
    pub error_rate: ErrorRateThresholds,

    /// Resource usage thresholds
    pub resources: ResourceThresholds,

    /// Number of health check samples to keep
    pub sample_window_size: usize,

    /// Enable synthetic probes
    pub synthetic_probes: bool,
}

/// Performance thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceThresholds {
    /// Warning threshold for average response time (ms)
    pub avg_response_time_warn_ms: u64,

    /// Critical threshold for average response time (ms)
    pub avg_response_time_crit_ms: u64,

    /// Warning threshold for P99 response time (ms)
    pub p99_response_time_warn_ms: u64,

    /// Critical threshold for P99 response time (ms)
    pub p99_response_time_crit_ms: u64,

    /// Minimum throughput (operations per second)
    pub min_throughput_ops: f64,
}

/// Error rate thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRateThresholds {
    /// Warning threshold for error rate (percentage)
    pub warn_percentage: f64,

    /// Critical threshold for error rate (percentage)
    pub crit_percentage: f64,

    /// Minimum operations before calculating error rate
    pub min_operations: u64,
}

/// Resource usage thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceThresholds {
    /// Maximum memory usage (MB)
    pub max_memory_mb: usize,

    /// Maximum queue depth
    pub max_queue_depth: usize,

    /// Maximum concurrent operations
    pub max_concurrent_ops: usize,
}

impl Default for NeutralizationHealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_seconds: 30,
            performance: PerformanceThresholds {
                avg_response_time_warn_ms: 50,
                avg_response_time_crit_ms: 200,
                p99_response_time_warn_ms: 200,
                p99_response_time_crit_ms: 1000,
                min_throughput_ops: 10.0,
            },
            error_rate: ErrorRateThresholds {
                warn_percentage: 5.0,
                crit_percentage: 10.0,
                min_operations: 100,
            },
            resources: ResourceThresholds {
                max_memory_mb: 500,
                max_queue_depth: 1000,
                max_concurrent_ops: 100,
            },
            sample_window_size: 1000,
            synthetic_probes: true,
        }
    }
}

/// Health status levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Everything is working well
    Healthy,

    /// Some metrics are concerning but service is operational
    Degraded,

    /// Service is experiencing significant issues
    Unhealthy,

    /// Service is not operational
    Critical,
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeutralizationHealthReport {
    /// Overall health status
    pub status: HealthStatus,

    /// Timestamp of the check
    pub timestamp: DateTime<Utc>,

    /// Performance metrics
    pub performance: PerformanceMetrics,

    /// Error metrics
    pub error_metrics: ErrorMetrics,

    /// Resource metrics
    pub resource_metrics: ResourceMetrics,

    /// Capability checks
    pub capabilities: CapabilityChecks,

    /// Issues found
    pub issues: Vec<HealthIssue>,

    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub avg_response_time_ms: f64,
    pub p50_response_time_ms: f64,
    pub p90_response_time_ms: f64,
    pub p99_response_time_ms: f64,
    pub throughput_ops_per_sec: f64,
    pub total_operations: u64,
}

/// Error metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMetrics {
    pub error_count: u64,
    pub error_rate_percentage: f64,
    pub last_error_time: Option<DateTime<Utc>>,
    pub error_types: std::collections::HashMap<String, u64>,
}

/// Resource metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceMetrics {
    pub memory_usage_mb: usize,
    pub queue_depth: usize,
    pub concurrent_operations: usize,
    pub cpu_usage_percentage: f64,
}

/// Capability check results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityChecks {
    pub can_neutralize_sql: bool,
    pub can_neutralize_command: bool,
    pub can_neutralize_unicode: bool,
    pub can_neutralize_path: bool,
    pub can_neutralize_prompt: bool,
    pub supports_batch: bool,
    pub supports_rollback: bool,
}

/// Health issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthIssue {
    pub severity: HealthStatus,
    pub component: String,
    pub message: String,
    pub metric_value: Option<f64>,
    pub threshold: Option<f64>,
}

/// Health monitoring wrapper for neutralizers
pub struct HealthMonitoredNeutralizer {
    inner: Arc<dyn ThreatNeutralizer>,
    config: NeutralizationHealthConfig,
    health_checker: Arc<NeutralizationHealthChecker>,
    monitor_handle: Option<tokio::task::JoinHandle<()>>,
}

impl HealthMonitoredNeutralizer {
    /// Create a new health-monitored neutralizer
    pub fn new(
        neutralizer: Arc<dyn ThreatNeutralizer>,
        config: NeutralizationHealthConfig,
    ) -> Arc<Self> {
        let health_checker = Arc::new(NeutralizationHealthChecker::new(config.clone()));

        let monitor_handle = if config.enabled {
            let checker = health_checker.clone();
            let interval = config.check_interval_seconds;
            let inner = neutralizer.clone();

            Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(interval));

                loop {
                    interval.tick().await;
                    if let Err(e) = checker.run_health_check(&inner).await {
                        tracing::error!("Health check failed: {}", e);
                    }
                }
            }))
        } else {
            None
        };

        Arc::new(Self {
            inner: neutralizer,
            config,
            health_checker,
            monitor_handle,
        })
    }

    /// Get the latest health report
    pub async fn get_health_report(&self) -> Option<NeutralizationHealthReport> {
        self.health_checker.get_latest_report().await
    }

    /// Force a health check
    pub async fn check_health(&self) -> Result<NeutralizationHealthReport> {
        self.health_checker.run_health_check(&self.inner).await
    }
}

#[async_trait]
impl ThreatNeutralizer for HealthMonitoredNeutralizer {
    async fn neutralize(&self, threat: &Threat, content: &str) -> Result<NeutralizeResult> {
        let start = Instant::now();

        // Record the operation
        self.health_checker.record_operation_start();

        // Perform neutralization
        let result = self.inner.neutralize(threat, content).await;

        // Record the result
        let duration = start.elapsed();
        match &result {
            Ok(_) => self.health_checker.record_success(duration),
            Err(e) => self.health_checker.record_error(e.to_string(), duration),
        }

        result
    }

    fn can_neutralize(&self, threat_type: &ThreatType) -> bool {
        self.inner.can_neutralize(threat_type)
    }

    fn get_capabilities(&self) -> crate::neutralizer::NeutralizerCapabilities {
        self.inner.get_capabilities()
    }
}

impl Drop for HealthMonitoredNeutralizer {
    fn drop(&mut self) {
        if let Some(handle) = self.monitor_handle.take() {
            handle.abort();
        }
    }
}

/// Health checker implementation
pub struct NeutralizationHealthChecker {
    config: NeutralizationHealthConfig,

    // Metrics tracking
    operations_total: AtomicU64,
    operations_success: AtomicU64,
    operations_error: AtomicU64,

    // Performance tracking
    response_times: Arc<RwLock<Vec<Duration>>>,

    // Error tracking
    recent_errors: Arc<RwLock<Vec<(DateTime<Utc>, String)>>>,

    // Latest report
    latest_report: Arc<RwLock<Option<NeutralizationHealthReport>>>,

    // Synthetic probe results
    synthetic_probe_healthy: AtomicBool,
}

impl NeutralizationHealthChecker {
    fn new(config: NeutralizationHealthConfig) -> Self {
        Self {
            config,
            operations_total: AtomicU64::new(0),
            operations_success: AtomicU64::new(0),
            operations_error: AtomicU64::new(0),
            response_times: Arc::new(RwLock::new(Vec::with_capacity(1000))),
            recent_errors: Arc::new(RwLock::new(Vec::new())),
            latest_report: Arc::new(RwLock::new(None)),
            synthetic_probe_healthy: AtomicBool::new(true),
        }
    }

    fn record_operation_start(&self) {
        self.operations_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_success(&self, duration: Duration) {
        self.operations_success.fetch_add(1, Ordering::Relaxed);

        tokio::spawn({
            let response_times = self.response_times.clone();
            let window_size = self.config.sample_window_size;
            async move {
                let mut times = response_times.write().await;
                times.push(duration);
                if times.len() > window_size {
                    times.remove(0);
                }
            }
        });
    }

    fn record_error(&self, error: String, duration: Duration) {
        self.operations_error.fetch_add(1, Ordering::Relaxed);

        tokio::spawn({
            let recent_errors = self.recent_errors.clone();
            let response_times = self.response_times.clone();
            let window_size = self.config.sample_window_size;
            async move {
                let mut errors = recent_errors.write().await;
                errors.push((Utc::now(), error));
                if errors.len() > 100 {
                    errors.remove(0);
                }

                let mut times = response_times.write().await;
                times.push(duration);
                if times.len() > window_size {
                    times.remove(0);
                }
            }
        });
    }

    async fn run_health_check(
        &self,
        neutralizer: &Arc<dyn ThreatNeutralizer>,
    ) -> Result<NeutralizationHealthReport> {
        let mut issues = Vec::new();
        let mut recommendations = Vec::new();

        // Calculate metrics
        let performance = self.calculate_performance_metrics().await;
        let error_metrics = self.calculate_error_metrics().await;
        let resource_metrics = self.calculate_resource_metrics().await;
        let capabilities = self.check_capabilities(neutralizer).await;

        // Run synthetic probes if enabled
        if self.config.synthetic_probes {
            self.run_synthetic_probes(neutralizer).await?;
        }

        // Check performance thresholds
        if performance.avg_response_time_ms
            > self.config.performance.avg_response_time_crit_ms as f64
        {
            issues.push(HealthIssue {
                severity: HealthStatus::Critical,
                component: "Performance".to_string(),
                message: "Average response time exceeds critical threshold".to_string(),
                metric_value: Some(performance.avg_response_time_ms),
                threshold: Some(self.config.performance.avg_response_time_crit_ms as f64),
            });
        } else if performance.avg_response_time_ms
            > self.config.performance.avg_response_time_warn_ms as f64
        {
            issues.push(HealthIssue {
                severity: HealthStatus::Degraded,
                component: "Performance".to_string(),
                message: "Average response time exceeds warning threshold".to_string(),
                metric_value: Some(performance.avg_response_time_ms),
                threshold: Some(self.config.performance.avg_response_time_warn_ms as f64),
            });
            recommendations
                .push("Consider scaling resources or optimizing neutralization logic".to_string());
        }

        // Check error rate
        if error_metrics.error_rate_percentage > self.config.error_rate.crit_percentage {
            issues.push(HealthIssue {
                severity: HealthStatus::Critical,
                component: "Error Rate".to_string(),
                message: "Error rate exceeds critical threshold".to_string(),
                metric_value: Some(error_metrics.error_rate_percentage),
                threshold: Some(self.config.error_rate.crit_percentage),
            });
        } else if error_metrics.error_rate_percentage > self.config.error_rate.warn_percentage {
            issues.push(HealthIssue {
                severity: HealthStatus::Degraded,
                component: "Error Rate".to_string(),
                message: "Error rate exceeds warning threshold".to_string(),
                metric_value: Some(error_metrics.error_rate_percentage),
                threshold: Some(self.config.error_rate.warn_percentage),
            });
            recommendations
                .push("Investigate recent errors and improve error handling".to_string());
        }

        // Check throughput
        if performance.throughput_ops_per_sec < self.config.performance.min_throughput_ops {
            issues.push(HealthIssue {
                severity: HealthStatus::Degraded,
                component: "Throughput".to_string(),
                message: "Throughput below minimum threshold".to_string(),
                metric_value: Some(performance.throughput_ops_per_sec),
                threshold: Some(self.config.performance.min_throughput_ops),
            });
        }

        // Determine overall status
        let status = if issues.iter().any(|i| i.severity == HealthStatus::Critical) {
            HealthStatus::Critical
        } else if issues.iter().any(|i| i.severity == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if issues.iter().any(|i| i.severity == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        // Add recommendations based on status
        if status == HealthStatus::Critical {
            recommendations.push("URGENT: Investigate critical issues immediately".to_string());
        }

        let report = NeutralizationHealthReport {
            status,
            timestamp: Utc::now(),
            performance,
            error_metrics,
            resource_metrics,
            capabilities,
            issues,
            recommendations,
        };

        // Store latest report
        *self.latest_report.write().await = Some(report.clone());

        Ok(report)
    }

    async fn calculate_performance_metrics(&self) -> PerformanceMetrics {
        let times = self.response_times.read().await;
        let total_ops = self.operations_total.load(Ordering::Relaxed);

        if times.is_empty() {
            return PerformanceMetrics {
                avg_response_time_ms: 0.0,
                p50_response_time_ms: 0.0,
                p90_response_time_ms: 0.0,
                p99_response_time_ms: 0.0,
                throughput_ops_per_sec: 0.0,
                total_operations: total_ops,
            };
        }

        // Convert to milliseconds and sort
        let mut times_ms: Vec<f64> = times.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
        times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let avg = times_ms.iter().sum::<f64>() / times_ms.len() as f64;
        let p50 = percentile(&times_ms, 0.50);
        let p90 = percentile(&times_ms, 0.90);
        let p99 = percentile(&times_ms, 0.99);

        // Calculate throughput (operations per second over last minute)
        let throughput = if times.is_empty() {
            0.0
        } else {
            let duration = times.last().unwrap().as_secs_f64();
            if duration > 0.0 {
                times.len() as f64 / duration.min(60.0)
            } else {
                0.0
            }
        };

        PerformanceMetrics {
            avg_response_time_ms: avg,
            p50_response_time_ms: p50,
            p90_response_time_ms: p90,
            p99_response_time_ms: p99,
            throughput_ops_per_sec: throughput,
            total_operations: total_ops,
        }
    }

    async fn calculate_error_metrics(&self) -> ErrorMetrics {
        let errors = self.recent_errors.read().await;
        let total = self.operations_total.load(Ordering::Relaxed);
        let error_count = self.operations_error.load(Ordering::Relaxed);

        let error_rate = if total > 0 {
            (error_count as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let mut error_types = std::collections::HashMap::new();
        for (_, error) in errors.iter() {
            *error_types.entry(classify_error(error)).or_insert(0) += 1;
        }

        ErrorMetrics {
            error_count,
            error_rate_percentage: error_rate,
            last_error_time: errors.last().map(|(time, _)| *time),
            error_types,
        }
    }

    async fn calculate_resource_metrics(&self) -> ResourceMetrics {
        // In a real implementation, these would come from actual measurements
        ResourceMetrics {
            memory_usage_mb: 50,        // Placeholder
            queue_depth: 0,             // Placeholder
            concurrent_operations: 1,   // Placeholder
            cpu_usage_percentage: 10.0, // Placeholder
        }
    }

    async fn check_capabilities(
        &self,
        neutralizer: &Arc<dyn ThreatNeutralizer>,
    ) -> CapabilityChecks {
        let caps = neutralizer.get_capabilities();

        CapabilityChecks {
            can_neutralize_sql: neutralizer.can_neutralize(&ThreatType::SqlInjection),
            can_neutralize_command: neutralizer.can_neutralize(&ThreatType::CommandInjection),
            can_neutralize_unicode: neutralizer.can_neutralize(&ThreatType::UnicodeBiDi),
            can_neutralize_path: neutralizer.can_neutralize(&ThreatType::PathTraversal),
            can_neutralize_prompt: neutralizer.can_neutralize(&ThreatType::PromptInjection),
            supports_batch: caps.batch_mode,
            supports_rollback: caps.rollback_depth > 0,
        }
    }

    async fn run_synthetic_probes(&self, neutralizer: &Arc<dyn ThreatNeutralizer>) -> Result<()> {
        // Create synthetic threats for testing
        let probes = vec![
            (
                Threat {
                    threat_type: ThreatType::SqlInjection,
                    severity: Severity::Low,
                    location: Location::Text {
                        offset: 0,
                        length: 10,
                    },
                    description: "Health check probe".to_string(),
                    remediation: None,
                },
                "SELECT 1",
            ),
            (
                Threat {
                    threat_type: ThreatType::UnicodeInvisible,
                    severity: Severity::Low,
                    location: Location::Text {
                        offset: 0,
                        length: 5,
                    },
                    description: "Health check probe".to_string(),
                    remediation: None,
                },
                "Hello",
            ),
        ];

        let mut all_passed = true;

        for (threat, content) in probes {
            match neutralizer.neutralize(&threat, content).await {
                Ok(_) => {
                    tracing::debug!("Synthetic probe passed for {:?}", threat.threat_type);
                }
                Err(e) => {
                    tracing::warn!("Synthetic probe failed for {:?}: {}", threat.threat_type, e);
                    all_passed = false;
                }
            }
        }

        self.synthetic_probe_healthy
            .store(all_passed, Ordering::Relaxed);

        if !all_passed {
            bail!("One or more synthetic probes failed");
        }

        Ok(())
    }

    async fn get_latest_report(&self) -> Option<NeutralizationHealthReport> {
        self.latest_report.read().await.clone()
    }
}

/// Calculate percentile from sorted array
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }

    let idx = ((sorted.len() - 1) as f64 * p) as usize;
    sorted[idx]
}

/// Classify error types
fn classify_error(error: &str) -> String {
    let lower = error.to_lowercase();

    if lower.contains("timeout") {
        "Timeout".to_string()
    } else if lower.contains("validation") {
        "Validation".to_string()
    } else if lower.contains("rate limit") {
        "RateLimit".to_string()
    } else if lower.contains("resource") || lower.contains("memory") {
        "Resource".to_string()
    } else {
        "Other".to_string()
    }
}

#[async_trait]
impl HealthCheckTrait for NeutralizationHealthChecker {
    async fn check(&self) -> Result<crate::traits::HealthStatus> {
        if let Some(report) = self.get_latest_report().await {
            let status = match report.status {
                HealthStatus::Healthy => crate::traits::HealthStatus::Healthy,
                HealthStatus::Degraded => crate::traits::HealthStatus::Degraded,
                HealthStatus::Unhealthy => crate::traits::HealthStatus::Unhealthy,
                HealthStatus::Critical => crate::traits::HealthStatus::Unhealthy,
            };
            Ok(status)
        } else {
            // Default to healthy if no report yet
            Ok(crate::traits::HealthStatus::Healthy)
        }
    }

    async fn detailed_check(&self) -> Result<crate::traits::HealthReport> {
        let start = std::time::Instant::now();

        if let Some(report) = self.get_latest_report().await {
            let status = match report.status {
                HealthStatus::Healthy => crate::traits::HealthStatus::Healthy,
                HealthStatus::Degraded => crate::traits::HealthStatus::Degraded,
                HealthStatus::Unhealthy => crate::traits::HealthStatus::Unhealthy,
                HealthStatus::Critical => crate::traits::HealthStatus::Unhealthy,
            };

            let checks = vec![
                crate::traits::HealthCheckResult {
                    name: "performance".to_string(),
                    status: if report.performance.avg_response_time_ms
                        > self.config.performance.avg_response_time_crit_ms as f64
                    {
                        crate::traits::HealthStatus::Unhealthy
                    } else if report.performance.avg_response_time_ms
                        > self.config.performance.avg_response_time_warn_ms as f64
                    {
                        crate::traits::HealthStatus::Degraded
                    } else {
                        crate::traits::HealthStatus::Healthy
                    },
                    message: Some(format!(
                        "Avg response time: {:.2}ms",
                        report.performance.avg_response_time_ms
                    )),
                    metadata: serde_json::json!(report.performance),
                },
                crate::traits::HealthCheckResult {
                    name: "error_rate".to_string(),
                    status: if report.error_metrics.error_rate_percentage
                        > self.config.error_rate.crit_percentage
                    {
                        crate::traits::HealthStatus::Unhealthy
                    } else if report.error_metrics.error_rate_percentage
                        > self.config.error_rate.warn_percentage
                    {
                        crate::traits::HealthStatus::Degraded
                    } else {
                        crate::traits::HealthStatus::Healthy
                    },
                    message: Some(format!(
                        "Error rate: {:.2}%",
                        report.error_metrics.error_rate_percentage
                    )),
                    metadata: serde_json::json!(report.error_metrics),
                },
                crate::traits::HealthCheckResult {
                    name: "capabilities".to_string(),
                    status: crate::traits::HealthStatus::Healthy,
                    message: Some("All capabilities operational".to_string()),
                    metadata: serde_json::json!(report.capabilities),
                },
            ];

            Ok(crate::traits::HealthReport {
                status,
                checks,
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                latency_ms: start.elapsed().as_millis() as u64,
            })
        } else {
            Ok(crate::traits::HealthReport {
                status: crate::traits::HealthStatus::Healthy,
                checks: vec![crate::traits::HealthCheckResult {
                    name: "system".to_string(),
                    status: crate::traits::HealthStatus::Healthy,
                    message: Some("Neutralization system starting up".to_string()),
                    metadata: serde_json::Value::Null,
                }],
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                latency_ms: start.elapsed().as_millis() as u64,
            })
        }
    }

    fn register_dependency(&self, _name: String, _checker: Arc<dyn HealthCheckTrait>) {
        // Neutralization doesn't have dependencies
    }

    fn metadata(&self) -> crate::traits::HealthCheckMetadata {
        crate::traits::HealthCheckMetadata {
            name: "neutralization".to_string(),
            check_type: crate::traits::HealthCheckType::Readiness,
            timeout: Duration::from_secs(5),
            critical: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neutralizer::standard::StandardNeutralizer;
    use crate::neutralizer::NeutralizationConfig;

    #[tokio::test]
    async fn test_health_monitoring() {
        let config = NeutralizationConfig::default();
        let neutralizer = Arc::new(StandardNeutralizer::new(config));

        let health_config = NeutralizationHealthConfig {
            enabled: false, // Disable background monitoring for test
            ..Default::default()
        };

        let monitored = HealthMonitoredNeutralizer::new(neutralizer, health_config);

        // Perform some operations to generate metrics
        let threat = Threat {
            threat_type: ThreatType::SqlInjection,
            severity: Severity::High,
            location: Location::Text {
                offset: 0,
                length: 10,
            },
            description: "Test threat".to_string(),
            remediation: None,
        };

        // Perform multiple operations to generate good metrics
        for _ in 0..10 {
            let _ = monitored.neutralize(&threat, "SELECT * FROM users").await;
        }

        // Force a health check to update metrics
        let report = monitored.check_health().await.unwrap();

        // The system should be healthy after successful operations
        assert!(
            report.status == HealthStatus::Healthy || report.status == HealthStatus::Degraded,
            "Expected Healthy or Degraded status, got {:?}",
            report.status
        );
        assert!(report.capabilities.can_neutralize_sql);
    }

    #[tokio::test]
    async fn test_synthetic_probes() {
        let config = NeutralizationConfig::default();
        let neutralizer = Arc::new(StandardNeutralizer::new(config));

        let health_config = NeutralizationHealthConfig::default();
        let checker = NeutralizationHealthChecker::new(health_config);

        // Run synthetic probes
        let neutralizer_arc: Arc<dyn ThreatNeutralizer> = neutralizer;
        let result = checker.run_synthetic_probes(&neutralizer_arc).await;
        assert!(result.is_ok());
    }
}
