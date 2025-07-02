//! Neutralization metrics for monitoring and observability
//!
//! Provides comprehensive metrics tracking for neutralization operations
//! to ensure production visibility and performance monitoring.

use crate::neutralizer::{NeutralizationMode, NeutralizeAction};
use crate::scanner::ThreatType;
use crate::telemetry::metrics::{Metric, MetricsCollector};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Neutralization metrics tracker
pub struct NeutralizationMetrics {
    collector: Arc<MetricsCollector>,
}

impl NeutralizationMetrics {
    pub const fn new(collector: Arc<MetricsCollector>) -> Self {
        Self { collector }
    }

    /// Record a neutralization attempt
    pub fn record_neutralization(
        &self,
        threat_type: &ThreatType,
        action: &NeutralizeAction,
        success: bool,
        duration: Duration,
        mode: NeutralizationMode,
    ) {
        let threat_str = format!("{threat_type:?}");
        let action_str = format!("{action:?}");
        let mode_str = format!("{mode:?}");

        // Neutralization counter by type, action, and status
        self.collector.increment_counter(
            "kindlyguard_neutralization_total",
            [
                ("threat_type".to_string(), threat_str.clone()),
                ("action".to_string(), action_str.clone()),
                ("mode".to_string(), mode_str),
                (
                    "status".to_string(),
                    if success { "success" } else { "failure" }.to_string(),
                ),
            ]
            .into(),
        );

        // Neutralization duration histogram
        if success {
            self.collector.observe_histogram(
                "kindlyguard_neutralization_duration_seconds",
                duration.as_secs_f64(),
                [
                    ("threat_type".to_string(), threat_str.clone()),
                    ("action".to_string(), action_str),
                ]
                .into(),
            );
        }

        // Track failures separately for alerting
        if !success {
            self.collector.increment_counter(
                "kindlyguard_neutralization_failures_total",
                [("threat_type".to_string(), threat_str)].into(),
            );
        }
    }

    /// Record batch neutralization
    pub fn record_batch_neutralization(
        &self,
        total_threats: usize,
        neutralized_count: usize,
        failed_count: usize,
        duration: Duration,
    ) {
        // Batch size histogram
        self.collector.observe_histogram(
            "kindlyguard_neutralization_batch_size",
            total_threats as f64,
            HashMap::new(),
        );

        // Batch duration histogram
        self.collector.observe_histogram(
            "kindlyguard_neutralization_batch_duration_seconds",
            duration.as_secs_f64(),
            HashMap::new(),
        );

        // Success rate gauge
        let success_rate = if total_threats > 0 {
            (neutralized_count as f64 / total_threats as f64) * 100.0
        } else {
            0.0
        };

        self.collector.set_gauge(
            "kindlyguard_neutralization_batch_success_rate",
            success_rate,
            HashMap::new(),
        );

        // Failed neutralizations counter
        if failed_count > 0 {
            self.collector.add_to_counter(
                "kindlyguard_neutralization_batch_failures_total",
                failed_count as u64,
                HashMap::new(),
            );
        }
    }

    /// Record neutralization recovery
    pub fn record_recovery(
        &self,
        threat_type: &ThreatType,
        recovery_attempts: u32,
        success: bool,
        total_duration: Duration,
    ) {
        let threat_str = format!("{threat_type:?}");

        // Recovery counter
        self.collector.increment_counter(
            "kindlyguard_neutralization_recovery_total",
            [
                ("threat_type".to_string(), threat_str.clone()),
                (
                    "status".to_string(),
                    if success { "recovered" } else { "failed" }.to_string(),
                ),
            ]
            .into(),
        );

        // Recovery attempts histogram
        self.collector.observe_histogram(
            "kindlyguard_neutralization_recovery_attempts",
            f64::from(recovery_attempts),
            [("threat_type".to_string(), threat_str.clone())].into(),
        );

        // Recovery duration
        if success {
            self.collector.observe_histogram(
                "kindlyguard_neutralization_recovery_duration_seconds",
                total_duration.as_secs_f64(),
                [("threat_type".to_string(), threat_str)].into(),
            );
        }
    }

    /// Record circuit breaker state change
    pub fn record_circuit_breaker_state(&self, state: &str) {
        self.collector.increment_counter(
            "kindlyguard_neutralization_circuit_breaker_transitions",
            [("state".to_string(), state.to_string())].into(),
        );

        // Also set a gauge for current state
        let state_value = match state {
            "closed" => 0.0,
            "open" => 1.0,
            "half_open" => 0.5,
            _ => -1.0,
        };

        self.collector.set_gauge(
            "kindlyguard_neutralization_circuit_breaker_state",
            state_value,
            HashMap::new(),
        );
    }

    /// Record content size processed
    pub fn record_content_size(&self, size_bytes: usize, threat_type: &ThreatType) {
        let threat_str = format!("{threat_type:?}");

        self.collector.observe_histogram(
            "kindlyguard_neutralization_content_size_bytes",
            size_bytes as f64,
            [("threat_type".to_string(), threat_str)].into(),
        );
    }

    /// Record validation failures
    pub fn record_validation_failure(&self, reason: &str) {
        self.collector.increment_counter(
            "kindlyguard_neutralization_validation_failures_total",
            [("reason".to_string(), reason.to_string())].into(),
        );
    }

    /// Record performance mode (standard vs enhanced)
    pub fn set_performance_mode(&self, enhanced: bool) {
        self.collector.set_gauge(
            "kindlyguard_neutralization_enhanced_mode",
            if enhanced { 1.0 } else { 0.0 },
            HashMap::new(),
        );
    }
}

/// Neutralization metrics summary
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NeutralizationMetricsSummary {
    pub total_neutralizations: u64,
    pub success_rate: f64,
    pub avg_duration_ms: f64,
    pub total_recoveries: u64,
    pub recovery_success_rate: f64,
    pub avg_content_size_kb: f64,
    pub enhanced_mode: bool,
    pub circuit_breaker_open: bool,
}

impl NeutralizationMetricsSummary {
    /// Calculate summary from raw metrics
    pub fn from_metrics(metrics: &[Metric]) -> Self {
        let mut total_neutralizations = 0u64;
        let mut successful_neutralizations = 0u64;
        let mut total_duration = 0.0f64;
        let mut duration_count = 0u64;
        let mut total_recoveries = 0u64;
        let mut successful_recoveries = 0u64;
        let mut total_content_size = 0.0f64;
        let mut content_size_count = 0u64;
        let mut enhanced_mode = false;
        let mut circuit_breaker_state = 0.0f64;

        for metric in metrics {
            match metric {
                Metric::Counter {
                    name,
                    value,
                    labels,
                } => {
                    if name == "kindlyguard_neutralization_total" {
                        total_neutralizations += value;
                        if labels.get("status") == Some(&"success".to_string()) {
                            successful_neutralizations += value;
                        }
                    } else if name == "kindlyguard_neutralization_recovery_total" {
                        total_recoveries += value;
                        if labels.get("status") == Some(&"recovered".to_string()) {
                            successful_recoveries += value;
                        }
                    }
                }
                Metric::Histogram {
                    name, sum, count, ..
                } => {
                    if name == "kindlyguard_neutralization_duration_seconds" {
                        total_duration += sum;
                        duration_count += count;
                    } else if name == "kindlyguard_neutralization_content_size_bytes" {
                        total_content_size += sum;
                        content_size_count += count;
                    }
                }
                Metric::Gauge { name, value, .. } => {
                    if name == "kindlyguard_neutralization_enhanced_mode" {
                        enhanced_mode = *value > 0.5;
                    } else if name == "kindlyguard_neutralization_circuit_breaker_state" {
                        circuit_breaker_state = *value;
                    }
                }
            }
        }

        Self {
            total_neutralizations,
            success_rate: if total_neutralizations > 0 {
                (successful_neutralizations as f64 / total_neutralizations as f64) * 100.0
            } else {
                0.0
            },
            avg_duration_ms: if duration_count > 0 {
                (total_duration / duration_count as f64) * 1000.0
            } else {
                0.0
            },
            total_recoveries,
            recovery_success_rate: if total_recoveries > 0 {
                (successful_recoveries as f64 / total_recoveries as f64) * 100.0
            } else {
                0.0
            },
            avg_content_size_kb: if content_size_count > 0 {
                (total_content_size / content_size_count as f64) / 1024.0
            } else {
                0.0
            },
            enhanced_mode,
            circuit_breaker_open: circuit_breaker_state > 0.5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neutralization_metrics() {
        let collector = Arc::new(MetricsCollector::new());
        let metrics = NeutralizationMetrics::new(collector.clone());

        // Record some neutralizations
        metrics.record_neutralization(
            &ThreatType::SqlInjection,
            &NeutralizeAction::Parameterized,
            true,
            Duration::from_millis(50),
            NeutralizationMode::Automatic,
        );

        metrics.record_neutralization(
            &ThreatType::UnicodeInvisible,
            &NeutralizeAction::Removed,
            false,
            Duration::from_millis(10),
            NeutralizationMode::ReportOnly,
        );

        let all_metrics = collector.get_metrics();

        // Check counters were recorded
        let total_counter = all_metrics.iter().find(|m| {
            matches!(m, Metric::Counter { name, .. } if name == "kindlyguard_neutralization_total")
        });
        assert!(total_counter.is_some());

        // Check failure counter
        let failure_counter = all_metrics.iter().find(|m| {
            matches!(m, Metric::Counter { name, .. } if name == "kindlyguard_neutralization_failures_total")
        });
        assert!(failure_counter.is_some());
    }

    #[test]
    fn test_batch_metrics() {
        let collector = Arc::new(MetricsCollector::new());
        let metrics = NeutralizationMetrics::new(collector.clone());

        metrics.record_batch_neutralization(10, 8, 2, Duration::from_millis(100));

        let all_metrics = collector.get_metrics();

        // Check success rate gauge
        let success_rate = all_metrics.iter().find(|m| {
            matches!(m, Metric::Gauge { name, .. } if name == "kindlyguard_neutralization_batch_success_rate")
        });

        match success_rate {
            Some(Metric::Gauge { value, .. }) => {
                assert!((value - 80.0).abs() < 0.01);
            }
            _ => panic!("Expected success rate gauge"),
        }
    }
}
