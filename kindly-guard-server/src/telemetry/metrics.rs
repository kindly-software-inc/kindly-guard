//! Metrics collection for monitoring and observability

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Metric types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Metric {
    /// Counter - monotonically increasing value
    Counter {
        name: String,
        value: u64,
        labels: HashMap<String, String>,
    },
    /// Gauge - value that can go up or down
    Gauge {
        name: String,
        value: f64,
        labels: HashMap<String, String>,
    },
    /// Histogram - distribution of values
    Histogram {
        name: String,
        buckets: Vec<(f64, u64)>, // (bucket_limit, count)
        sum: f64,
        count: u64,
        labels: HashMap<String, String>,
    },
}

/// Metrics collector
pub struct MetricsCollector {
    metrics: Arc<RwLock<MetricsState>>,
}

struct MetricsState {
    counters: HashMap<String, CounterState>,
    gauges: HashMap<String, GaugeState>,
    histograms: HashMap<String, HistogramState>,
    last_reset: Instant,
}

struct CounterState {
    value: u64,
    labels: HashMap<String, String>,
}

struct GaugeState {
    value: f64,
    labels: HashMap<String, String>,
}

struct HistogramState {
    buckets: Vec<f64>,
    bucket_counts: Vec<u64>,
    sum: f64,
    count: u64,
    labels: HashMap<String, String>,
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(MetricsState {
                counters: HashMap::new(),
                gauges: HashMap::new(),
                histograms: HashMap::new(),
                last_reset: Instant::now(),
            })),
        }
    }

    /// Increment a counter
    pub fn increment_counter(&self, name: &str, labels: HashMap<String, String>) {
        let mut state = self.metrics.write();
        let counter = state
            .counters
            .entry(name.to_string())
            .or_insert(CounterState { value: 0, labels });
        counter.value += 1;
    }

    /// Add to a counter
    pub fn add_to_counter(&self, name: &str, value: u64, labels: HashMap<String, String>) {
        let mut state = self.metrics.write();
        let counter = state
            .counters
            .entry(name.to_string())
            .or_insert(CounterState { value: 0, labels });
        counter.value += value;
    }

    /// Set a gauge value
    pub fn set_gauge(&self, name: &str, value: f64, labels: HashMap<String, String>) {
        let mut state = self.metrics.write();
        state
            .gauges
            .insert(name.to_string(), GaugeState { value, labels });
    }

    /// Record a histogram observation
    pub fn observe_histogram(&self, name: &str, value: f64, labels: HashMap<String, String>) {
        let mut state = self.metrics.write();

        let histogram =
            state
                .histograms
                .entry(name.to_string())
                .or_insert_with(|| HistogramState {
                    buckets: vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0],
                    bucket_counts: vec![0; 9],
                    sum: 0.0,
                    count: 0,
                    labels,
                });

        // Update buckets
        for (i, &bucket_limit) in histogram.buckets.iter().enumerate() {
            if value <= bucket_limit {
                histogram.bucket_counts[i] += 1;
            }
        }

        histogram.sum += value;
        histogram.count += 1;
    }

    /// Get all current metrics
    pub fn get_metrics(&self) -> Vec<Metric> {
        let state = self.metrics.read();
        let mut metrics = Vec::new();

        // Collect counters
        for (name, counter) in &state.counters {
            metrics.push(Metric::Counter {
                name: name.clone(),
                value: counter.value,
                labels: counter.labels.clone(),
            });
        }

        // Collect gauges
        for (name, gauge) in &state.gauges {
            metrics.push(Metric::Gauge {
                name: name.clone(),
                value: gauge.value,
                labels: gauge.labels.clone(),
            });
        }

        // Collect histograms
        for (name, histogram) in &state.histograms {
            let mut buckets = Vec::new();
            for (i, &limit) in histogram.buckets.iter().enumerate() {
                buckets.push((limit, histogram.bucket_counts[i]));
            }

            metrics.push(Metric::Histogram {
                name: name.clone(),
                buckets,
                sum: histogram.sum,
                count: histogram.count,
                labels: histogram.labels.clone(),
            });
        }

        metrics
    }

    /// Reset all metrics
    pub fn reset(&self) {
        let mut state = self.metrics.write();
        state.counters.clear();
        state.gauges.clear();
        state.histograms.clear();
        state.last_reset = Instant::now();
    }
}

/// CLI command metrics
pub struct CommandMetrics {
    collector: Arc<MetricsCollector>,
}

impl CommandMetrics {
    pub const fn new(collector: Arc<MetricsCollector>) -> Self {
        Self { collector }
    }

    /// Record command execution
    pub fn record_command_execution(&self, command: &str, success: bool, duration: Duration) {
        // Command counter
        self.collector.increment_counter(
            "kindlyguard_commands_total",
            [
                ("command".to_string(), command.to_string()),
                (
                    "status".to_string(),
                    if success { "success" } else { "error" }.to_string(),
                ),
            ]
            .into(),
        );

        // Command duration histogram
        self.collector.observe_histogram(
            "kindlyguard_command_duration_seconds",
            duration.as_secs_f64(),
            [("command".to_string(), command.to_string())].into(),
        );
    }

    /// Record threat detection
    pub fn record_threat_detected(&self, threat_type: &str, severity: &str) {
        self.collector.increment_counter(
            "kindlyguard_threats_detected_total",
            [
                ("type".to_string(), threat_type.to_string()),
                ("severity".to_string(), severity.to_string()),
            ]
            .into(),
        );
    }

    /// Update active connections gauge
    pub fn set_active_connections(&self, count: f64) {
        self.collector
            .set_gauge("kindlyguard_active_connections", count, HashMap::new());
    }
}

/// Metrics snapshot for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: DateTime<Utc>,
    pub metrics: Vec<Metric>,
    pub summary: MetricsSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub total_commands: u64,
    pub error_rate: f64,
    pub avg_command_duration_ms: f64,
    pub total_threats_detected: u64,
    pub active_connections: u64,
}

impl MetricsSnapshot {
    pub fn from_collector(collector: &MetricsCollector) -> Self {
        let metrics = collector.get_metrics();
        let summary = Self::calculate_summary(&metrics);

        Self {
            timestamp: Utc::now(),
            metrics,
            summary,
        }
    }

    fn calculate_summary(metrics: &[Metric]) -> MetricsSummary {
        let mut total_commands = 0u64;
        let mut error_commands = 0u64;
        let mut total_duration = 0.0f64;
        let mut duration_count = 0u64;
        let mut total_threats = 0u64;
        let mut active_connections = 0u64;

        for metric in metrics {
            match metric {
                Metric::Counter {
                    name,
                    value,
                    labels,
                } => {
                    if name == "kindlyguard_commands_total" {
                        total_commands += value;
                        if labels.get("status") == Some(&"error".to_string()) {
                            error_commands += value;
                        }
                    } else if name == "kindlyguard_threats_detected_total" {
                        total_threats += value;
                    }
                }
                Metric::Histogram {
                    name, sum, count, ..
                } => {
                    if name == "kindlyguard_command_duration_seconds" {
                        total_duration += sum;
                        duration_count += count;
                    }
                }
                Metric::Gauge { name, value, .. } => {
                    if name == "kindlyguard_active_connections" {
                        active_connections = *value as u64;
                    }
                }
            }
        }

        MetricsSummary {
            total_commands,
            error_rate: if total_commands > 0 {
                error_commands as f64 / total_commands as f64
            } else {
                0.0
            },
            avg_command_duration_ms: if duration_count > 0 {
                (total_duration / duration_count as f64) * 1000.0
            } else {
                0.0
            },
            total_threats_detected: total_threats,
            active_connections,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_metrics() {
        let collector = MetricsCollector::new();

        collector.increment_counter("test_counter", HashMap::new());
        collector.increment_counter("test_counter", HashMap::new());
        collector.add_to_counter("test_counter", 3, HashMap::new());

        let metrics = collector.get_metrics();
        assert_eq!(metrics.len(), 1);

        match &metrics[0] {
            Metric::Counter { name, value, .. } => {
                assert_eq!(name, "test_counter");
                assert_eq!(*value, 5);
            }
            _ => panic!("Expected counter metric"),
        }
    }

    #[test]
    fn test_histogram_metrics() {
        let collector = MetricsCollector::new();

        collector.observe_histogram("test_histogram", 0.002, HashMap::new());
        collector.observe_histogram("test_histogram", 0.02, HashMap::new());
        collector.observe_histogram("test_histogram", 0.2, HashMap::new());

        let metrics = collector.get_metrics();
        assert_eq!(metrics.len(), 1);

        match &metrics[0] {
            Metric::Histogram {
                name, count, sum, ..
            } => {
                assert_eq!(name, "test_histogram");
                assert_eq!(*count, 3);
                assert!((sum - 0.222).abs() < 0.0001);
            }
            _ => panic!("Expected histogram metric"),
        }
    }
}
