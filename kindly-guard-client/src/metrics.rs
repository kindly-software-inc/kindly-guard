//! Metrics collection for performance monitoring

use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;
use parking_lot::RwLock;

use crate::traits::{MetricsCollector, MetricsSummary};

/// Metrics collector implementation
pub struct MetricsCollectorImpl {
    total_requests: Arc<RwLock<u64>>,
    total_errors: Arc<RwLock<u64>>,
    latencies: Arc<RwLock<Vec<f64>>>,
    errors_by_type: Arc<RwLock<HashMap<String, u64>>>,
}

impl MetricsCollectorImpl {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            total_requests: Arc::new(RwLock::new(0)),
            total_errors: Arc::new(RwLock::new(0)),
            latencies: Arc::new(RwLock::new(Vec::new())),
            errors_by_type: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl MetricsCollector for MetricsCollectorImpl {
    fn record_latency(&self, _method: &str, duration: Duration) {
        let mut requests = self.total_requests.write();
        *requests += 1;
        
        let mut latencies = self.latencies.write();
        latencies.push(duration.as_secs_f64() * 1000.0); // Convert to ms
    }
    
    fn record_error(&self, _method: &str, error: &str) {
        let mut errors = self.total_errors.write();
        *errors += 1;
        
        let mut errors_by_type = self.errors_by_type.write();
        let error_type = if error.contains("rate") {
            "rate_limit"
        } else if error.contains("auth") || error.contains("401") {
            "authentication"
        } else if error.contains("threat") {
            "threat_detected"
        } else {
            "other"
        };
        
        *errors_by_type.entry(error_type.to_string()).or_insert(0) += 1;
    }
    
    fn get_summary(&self) -> MetricsSummary {
        let total_requests = *self.total_requests.read();
        let total_errors = *self.total_errors.read();
        let latencies = self.latencies.read();
        let errors_by_type = self.errors_by_type.read().clone();
        
        let (avg_latency_ms, p99_latency_ms) = if !latencies.is_empty() {
            let sum: f64 = latencies.iter().sum();
            let avg = sum / latencies.len() as f64;
            
            let mut sorted = latencies.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let p99_idx = ((sorted.len() as f64) * 0.99) as usize;
            let p99 = sorted.get(p99_idx).copied().unwrap_or(avg);
            
            (avg, p99)
        } else {
            (0.0, 0.0)
        };
        
        MetricsSummary {
            total_requests,
            total_errors,
            avg_latency_ms,
            p99_latency_ms,
            errors_by_type,
        }
    }
}

impl Default for MetricsCollectorImpl {
    fn default() -> Self {
        Self::new()
    }
}