//! Metrics collection and export for monitoring
//! Provides Prometheus-compatible metrics without external dependencies

use std::sync::atomic::{AtomicU64, AtomicI64, Ordering};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;
use std::time::{Instant, Duration};
use serde::{Serialize, Deserialize};

/// Metrics registry for all application metrics
pub struct MetricsRegistry {
    counters: RwLock<HashMap<String, Arc<Counter>>>,
    gauges: RwLock<HashMap<String, Arc<Gauge>>>,
    histograms: RwLock<HashMap<String, Arc<Histogram>>>,
    start_time: Instant,
}

impl MetricsRegistry {
    /// Create a new metrics registry
    pub fn new() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
            start_time: Instant::now(),
        }
    }
    
    /// Register or get a counter
    pub fn counter(&self, name: &str, help: &str) -> Arc<Counter> {
        let mut counters = self.counters.write().unwrap();
        counters.entry(name.to_string())
            .or_insert_with(|| Arc::new(Counter::new(name, help)))
            .clone()
    }
    
    /// Register or get a gauge
    pub fn gauge(&self, name: &str, help: &str) -> Arc<Gauge> {
        let mut gauges = self.gauges.write().unwrap();
        gauges.entry(name.to_string())
            .or_insert_with(|| Arc::new(Gauge::new(name, help)))
            .clone()
    }
    
    /// Register or get a histogram
    pub fn histogram(&self, name: &str, help: &str, buckets: Vec<f64>) -> Arc<Histogram> {
        let mut histograms = self.histograms.write().unwrap();
        histograms.entry(name.to_string())
            .or_insert_with(|| Arc::new(Histogram::new(name, help, buckets)))
            .clone()
    }
    
    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();
        
        // Add process metrics
        output.push_str(&format!(
            "# HELP kindlyguard_up Whether the server is up\n\
             # TYPE kindlyguard_up gauge\n\
             kindlyguard_up 1\n\n"
        ));
        
        output.push_str(&format!(
            "# HELP kindlyguard_uptime_seconds Server uptime in seconds\n\
             # TYPE kindlyguard_uptime_seconds gauge\n\
             kindlyguard_uptime_seconds {}\n\n",
            self.start_time.elapsed().as_secs()
        ));
        
        // Export counters
        let counters = self.counters.read().unwrap();
        for (_, counter) in counters.iter() {
            output.push_str(&counter.export_prometheus());
            output.push_str("\n");
        }
        
        // Export gauges
        let gauges = self.gauges.read().unwrap();
        for (_, gauge) in gauges.iter() {
            output.push_str(&gauge.export_prometheus());
            output.push_str("\n");
        }
        
        // Export histograms
        let histograms = self.histograms.read().unwrap();
        for (_, histogram) in histograms.iter() {
            output.push_str(&histogram.export_prometheus());
            output.push_str("\n");
        }
        
        output
    }
    
    /// Export metrics as JSON
    pub fn export_json(&self) -> serde_json::Value {
        let mut metrics = serde_json::Map::new();
        
        // Add meta information
        metrics.insert("uptime_seconds".to_string(), 
            serde_json::Value::Number(serde_json::Number::from(
                self.start_time.elapsed().as_secs()
            )));
        
        // Collect all metrics
        let mut all_metrics = Vec::new();
        
        let counters = self.counters.read().unwrap();
        for (name, counter) in counters.iter() {
            all_metrics.push(serde_json::json!({
                "name": name,
                "type": "counter",
                "value": counter.value(),
                "help": counter.help
            }));
        }
        
        let gauges = self.gauges.read().unwrap();
        for (name, gauge) in gauges.iter() {
            all_metrics.push(serde_json::json!({
                "name": name,
                "type": "gauge",
                "value": gauge.value(),
                "help": gauge.help
            }));
        }
        
        let histograms = self.histograms.read().unwrap();
        for (name, histogram) in histograms.iter() {
            all_metrics.push(serde_json::json!({
                "name": name,
                "type": "histogram",
                "stats": histogram.stats(),
                "help": histogram.help
            }));
        }
        
        metrics.insert("metrics".to_string(), serde_json::Value::Array(all_metrics));
        serde_json::Value::Object(metrics)
    }
}


/// Counter metric that only increases
pub struct Counter {
    name: String,
    help: String,
    value: AtomicU64,
}

impl Counter {
    fn new(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            value: AtomicU64::new(0),
        }
    }
    
    /// Increment the counter
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Increment by a specific amount
    pub fn inc_by(&self, amount: u64) {
        self.value.fetch_add(amount, Ordering::Relaxed);
    }
    
    /// Get current value
    pub fn value(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
    
    /// Export in Prometheus format
    fn export_prometheus(&self) -> String {
        format!(
            "# HELP {} {}\n# TYPE {} counter\n{} {}",
            self.name, self.help, self.name, self.name, self.value()
        )
    }
}

/// Gauge metric that can increase or decrease
pub struct Gauge {
    name: String,
    help: String,
    value: AtomicI64,
}

impl Gauge {
    fn new(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            value: AtomicI64::new(0),
        }
    }
    
    /// Set the gauge value
    pub fn set(&self, value: i64) {
        self.value.store(value, Ordering::Relaxed);
    }
    
    /// Increment the gauge
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Decrement the gauge
    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }
    
    /// Get current value
    pub fn value(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }
    
    /// Export in Prometheus format
    fn export_prometheus(&self) -> String {
        format!(
            "# HELP {} {}\n# TYPE {} gauge\n{} {}",
            self.name, self.help, self.name, self.name, self.value()
        )
    }
}

/// Histogram metric for recording distributions
pub struct Histogram {
    name: String,
    help: String,
    buckets: Vec<f64>,
    bucket_counts: Vec<AtomicU64>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn new(name: &str, help: &str, mut buckets: Vec<f64>) -> Self {
        buckets.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let bucket_counts = buckets.iter().map(|_| AtomicU64::new(0)).collect();
        
        Self {
            name: name.to_string(),
            help: help.to_string(),
            buckets,
            bucket_counts,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
    
    /// Record an observation
    pub fn observe(&self, value: f64) {
        // Update buckets
        for (i, &bucket) in self.buckets.iter().enumerate() {
            if value <= bucket {
                self.bucket_counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        
        // Update sum and count
        let value_bits = (value * 1000.0) as u64; // Store as millis for precision
        self.sum.fetch_add(value_bits, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Get statistics
    pub fn stats(&self) -> HistogramStats {
        let count = self.count.load(Ordering::Relaxed);
        let sum_bits = self.sum.load(Ordering::Relaxed);
        let sum = sum_bits as f64 / 1000.0;
        
        HistogramStats {
            count,
            sum,
            average: if count > 0 { sum / count as f64 } else { 0.0 },
        }
    }
    
    /// Export in Prometheus format
    fn export_prometheus(&self) -> String {
        let mut output = format!(
            "# HELP {} {}\n# TYPE {} histogram\n",
            self.name, self.help, self.name
        );
        
        // Export buckets
        for (i, &bucket) in self.buckets.iter().enumerate() {
            let count = self.bucket_counts[i].load(Ordering::Relaxed);
            output.push_str(&format!(
                "{}_bucket{{le=\"{}\"}} {}\n",
                self.name, bucket, count
            ));
        }
        
        // Export +Inf bucket (total count)
        let total_count = self.count.load(Ordering::Relaxed);
        output.push_str(&format!(
            "{}_bucket{{le=\"+Inf\"}} {}\n",
            self.name, total_count
        ));
        
        // Export sum and count
        let sum = self.sum.load(Ordering::Relaxed) as f64 / 1000.0;
        output.push_str(&format!("{}_sum {}\n", self.name, sum));
        output.push_str(&format!("{}_count {}", self.name, total_count));
        
        output
    }
}

/// Histogram statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramStats {
    pub count: u64,
    pub sum: f64,
    pub average: f64,
}

/// Timer for measuring durations
pub struct Timer {
    histogram: Arc<Histogram>,
    start: Instant,
}

impl Timer {
    /// Create a new timer
    pub fn new(histogram: Arc<Histogram>) -> Self {
        Self {
            histogram,
            start: Instant::now(),
        }
    }
    
    /// Record the elapsed time
    pub fn observe_duration(self) {
        let duration = self.start.elapsed();
        self.histogram.observe(duration.as_secs_f64());
    }
}

/// Default metrics for KindlyGuard
pub struct KindlyMetrics {
    // Request metrics
    pub requests_total: Arc<Counter>,
    pub requests_failed: Arc<Counter>,
    pub request_duration: Arc<Histogram>,
    
    // Security metrics
    pub threats_detected: Arc<Counter>,
    pub auth_attempts: Arc<Counter>,
    pub auth_failures: Arc<Counter>,
    pub rate_limit_hits: Arc<Counter>,
    
    // Connection metrics
    pub active_connections: Arc<Gauge>,
    pub connections_total: Arc<Counter>,
    
    // Scanner metrics
    pub scans_total: Arc<Counter>,
    pub scan_duration: Arc<Histogram>,
}

impl KindlyMetrics {
    /// Create default metrics
    pub fn new(registry: &MetricsRegistry) -> Self {
        Self {
            // Request metrics
            requests_total: registry.counter(
                "kindlyguard_requests_total",
                "Total number of requests processed"
            ),
            requests_failed: registry.counter(
                "kindlyguard_requests_failed_total",
                "Total number of failed requests"
            ),
            request_duration: registry.histogram(
                "kindlyguard_request_duration_seconds",
                "Request duration in seconds",
                vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
            ),
            
            // Security metrics
            threats_detected: registry.counter(
                "kindlyguard_threats_detected_total",
                "Total number of threats detected"
            ),
            auth_attempts: registry.counter(
                "kindlyguard_auth_attempts_total",
                "Total number of authentication attempts"
            ),
            auth_failures: registry.counter(
                "kindlyguard_auth_failures_total",
                "Total number of authentication failures"
            ),
            rate_limit_hits: registry.counter(
                "kindlyguard_rate_limit_hits_total",
                "Total number of rate limit hits"
            ),
            
            // Connection metrics
            active_connections: registry.gauge(
                "kindlyguard_active_connections",
                "Number of active connections"
            ),
            connections_total: registry.counter(
                "kindlyguard_connections_total",
                "Total number of connections"
            ),
            
            // Scanner metrics
            scans_total: registry.counter(
                "kindlyguard_scans_total",
                "Total number of scans performed"
            ),
            scan_duration: registry.histogram(
                "kindlyguard_scan_duration_seconds",
                "Scan duration in seconds",
                vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1]
            ),
        }
    }
}