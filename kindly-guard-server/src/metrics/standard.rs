// Copyright 2025 Kindly Software Inc.
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
//! Standard metrics implementation using RwLock
//! This is the default implementation that works well for most use cases

use crate::traits::{CounterTrait, GaugeTrait, HistogramStats, HistogramTrait, MetricsProvider};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// Standard metrics registry implementation
pub struct StandardMetricsProvider {
    counters: RwLock<HashMap<String, Arc<StandardCounter>>>,
    gauges: RwLock<HashMap<String, Arc<StandardGauge>>>,
    histograms: RwLock<HashMap<String, Arc<StandardHistogram>>>,
    start_time: Instant,
}

impl Default for StandardMetricsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardMetricsProvider {
    /// Create a new standard metrics provider
    pub fn new() -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            gauges: RwLock::new(HashMap::new()),
            histograms: RwLock::new(HashMap::new()),
            start_time: Instant::now(),
        }
    }
}

impl MetricsProvider for StandardMetricsProvider {
    fn counter(&self, name: &str, help: &str) -> Arc<dyn CounterTrait> {
        let mut counters = self.counters.write().unwrap();
        let counter = counters
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(StandardCounter::new(name, help)))
            .clone();
        counter as Arc<dyn CounterTrait>
    }

    fn gauge(&self, name: &str, help: &str) -> Arc<dyn GaugeTrait> {
        let mut gauges = self.gauges.write().unwrap();
        let gauge = gauges
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(StandardGauge::new(name, help)))
            .clone();
        gauge as Arc<dyn GaugeTrait>
    }

    fn histogram(&self, name: &str, help: &str, buckets: Vec<f64>) -> Arc<dyn HistogramTrait> {
        let mut histograms = self.histograms.write().unwrap();
        let histogram = histograms
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(StandardHistogram::new(name, help, buckets.clone())))
            .clone();
        histogram as Arc<dyn HistogramTrait>
    }

    fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Add process metrics
        output.push_str(
            "# HELP kindlyguard_up Whether the server is up\n\
             # TYPE kindlyguard_up gauge\n\
             kindlyguard_up 1\n\n",
        );

        output.push_str(&format!(
            "# HELP kindlyguard_uptime_seconds Server uptime in seconds\n\
             # TYPE kindlyguard_uptime_seconds gauge\n\
             kindlyguard_uptime_seconds {}\n\n",
            self.uptime_seconds()
        ));

        // Export counters
        let counters = self.counters.read().unwrap();
        for counter in counters.values() {
            output.push_str(&counter.export_prometheus());
            output.push('\n');
        }

        // Export gauges
        let gauges = self.gauges.read().unwrap();
        for gauge in gauges.values() {
            output.push_str(&gauge.export_prometheus());
            output.push('\n');
        }

        // Export histograms
        let histograms = self.histograms.read().unwrap();
        for histogram in histograms.values() {
            output.push_str(&histogram.export_prometheus());
            output.push('\n');
        }

        output
    }

    fn export_json(&self) -> serde_json::Value {
        let mut metrics = serde_json::Map::new();

        metrics.insert(
            "uptime_seconds".to_string(),
            serde_json::Value::Number(serde_json::Number::from(self.uptime_seconds())),
        );

        let mut all_metrics = Vec::new();

        let counters = self.counters.read().unwrap();
        for (name, counter) in counters.iter() {
            all_metrics.push(serde_json::json!({
                "name": name,
                "type": "counter",
                "value": counter.value(),
                "help": &counter.help
            }));
        }

        let gauges = self.gauges.read().unwrap();
        for (name, gauge) in gauges.iter() {
            all_metrics.push(serde_json::json!({
                "name": name,
                "type": "gauge",
                "value": gauge.value(),
                "help": &gauge.help
            }));
        }

        let histograms = self.histograms.read().unwrap();
        for (name, histogram) in histograms.iter() {
            all_metrics.push(serde_json::json!({
                "name": name,
                "type": "histogram",
                "stats": histogram.stats(),
                "help": &histogram.help
            }));
        }

        metrics.insert("metrics".to_string(), serde_json::Value::Array(all_metrics));
        serde_json::Value::Object(metrics)
    }

    fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

/// Standard counter implementation
struct StandardCounter {
    name: String,
    help: String,
    value: AtomicU64,
}

impl StandardCounter {
    fn new(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            value: AtomicU64::new(0),
        }
    }

    fn export_prometheus(&self) -> String {
        format!(
            "# HELP {} {}\n# TYPE {} counter\n{} {}",
            self.name,
            self.help,
            self.name,
            self.name,
            self.value()
        )
    }
}

impl CounterTrait for StandardCounter {
    fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    fn inc_by(&self, amount: u64) {
        self.value.fetch_add(amount, Ordering::Relaxed);
    }

    fn value(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Standard gauge implementation
struct StandardGauge {
    name: String,
    help: String,
    value: AtomicI64,
}

impl StandardGauge {
    fn new(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            value: AtomicI64::new(0),
        }
    }

    fn export_prometheus(&self) -> String {
        format!(
            "# HELP {} {}\n# TYPE {} gauge\n{} {}",
            self.name,
            self.help,
            self.name,
            self.name,
            self.value()
        )
    }
}

impl GaugeTrait for StandardGauge {
    fn set(&self, value: i64) {
        self.value.store(value, Ordering::Relaxed);
    }

    fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    fn value(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Standard histogram implementation
struct StandardHistogram {
    name: String,
    help: String,
    buckets: Vec<f64>,
    bucket_counts: Vec<AtomicU64>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl StandardHistogram {
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

impl HistogramTrait for StandardHistogram {
    fn observe(&self, value: f64) {
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

    fn stats(&self) -> HistogramStats {
        let count = self.count.load(Ordering::Relaxed);
        let sum_bits = self.sum.load(Ordering::Relaxed);
        let sum = sum_bits as f64 / 1000.0;

        HistogramStats {
            count,
            sum,
            average: if count > 0 { sum / count as f64 } else { 0.0 },
        }
    }
}
