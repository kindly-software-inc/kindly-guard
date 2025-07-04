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
use kindly_guard_server::{
    config::Config,
    neutralizer::{NeutralizeAction, NeutralizeResult, ThreatNeutralizer},
    scanner::{SecurityScanner, Severity, Threat, ThreatType},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::runtime::Runtime;

/// Performance baseline data for a specific operation
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PerformanceBaseline {
    operation: String,
    implementation: String,
    mean_duration_ns: u64,
    std_deviation_ns: u64,
    samples: usize,
    timestamp: chrono::DateTime<chrono::Utc>,
    rust_version: String,
    os: String,
}

/// Performance measurement result
#[derive(Debug)]
struct PerformanceMeasurement {
    durations: Vec<Duration>,
    mean: Duration,
    std_dev: Duration,
    min: Duration,
    max: Duration,
    p50: Duration,
    p95: Duration,
    p99: Duration,
}

impl PerformanceMeasurement {
    fn from_durations(mut durations: Vec<Duration>) -> Self {
        durations.sort_unstable();

        let sum: Duration = durations.iter().sum();
        let mean = sum / durations.len() as u32;

        let variance: f64 = durations
            .iter()
            .map(|d| {
                let diff = d.as_nanos() as f64 - mean.as_nanos() as f64;
                diff * diff
            })
            .sum::<f64>()
            / durations.len() as f64;

        let std_dev = Duration::from_nanos(variance.sqrt() as u64);

        let p50_idx = durations.len() / 2;
        let p95_idx = (durations.len() as f64 * 0.95) as usize;
        let p99_idx = (durations.len() as f64 * 0.99) as usize;

        Self {
            mean,
            std_dev,
            min: durations[0],
            max: durations[durations.len() - 1],
            p50: durations[p50_idx],
            p95: durations[p95_idx.min(durations.len() - 1)],
            p99: durations[p99_idx.min(durations.len() - 1)],
            durations,
        }
    }

    fn to_baseline(&self, operation: &str, implementation: &str) -> PerformanceBaseline {
        PerformanceBaseline {
            operation: operation.to_string(),
            implementation: implementation.to_string(),
            mean_duration_ns: self.mean.as_nanos() as u64,
            std_deviation_ns: self.std_dev.as_nanos() as u64,
            samples: self.durations.len(),
            timestamp: chrono::Utc::now(),
            rust_version: env!("RUSTC_VERSION").to_string(),
            os: std::env::consts::OS.to_string(),
        }
    }
}

/// Performance regression detector
struct RegressionDetector {
    baseline_path: PathBuf,
    regression_threshold: f64, // Default 20% (0.2)
}

impl RegressionDetector {
    fn new() -> Self {
        Self {
            baseline_path: PathBuf::from("tests/performance_baselines.json"),
            regression_threshold: 0.2,
        }
    }

    fn load_baselines(&self) -> HashMap<String, PerformanceBaseline> {
        if let Ok(data) = fs::read_to_string(&self.baseline_path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            HashMap::new()
        }
    }

    fn save_baselines(&self, baselines: &HashMap<String, PerformanceBaseline>) {
        if let Ok(data) = serde_json::to_string_pretty(baselines) {
            let _ = fs::create_dir_all(self.baseline_path.parent().unwrap());
            let _ = fs::write(&self.baseline_path, data);
        }
    }

    fn detect_regression(
        &self,
        current: &PerformanceMeasurement,
        baseline: &PerformanceBaseline,
    ) -> Option<RegressionReport> {
        let current_mean = current.mean.as_nanos() as f64;
        let baseline_mean = baseline.mean_duration_ns as f64;

        // Calculate percentage change
        let change = (current_mean - baseline_mean) / baseline_mean;

        // Account for standard deviation in comparison
        let combined_std_dev =
            (current.std_dev.as_nanos() as f64 + baseline.std_deviation_ns as f64) / 2.0;
        let significant_change = (current_mean - baseline_mean).abs() > combined_std_dev * 2.0;

        if change > self.regression_threshold && significant_change {
            Some(RegressionReport {
                operation: baseline.operation.clone(),
                implementation: baseline.implementation.clone(),
                baseline_mean: Duration::from_nanos(baseline.mean_duration_ns),
                current_mean: current.mean,
                percentage_change: change * 100.0,
                is_regression: true,
                details: format!(
                    "Performance regression detected: {:.1}% slower than baseline",
                    change * 100.0
                ),
            })
        } else if change < -self.regression_threshold && significant_change {
            Some(RegressionReport {
                operation: baseline.operation.clone(),
                implementation: baseline.implementation.clone(),
                baseline_mean: Duration::from_nanos(baseline.mean_duration_ns),
                current_mean: current.mean,
                percentage_change: change * 100.0,
                is_regression: false,
                details: format!(
                    "Performance improvement detected: {:.1}% faster than baseline",
                    -change * 100.0
                ),
            })
        } else {
            None
        }
    }
}

/// Regression analysis report
#[derive(Debug)]
struct RegressionReport {
    operation: String,
    implementation: String,
    baseline_mean: Duration,
    current_mean: Duration,
    percentage_change: f64,
    is_regression: bool,
    details: String,
}

/// Test data generators
mod test_data {
    use super::*;

    pub fn generate_threats(count: usize) -> Vec<Threat> {
        (0..count)
            .map(|i| Threat {
                threat_type: match i % 5 {
                    0 => ThreatType::SqlInjection,
                    1 => ThreatType::CommandInjection,
                    2 => ThreatType::XssAttempt,
                    3 => ThreatType::PathTraversal,
                    _ => ThreatType::UnicodeExploit,
                },
                severity: match i % 3 {
                    0 => Severity::Low,
                    1 => Severity::Medium,
                    _ => Severity::High,
                },
                location: kindly_guard_server::scanner::Location::Text {
                    offset: i * 10,
                    length: 10,
                },
                description: format!("Test threat {}", i),
                remediation: None,
            })
            .collect()
    }

    pub fn generate_content_samples(count: usize) -> Vec<String> {
        (0..count)
            .map(|i| match i % 5 {
                0 => format!("SELECT * FROM users WHERE id = '{}'", i),
                1 => format!("rm -rf /tmp/test{} && echo done", i),
                2 => format!("<script>alert('{}')</script>", i),
                3 => format!("../../etc/passwd{}", i),
                _ => format!("Normal content with unicode: test{} \u{202E}", i),
            })
            .collect()
    }

    pub fn generate_large_content(size_kb: usize) -> String {
        let base = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";
        let repeat_count = (size_kb * 1024) / base.len();
        base.repeat(repeat_count)
    }
}

/// Performance benchmark runner
struct BenchmarkRunner {
    runtime: Runtime,
    warmup_iterations: usize,
    measurement_iterations: usize,
}

impl BenchmarkRunner {
    fn new() -> Self {
        Self {
            runtime: Runtime::new().unwrap(),
            warmup_iterations: 100,
            measurement_iterations: 1000,
        }
    }

    fn measure_neutralization<N: ThreatNeutralizer + Send + Sync + 'static>(
        &self,
        neutralizer: Arc<N>,
        threats: &[Threat],
        content: &str,
    ) -> PerformanceMeasurement {
        // Warmup
        for threat in threats.iter().cycle().take(self.warmup_iterations) {
            let _ = self
                .runtime
                .block_on(neutralizer.neutralize(threat, content));
        }

        // Measurement
        let mut durations = Vec::with_capacity(self.measurement_iterations);

        for threat in threats.iter().cycle().take(self.measurement_iterations) {
            let neutralizer = neutralizer.clone();
            let threat = threat.clone();
            let content = content.to_string();

            let start = Instant::now();
            let _ = self
                .runtime
                .block_on(async move { neutralizer.neutralize(&threat, &content).await });
            durations.push(start.elapsed());
        }

        PerformanceMeasurement::from_durations(durations)
    }

    fn measure_scanning<S: SecurityScanner + Send + Sync + 'static>(
        &self,
        scanner: Arc<S>,
        content_samples: &[String],
    ) -> PerformanceMeasurement {
        // Warmup
        for content in content_samples.iter().cycle().take(self.warmup_iterations) {
            let _ = scanner.scan_text(content);
        }

        // Measurement
        let mut durations = Vec::with_capacity(self.measurement_iterations);

        for content in content_samples
            .iter()
            .cycle()
            .take(self.measurement_iterations)
        {
            let scanner = scanner.clone();
            let content = content.clone();

            let start = Instant::now();
            let _ = scanner.scan_text(&content);
            durations.push(start.elapsed());
        }

        PerformanceMeasurement::from_durations(durations)
    }

    fn measure_batch_operation<F, T>(
        &self,
        operation: F,
        batch_size: usize,
    ) -> PerformanceMeasurement
    where
        F: Fn() -> T + Clone + Send + 'static,
        T: Send + 'static,
    {
        // Warmup
        for _ in 0..self.warmup_iterations {
            for _ in 0..batch_size {
                operation();
            }
        }

        // Measurement
        let mut durations = Vec::with_capacity(self.measurement_iterations);

        for _ in 0..self.measurement_iterations {
            let start = Instant::now();
            for _ in 0..batch_size {
                operation();
            }
            durations.push(start.elapsed() / batch_size as u32);
        }

        PerformanceMeasurement::from_durations(durations)
    }
}

// Test modules
#[cfg(test)]
mod tests {
    use super::*;
    use kindly_guard_server::resilience::{create_circuit_breaker, create_retry_strategy};

    fn create_test_config() -> Config {
        Config::default()
    }

    fn create_standard_neutralizer() -> Arc<dyn ThreatNeutralizer> {
        let config = create_test_config();
        Arc::new(kindly_guard_server::standard_impl::StandardNeutralizer::new())
    }

    #[cfg(feature = "enhanced")]
    fn create_enhanced_neutralizer() -> Arc<dyn ThreatNeutralizer> {
        let config = create_test_config();
        Arc::new(kindly_guard_server::enhanced_impl::EnhancedNeutralizer::new(config))
    }

    fn create_standard_scanner() -> Arc<dyn SecurityScanner> {
        Arc::new(kindly_guard_server::scanner::create_scanner())
    }

    #[test]
    fn test_neutralization_performance_baseline() {
        let runner = BenchmarkRunner::new();
        let detector = RegressionDetector::new();
        let mut baselines = detector.load_baselines();

        let neutralizer = create_standard_neutralizer();
        let threats = test_data::generate_threats(10);
        let content = "Test content with potential threats";

        let measurement = runner.measure_neutralization(neutralizer, &threats, content);

        println!("Standard Neutralization Performance:");
        println!("  Mean: {:?}", measurement.mean);
        println!("  Std Dev: {:?}", measurement.std_dev);
        println!("  P50: {:?}", measurement.p50);
        println!("  P95: {:?}", measurement.p95);
        println!("  P99: {:?}", measurement.p99);

        let key = "neutralization_standard".to_string();
        if let Some(baseline) = baselines.get(&key) {
            if let Some(report) = detector.detect_regression(&measurement, baseline) {
                if report.is_regression {
                    panic!("{}", report.details);
                } else {
                    println!("{}", report.details);
                }
            }
        } else {
            // Save as new baseline
            baselines.insert(key, measurement.to_baseline("neutralization", "standard"));
            detector.save_baselines(&baselines);
        }
    }

    #[cfg(feature = "enhanced")]
    #[test]
    fn test_enhanced_neutralization_performance() {
        let runner = BenchmarkRunner::new();
        let detector = RegressionDetector::new();
        let mut baselines = detector.load_baselines();

        let neutralizer = create_enhanced_neutralizer();
        let threats = test_data::generate_threats(10);
        let content = "Test content with potential threats";

        let measurement = runner.measure_neutralization(neutralizer, &threats, content);

        println!("Enhanced Neutralization Performance:");
        println!("  Mean: {:?}", measurement.mean);
        println!("  Std Dev: {:?}", measurement.std_dev);
        println!("  P50: {:?}", measurement.p50);
        println!("  P95: {:?}", measurement.p95);
        println!("  P99: {:?}", measurement.p99);

        let key = "neutralization_enhanced".to_string();
        if let Some(baseline) = baselines.get(&key) {
            if let Some(report) = detector.detect_regression(&measurement, baseline) {
                if report.is_regression {
                    panic!("{}", report.details);
                } else {
                    println!("{}", report.details);
                }
            }
        } else {
            baselines.insert(key, measurement.to_baseline("neutralization", "enhanced"));
            detector.save_baselines(&baselines);
        }
    }

    #[test]
    fn test_scanning_performance_baseline() {
        let runner = BenchmarkRunner::new();
        let detector = RegressionDetector::new();
        let mut baselines = detector.load_baselines();

        let scanner = create_standard_scanner();
        let content_samples = test_data::generate_content_samples(50);

        let measurement = runner.measure_scanning(scanner, &content_samples);

        println!("Scanning Performance:");
        println!("  Mean: {:?}", measurement.mean);
        println!("  Std Dev: {:?}", measurement.std_dev);
        println!("  P50: {:?}", measurement.p50);
        println!("  P95: {:?}", measurement.p95);
        println!("  P99: {:?}", measurement.p99);

        let key = "scanning_standard".to_string();
        if let Some(baseline) = baselines.get(&key) {
            if let Some(report) = detector.detect_regression(&measurement, baseline) {
                if report.is_regression {
                    panic!("{}", report.details);
                } else {
                    println!("{}", report.details);
                }
            }
        } else {
            baselines.insert(key, measurement.to_baseline("scanning", "standard"));
            detector.save_baselines(&baselines);
        }
    }

    #[test]
    fn test_large_content_performance() {
        let runner = BenchmarkRunner::new();
        let detector = RegressionDetector::new();
        let mut baselines = detector.load_baselines();

        let scanner = create_standard_scanner();
        let large_content = test_data::generate_large_content(100); // 100KB

        let measurement = runner.measure_batch_operation(|| scanner.scan_text(&large_content), 1);

        println!("Large Content Scanning Performance:");
        println!("  Mean: {:?}", measurement.mean);
        println!("  P99: {:?}", measurement.p99);

        let key = "large_content_scanning".to_string();
        if let Some(baseline) = baselines.get(&key) {
            if let Some(report) = detector.detect_regression(&measurement, baseline) {
                if report.is_regression {
                    panic!("{}", report.details);
                }
            }
        } else {
            baselines.insert(key, measurement.to_baseline("large_content", "standard"));
            detector.save_baselines(&baselines);
        }
    }

    #[test]
    fn test_batch_neutralization_performance() {
        let runner = BenchmarkRunner::new();
        let detector = RegressionDetector::new();
        let mut baselines = detector.load_baselines();

        let neutralizer = create_standard_neutralizer();
        let threats = test_data::generate_threats(100);
        let contents = test_data::generate_content_samples(100);

        let runtime = Runtime::new().unwrap();
        let measurement = runner.measure_batch_operation(
            move || {
                let neutralizer = neutralizer.clone();
                let threat = &threats[0];
                let content = &contents[0];
                runtime.block_on(async { neutralizer.neutralize(threat, content).await })
            },
            10, // Batch size
        );

        println!("Batch Neutralization Performance:");
        println!("  Mean per operation: {:?}", measurement.mean);
        println!("  P99 per operation: {:?}", measurement.p99);

        let key = "batch_neutralization".to_string();
        if let Some(baseline) = baselines.get(&key) {
            if let Some(report) = detector.detect_regression(&measurement, baseline) {
                if report.is_regression && report.percentage_change > 25.0 {
                    panic!("Significant regression: {}", report.details);
                }
            }
        } else {
            baselines.insert(
                key,
                measurement.to_baseline("batch_neutralization", "standard"),
            );
            detector.save_baselines(&baselines);
        }
    }

    #[test]
    fn test_statistical_significance() {
        // Test that our statistical analysis properly reduces false positives
        let detector = RegressionDetector::new();

        // Create baseline with known values
        let baseline = PerformanceBaseline {
            operation: "test_op".to_string(),
            implementation: "test".to_string(),
            mean_duration_ns: 1_000_000, // 1ms
            std_deviation_ns: 50_000,    // 50us
            samples: 1000,
            timestamp: chrono::Utc::now(),
            rust_version: "test".to_string(),
            os: "test".to_string(),
        };

        // Test within normal variation (should not trigger regression)
        let normal_variation = PerformanceMeasurement {
            durations: vec![Duration::from_micros(1050); 100],
            mean: Duration::from_micros(1050),
            std_dev: Duration::from_micros(50),
            min: Duration::from_micros(1000),
            max: Duration::from_micros(1100),
            p50: Duration::from_micros(1050),
            p95: Duration::from_micros(1090),
            p99: Duration::from_micros(1095),
        };

        assert!(detector
            .detect_regression(&normal_variation, &baseline)
            .is_none());

        // Test significant regression (should trigger)
        let regression = PerformanceMeasurement {
            durations: vec![Duration::from_micros(1300); 100],
            mean: Duration::from_micros(1300),
            std_dev: Duration::from_micros(50),
            min: Duration::from_micros(1250),
            max: Duration::from_micros(1350),
            p50: Duration::from_micros(1300),
            p95: Duration::from_micros(1340),
            p99: Duration::from_micros(1345),
        };

        let report = detector.detect_regression(&regression, &baseline).unwrap();
        assert!(report.is_regression);
        assert!(report.percentage_change > 20.0);
    }

    #[test]
    fn test_performance_report_generation() {
        let runner = BenchmarkRunner::new();
        let scanner = create_standard_scanner();
        let content_samples = test_data::generate_content_samples(10);

        let measurement = runner.measure_scanning(scanner, &content_samples);

        // Generate detailed performance report
        let report = format!(
            r#"Performance Report
==================
Operation: Text Scanning
Implementation: Standard
Samples: {}

Timing Statistics:
  Mean:     {:?}
  Std Dev:  {:?}
  Min:      {:?}
  Max:      {:?}
  
Percentiles:
  P50:      {:?}
  P95:      {:?}
  P99:      {:?}

Throughput:
  Ops/sec:  {:.2}
"#,
            measurement.durations.len(),
            measurement.mean,
            measurement.std_dev,
            measurement.min,
            measurement.max,
            measurement.p50,
            measurement.p95,
            measurement.p99,
            1_000_000_000.0 / measurement.mean.as_nanos() as f64
        );

        println!("{}", report);

        // Ensure report contains expected data
        assert!(report.contains("Performance Report"));
        assert!(report.contains("Ops/sec"));
    }
}

// Integration with CI/CD
#[cfg(test)]
mod ci_integration {
    use super::*;

    #[test]
    #[ignore] // Run with: cargo test --ignored -- --nocapture
    fn generate_ci_performance_report() {
        let runner = BenchmarkRunner::new();
        let detector = RegressionDetector::new();
        let baselines = detector.load_baselines();

        let mut has_regression = false;
        let mut report = String::from("CI Performance Report\n=====================\n\n");

        // Test all critical operations
        let operations = vec![
            ("neutralization", "Threat Neutralization"),
            ("scanning", "Content Scanning"),
            ("batch_ops", "Batch Operations"),
        ];

        for (key, name) in operations {
            report.push_str(&format!("{}\n", name));
            report.push_str(&format!("{}\n", "-".repeat(name.len())));

            if let Some(baseline) = baselines.get(&format!("{}_standard", key)) {
                report.push_str(&format!(
                    "Baseline: {:?} (±{:?})\n",
                    Duration::from_nanos(baseline.mean_duration_ns),
                    Duration::from_nanos(baseline.std_deviation_ns)
                ));

                // Would run actual measurement here in CI
                report.push_str("Current: [Would measure in CI]\n");
                report.push_str("Status: [Would compare in CI]\n");
            } else {
                report.push_str("No baseline established\n");
            }

            report.push_str("\n");
        }

        // Output for CI systems
        println!("{}", report);

        if has_regression {
            panic!("Performance regressions detected!");
        }
    }
}
