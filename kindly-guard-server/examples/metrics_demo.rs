// Example demonstrating the new metrics methods
use kindly_guard_server::telemetry::metrics::MetricsCollector;
use std::time::Duration;
use std::thread;

fn main() {
    // Create a metrics collector
    let collector = MetricsCollector::new();

    // Simulate various operations
    println!("Recording metrics...");

    // Record some errors
    collector.record_error("connection_timeout");
    collector.record_error("invalid_input");
    collector.record_error("connection_timeout"); // duplicate to show counting

    // Record successful scans
    collector.record_scan_success("unicode");
    collector.record_scan_success("injection");
    collector.record_scan_success("xss");
    collector.record_scan_success("unicode"); // another unicode scan

    // Record storage operations
    collector.record_storage_success("write");
    collector.record_storage_success("read");
    collector.record_storage_success("delete");

    // Record service status events
    collector.record_service_unavailable();
    thread::sleep(Duration::from_millis(100));
    collector.record_degraded_service();

    // Record verification success
    collector.record_verification_success();
    collector.record_verification_success();

    // Get a snapshot of metrics
    let snapshot = collector.get_snapshot();

    // Display the metrics
    println!("\nMetrics Snapshot at: {}", snapshot.timestamp);
    println!("==========================================");
    
    for metric in &snapshot.metrics {
        match metric {
            kindly_guard_server::telemetry::metrics::Metric::Counter { name, value, labels } => {
                if labels.is_empty() {
                    println!("{}: {}", name, value);
                } else {
                    let label_str: Vec<String> = labels.iter()
                        .map(|(k, v)| format!("{}={}", k, v))
                        .collect();
                    println!("{}{{{}}}: {}", name, label_str.join(","), value);
                }
            }
            _ => {} // We're only using counters in this demo
        }
    }

    println!("\nSummary:");
    println!("Total commands: {}", snapshot.summary.total_commands);
    println!("Error rate: {:.2}%", snapshot.summary.error_rate * 100.0);
    println!("Total threats detected: {}", snapshot.summary.total_threats_detected);
}