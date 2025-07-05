//! Example demonstrating flaky test management
//!
//! Run with: cargo run --example flaky_test_example

use std::path::Path;
use std::time::Duration;

use chrono::Utc;
use xtask::test::{
    BackoffStrategy, FlakyTestManager, RetryPolicy, TestExecution,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize manager with a temp directory for this example
    let temp_dir = tempfile::tempdir()?;
    let manager = FlakyTestManager::new(temp_dir.path()).await?;

    // Simulate a flaky test with intermittent failures
    println!("Simulating flaky test executions...");
    for i in 0..20 {
        let execution = TestExecution {
            test_name: "tests::network::connection_test".to_string(),
            timestamp: Utc::now(),
            passed: i % 3 != 0, // Fails every 3rd run
            duration: Duration::from_millis(100 + (i * 10) % 50),
            retry_attempt: 0,
            error_message: if i % 3 == 0 {
                Some(format!("Connection timeout on attempt {}", i))
            } else {
                None
            },
            output: None,
        };
        
        manager.record_execution(execution).await?;
    }

    // Simulate a consistently passing test
    for i in 0..10 {
        let execution = TestExecution {
            test_name: "tests::unit::math_test".to_string(),
            timestamp: Utc::now(),
            passed: true,
            duration: Duration::from_millis(5),
            retry_attempt: 0,
            error_message: None,
            output: None,
        };
        
        manager.record_execution(execution).await?;
    }

    // Check flaky tests
    println!("\n=== Flaky Tests ===");
    let flaky_tests = manager.get_flaky_tests().await;
    for (name, stats) in &flaky_tests {
        println!(
            "{}: flakiness={:.2}, pass_rate={:.1}%",
            name,
            stats.flakiness_score,
            (stats.passed_runs as f64 / stats.total_runs as f64) * 100.0
        );
    }

    // Get retry policy for the flaky test
    let policy = manager.get_retry_policy("tests::network::connection_test").await;
    println!(
        "\nRetry policy for flaky test: {} retries with {:?} backoff",
        policy.max_retries,
        match &policy.backoff {
            BackoffStrategy::None => "no",
            BackoffStrategy::Fixed { .. } => "fixed",
            BackoffStrategy::Linear { .. } => "linear",
            BackoffStrategy::Exponential { .. } => "exponential",
            BackoffStrategy::ExponentialJitter { .. } => "exponential with jitter",
        }
    );

    // Generate report
    let report = manager.generate_report(&xtask::utils::Context::default()).await?;
    println!("\n=== Flakiness Report Summary ===");
    println!("Total tests tracked: {}", report.total_tests);
    println!("Flaky tests: {}", report.flaky_tests);
    println!("Quarantined tests: {}", report.quarantined_tests);

    // Generate nextest configuration
    println!("\n=== Generated Nextest Config ===");
    let nextest_config = manager.generate_nextest_config().await?;
    println!("{}", nextest_config);

    // Demonstrate quarantine
    manager.quarantine_test(
        "tests::network::connection_test",
        "Too flaky for CI".to_string()
    ).await?;
    
    let quarantined = manager.get_quarantined_tests().await;
    println!("\n=== Quarantined Tests ===");
    for (name, stats) in quarantined {
        println!(
            "{}: {}",
            name,
            stats.quarantine_reason.unwrap_or_else(|| "No reason".to_string())
        );
    }

    Ok(())
}