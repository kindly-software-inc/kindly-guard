//! Integration tests for flaky test management

use std::time::Duration;

use chrono::Utc;
use tempfile::TempDir;
use xtask::test::{BackoffStrategy, FlakyTestManager, RetryPolicy, TestExecution};

#[tokio::test]
async fn test_flaky_detection() {
    let temp_dir = TempDir::new().unwrap();
    let manager = FlakyTestManager::new(temp_dir.path()).await.unwrap();

    // Simulate a flaky test pattern
    for i in 0..10 {
        let execution = TestExecution {
            test_name: "flaky::test".to_string(),
            timestamp: Utc::now(),
            passed: i % 3 != 0, // Fails every 3rd run
            duration: Duration::from_millis(100),
            retry_attempt: 0,
            error_message: if i % 3 == 0 {
                Some("Intermittent failure".to_string())
            } else {
                None
            },
            output: None,
        };
        
        manager.record_execution(execution).await.unwrap();
    }

    // Check if test is detected as flaky
    let flaky_tests = manager.get_flaky_tests().await;
    assert_eq!(flaky_tests.len(), 1);
    assert_eq!(flaky_tests[0].0, "flaky::test");
    assert!(flaky_tests[0].1.flakiness_score > 0.1);
}

#[tokio::test]
async fn test_quarantine_functionality() {
    let temp_dir = TempDir::new().unwrap();
    let manager = FlakyTestManager::new(temp_dir.path()).await.unwrap();

    // Quarantine a test
    manager
        .quarantine_test("problem::test", "Manual quarantine".to_string())
        .await
        .unwrap();

    // Verify it's quarantined
    let quarantined = manager.get_quarantined_tests().await;
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].0, "problem::test");
    assert_eq!(
        quarantined[0].1.quarantine_reason,
        Some("Manual quarantine".to_string())
    );

    // Un-quarantine
    manager.unquarantine_test("problem::test").await.unwrap();

    // Verify it's no longer quarantined
    let quarantined = manager.get_quarantined_tests().await;
    assert_eq!(quarantined.len(), 0);
}

#[tokio::test]
async fn test_retry_policy_generation() {
    let temp_dir = TempDir::new().unwrap();
    let manager = FlakyTestManager::new(temp_dir.path()).await.unwrap();

    // Create a custom retry policy
    let custom_policy = RetryPolicy {
        max_retries: 5,
        backoff: BackoffStrategy::Exponential {
            base: Duration::from_millis(200),
            max: Duration::from_secs(10),
        },
        fail_fast: false,
    };

    manager
        .set_retry_policy("custom::test".to_string(), custom_policy.clone())
        .await
        .unwrap();

    // Verify the policy is returned
    let policy = manager.get_retry_policy("custom::test").await;
    assert_eq!(policy.max_retries, 5);
}

#[tokio::test]
async fn test_nextest_config_generation() {
    let temp_dir = TempDir::new().unwrap();
    let manager = FlakyTestManager::new(temp_dir.path()).await.unwrap();

    // Record some flaky test data
    for i in 0..10 {
        let execution = TestExecution {
            test_name: "tests::flaky_one".to_string(),
            timestamp: Utc::now(),
            passed: i % 2 == 0,
            duration: Duration::from_millis(50),
            retry_attempt: 0,
            error_message: None,
            output: None,
        };
        
        manager.record_execution(execution).await.unwrap();
    }

    // Generate nextest config
    let config = manager.generate_nextest_config().await.unwrap();
    
    // Verify it contains proper configuration
    assert!(config.contains("[profile.default]"));
    assert!(config.contains("retries"));
    assert!(config.contains("tests::flaky_one"));
}

#[tokio::test]
async fn test_persistence() {
    let temp_dir = TempDir::new().unwrap();
    
    // Create manager and record data
    {
        let manager = FlakyTestManager::new(temp_dir.path()).await.unwrap();
        
        let execution = TestExecution {
            test_name: "persistent::test".to_string(),
            timestamp: Utc::now(),
            passed: false,
            duration: Duration::from_millis(100),
            retry_attempt: 0,
            error_message: Some("Test failed".to_string()),
            output: None,
        };
        
        manager.record_execution(execution).await.unwrap();
    }

    // Create new manager and verify data persisted
    {
        let manager = FlakyTestManager::new(temp_dir.path()).await.unwrap();
        let flaky_tests = manager.get_flaky_tests().await;
        
        // Should have the test data
        assert!(flaky_tests.iter().any(|(name, _)| name == "persistent::test"));
    }
}

#[test]
fn test_backoff_strategies() {
    // Test exponential backoff
    let strategy = BackoffStrategy::Exponential {
        base: Duration::from_millis(100),
        max: Duration::from_secs(10),
    };
    
    assert_eq!(
        FlakyTestManager::calculate_backoff(&strategy, 1),
        Duration::from_millis(100)
    );
    assert_eq!(
        FlakyTestManager::calculate_backoff(&strategy, 2),
        Duration::from_millis(200)
    );
    assert_eq!(
        FlakyTestManager::calculate_backoff(&strategy, 3),
        Duration::from_millis(400)
    );
    
    // Test max limit
    assert_eq!(
        FlakyTestManager::calculate_backoff(&strategy, 20),
        Duration::from_secs(10)
    );
    
    // Test linear backoff
    let linear = BackoffStrategy::Linear {
        base: Duration::from_millis(50),
    };
    
    assert_eq!(
        FlakyTestManager::calculate_backoff(&linear, 1),
        Duration::from_millis(50)
    );
    assert_eq!(
        FlakyTestManager::calculate_backoff(&linear, 3),
        Duration::from_millis(150)
    );
}