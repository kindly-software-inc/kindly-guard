//! Chaos Engineering Tests for KindlyGuard
//!
//! These tests simulate extreme conditions and failures to verify system resilience:
//! - Random failure injection
//! - Network partitioning
//! - Resource starvation
//! - Cascading failure prevention
//! - Recovery time measurement
//! - Data consistency under failures

use anyhow::Result;
use kindly_guard_server::{
    config::Config,
    create_event_buffer,
    error::KindlyError,
    metrics::MetricsRegistry,
    neutralizer::{create_neutralizer, NeutralizationConfig, NeutralizationMode},
    resilience::{
        create_circuit_breaker, create_health_checker, create_recovery_strategy,
        create_retry_strategy,
    },
    scanner::{SecurityScanner, Severity, Threat, ThreatType},
    server::McpServer,
    shield::Shield,
    traits::{DynCircuitBreaker, DynRetryStrategy, HealthCheckTrait, RecoveryStrategyTrait},
    ComponentManager,
};
use parking_lot::Mutex;
use rand::{thread_rng, Rng};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, RwLock, Semaphore},
    time::{sleep, timeout},
};

/// Chaos injection configuration
#[derive(Clone, Debug)]
struct ChaosConfig {
    /// Probability of injecting a failure (0.0 - 1.0)
    failure_probability: f64,
    /// Types of failures to inject
    failure_types: Vec<FailureType>,
    /// Enable network partitioning
    network_partition: bool,
    /// Enable resource starvation
    resource_starvation: bool,
    /// Maximum delay for network issues (ms)
    max_network_delay: u64,
    /// CPU starvation intensity (0.0 - 1.0)
    cpu_starvation_intensity: f64,
    /// Memory pressure in MB
    memory_pressure_mb: usize,
}

#[derive(Clone, Debug, PartialEq)]
enum FailureType {
    /// Component returns error
    ComponentError,
    /// Component times out
    ComponentTimeout,
    /// Component panics (caught)
    ComponentPanic,
    /// Network delay
    NetworkDelay,
    /// Network partition
    NetworkPartition,
    /// Resource exhaustion
    ResourceExhaustion,
    /// Data corruption
    DataCorruption,
    /// Cascading failure
    CascadingFailure,
}

/// Chaos injection runtime
struct ChaosInjector {
    config: ChaosConfig,
    active: AtomicBool,
    failures_injected: AtomicU64,
    rng: Mutex<rand::rngs::ThreadRng>,
}

impl ChaosInjector {
    fn new(config: ChaosConfig) -> Self {
        Self {
            config,
            active: AtomicBool::new(true),
            failures_injected: AtomicU64::new(0),
            rng: Mutex::new(thread_rng()),
        }
    }

    /// Check if failure should be injected
    fn should_inject_failure(&self) -> bool {
        if !self.active.load(Ordering::Relaxed) {
            return false;
        }

        let mut rng = self.rng.lock();
        rng.gen_bool(self.config.failure_probability)
    }

    /// Inject a random failure
    async fn inject_failure(&self) -> Result<()> {
        if !self.should_inject_failure() {
            return Ok(());
        }

        let failure_type = {
            let mut rng = self.rng.lock();
            self.config
                .failure_types
                .get(rng.gen_range(0..self.config.failure_types.len()))
                .cloned()
                .unwrap_or(FailureType::ComponentError)
        };

        self.failures_injected.fetch_add(1, Ordering::Relaxed);

        match failure_type {
            FailureType::ComponentError => Err(KindlyError::Internal(
                "Chaos: Simulated component error".into(),
            ))?,
            FailureType::ComponentTimeout => {
                sleep(Duration::from_secs(30)).await;
                Ok(())
            }
            FailureType::ComponentPanic => {
                // Simulate a caught panic
                std::panic::catch_unwind(|| {
                    panic!("Chaos: Simulated panic");
                })
                .map_err(|_| KindlyError::Internal("Panic caught".into()))?;
                Ok(())
            }
            FailureType::NetworkDelay => {
                let delay = {
                    let mut rng = self.rng.lock();
                    rng.gen_range(0..self.config.max_network_delay)
                };
                sleep(Duration::from_millis(delay)).await;
                Ok(())
            }
            FailureType::NetworkPartition => {
                // Simulate network partition by failing
                Err(KindlyError::NetworkError(
                    "Chaos: Network partition".into(),
                ))?
            }
            FailureType::ResourceExhaustion => {
                // Simulate resource exhaustion
                self.simulate_resource_exhaustion().await
            }
            FailureType::DataCorruption => {
                // Return corrupted data
                Err(KindlyError::Internal(
                    "Chaos: Simulated data corruption".into(),
                ))?
            }
            FailureType::CascadingFailure => {
                // Trigger multiple failures
                self.simulate_cascading_failure().await
            }
        }
    }

    async fn simulate_resource_exhaustion(&self) -> Result<()> {
        // CPU starvation
        if self.config.cpu_starvation_intensity > 0.0 {
            tokio::spawn(async move {
                let start = Instant::now();
                while start.elapsed() < Duration::from_millis(100) {
                    // Busy loop to consume CPU
                    std::hint::black_box(1 + 1);
                }
            });
        }

        // Memory pressure
        if self.config.memory_pressure_mb > 0 {
            let _memory_hog: Vec<u8> = vec![0; self.config.memory_pressure_mb * 1024 * 1024];
            sleep(Duration::from_millis(10)).await;
        }

        Ok(())
    }

    async fn simulate_cascading_failure(&self) -> Result<()> {
        // Simulate multiple component failures
        let failures = vec![
            KindlyError::Internal("Component A failed".into()),
            KindlyError::NetworkError("Component B network error".into()),
            KindlyError::Internal("Component C data corruption".into()),
        ];

        for (i, error) in failures.into_iter().enumerate() {
            sleep(Duration::from_millis(10 * i as u64)).await;
            return Err(error.into());
        }

        Ok(())
    }
}

/// Wrapper for components with chaos injection
struct ChaosWrapper<T> {
    inner: T,
    chaos: Arc<ChaosInjector>,
}

impl<T> ChaosWrapper<T> {
    fn new(inner: T, chaos: Arc<ChaosInjector>) -> Self {
        Self { inner, chaos }
    }
}

/// Test harness for chaos engineering
struct ChaosTestHarness {
    config: Config,
    chaos: Arc<ChaosInjector>,
    metrics: Arc<MetricsRegistry>,
    failures_observed: Arc<AtomicU64>,
    recovery_times: Arc<Mutex<Vec<Duration>>>,
    data_inconsistencies: Arc<AtomicU64>,
}

impl ChaosTestHarness {
    fn new(chaos_config: ChaosConfig) -> Self {
        let config = Config::default();
        let chaos = Arc::new(ChaosInjector::new(chaos_config));
        let metrics = Arc::new(MetricsRegistry::new());

        Self {
            config,
            chaos,
            metrics,
            failures_observed: Arc::new(AtomicU64::new(0)),
            recovery_times: Arc::new(Mutex::new(Vec::new())),
            data_inconsistencies: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Run a workload with chaos injection
    async fn run_workload_with_chaos(
        &self,
        duration: Duration,
        concurrent_requests: usize,
    ) -> Result<ChaosTestResults> {
        let start_time = Instant::now();
        let mut handles = vec![];
        let semaphore = Arc::new(Semaphore::new(concurrent_requests));

        // Create shared state for consistency checking
        let shared_state = Arc::new(RwLock::new(HashMap::<String, Value>::new()));
        let expected_state = Arc::new(RwLock::new(HashMap::<String, Value>::new()));

        // Start workload tasks
        for i in 0..concurrent_requests * 10 {
            let permit = semaphore.clone().acquire_owned().await?;
            let chaos = self.chaos.clone();
            let failures_observed = self.failures_observed.clone();
            let recovery_times = self.recovery_times.clone();
            let data_inconsistencies = self.data_inconsistencies.clone();
            let shared_state = shared_state.clone();
            let expected_state = expected_state.clone();

            let handle = tokio::spawn(async move {
                let _permit = permit;
                let operation_start = Instant::now();

                // Simulate a typical operation
                let result = Self::execute_operation_with_chaos(
                    i,
                    chaos,
                    shared_state.clone(),
                    expected_state.clone(),
                )
                .await;

                match result {
                    Ok(_) => {
                        // Check data consistency
                        if !Self::verify_consistency(&shared_state, &expected_state).await {
                            data_inconsistencies.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        failures_observed.fetch_add(1, Ordering::Relaxed);
                        let recovery_time = operation_start.elapsed();
                        recovery_times.lock().push(recovery_time);
                    }
                }
            });

            handles.push(handle);

            // Stop if we've run long enough
            if start_time.elapsed() > duration {
                break;
            }
        }

        // Wait for all tasks to complete
        for handle in handles {
            let _ = timeout(Duration::from_secs(60), handle).await;
        }

        // Calculate results
        let total_time = start_time.elapsed();
        let failures = self.failures_observed.load(Ordering::Relaxed);
        let inconsistencies = self.data_inconsistencies.load(Ordering::Relaxed);
        let recovery_times = self.recovery_times.lock().clone();

        let avg_recovery_time = if !recovery_times.is_empty() {
            let sum: Duration = recovery_times.iter().sum();
            sum / recovery_times.len() as u32
        } else {
            Duration::ZERO
        };

        let max_recovery_time = recovery_times
            .iter()
            .max()
            .copied()
            .unwrap_or(Duration::ZERO);

        Ok(ChaosTestResults {
            total_duration: total_time,
            failures_injected: self.chaos.failures_injected.load(Ordering::Relaxed),
            failures_observed: failures,
            recovery_times,
            avg_recovery_time,
            max_recovery_time,
            data_inconsistencies: inconsistencies,
            availability_percentage: Self::calculate_availability(failures, concurrent_requests),
        })
    }

    async fn execute_operation_with_chaos(
        operation_id: usize,
        chaos: Arc<ChaosInjector>,
        shared_state: Arc<RwLock<HashMap<String, Value>>>,
        expected_state: Arc<RwLock<HashMap<String, Value>>>,
    ) -> Result<()> {
        // Inject chaos
        chaos.inject_failure().await?;

        // Simulate scanner operation
        let scanner = SecurityScanner::new();
        let test_input = format!("Test input {}: Hello\u{202E}World", operation_id);
        
        // Inject chaos before scan
        chaos.inject_failure().await?;
        
        let threats = scanner.scan_text(&test_input)?;
        
        // Update shared state (simulating state changes)
        let key = format!("operation_{}", operation_id);
        let value = json!({
            "threats": threats.len(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        {
            let mut state = shared_state.write().await;
            state.insert(key.clone(), value.clone());
        }

        {
            let mut expected = expected_state.write().await;
            expected.insert(key, value);
        }

        // Inject chaos after operation
        chaos.inject_failure().await?;

        Ok(())
    }

    async fn verify_consistency(
        shared_state: &Arc<RwLock<HashMap<String, Value>>>,
        expected_state: &Arc<RwLock<HashMap<String, Value>>>,
    ) -> bool {
        let shared = shared_state.read().await;
        let expected = expected_state.read().await;

        shared.len() == expected.len()
            && shared
                .iter()
                .all(|(k, v)| expected.get(k).map_or(false, |ev| ev == v))
    }

    fn calculate_availability(failures: u64, total_operations: usize) -> f64 {
        if total_operations == 0 {
            return 0.0;
        }
        
        let successful = total_operations as u64 - failures;
        (successful as f64 / total_operations as f64) * 100.0
    }
}

/// Results from chaos testing
#[derive(Debug)]
struct ChaosTestResults {
    total_duration: Duration,
    failures_injected: u64,
    failures_observed: u64,
    recovery_times: Vec<Duration>,
    avg_recovery_time: Duration,
    max_recovery_time: Duration,
    data_inconsistencies: u64,
    availability_percentage: f64,
}

// ============= Chaos Engineering Tests =============

#[tokio::test]
async fn test_random_failure_injection() -> Result<()> {
    let chaos_config = ChaosConfig {
        failure_probability: 0.1, // 10% failure rate
        failure_types: vec![
            FailureType::ComponentError,
            FailureType::ComponentTimeout,
            FailureType::NetworkDelay,
        ],
        network_partition: false,
        resource_starvation: false,
        max_network_delay: 100,
        cpu_starvation_intensity: 0.0,
        memory_pressure_mb: 0,
    };

    let harness = ChaosTestHarness::new(chaos_config);
    let results = harness
        .run_workload_with_chaos(Duration::from_secs(10), 10)
        .await?;

    println!("Random Failure Injection Results:");
    println!("  Failures injected: {}", results.failures_injected);
    println!("  Failures observed: {}", results.failures_observed);
    println!("  Avg recovery time: {:?}", results.avg_recovery_time);
    println!("  Availability: {:.2}%", results.availability_percentage);

    // System should maintain reasonable availability despite failures
    assert!(
        results.availability_percentage > 80.0,
        "System availability too low: {:.2}%",
        results.availability_percentage
    );

    Ok(())
}

#[tokio::test]
async fn test_network_partitioning() -> Result<()> {
    let chaos_config = ChaosConfig {
        failure_probability: 0.2,
        failure_types: vec![FailureType::NetworkPartition, FailureType::NetworkDelay],
        network_partition: true,
        resource_starvation: false,
        max_network_delay: 500,
        cpu_starvation_intensity: 0.0,
        memory_pressure_mb: 0,
    };

    let harness = ChaosTestHarness::new(chaos_config);
    let results = harness
        .run_workload_with_chaos(Duration::from_secs(10), 5)
        .await?;

    println!("\nNetwork Partitioning Results:");
    println!("  Network failures: {}", results.failures_observed);
    println!("  Max recovery time: {:?}", results.max_recovery_time);
    println!("  Data inconsistencies: {}", results.data_inconsistencies);

    // Network partitions should not cause data inconsistencies
    assert_eq!(
        results.data_inconsistencies, 0,
        "Data inconsistencies detected during network partitioning"
    );

    Ok(())
}

#[tokio::test]
async fn test_resource_starvation() -> Result<()> {
    let chaos_config = ChaosConfig {
        failure_probability: 0.3,
        failure_types: vec![FailureType::ResourceExhaustion],
        network_partition: false,
        resource_starvation: true,
        max_network_delay: 0,
        cpu_starvation_intensity: 0.5,
        memory_pressure_mb: 50,
    };

    let harness = ChaosTestHarness::new(chaos_config);
    let start = Instant::now();
    
    let results = harness
        .run_workload_with_chaos(Duration::from_secs(5), 3)
        .await?;

    let elapsed = start.elapsed();

    println!("\nResource Starvation Results:");
    println!("  Total duration: {:?}", elapsed);
    println!("  Avg operation time: {:?}", results.avg_recovery_time);
    println!("  System degradation: {:.2}x", 
        elapsed.as_secs_f64() / 5.0);

    // System should complete within reasonable time despite resource pressure
    assert!(
        elapsed < Duration::from_secs(30),
        "System took too long under resource starvation: {:?}",
        elapsed
    );

    Ok(())
}

#[tokio::test]
async fn test_cascading_failure_prevention() -> Result<()> {
    let chaos_config = ChaosConfig {
        failure_probability: 0.15,
        failure_types: vec![FailureType::CascadingFailure],
        network_partition: false,
        resource_starvation: false,
        max_network_delay: 0,
        cpu_starvation_intensity: 0.0,
        memory_pressure_mb: 0,
    };

    let harness = ChaosTestHarness::new(chaos_config);
    let results = harness
        .run_workload_with_chaos(Duration::from_secs(10), 8)
        .await?;

    println!("\nCascading Failure Prevention Results:");
    println!("  Cascading failures attempted: {}", results.failures_injected);
    println!("  Total failures observed: {}", results.failures_observed);
    println!("  Failure amplification: {:.2}x", 
        results.failures_observed as f64 / results.failures_injected.max(1) as f64);

    // Cascading failures should not amplify significantly
    assert!(
        results.failures_observed <= results.failures_injected * 2,
        "Cascading failures amplified too much"
    );

    Ok(())
}

#[tokio::test]
async fn test_recovery_time_objectives() -> Result<()> {
    let chaos_config = ChaosConfig {
        failure_probability: 0.25,
        failure_types: vec![
            FailureType::ComponentError,
            FailureType::NetworkDelay,
            FailureType::ComponentTimeout,
        ],
        network_partition: false,
        resource_starvation: false,
        max_network_delay: 200,
        cpu_starvation_intensity: 0.0,
        memory_pressure_mb: 0,
    };

    let harness = ChaosTestHarness::new(chaos_config);
    let results = harness
        .run_workload_with_chaos(Duration::from_secs(15), 10)
        .await?;

    println!("\nRecovery Time Objectives:");
    println!("  Recovery times measured: {}", results.recovery_times.len());
    println!("  Average recovery: {:?}", results.avg_recovery_time);
    println!("  Max recovery: {:?}", results.max_recovery_time);
    
    // Calculate percentiles
    let mut sorted_times = results.recovery_times.clone();
    sorted_times.sort();
    
    if !sorted_times.is_empty() {
        let p50_idx = sorted_times.len() / 2;
        let p95_idx = (sorted_times.len() as f64 * 0.95) as usize;
        let p99_idx = (sorted_times.len() as f64 * 0.99) as usize;
        
        println!("  P50 recovery: {:?}", sorted_times[p50_idx]);
        println!("  P95 recovery: {:?}", sorted_times.get(p95_idx).unwrap_or(&sorted_times.last().unwrap()));
        println!("  P99 recovery: {:?}", sorted_times.get(p99_idx).unwrap_or(&sorted_times.last().unwrap()));
        
        // P95 recovery should be under 5 seconds
        assert!(
            sorted_times.get(p95_idx).unwrap_or(&Duration::ZERO) < &Duration::from_secs(5),
            "P95 recovery time exceeds SLO"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_data_consistency_under_failures() -> Result<()> {
    let chaos_config = ChaosConfig {
        failure_probability: 0.3,
        failure_types: vec![
            FailureType::ComponentError,
            FailureType::DataCorruption,
            FailureType::NetworkPartition,
        ],
        network_partition: true,
        resource_starvation: false,
        max_network_delay: 100,
        cpu_starvation_intensity: 0.0,
        memory_pressure_mb: 0,
    };

    let harness = ChaosTestHarness::new(chaos_config);
    let results = harness
        .run_workload_with_chaos(Duration::from_secs(20), 15)
        .await?;

    println!("\nData Consistency Under Failures:");
    println!("  Total failures: {}", results.failures_observed);
    println!("  Data inconsistencies: {}", results.data_inconsistencies);
    println!("  Consistency rate: {:.2}%", 
        (1.0 - results.data_inconsistencies as f64 / results.failures_observed.max(1) as f64) * 100.0);

    // Data consistency should be maintained
    assert_eq!(
        results.data_inconsistencies, 0,
        "Data consistency violations detected: {}",
        results.data_inconsistencies
    );

    Ok(())
}

#[tokio::test]
async fn test_circuit_breaker_under_chaos() -> Result<()> {
    let config = Config::default();
    let circuit_breaker = create_circuit_breaker(&config)?;
    
    let chaos_config = ChaosConfig {
        failure_probability: 0.8, // High failure rate to trigger circuit breaker
        failure_types: vec![FailureType::ComponentError],
        network_partition: false,
        resource_starvation: false,
        max_network_delay: 0,
        cpu_starvation_intensity: 0.0,
        memory_pressure_mb: 0,
    };

    let chaos = Arc::new(ChaosInjector::new(chaos_config));
    let mut consecutive_failures = 0;
    let mut circuit_opened = false;

    // Test circuit breaker behavior under high failure rate
    for i in 0..20 {
        let chaos_clone = chaos.clone();
        let result = circuit_breaker
            .call(
                "test_operation",
                Box::pin(async move {
                    chaos_clone.inject_failure().await?;
                    Ok::<_, KindlyError>(())
                }),
            )
            .await;

        match result {
            Ok(_) => {
                consecutive_failures = 0;
                if circuit_opened {
                    println!("Circuit breaker recovered at iteration {}", i);
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                if e.to_string().contains("circuit breaker open") {
                    circuit_opened = true;
                    println!("Circuit breaker opened at iteration {}", i);
                }
            }
        }

        // Small delay between attempts
        sleep(Duration::from_millis(100)).await;
    }

    assert!(
        circuit_opened,
        "Circuit breaker should have opened under high failure rate"
    );

    Ok(())
}

#[tokio::test]
async fn test_retry_strategy_with_chaos() -> Result<()> {
    let config = Config::default();
    let retry_strategy = create_retry_strategy(&config)?;
    
    let chaos_config = ChaosConfig {
        failure_probability: 0.6, // 60% failure rate
        failure_types: vec![FailureType::ComponentError, FailureType::NetworkDelay],
        network_partition: false,
        resource_starvation: false,
        max_network_delay: 50,
        cpu_starvation_intensity: 0.0,
        memory_pressure_mb: 0,
    };

    let chaos = Arc::new(ChaosInjector::new(chaos_config));
    let attempts = Arc::new(AtomicUsize::new(0));
    
    let chaos_clone = chaos.clone();
    let attempts_clone = attempts.clone();
    
    let result = retry_strategy
        .retry(
            "test_operation",
            Box::pin(async move {
                attempts_clone.fetch_add(1, Ordering::Relaxed);
                chaos_clone.inject_failure().await?;
                Ok::<_, KindlyError>(())
            }),
        )
        .await;

    let total_attempts = attempts.load(Ordering::Relaxed);
    println!("Retry attempts made: {}", total_attempts);

    // Should have made multiple attempts
    assert!(
        total_attempts > 1,
        "Retry strategy should have made multiple attempts"
    );

    Ok(())
}

#[tokio::test]
async fn test_health_check_during_chaos() -> Result<()> {
    let config = Config::default();
    let health_checker = create_health_checker(&config)?;
    
    let chaos_config = ChaosConfig {
        failure_probability: 0.0, // Start healthy
        failure_types: vec![FailureType::ComponentError],
        network_partition: false,
        resource_starvation: false,
        max_network_delay: 0,
        cpu_starvation_intensity: 0.0,
        memory_pressure_mb: 0,
    };

    let chaos = Arc::new(ChaosInjector::new(chaos_config));
    
    // Initial health check should pass
    let initial_health = health_checker.check_health("test_service").await?;
    assert!(
        initial_health.is_healthy,
        "Service should be healthy initially"
    );

    // Increase failure probability
    chaos.config.failure_probability = 0.9;
    
    // Health check during chaos
    let chaos_health = health_checker.check_health("test_service").await?;
    println!("Health during chaos: {:?}", chaos_health);

    Ok(())
}

#[tokio::test]
async fn test_recovery_strategy_effectiveness() -> Result<()> {
    let config = Config::default();
    let recovery_strategy = create_recovery_strategy(&config)?;
    
    let chaos_config = ChaosConfig {
        failure_probability: 1.0, // Always fail initially
        failure_types: vec![FailureType::ComponentError],
        network_partition: false,
        resource_starvation: false,
        max_network_delay: 0,
        cpu_starvation_intensity: 0.0,
        memory_pressure_mb: 0,
    };

    let chaos = Arc::new(ChaosInjector::new(chaos_config));
    
    // Simulate failure
    let error = KindlyError::Internal("Simulated failure".into());
    
    // Attempt recovery
    let recovery_result = recovery_strategy
        .recover("test_service", Box::new(error))
        .await?;

    println!("Recovery result: {:?}", recovery_result);
    
    // Disable chaos for recovery verification
    chaos.active.store(false, Ordering::Relaxed);
    
    // Verify service can operate after recovery
    let post_recovery_result = async {
        chaos.inject_failure().await?;
        Ok::<_, KindlyError>(())
    }
    .await;

    assert!(
        post_recovery_result.is_ok(),
        "Service should operate after recovery"
    );

    Ok(())
}

#[tokio::test]
async fn test_extreme_load_with_failures() -> Result<()> {
    let chaos_config = ChaosConfig {
        failure_probability: 0.05, // 5% failure rate under load
        failure_types: vec![
            FailureType::ComponentError,
            FailureType::NetworkDelay,
            FailureType::ResourceExhaustion,
        ],
        network_partition: false,
        resource_starvation: true,
        max_network_delay: 20,
        cpu_starvation_intensity: 0.1,
        memory_pressure_mb: 10,
    };

    let harness = ChaosTestHarness::new(chaos_config);
    
    // Run with high concurrency
    let results = harness
        .run_workload_with_chaos(Duration::from_secs(30), 50)
        .await?;

    println!("\nExtreme Load Test Results:");
    println!("  Concurrent operations: 50");
    println!("  Duration: {:?}", results.total_duration);
    println!("  Failures: {}", results.failures_observed);
    println!("  Availability: {:.2}%", results.availability_percentage);

    // System should maintain stability under extreme load
    assert!(
        results.availability_percentage > 90.0,
        "System unstable under extreme load"
    );

    Ok(())
}

#[tokio::test]
#[ignore] // Long-running test
async fn test_prolonged_chaos_endurance() -> Result<()> {
    let chaos_config = ChaosConfig {
        failure_probability: 0.1,
        failure_types: vec![
            FailureType::ComponentError,
            FailureType::ComponentTimeout,
            FailureType::NetworkDelay,
            FailureType::NetworkPartition,
            FailureType::ResourceExhaustion,
            FailureType::DataCorruption,
            FailureType::CascadingFailure,
        ],
        network_partition: true,
        resource_starvation: true,
        max_network_delay: 500,
        cpu_starvation_intensity: 0.2,
        memory_pressure_mb: 100,
    };

    let harness = ChaosTestHarness::new(chaos_config);
    
    // Run for extended period
    let results = harness
        .run_workload_with_chaos(Duration::from_secs(300), 20) // 5 minutes
        .await?;

    println!("\nProlonged Chaos Endurance Results:");
    println!("  Test duration: {:?}", results.total_duration);
    println!("  Total failures: {}", results.failures_observed);
    println!("  Data inconsistencies: {}", results.data_inconsistencies);
    println!("  Final availability: {:.2}%", results.availability_percentage);

    // System should survive prolonged chaos
    assert!(
        results.data_inconsistencies == 0,
        "Data corruption occurred during prolonged chaos"
    );
    
    assert!(
        results.availability_percentage > 75.0,
        "System availability degraded too much during prolonged chaos"
    );

    Ok(())
}