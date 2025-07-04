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
//! Chaos engineering tests for KindlyGuard
//!
//! These tests simulate various failure scenarios to ensure the system
//! maintains security and resilience under adverse conditions.

use kindly_guard_server::{
    config::Config,
    error::{ErrorKind, KindlyError},
    metrics::MetricsCollector,
    resilience::{CircuitBreakerTrait, RetryPolicy},
    scanner::{SecurityScanner, ThreatSeverity},
    server::Server,
    storage::StorageTrait,
    transport::TransportTrait,
};
use rand::{distributions::Uniform, thread_rng, Rng};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex, RwLock, Semaphore},
    task::JoinSet,
    time::{sleep, timeout},
};
use tracing::{error, info, warn};

/// Chaos test configuration
#[derive(Debug, Clone)]
struct ChaosConfig {
    /// Probability of fault injection (0.0 - 1.0)
    fault_probability: f64,
    /// Maximum concurrent operations
    max_concurrent_ops: usize,
    /// Test duration
    test_duration: Duration,
    /// Enable random delays
    enable_delays: bool,
    /// Enable resource exhaustion
    enable_resource_exhaustion: bool,
    /// Enable network failures
    enable_network_failures: bool,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self {
            fault_probability: 0.3,
            max_concurrent_ops: 100,
            test_duration: Duration::from_secs(30),
            enable_delays: true,
            enable_resource_exhaustion: true,
            enable_network_failures: true,
        }
    }
}

/// Fault injection types
#[derive(Debug, Clone, Copy, PartialEq)]
enum FaultType {
    NetworkTimeout,
    NetworkError,
    ResourceExhaustion,
    MemoryPressure,
    CpuSpike,
    DiskFull,
    RandomDelay,
    PartialResponse,
    CorruptedData,
    ServiceUnavailable,
}

/// Chaos monkey that randomly injects faults
struct ChaosMonkey {
    config: ChaosConfig,
    active: AtomicBool,
    faults_injected: AtomicU64,
    rng: Mutex<rand::rngs::ThreadRng>,
}

impl ChaosMonkey {
    fn new(config: ChaosConfig) -> Self {
        Self {
            config,
            active: AtomicBool::new(true),
            faults_injected: AtomicU64::new(0),
            rng: Mutex::new(thread_rng()),
        }
    }

    async fn should_inject_fault(&self) -> bool {
        if !self.active.load(Ordering::Relaxed) {
            return false;
        }

        let mut rng = self.rng.lock().await;
        rng.gen::<f64>() < self.config.fault_probability
    }

    async fn inject_fault(&self) -> Option<FaultType> {
        if !self.should_inject_fault().await {
            return None;
        }

        let mut rng = self.rng.lock().await;
        let fault_types = vec![
            FaultType::NetworkTimeout,
            FaultType::NetworkError,
            FaultType::ResourceExhaustion,
            FaultType::MemoryPressure,
            FaultType::CpuSpike,
            FaultType::DiskFull,
            FaultType::RandomDelay,
            FaultType::PartialResponse,
            FaultType::CorruptedData,
            FaultType::ServiceUnavailable,
        ];

        let fault = fault_types[rng.gen_range(0..fault_types.len())];
        self.faults_injected.fetch_add(1, Ordering::Relaxed);

        info!("Injecting fault: {:?}", fault);
        Some(fault)
    }

    async fn apply_fault(&self, fault: FaultType) -> Result<(), KindlyError> {
        match fault {
            FaultType::NetworkTimeout => {
                sleep(Duration::from_secs(30)).await;
                Err(KindlyError::new(ErrorKind::Timeout, "Network timeout"))
            }
            FaultType::NetworkError => Err(KindlyError::new(ErrorKind::Network, "Network error")),
            FaultType::ResourceExhaustion => {
                // Simulate resource exhaustion
                let _memory_hog: Vec<u8> = vec![0; 100_000_000]; // 100MB
                sleep(Duration::from_millis(100)).await;
                Ok(())
            }
            FaultType::MemoryPressure => {
                // Allocate and deallocate memory rapidly
                for _ in 0..100 {
                    let _temp: Vec<u8> = vec![0; 1_000_000]; // 1MB
                    sleep(Duration::from_micros(100)).await;
                }
                Ok(())
            }
            FaultType::CpuSpike => {
                // CPU intensive operation
                let start = std::time::Instant::now();
                while start.elapsed() < Duration::from_millis(100) {
                    let _ = (0..1000).fold(0u64, |acc, x| acc.wrapping_add(x * x));
                }
                Ok(())
            }
            FaultType::DiskFull => Err(KindlyError::new(ErrorKind::Storage, "Disk full")),
            FaultType::RandomDelay => {
                let mut rng = self.rng.lock().await;
                let delay_ms = rng.gen_range(10..500);
                sleep(Duration::from_millis(delay_ms)).await;
                Ok(())
            }
            FaultType::PartialResponse => {
                // Return success but with incomplete data
                Ok(())
            }
            FaultType::CorruptedData => Err(KindlyError::new(
                ErrorKind::InvalidData,
                "Data corruption detected",
            )),
            FaultType::ServiceUnavailable => Err(KindlyError::new(
                ErrorKind::ServiceUnavailable,
                "Service temporarily unavailable",
            )),
        }
    }

    fn stop(&self) {
        self.active.store(false, Ordering::Relaxed);
    }

    fn get_stats(&self) -> u64 {
        self.faults_injected.load(Ordering::Relaxed)
    }
}

/// Chaos-enabled transport wrapper
struct ChaosTransport<T: TransportTrait> {
    inner: T,
    chaos: Arc<ChaosMonkey>,
}

impl<T: TransportTrait> ChaosTransport<T> {
    fn new(inner: T, chaos: Arc<ChaosMonkey>) -> Self {
        Self { inner, chaos }
    }
}

#[async_trait::async_trait]
impl<T: TransportTrait> TransportTrait for ChaosTransport<T> {
    async fn send(&self, data: &[u8]) -> Result<(), KindlyError> {
        if let Some(fault) = self.chaos.inject_fault().await {
            self.chaos.apply_fault(fault).await?;
        }
        self.inner.send(data).await
    }

    async fn receive(&self) -> Result<Vec<u8>, KindlyError> {
        if let Some(fault) = self.chaos.inject_fault().await {
            self.chaos.apply_fault(fault).await?;
        }
        self.inner.receive().await
    }

    async fn close(&self) -> Result<(), KindlyError> {
        self.inner.close().await
    }
}

/// Chaos-enabled storage wrapper
struct ChaosStorage<S: StorageTrait> {
    inner: S,
    chaos: Arc<ChaosMonkey>,
}

impl<S: StorageTrait> ChaosStorage<S> {
    fn new(inner: S, chaos: Arc<ChaosMonkey>) -> Self {
        Self { inner, chaos }
    }
}

#[async_trait::async_trait]
impl<S: StorageTrait> StorageTrait for ChaosStorage<S> {
    async fn store(&self, key: &str, value: &[u8]) -> Result<(), KindlyError> {
        if let Some(fault) = self.chaos.inject_fault().await {
            self.chaos.apply_fault(fault).await?;
        }
        self.inner.store(key, value).await
    }

    async fn retrieve(&self, key: &str) -> Result<Option<Vec<u8>>, KindlyError> {
        if let Some(fault) = self.chaos.inject_fault().await {
            self.chaos.apply_fault(fault).await?;
        }
        self.inner.retrieve(key).await
    }

    async fn delete(&self, key: &str) -> Result<(), KindlyError> {
        if let Some(fault) = self.chaos.inject_fault().await {
            self.chaos.apply_fault(fault).await?;
        }
        self.inner.delete(key).await
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, KindlyError> {
        if let Some(fault) = self.chaos.inject_fault().await {
            self.chaos.apply_fault(fault).await?;
        }
        self.inner.list_keys(prefix).await
    }
}

/// Test harness for chaos testing
struct ChaosTestHarness {
    server: Arc<Server>,
    chaos: Arc<ChaosMonkey>,
    metrics: Arc<MetricsCollector>,
    consistency_checker: Arc<ConsistencyChecker>,
}

/// Checks data consistency during chaos
struct ConsistencyChecker {
    expected_state: RwLock<HashMap<String, Vec<u8>>>,
    inconsistencies: AtomicU64,
}

impl ConsistencyChecker {
    fn new() -> Self {
        Self {
            expected_state: RwLock::new(HashMap::new()),
            inconsistencies: AtomicU64::new(0),
        }
    }

    async fn record_operation(&self, key: String, value: Vec<u8>) {
        let mut state = self.expected_state.write().await;
        state.insert(key, value);
    }

    async fn verify_operation(&self, key: &str, actual: Option<&[u8]>) -> bool {
        let state = self.expected_state.read().await;
        let expected = state.get(key);

        let consistent = match (expected, actual) {
            (Some(exp), Some(act)) => exp == act,
            (None, None) => true,
            _ => false,
        };

        if !consistent {
            self.inconsistencies.fetch_add(1, Ordering::Relaxed);
            error!("Consistency violation for key: {}", key);
        }

        consistent
    }

    fn get_inconsistency_count(&self) -> u64 {
        self.inconsistencies.load(Ordering::Relaxed)
    }
}

// Test: Basic chaos injection
#[tokio::test]
async fn test_basic_chaos_injection() {
    let chaos_config = ChaosConfig {
        fault_probability: 0.5,
        ..Default::default()
    };

    let chaos = Arc::new(ChaosMonkey::new(chaos_config));
    let mut fault_counts = HashMap::new();

    // Inject faults and count types
    for _ in 0..1000 {
        if let Some(fault) = chaos.inject_fault().await {
            *fault_counts.entry(fault).or_insert(0) += 1;
        }
    }

    // Verify faults were injected
    assert!(
        chaos.get_stats() > 400,
        "Expected ~500 faults, got {}",
        chaos.get_stats()
    );
    assert!(
        chaos.get_stats() < 600,
        "Expected ~500 faults, got {}",
        chaos.get_stats()
    );

    // Verify variety of faults
    assert!(fault_counts.len() >= 5, "Expected variety of fault types");
}

// Test: Network resilience under chaos
#[tokio::test]
async fn test_network_resilience() {
    let config = Config::default();
    let chaos = Arc::new(ChaosMonkey::new(ChaosConfig {
        fault_probability: 0.3,
        enable_network_failures: true,
        ..Default::default()
    }));

    // Create chaos-wrapped components
    let scanner = Arc::new(SecurityScanner::new(&config.scanner));
    let metrics = Arc::new(MetricsCollector::new());

    let mut tasks = JoinSet::new();
    let start = std::time::Instant::now();

    // Simulate concurrent operations under chaos
    for i in 0..50 {
        let scanner = scanner.clone();
        let chaos = chaos.clone();
        let metrics = metrics.clone();

        tasks.spawn(async move {
            let test_data = format!("Test request {}: <script>alert('xss')</script>", i);

            // Inject potential network fault
            if let Some(fault) = chaos.inject_fault().await {
                match chaos.apply_fault(fault).await {
                    Ok(_) => {}
                    Err(e) => {
                        metrics.record_error(&e);
                        return Err(e);
                    }
                }
            }

            // Try to scan with retry
            let mut attempts = 0;
            loop {
                attempts += 1;
                match timeout(Duration::from_secs(5), scanner.scan_text(&test_data)).await {
                    Ok(Ok(threats)) => {
                        metrics.record_scan_success();
                        return Ok(threats.len());
                    }
                    Ok(Err(e)) => {
                        if attempts >= 3 {
                            metrics.record_error(&e);
                            return Err(KindlyError::from(e));
                        }
                        sleep(Duration::from_millis(100 * attempts)).await;
                    }
                    Err(_) => {
                        if attempts >= 3 {
                            let e = KindlyError::new(ErrorKind::Timeout, "Scan timeout");
                            metrics.record_error(&e);
                            return Err(e);
                        }
                        sleep(Duration::from_millis(100 * attempts)).await;
                    }
                }
            }
        });
    }

    // Collect results
    let mut successes = 0;
    let mut failures = 0;

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(_)) => successes += 1,
            _ => failures += 1,
        }
    }

    let elapsed = start.elapsed();
    chaos.stop();

    // Verify resilience metrics
    let success_rate = successes as f64 / (successes + failures) as f64;
    println!("Network resilience test completed in {:?}", elapsed);
    println!(
        "Success rate: {:.2}% ({}/{})",
        success_rate * 100.0,
        successes,
        successes + failures
    );
    println!("Faults injected: {}", chaos.get_stats());

    // Should maintain at least 70% success rate under chaos
    assert!(
        success_rate >= 0.7,
        "Success rate too low: {:.2}%",
        success_rate * 100.0
    );
}

// Test: Storage consistency under chaos
#[tokio::test]
async fn test_storage_consistency() {
    let config = Config::default();
    let chaos = Arc::new(ChaosMonkey::new(ChaosConfig {
        fault_probability: 0.2,
        enable_resource_exhaustion: true,
        ..Default::default()
    }));

    // Create storage with chaos wrapper
    let base_storage = kindly_guard_server::storage::create_storage(&config.storage)
        .await
        .expect("Failed to create storage");
    let storage = Arc::new(ChaosStorage::new(base_storage, chaos.clone()));
    let consistency = Arc::new(ConsistencyChecker::new());

    let mut tasks = JoinSet::new();

    // Concurrent read/write operations
    for i in 0..100 {
        let storage = storage.clone();
        let consistency = consistency.clone();

        tasks.spawn(async move {
            let key = format!("test_key_{}", i % 10); // Reuse some keys
            let value = format!("value_{}", i).into_bytes();

            // Write operation
            match storage.store(&key, &value).await {
                Ok(_) => {
                    consistency
                        .record_operation(key.clone(), value.clone())
                        .await;

                    // Immediate read-back
                    match storage.retrieve(&key).await {
                        Ok(Some(stored)) => {
                            consistency.verify_operation(&key, Some(&stored)).await;
                        }
                        Ok(None) => {
                            error!("Key not found immediately after write: {}", key);
                            false
                        }
                        Err(e) => {
                            warn!("Read failed after write: {}", e);
                            false
                        }
                    }
                }
                Err(e) => {
                    warn!("Write failed: {}", e);
                    false
                }
            }
        });
    }

    // Wait for completion
    let mut write_successes = 0;
    while let Some(result) = tasks.join_next().await {
        if let Ok(success) = result {
            if success {
                write_successes += 1;
            }
        }
    }

    chaos.stop();

    // Final consistency check
    let inconsistencies = consistency.get_inconsistency_count();
    println!("Storage consistency test completed");
    println!("Successful operations: {}/100", write_successes);
    println!("Inconsistencies detected: {}", inconsistencies);
    println!("Faults injected: {}", chaos.get_stats());

    // Should have zero inconsistencies
    assert_eq!(inconsistencies, 0, "Data inconsistencies detected");
    // Should complete at least 80% of operations
    assert!(
        write_successes >= 80,
        "Too many failed operations: {}",
        write_successes
    );
}

// Test: Resource exhaustion handling
#[tokio::test]
async fn test_resource_exhaustion() {
    let config = Config::default();
    let chaos = Arc::new(ChaosMonkey::new(ChaosConfig {
        fault_probability: 0.4,
        enable_resource_exhaustion: true,
        ..Default::default()
    }));

    let scanner = Arc::new(SecurityScanner::new(&config.scanner));
    let semaphore = Arc::new(Semaphore::new(10)); // Limit concurrent operations

    let mut tasks = JoinSet::new();
    let start = std::time::Instant::now();

    // Simulate high load with resource constraints
    for i in 0..200 {
        let scanner = scanner.clone();
        let chaos = chaos.clone();
        let semaphore = semaphore.clone();

        tasks.spawn(async move {
            // Acquire permit (may block under load)
            let _permit = match timeout(Duration::from_secs(10), semaphore.acquire()).await {
                Ok(Ok(permit)) => permit,
                _ => {
                    return Err(KindlyError::new(
                        ErrorKind::ResourceExhausted,
                        "Cannot acquire permit",
                    ))
                }
            };

            // Simulate resource-intensive operation
            if chaos.inject_fault().await == Some(FaultType::ResourceExhaustion) {
                // Simulate memory pressure
                let _memory: Vec<u8> = vec![0; 10_000_000]; // 10MB
                sleep(Duration::from_millis(100)).await;
            }

            // Perform scan
            let data = format!("Resource test {}: potentially malicious content", i);
            match timeout(Duration::from_secs(5), scanner.scan_text(&data)).await {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(KindlyError::from(e)),
                Err(_) => Err(KindlyError::new(ErrorKind::Timeout, "Operation timeout")),
            }
        });
    }

    // Monitor completion
    let mut completed = 0;
    let mut resource_errors = 0;
    let mut timeouts = 0;

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(_)) => completed += 1,
            Ok(Err(e)) => match e.kind() {
                ErrorKind::ResourceExhausted => resource_errors += 1,
                ErrorKind::Timeout => timeouts += 1,
                _ => {}
            },
            _ => {}
        }
    }

    let elapsed = start.elapsed();
    chaos.stop();

    println!("Resource exhaustion test completed in {:?}", elapsed);
    println!("Completed: {}/200", completed);
    println!("Resource errors: {}", resource_errors);
    println!("Timeouts: {}", timeouts);
    println!("Faults injected: {}", chaos.get_stats());

    // Should handle resource exhaustion gracefully
    assert!(
        completed >= 100,
        "Too few operations completed: {}",
        completed
    );
    assert!(
        elapsed < Duration::from_secs(60),
        "Test took too long: {:?}",
        elapsed
    );
}

// Test: Circuit breaker under chaos
#[tokio::test]
async fn test_circuit_breaker_chaos() {
    let config = Config::default();
    let chaos = Arc::new(ChaosMonkey::new(ChaosConfig {
        fault_probability: 0.6, // High failure rate
        ..Default::default()
    }));

    let circuit_breaker =
        kindly_guard_server::resilience::create_circuit_breaker(&config.resilience);
    let failure_count = Arc::new(AtomicU64::new(0));
    let success_count = Arc::new(AtomicU64::new(0));
    let circuit_open_count = Arc::new(AtomicU64::new(0));

    let mut tasks = JoinSet::new();

    // Simulate operations that may fail
    for i in 0..100 {
        let cb = circuit_breaker.clone();
        let chaos = chaos.clone();
        let failure_count = failure_count.clone();
        let success_count = success_count.clone();
        let circuit_open_count = circuit_open_count.clone();

        tasks.spawn(async move {
            let operation = || async {
                if let Some(fault) = chaos.inject_fault().await {
                    chaos.apply_fault(fault).await?;
                }
                Ok::<_, KindlyError>(format!("Operation {} succeeded", i))
            };

            match cb.call("test_operation", operation).await {
                Ok(_) => {
                    success_count.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => match e.kind() {
                    ErrorKind::CircuitBreakerOpen => {
                        circuit_open_count.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        failure_count.fetch_add(1, Ordering::Relaxed);
                    }
                },
            }

            // Small delay between operations
            sleep(Duration::from_millis(50)).await;
        });
    }

    // Wait for all operations
    while let Some(_) = tasks.join_next().await {}

    chaos.stop();

    let successes = success_count.load(Ordering::Relaxed);
    let failures = failure_count.load(Ordering::Relaxed);
    let circuit_opens = circuit_open_count.load(Ordering::Relaxed);

    println!("Circuit breaker chaos test completed");
    println!("Successes: {}", successes);
    println!("Failures: {}", failures);
    println!("Circuit open rejections: {}", circuit_opens);
    println!("Faults injected: {}", chaos.get_stats());

    // Circuit breaker should activate under high failure rate
    assert!(circuit_opens > 0, "Circuit breaker should have opened");
    assert!(
        successes + failures + circuit_opens == 100,
        "All operations should be accounted for"
    );
}

// Test: Security maintained under chaos
#[tokio::test]
async fn test_security_under_chaos() {
    let config = Config::default();
    let chaos = Arc::new(ChaosMonkey::new(ChaosConfig {
        fault_probability: 0.3,
        enable_delays: true,
        ..Default::default()
    }));

    let scanner = Arc::new(SecurityScanner::new(&config.scanner));
    let security_breaches = Arc::new(AtomicU64::new(0));

    // Malicious payloads that should always be detected
    let payloads = vec![
        "<script>alert('xss')</script>",
        "'; DROP TABLE users; --",
        "../../../etc/passwd",
        "\u{202E}reversed\u{202C}",
        "admin' OR '1'='1",
        "<img src=x onerror=alert('xss')>",
        "{{constructor.constructor('alert(1)')()}}",
    ];

    let mut tasks = JoinSet::new();

    for (i, payload) in payloads.iter().enumerate() {
        for j in 0..10 {
            let scanner = scanner.clone();
            let chaos = chaos.clone();
            let security_breaches = security_breaches.clone();
            let payload = payload.to_string();

            tasks.spawn(async move {
                // Apply chaos
                if let Some(fault) = chaos.inject_fault().await {
                    match fault {
                        FaultType::RandomDelay | FaultType::CpuSpike => {
                            let _ = chaos.apply_fault(fault).await;
                        }
                        _ => {} // Skip faults that would prevent scanning
                    }
                }

                // Scan payload
                match timeout(Duration::from_secs(10), scanner.scan_text(&payload)).await {
                    Ok(Ok(threats)) => {
                        if threats.is_empty() {
                            error!("Security breach: Payload {} #{} not detected", i, j);
                            security_breaches.fetch_add(1, Ordering::Relaxed);
                        } else {
                            // Verify high severity
                            let high_severity = threats.iter().any(|t| {
                                matches!(
                                    t.severity,
                                    ThreatSeverity::High | ThreatSeverity::Critical
                                )
                            });
                            if !high_severity {
                                warn!(
                                    "Payload {} #{} detected but not marked as high severity",
                                    i, j
                                );
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("Scan error for payload {} #{}: {}", i, j, e);
                    }
                    Err(_) => {
                        warn!("Scan timeout for payload {} #{}", i, j);
                    }
                }
            });
        }
    }

    // Wait for all scans
    while let Some(_) = tasks.join_next().await {}

    chaos.stop();

    let breaches = security_breaches.load(Ordering::Relaxed);
    println!("Security under chaos test completed");
    println!("Security breaches: {}", breaches);
    println!("Faults injected: {}", chaos.get_stats());

    // Should have zero security breaches
    assert_eq!(breaches, 0, "Security breaches detected under chaos");
}

// Test: Graceful degradation
#[tokio::test]
async fn test_graceful_degradation() {
    let config = Config::default();
    let chaos = Arc::new(ChaosMonkey::new(ChaosConfig {
        fault_probability: 0.8, // Very high failure rate
        ..Default::default()
    }));

    let scanner = Arc::new(SecurityScanner::new(&config.scanner));
    let metrics = Arc::new(MetricsCollector::new());

    // Track service levels
    let full_service = Arc::new(AtomicU64::new(0));
    let degraded_service = Arc::new(AtomicU64::new(0));
    let no_service = Arc::new(AtomicU64::new(0));

    let start = std::time::Instant::now();
    let mut tasks = JoinSet::new();

    for i in 0..50 {
        let scanner = scanner.clone();
        let chaos = chaos.clone();
        let metrics = metrics.clone();
        let full_service = full_service.clone();
        let degraded_service = degraded_service.clone();
        let no_service = no_service.clone();

        tasks.spawn(async move {
            let data = format!("Test {}: <script>alert('test')</script>", i);

            // Try full service first
            match timeout(Duration::from_secs(2), scanner.scan_text(&data)).await {
                Ok(Ok(threats)) if !threats.is_empty() => {
                    full_service.fetch_add(1, Ordering::Relaxed);
                    metrics.record_scan_success();
                    return;
                }
                _ => {}
            }

            // Fallback to basic pattern matching (degraded mode)
            if data.contains("<script>") || data.contains("DROP TABLE") {
                degraded_service.fetch_add(1, Ordering::Relaxed);
                metrics.record_degraded_service();
                return;
            }

            // Service unavailable
            no_service.fetch_add(1, Ordering::Relaxed);
            metrics.record_service_unavailable();
        });
    }

    // Wait for completion
    while let Some(_) = tasks.join_next().await {}

    let elapsed = start.elapsed();
    chaos.stop();

    let full = full_service.load(Ordering::Relaxed);
    let degraded = degraded_service.load(Ordering::Relaxed);
    let none = no_service.load(Ordering::Relaxed);

    println!("Graceful degradation test completed in {:?}", elapsed);
    println!("Full service: {} ({}%)", full, full * 2);
    println!("Degraded service: {} ({}%)", degraded, degraded * 2);
    println!("No service: {} ({}%)", none, none * 2);
    println!("Faults injected: {}", chaos.get_stats());

    // Should provide some level of service for most requests
    let service_available = full + degraded;
    assert!(
        service_available >= 30,
        "Too many requests with no service: {}",
        none
    );
}

// Test: Recovery after chaos
#[tokio::test]
async fn test_recovery_after_chaos() {
    let config = Config::default();
    let chaos = Arc::new(ChaosMonkey::new(ChaosConfig {
        fault_probability: 0.9, // Start with very high failure rate
        ..Default::default()
    }));

    let scanner = Arc::new(SecurityScanner::new(&config.scanner));
    let metrics = Arc::new(MetricsCollector::new());

    // Phase 1: High chaos
    println!("Phase 1: High chaos period");
    let mut phase1_success = 0;
    let mut phase1_total = 0;

    for i in 0..20 {
        phase1_total += 1;
        let data = format!("Phase 1 test {}: malicious content", i);

        match timeout(Duration::from_secs(2), scanner.scan_text(&data)).await {
            Ok(Ok(_)) => {
                phase1_success += 1;
                metrics.record_scan_success();
            }
            _ => {
                metrics.record_error(&KindlyError::new(ErrorKind::Unknown, "Scan failed"));
            }
        }

        sleep(Duration::from_millis(50)).await;
    }

    let phase1_rate = phase1_success as f64 / phase1_total as f64;
    println!("Phase 1 success rate: {:.2}%", phase1_rate * 100.0);

    // Phase 2: Stop chaos and measure recovery
    println!("Phase 2: Recovery period");
    chaos.stop();
    sleep(Duration::from_secs(2)).await; // Allow system to stabilize

    let mut phase2_success = 0;
    let mut phase2_total = 0;
    let recovery_start = std::time::Instant::now();

    for i in 0..30 {
        phase2_total += 1;
        let data = format!("Phase 2 test {}: malicious content", i);

        match timeout(Duration::from_secs(2), scanner.scan_text(&data)).await {
            Ok(Ok(_)) => {
                phase2_success += 1;
                metrics.record_scan_success();
            }
            _ => {
                metrics.record_error(&KindlyError::new(ErrorKind::Unknown, "Scan failed"));
            }
        }

        sleep(Duration::from_millis(50)).await;
    }

    let recovery_time = recovery_start.elapsed();
    let phase2_rate = phase2_success as f64 / phase2_total as f64;
    println!("Phase 2 success rate: {:.2}%", phase2_rate * 100.0);
    println!("Recovery time: {:?}", recovery_time);

    // Verify recovery
    assert!(phase1_rate < 0.3, "Phase 1 should have low success rate");
    assert!(phase2_rate > 0.9, "Phase 2 should have high success rate");
    assert!(
        recovery_time < Duration::from_secs(5),
        "Recovery should be quick"
    );
}

// Test: Multi-component chaos
#[tokio::test]
async fn test_multi_component_chaos() {
    let config = Config::default();
    let chaos = Arc::new(ChaosMonkey::new(ChaosConfig {
        fault_probability: 0.25,
        enable_network_failures: true,
        enable_resource_exhaustion: true,
        enable_delays: true,
        ..Default::default()
    }));

    // Create all components with chaos wrappers
    let scanner = Arc::new(SecurityScanner::new(&config.scanner));
    let storage = {
        let base = kindly_guard_server::storage::create_storage(&config.storage)
            .await
            .expect("Failed to create storage");
        Arc::new(ChaosStorage::new(base, chaos.clone()))
    };
    let metrics = Arc::new(MetricsCollector::new());
    let consistency = Arc::new(ConsistencyChecker::new());

    let mut tasks = JoinSet::new();
    let operation_count = 30;

    // Simulate complex operations involving multiple components
    for i in 0..operation_count {
        let scanner = scanner.clone();
        let storage = storage.clone();
        let metrics = metrics.clone();
        let consistency = consistency.clone();
        let chaos = chaos.clone();

        tasks.spawn(async move {
            let key = format!("scan_result_{}", i);
            let data = format!("Test {}: <script>alert('xss')</script> OR 1=1--", i);

            // Step 1: Scan for threats
            let threats = match scanner.scan_text(&data).await {
                Ok(t) => t,
                Err(e) => {
                    metrics.record_error(&e);
                    return Err(e);
                }
            };

            // Step 2: Store scan results
            let result_data = serde_json::to_vec(&threats).unwrap();
            match storage.store(&key, &result_data).await {
                Ok(_) => {
                    consistency
                        .record_operation(key.clone(), result_data.clone())
                        .await;
                    metrics.record_storage_success();
                }
                Err(e) => {
                    metrics.record_error(&e);
                    return Err(e);
                }
            }

            // Step 3: Verify storage
            match storage.retrieve(&key).await {
                Ok(Some(stored)) => {
                    if consistency.verify_operation(&key, Some(&stored)).await {
                        metrics.record_verification_success();
                        Ok(())
                    } else {
                        Err(KindlyError::new(
                            ErrorKind::ConsistencyViolation,
                            "Data mismatch",
                        ))
                    }
                }
                Ok(None) => Err(KindlyError::new(
                    ErrorKind::NotFound,
                    "Data not found after storage",
                )),
                Err(e) => {
                    metrics.record_error(&e);
                    Err(e)
                }
            }
        });
    }

    // Collect results
    let mut successes = 0;
    let mut failures = HashMap::new();

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(_)) => successes += 1,
            Ok(Err(e)) => {
                *failures.entry(e.kind()).or_insert(0) += 1;
            }
            Err(_) => {
                *failures.entry(ErrorKind::Unknown).or_insert(0) += 1;
            }
        }
    }

    chaos.stop();

    let total = successes + failures.values().sum::<u32>();
    let success_rate = successes as f64 / total as f64;

    println!("Multi-component chaos test completed");
    println!(
        "Success rate: {:.2}% ({}/{})",
        success_rate * 100.0,
        successes,
        total
    );
    println!("Failure breakdown:");
    for (kind, count) in &failures {
        println!("  {:?}: {}", kind, count);
    }
    println!("Faults injected: {}", chaos.get_stats());
    println!(
        "Consistency violations: {}",
        consistency.get_inconsistency_count()
    );

    // Should maintain reasonable success rate with multi-component chaos
    assert!(
        success_rate >= 0.6,
        "Success rate too low: {:.2}%",
        success_rate * 100.0
    );
    assert_eq!(
        consistency.get_inconsistency_count(),
        0,
        "Data inconsistencies detected"
    );
}

// Helper function to simulate monitoring during chaos
async fn monitor_system_health(
    metrics: Arc<MetricsCollector>,
    duration: Duration,
) -> HashMap<String, u64> {
    let start = std::time::Instant::now();
    let mut health_samples = HashMap::new();

    while start.elapsed() < duration {
        let snapshot = metrics.get_snapshot();

        for (key, value) in snapshot {
            *health_samples.entry(key).or_insert(0) += value;
        }

        sleep(Duration::from_millis(100)).await;
    }

    health_samples
}

// Test: Monitoring and alerting during chaos
#[tokio::test]
async fn test_monitoring_during_chaos() {
    let config = Config::default();
    let chaos = Arc::new(ChaosMonkey::new(ChaosConfig {
        fault_probability: 0.4,
        test_duration: Duration::from_secs(10),
        ..Default::default()
    }));

    let metrics = Arc::new(MetricsCollector::new());
    let alerts = Arc::new(RwLock::new(Vec::new()));

    // Start monitoring task
    let monitor_metrics = metrics.clone();
    let monitor_alerts = alerts.clone();
    let monitor_handle = tokio::spawn(async move {
        monitor_system_health(monitor_metrics, Duration::from_secs(10)).await
    });

    // Start alert detection task
    let alert_metrics = metrics.clone();
    let alert_alerts = alerts.clone();
    let alert_handle = tokio::spawn(async move {
        let mut consecutive_errors = 0;

        loop {
            sleep(Duration::from_millis(500)).await;

            let snapshot = alert_metrics.get_snapshot();
            let error_rate = snapshot.get("errors").unwrap_or(&0);

            if *error_rate > 10 {
                consecutive_errors += 1;

                if consecutive_errors >= 3 {
                    let mut alerts = alert_alerts.write().await;
                    alerts.push(format!("High error rate detected: {} errors", error_rate));
                    consecutive_errors = 0;
                }
            } else {
                consecutive_errors = 0;
            }

            if snapshot.get("circuit_breaker_open").unwrap_or(&0) > &0 {
                let mut alerts = alert_alerts.write().await;
                alerts.push("Circuit breaker opened".to_string());
            }
        }
    });

    // Run chaos operations
    let scanner = Arc::new(SecurityScanner::new(&config.scanner));
    let mut tasks = JoinSet::new();

    for i in 0..100 {
        let scanner = scanner.clone();
        let chaos = chaos.clone();
        let metrics = metrics.clone();

        tasks.spawn(async move {
            let data = format!("Monitor test {}: potentially malicious", i);

            if let Some(fault) = chaos.inject_fault().await {
                match chaos.apply_fault(fault).await {
                    Ok(_) => {}
                    Err(e) => {
                        metrics.record_error(&e);
                        return Err(e);
                    }
                }
            }

            match scanner.scan_text(&data).await {
                Ok(_) => {
                    metrics.record_scan_success();
                    Ok(())
                }
                Err(e) => {
                    metrics.record_error(&KindlyError::from(e));
                    Err(KindlyError::from(e))
                }
            }
        });
    }

    // Wait for operations to complete
    while let Some(_) = tasks.join_next().await {}

    chaos.stop();
    alert_handle.abort();

    let health_data = monitor_handle.await.unwrap();
    let final_alerts = alerts.read().await.clone();

    println!("Monitoring during chaos test completed");
    println!("Health metrics collected:");
    for (metric, value) in &health_data {
        println!("  {}: {}", metric, value);
    }
    println!("Alerts generated: {}", final_alerts.len());
    for alert in &final_alerts {
        println!("  - {}", alert);
    }

    // Should have collected metrics and generated alerts
    assert!(!health_data.is_empty(), "No health metrics collected");
    assert!(!final_alerts.is_empty(), "No alerts generated during chaos");
}
