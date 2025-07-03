//! Load Testing Scenarios for KindlyGuard
//! Tests system behavior under various load patterns to ensure security and stability

use kindly_guard_server::{
    Config, McpServer, ScannerConfig, SecurityScanner, ThreatNeutralizer,
    create_neutralizer, Shield,
    protocol::{JsonRpcRequest, RequestId, JsonRpcResponse},
};
use serde_json::{json, Value};
use std::sync::{Arc, atomic::{AtomicU64, AtomicBool, Ordering}};
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, RwLock};
use tokio::time::{sleep, timeout};
use futures::stream::{self, StreamExt};
use rand::Rng;

mod helpers;
use helpers::*;

/// Statistics collector for load tests
#[derive(Debug, Default)]
struct LoadTestStats {
    total_requests: AtomicU64,
    successful_requests: AtomicU64,
    failed_requests: AtomicU64,
    threats_detected: AtomicU64,
    threats_neutralized: AtomicU64,
    rate_limited_requests: AtomicU64,
    total_latency_us: AtomicU64,
    max_latency_us: AtomicU64,
    memory_peak_bytes: AtomicU64,
}

impl LoadTestStats {
    fn record_request(&self, success: bool, latency: Duration) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        
        if success {
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        }
        
        let latency_us = latency.as_micros() as u64;
        self.total_latency_us.fetch_add(latency_us, Ordering::Relaxed);
        
        // Update max latency
        let mut current_max = self.max_latency_us.load(Ordering::Relaxed);
        while latency_us > current_max {
            match self.max_latency_us.compare_exchange_weak(
                current_max,
                latency_us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_max = actual,
            }
        }
    }
    
    fn record_threat_detected(&self) {
        self.threats_detected.fetch_add(1, Ordering::Relaxed);
    }
    
    fn record_threat_neutralized(&self) {
        self.threats_neutralized.fetch_add(1, Ordering::Relaxed);
    }
    
    fn record_rate_limited(&self) {
        self.rate_limited_requests.fetch_add(1, Ordering::Relaxed);
    }
    
    fn update_memory_peak(&self, bytes: u64) {
        let mut current_peak = self.memory_peak_bytes.load(Ordering::Relaxed);
        while bytes > current_peak {
            match self.memory_peak_bytes.compare_exchange_weak(
                current_peak,
                bytes,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_peak = actual,
            }
        }
    }
    
    fn get_average_latency_ms(&self) -> f64 {
        let total_requests = self.total_requests.load(Ordering::Relaxed);
        if total_requests == 0 {
            return 0.0;
        }
        
        let total_latency_us = self.total_latency_us.load(Ordering::Relaxed);
        (total_latency_us as f64 / total_requests as f64) / 1000.0
    }
    
    fn get_throughput(&self, duration: Duration) -> f64 {
        let total_requests = self.total_requests.load(Ordering::Relaxed);
        total_requests as f64 / duration.as_secs_f64()
    }
    
    fn print_summary(&self, test_name: &str, duration: Duration) {
        println!("\n=== Load Test Results: {} ===", test_name);
        println!("Duration: {:.2}s", duration.as_secs_f64());
        println!("Total Requests: {}", self.total_requests.load(Ordering::Relaxed));
        println!("Successful: {}", self.successful_requests.load(Ordering::Relaxed));
        println!("Failed: {}", self.failed_requests.load(Ordering::Relaxed));
        println!("Rate Limited: {}", self.rate_limited_requests.load(Ordering::Relaxed));
        println!("Threats Detected: {}", self.threats_detected.load(Ordering::Relaxed));
        println!("Threats Neutralized: {}", self.threats_neutralized.load(Ordering::Relaxed));
        println!("Throughput: {:.2} req/s", self.get_throughput(duration));
        println!("Average Latency: {:.2} ms", self.get_average_latency_ms());
        println!("Max Latency: {:.2} ms", self.max_latency_us.load(Ordering::Relaxed) as f64 / 1000.0);
        println!("Peak Memory: {:.2} MB", self.memory_peak_bytes.load(Ordering::Relaxed) as f64 / 1024.0 / 1024.0);
        println!();
    }
}

/// Create a test payload with optional threat
fn create_test_payload(include_threat: bool, threat_type: &str) -> Value {
    let text = if include_threat {
        match threat_type {
            "sql_injection" => "SELECT * FROM users WHERE id = '1' OR '1'='1'; DROP TABLE users; --",
            "xss" => "<script>alert('XSS')</script><img src=x onerror=alert(1)>",
            "unicode" => "Hello\u{202E}World\u{200B}\u{200C}\u{200D}",
            "command_injection" => "echo 'safe' && rm -rf / || cat /etc/passwd",
            _ => "benign content",
        }
    } else {
        "This is completely safe content with no threats"
    };
    
    // Use the MCP tools/call format
    json!({
        "name": "security:scan",
        "arguments": {
            "text": text,
            "scan_type": "full"
        }
    })
}

/// Monitor memory usage during test
async fn memory_monitor(stats: Arc<LoadTestStats>, stop_signal: Arc<AtomicBool>) {
    while !stop_signal.load(Ordering::Relaxed) {
        // Get current memory usage (simplified - in real scenario would use system metrics)
        #[cfg(feature = "jemalloc")]
        {
            use jemalloc_ctl::{stats, epoch};
            let _ = epoch::advance();
            if let Ok(allocated) = stats::allocated::read() {
                stats.update_memory_peak(allocated);
            }
        }
        
        sleep(Duration::from_millis(100)).await;
    }
}

/// Test steady load pattern
#[tokio::test]
async fn test_steady_load() {
    let config = create_test_config();
    let server = create_test_server(config).await;
    let stats = Arc::new(LoadTestStats::default());
    let stop_signal = Arc::new(AtomicBool::new(false));
    
    // Start memory monitor
    let monitor_stats = stats.clone();
    let monitor_signal = stop_signal.clone();
    let monitor_handle = tokio::spawn(memory_monitor(monitor_stats, monitor_signal));
    
    let test_duration = Duration::from_secs(10);
    let requests_per_second = 1000;
    let request_interval = Duration::from_micros(1_000_000 / requests_per_second);
    
    let start_time = Instant::now();
    let end_time = start_time + test_duration;
    
    // Spawn concurrent workers
    let num_workers = 10;
    let semaphore = Arc::new(Semaphore::new(num_workers));
    
    while Instant::now() < end_time {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let server_clone = server.clone();
        let stats_clone = stats.clone();
        
        tokio::spawn(async move {
            let request_start = Instant::now();
            let payload = create_test_payload(false, "");
            
            match timeout(Duration::from_secs(5), 
                send_request(&server_clone, "tools/call", payload)).await {
                Ok(Ok(response)) => {
                    stats_clone.record_request(true, request_start.elapsed());
                    
                    // Check if any threats were detected
                    if let Some(threats) = response.get("threats") {
                        if let Some(arr) = threats.as_array() {
                            if !arr.is_empty() {
                                stats_clone.record_threat_detected();
                            }
                        }
                    }
                }
                Ok(Err(_)) => {
                    stats_clone.record_request(false, request_start.elapsed());
                }
                Err(_) => {
                    // Timeout
                    stats_clone.record_request(false, Duration::from_secs(5));
                }
            }
            
            drop(permit);
        });
        
        sleep(request_interval).await;
    }
    
    // Wait for all requests to complete
    for _ in 0..num_workers {
        let _ = semaphore.acquire().await;
    }
    
    stop_signal.store(true, Ordering::Relaxed);
    let _ = monitor_handle.await;
    
    let test_duration = start_time.elapsed();
    stats.print_summary("Steady Load", test_duration);
    
    // Assertions
    let success_rate = stats.successful_requests.load(Ordering::Relaxed) as f64 
        / stats.total_requests.load(Ordering::Relaxed) as f64;
    assert!(success_rate > 0.95, "Success rate should be above 95%");
    assert!(stats.get_average_latency_ms() < 50.0, "Average latency should be under 50ms");
}

/// Test burst load pattern
#[tokio::test]
async fn test_burst_load() {
    let config = create_test_config();
    let server = create_test_server(config).await;
    let stats = Arc::new(LoadTestStats::default());
    
    let burst_size = 5000;
    let burst_duration = Duration::from_secs(2);
    let quiet_duration = Duration::from_secs(3);
    let num_bursts = 3;
    
    for burst_num in 0..num_bursts {
        println!("Starting burst {}", burst_num + 1);
        
        let burst_start = Instant::now();
        
        // Send burst of requests
        let mut handles = Vec::new();
        for i in 0..burst_size {
            let server_clone = server.clone();
            let stats_clone = stats.clone();
            let include_threat = i % 10 == 0; // 10% with threats
            
            let handle = tokio::spawn(async move {
                let request_start = Instant::now();
                let threat_type = match i % 4 {
                    0 => "sql_injection",
                    1 => "xss",
                    2 => "unicode",
                    _ => "command_injection",
                };
                let payload = create_test_payload(include_threat, threat_type);
                
                match timeout(Duration::from_secs(10), 
                    send_request(&server_clone, "tools/call", payload)).await {
                    Ok(Ok(response)) => {
                        stats_clone.record_request(true, request_start.elapsed());
                        
                        if let Some(threats) = response.get("threats") {
                            if let Some(arr) = threats.as_array() {
                                if !arr.is_empty() {
                                    stats_clone.record_threat_detected();
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        stats_clone.record_request(false, request_start.elapsed());
                        if e.to_string().contains("rate limit") {
                            stats_clone.record_rate_limited();
                        }
                    }
                    Err(_) => {
                        stats_clone.record_request(false, Duration::from_secs(10));
                    }
                }
            });
            
            handles.push(handle);
            
            // Spread requests over burst duration
            if i % 100 == 0 {
                sleep(burst_duration / (burst_size as u32 / 100)).await;
            }
        }
        
        // Wait for burst to complete
        for handle in handles {
            let _ = handle.await;
        }
        
        println!("Burst {} completed in {:?}", burst_num + 1, burst_start.elapsed());
        
        // Quiet period between bursts
        if burst_num < num_bursts - 1 {
            sleep(quiet_duration).await;
        }
    }
    
    stats.print_summary("Burst Load", Duration::from_secs((num_bursts * 5) as u64));
    
    // Verify system handled bursts
    assert!(stats.successful_requests.load(Ordering::Relaxed) > 0);
    assert!(stats.threats_detected.load(Ordering::Relaxed) > 0, "Should detect some threats");
}

/// Test gradual ramp-up load pattern
#[tokio::test]
async fn test_gradual_ramp() {
    let config = create_test_config();
    let server = create_test_server(config).await;
    let stats = Arc::new(LoadTestStats::default());
    let stop_signal = Arc::new(AtomicBool::new(false));
    
    let initial_rps = 100;
    let max_rps = 2000;
    let ramp_duration = Duration::from_secs(30);
    let sustain_duration = Duration::from_secs(10);
    
    let test_start = Instant::now();
    
    // Ramp up phase
    let ramp_steps = 10;
    let step_duration = ramp_duration / ramp_steps;
    let rps_increment = (max_rps - initial_rps) / ramp_steps;
    
    for step in 0..ramp_steps {
        let current_rps = initial_rps + (step * rps_increment);
        println!("Ramping up: {} req/s", current_rps);
        
        let step_end = Instant::now() + step_duration;
        
        while Instant::now() < step_end && !stop_signal.load(Ordering::Relaxed) {
            let server_clone = server.clone();
            let stats_clone = stats.clone();
            
            tokio::spawn(async move {
                let request_start = Instant::now();
                let payload = create_test_payload(false, "");
                
                match timeout(Duration::from_secs(5),
                    send_request(&server_clone, "tools/call", payload)).await {
                    Ok(Ok(_)) => {
                        stats_clone.record_request(true, request_start.elapsed());
                    }
                    Ok(Err(_)) => {
                        stats_clone.record_request(false, request_start.elapsed());
                    }
                    Err(_) => {
                        stats_clone.record_request(false, Duration::from_secs(5));
                    }
                }
            });
            
            sleep(Duration::from_micros(1_000_000 / current_rps as u64)).await;
        }
    }
    
    // Sustain at max load
    println!("Sustaining at {} req/s", max_rps);
    let sustain_end = Instant::now() + sustain_duration;
    
    while Instant::now() < sustain_end && !stop_signal.load(Ordering::Relaxed) {
        let server_clone = server.clone();
        let stats_clone = stats.clone();
        
        tokio::spawn(async move {
            let request_start = Instant::now();
            let payload = create_test_payload(false, "");
            
            match timeout(Duration::from_secs(5),
                server_clone.handle_request("scan_text", payload)).await {
                Ok(Ok(_)) => {
                    stats_clone.record_request(true, request_start.elapsed());
                }
                Ok(Err(_)) => {
                    stats_clone.record_request(false, request_start.elapsed());
                }
                Err(_) => {
                    stats_clone.record_request(false, Duration::from_secs(5));
                }
            }
        });
        
        sleep(Duration::from_micros(1_000_000 / max_rps as u64)).await;
    }
    
    stop_signal.store(true, Ordering::Relaxed);
    
    let total_duration = test_start.elapsed();
    stats.print_summary("Gradual Ramp", total_duration);
    
    // System should maintain performance
    assert!(stats.get_average_latency_ms() < 100.0, "Average latency should stay reasonable");
}

/// Test mixed workload with different threat types
#[tokio::test]
async fn test_mixed_workload() {
    let config = create_test_config();
    let server = create_test_server(config).await;
    let stats = Arc::new(LoadTestStats::default());
    
    let test_duration = Duration::from_secs(20);
    let test_start = Instant::now();
    
    // Define workload mix
    let workload_mix = vec![
        (40, "benign"),           // 40% benign traffic
        (20, "sql_injection"),    // 20% SQL injection attempts
        (15, "xss"),              // 15% XSS attempts
        (15, "unicode"),          // 15% Unicode attacks
        (10, "command_injection"), // 10% Command injection
    ];
    
    let total_requests = 10000;
    let mut handles = Vec::new();
    
    for i in 0..total_requests {
        // Select workload type based on distribution
        let mut cumulative = 0;
        let random_val = i % 100;
        let mut selected_type = "benign";
        
        for (percentage, threat_type) in &workload_mix {
            cumulative += percentage;
            if random_val < cumulative {
                selected_type = threat_type;
                break;
            }
        }
        
        let server_clone = server.clone();
        let stats_clone = stats.clone();
        let include_threat = selected_type != "benign";
        let threat_type = selected_type.to_string();
        
        let handle = tokio::spawn(async move {
            let request_start = Instant::now();
            let payload = create_test_payload(include_threat, &threat_type);
            
            match timeout(Duration::from_secs(5),
                server_clone.handle_request("scan_text", payload)).await {
                Ok(Ok(response)) => {
                    stats_clone.record_request(true, request_start.elapsed());
                    
                    if let Some(threats) = response.get("threats") {
                        if let Some(arr) = threats.as_array() {
                            if !arr.is_empty() {
                                stats_clone.record_threat_detected();
                                
                                // Check if neutralization occurred
                                if response.get("neutralized").is_some() {
                                    stats_clone.record_threat_neutralized();
                                }
                            }
                        }
                    }
                }
                Ok(Err(_)) => {
                    stats_clone.record_request(false, request_start.elapsed());
                }
                Err(_) => {
                    stats_clone.record_request(false, Duration::from_secs(5));
                }
            }
        });
        
        handles.push(handle);
        
        // Spread requests over time
        if i % 100 == 0 {
            sleep(Duration::from_millis(10)).await;
        }
    }
    
    // Wait for all requests
    for handle in handles {
        let _ = handle.await;
    }
    
    let total_duration = test_start.elapsed();
    stats.print_summary("Mixed Workload", total_duration);
    
    // Verify threat detection
    let total_threats_expected = (total_requests as f64 * 0.6) as u64; // 60% have threats
    let threats_detected = stats.threats_detected.load(Ordering::Relaxed);
    assert!(threats_detected > total_threats_expected * 9 / 10, 
        "Should detect at least 90% of threats");
}

/// Test rate limiting under load
#[tokio::test]
async fn test_rate_limiting_under_load() {
    let mut config = create_test_config();
    // Configure aggressive rate limiting
    config.rate_limit = Some(kindly_guard_server::RateLimitConfig {
        enabled: true,
        requests_per_second: 100,
        burst_size: 200,
        window_seconds: 1,
    });
    
    let server = create_test_server(config).await;
    let stats = Arc::new(LoadTestStats::default());
    
    // Try to send way more than rate limit allows
    let target_rps = 1000; // 10x the limit
    let test_duration = Duration::from_secs(10);
    let test_start = Instant::now();
    
    while test_start.elapsed() < test_duration {
        for _ in 0..10 {
            let server_clone = server.clone();
            let stats_clone = stats.clone();
            
            tokio::spawn(async move {
                let request_start = Instant::now();
                let payload = create_test_payload(false, "");
                
                match send_request(&server_clone, "tools/call", payload).await {
                    Ok(_) => {
                        stats_clone.record_request(true, request_start.elapsed());
                    }
                    Err(e) => {
                        stats_clone.record_request(false, request_start.elapsed());
                        if e.to_string().contains("rate limit") {
                            stats_clone.record_rate_limited();
                        }
                    }
                }
            });
        }
        
        sleep(Duration::from_millis(10)).await;
    }
    
    // Wait a bit for requests to complete
    sleep(Duration::from_secs(2)).await;
    
    stats.print_summary("Rate Limiting", test_start.elapsed());
    
    // Verify rate limiting worked
    let rate_limited = stats.rate_limited_requests.load(Ordering::Relaxed);
    assert!(rate_limited > 0, "Should have rate limited some requests");
    
    // Successful requests should be around the rate limit
    let successful = stats.successful_requests.load(Ordering::Relaxed);
    let expected_max = 100 * 10 + 200; // rate * seconds + burst
    assert!(successful <= expected_max * 2, "Rate limiting should constrain throughput");
}

/// Test sustained load for memory leaks
#[tokio::test]
#[ignore] // This test takes a long time
async fn test_sustained_load() {
    let config = create_test_config();
    let server = create_test_server(config).await;
    let stats = Arc::new(LoadTestStats::default());
    let stop_signal = Arc::new(AtomicBool::new(false));
    
    // Monitor memory
    let monitor_stats = stats.clone();
    let monitor_signal = stop_signal.clone();
    let monitor_handle = tokio::spawn(memory_monitor(monitor_stats, monitor_signal));
    
    let test_duration = Duration::from_secs(300); // 5 minutes
    let target_rps = 500;
    let test_start = Instant::now();
    
    // Record memory samples
    let memory_samples = Arc::new(RwLock::new(Vec::new()));
    
    // Sample memory periodically
    let sample_stats = stats.clone();
    let sample_memory = memory_samples.clone();
    let sample_handle = tokio::spawn(async move {
        while test_start.elapsed() < test_duration {
            let current_memory = sample_stats.memory_peak_bytes.load(Ordering::Relaxed);
            sample_memory.write().await.push((test_start.elapsed(), current_memory));
            sleep(Duration::from_secs(10)).await;
        }
    });
    
    // Generate sustained load
    while test_start.elapsed() < test_duration {
        for _ in 0..10 {
            let server_clone = server.clone();
            let stats_clone = stats.clone();
            
            tokio::spawn(async move {
                let request_start = Instant::now();
                let include_threat = rand::thread_rng().gen_bool(0.5);
                let payload = create_test_payload(include_threat, "mixed");
                
                match timeout(Duration::from_secs(5),
                    send_request(&server_clone, "tools/call", payload)).await {
                    Ok(Ok(_)) => {
                        stats_clone.record_request(true, request_start.elapsed());
                    }
                    Ok(Err(_)) => {
                        stats_clone.record_request(false, request_start.elapsed());
                    }
                    Err(_) => {
                        stats_clone.record_request(false, Duration::from_secs(5));
                    }
                }
            });
        }
        
        sleep(Duration::from_millis(1000 / target_rps * 10)).await;
    }
    
    stop_signal.store(true, Ordering::Relaxed);
    let _ = monitor_handle.await;
    let _ = sample_handle.await;
    
    stats.print_summary("Sustained Load", test_start.elapsed());
    
    // Analyze memory trend
    let samples = memory_samples.read().await;
    if samples.len() > 2 {
        let first_sample = samples[0].1;
        let last_sample = samples[samples.len() - 1].1;
        let memory_growth = last_sample.saturating_sub(first_sample);
        let growth_percentage = (memory_growth as f64 / first_sample as f64) * 100.0;
        
        println!("Memory growth: {:.2} MB ({:.2}%)", 
            memory_growth as f64 / 1024.0 / 1024.0,
            growth_percentage);
        
        // Assert no significant memory leak
        assert!(growth_percentage < 50.0, "Memory should not grow more than 50%");
    }
    
    // Performance should remain stable
    assert!(stats.get_average_latency_ms() < 100.0, "Performance should remain stable");
}

/// Test performance degradation curve
#[tokio::test]
async fn test_performance_degradation() {
    let config = create_test_config();
    let server = create_test_server(config).await;
    
    // Test at increasing load levels
    let load_levels = vec![100, 500, 1000, 2000, 5000, 10000];
    let mut results = Vec::new();
    
    for target_rps in load_levels {
        println!("\nTesting at {} req/s", target_rps);
        let stats = Arc::new(LoadTestStats::default());
        let test_duration = Duration::from_secs(10);
        let test_start = Instant::now();
        
        // Generate load at target RPS
        let mut request_count = 0;
        while test_start.elapsed() < test_duration {
            let batch_size = std::cmp::min(100, target_rps / 10);
            
            for _ in 0..batch_size {
                let server_clone = server.clone();
                let stats_clone = stats.clone();
                
                tokio::spawn(async move {
                    let request_start = Instant::now();
                    let payload = create_test_payload(false, "");
                    
                    match timeout(Duration::from_secs(5),
                        send_request(&server_clone, "tools/call", payload)).await {
                        Ok(Ok(_)) => {
                            stats_clone.record_request(true, request_start.elapsed());
                        }
                        Ok(Err(_)) => {
                            stats_clone.record_request(false, request_start.elapsed());
                        }
                        Err(_) => {
                            stats_clone.record_request(false, Duration::from_secs(5));
                        }
                    }
                });
                
                request_count += 1;
            }
            
            // Sleep to maintain target RPS
            let expected_elapsed = Duration::from_millis(request_count * 1000 / target_rps as u64);
            let actual_elapsed = test_start.elapsed();
            if expected_elapsed > actual_elapsed {
                sleep(expected_elapsed - actual_elapsed).await;
            }
        }
        
        // Wait for requests to complete
        sleep(Duration::from_secs(2)).await;
        
        let avg_latency = stats.get_average_latency_ms();
        let max_latency = stats.max_latency_us.load(Ordering::Relaxed) as f64 / 1000.0;
        let success_rate = stats.successful_requests.load(Ordering::Relaxed) as f64
            / stats.total_requests.load(Ordering::Relaxed) as f64;
        let actual_throughput = stats.get_throughput(test_duration);
        
        results.push((target_rps, actual_throughput, avg_latency, max_latency, success_rate));
        
        println!("Target RPS: {}, Actual: {:.2}, Avg Latency: {:.2}ms, Success Rate: {:.2}%",
            target_rps, actual_throughput, avg_latency, success_rate * 100.0);
    }
    
    // Print degradation curve
    println!("\n=== Performance Degradation Curve ===");
    println!("Target RPS | Actual RPS | Avg Latency | Max Latency | Success Rate");
    println!("-----------|------------|-------------|-------------|-------------");
    for (target, actual, avg_lat, max_lat, success) in &results {
        println!("{:10} | {:10.2} | {:11.2} | {:11.2} | {:11.2}%",
            target, actual, avg_lat, max_lat, success * 100.0);
    }
    
    // Find breaking point (where success rate drops below 95%)
    let breaking_point = results.iter()
        .find(|(_, _, _, _, success)| *success < 0.95)
        .map(|(target, _, _, _, _)| *target);
    
    if let Some(bp) = breaking_point {
        println!("\nBreaking point: {} req/s", bp);
    } else {
        println!("\nNo breaking point found within test range");
    }
    
    // Verify graceful degradation
    let latencies: Vec<f64> = results.iter().map(|(_, _, lat, _, _)| *lat).collect();
    for i in 1..latencies.len() {
        // Latency should increase but not exponentially
        assert!(latencies[i] < latencies[i-1] * 3.0, 
            "Latency should not increase exponentially");
    }
}

/// Helper function to create test config
fn create_test_config() -> Config {
    use kindly_guard_server::config::RateLimitConfig;
    
    Config {
        scanner: ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            xss_detection: Some(true),
            enhanced_mode: Some(false), // Use standard mode for consistent testing
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
        },
        rate_limit: Some(RateLimitConfig {
            enabled: true,
            requests_per_second: 1000,
            burst_size: 2000,
            window_seconds: 1,
        }),
        ..Default::default()
    }
}

/// Helper function to create test server
async fn create_test_server(config: Config) -> Arc<McpServer> {
    Arc::new(McpServer::new(config).expect("Failed to create server"))
}

/// Helper to send a request to the server
async fn send_request(
    server: &Arc<McpServer>,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    use kindly_guard_server::protocol::{JsonRpcRequest, RequestId};
    
    // Create a simple wrapper that calls the handle_message method
    let request_json = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });
    
    let request_str = serde_json::to_string(&request_json).unwrap();
    
    // Use the public handle_message interface
    if let Some(response_str) = server.handle_message(&request_str).await {
        // Parse the response
        if let Ok(response_json) = serde_json::from_str::<Value>(&response_str) {
            if let Some(error) = response_json.get("error") {
                Err(error.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Unknown error")
                    .to_string())
            } else if let Some(result) = response_json.get("result") {
                Ok(result.clone())
            } else {
                Err("No result or error in response".to_string())
            }
        } else {
            Err("Failed to parse response JSON".to_string())
        }
    } else {
        // No response means it was a notification
        Err("No response received".to_string())
    }
}