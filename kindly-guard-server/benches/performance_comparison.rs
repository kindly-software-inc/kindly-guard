//! Performance comparison benchmarks between standard and enhanced modes

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use kindly_guard_server::{
    config::{Config, EventProcessorConfig},
    component_selector::ComponentManager,
    traits::{SecurityEvent, RateLimitKey},
};
use std::time::Duration;
use tokio::runtime::Runtime;

fn create_test_config(enhanced: bool) -> Config {
    let mut config = Config::default();
    config.event_processor.enabled = enhanced;
    config.event_processor.buffer_size_mb = 10;
    config.event_processor.max_endpoints = 1000;
    config.event_processor.rate_limit = 10000.0;
    config
}

fn create_test_event(client_id: &str) -> SecurityEvent {
    SecurityEvent {
        event_type: "request".to_string(),
        client_id: client_id.to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        metadata: serde_json::json!({
            "method": "test",
            "path": "/api/test"
        }),
    }
}

fn bench_event_processing(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("event_processing");
    group.measurement_time(Duration::from_secs(10));
    
    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";
        let config = create_test_config(enhanced);
        let manager = ComponentManager::new(&config).unwrap();
        let processor = manager.event_processor();
        
        group.bench_with_input(
            BenchmarkId::from_parameter(mode),
            &mode,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    let event = create_test_event("test_client");
                    processor.process_event(event).await.unwrap()
                });
            },
        );
    }
    
    group.finish();
}

fn bench_rate_limiting(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("rate_limiting");
    group.measurement_time(Duration::from_secs(10));
    
    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";
        let config = create_test_config(enhanced);
        let manager = ComponentManager::new(&config).unwrap();
        let rate_limiter = manager.rate_limiter();
        
        group.bench_with_input(
            BenchmarkId::from_parameter(mode),
            &mode,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    let key = RateLimitKey {
                        client_id: "test_client".to_string(),
                        method: Some("test".to_string()),
                    };
                    rate_limiter.check_rate_limit(&key).await.unwrap()
                });
            },
        );
    }
    
    group.finish();
}

fn bench_threat_scanning(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("threat_scanning");
    group.measurement_time(Duration::from_secs(10));
    
    let test_data = b"SELECT * FROM users WHERE id = '1' OR '1'='1'; -- SQL injection attempt";
    
    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";
        let config = create_test_config(enhanced);
        let manager = ComponentManager::new(&config).unwrap();
        let scanner = manager.scanner();
        
        group.bench_with_input(
            BenchmarkId::from_parameter(mode),
            &mode,
            |b, _| {
                b.iter(|| {
                    scanner.enhanced_scan(test_data).unwrap()
                });
            },
        );
    }
    
    group.finish();
}

fn bench_correlation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("correlation");
    group.measurement_time(Duration::from_secs(10));
    
    // Create a batch of events for correlation
    let events: Vec<SecurityEvent> = (0..100)
        .map(|i| {
            let client_id = if i % 10 == 0 { "attacker" } else { "normal_user" };
            let event_type = if i % 10 == 0 { "auth_failure" } else { "request" };
            SecurityEvent {
                event_type: event_type.to_string(),
                client_id: client_id.to_string(),
                timestamp: i as u64,
                metadata: serde_json::json!({}),
            }
        })
        .collect();
    
    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";
        let config = create_test_config(enhanced);
        let manager = ComponentManager::new(&config).unwrap();
        let correlation_engine = manager.correlation_engine();
        
        group.bench_with_input(
            BenchmarkId::from_parameter(mode),
            &mode,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    correlation_engine.correlate(&events).await.unwrap()
                });
            },
        );
    }
    
    group.finish();
}

fn bench_high_load(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let mut group = c.benchmark_group("high_load");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);
    
    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";
        let config = create_test_config(enhanced);
        let manager = ComponentManager::new(&config).unwrap();
        
        group.bench_with_input(
            BenchmarkId::from_parameter(mode),
            &mode,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    // Simulate high load with multiple operations
                    let mut handles = vec![];
                    
                    // Process 1000 events from 100 different clients
                    for i in 0..1000 {
                        let client_id = format!("client_{}", i % 100);
                        let event = create_test_event(&client_id);
                        let processor = manager.event_processor().clone();
                        
                        let handle = tokio::spawn(async move {
                            processor.process_event(event).await
                        });
                        handles.push(handle);
                    }
                    
                    // Wait for all to complete
                    for handle in handles {
                        let _ = handle.await;
                    }
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_event_processing,
    bench_rate_limiting,
    bench_threat_scanning,
    bench_correlation,
    bench_high_load
);
criterion_main!(benches);