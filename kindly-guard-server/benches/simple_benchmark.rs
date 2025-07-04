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
//! Simple performance benchmarks comparing standard and enhanced modes

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use kindly_guard_server::{
    component_selector::ComponentManager,
    config::Config,
    traits::{RateLimitKey, SecurityEvent},
};
use std::time::Duration;

fn create_test_config(enhanced: bool) -> Config {
    let mut config = Config::default();
    config.event_processor.enabled = enhanced;
    config
}

fn create_test_event(client_id: &str, idx: u64) -> SecurityEvent {
    SecurityEvent {
        event_type: "request".to_string(),
        client_id: client_id.to_string(),
        timestamp: idx,
        metadata: serde_json::json!({
            "method": "test",
            "path": "/api/test",
            "index": idx
        }),
    }
}

fn bench_event_processing_sync(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_processing_sync");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    // Create runtime for async operations
    let rt = tokio::runtime::Runtime::new().unwrap();

    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";
        let config = create_test_config(enhanced);
        let manager = ComponentManager::new(&config).unwrap();
        let processor = manager.event_processor();

        group.bench_with_input(BenchmarkId::from_parameter(mode), &mode, |b, _| {
            let mut idx = 0u64;
            b.iter(|| {
                let event = create_test_event("bench_client", idx);
                idx += 1;
                rt.block_on(async { processor.process_event(event).await.unwrap() })
            });
        });
    }

    group.finish();
}

fn bench_rate_limiting_sync(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiting_sync");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    let rt = tokio::runtime::Runtime::new().unwrap();

    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";
        let config = create_test_config(enhanced);
        let manager = ComponentManager::new(&config).unwrap();
        let rate_limiter = manager.rate_limiter();

        group.bench_with_input(BenchmarkId::from_parameter(mode), &mode, |b, _| {
            let mut client_idx = 0;
            b.iter(|| {
                // Use different clients to avoid rate limit exhaustion
                let key = RateLimitKey {
                    client_id: format!("bench_client_{}", client_idx % 100),
                    method: Some("test".to_string()),
                };
                client_idx += 1;
                rt.block_on(async { rate_limiter.check_rate_limit(&key).await.unwrap() })
            });
        });
    }

    group.finish();
}

fn bench_scanner_sync(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanner_sync");
    group.measurement_time(Duration::from_secs(5));

    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";
        let config = create_test_config(enhanced);
        let manager = ComponentManager::new(&config).unwrap();
        let scanner = manager.scanner();

        // Test data with potential threats
        let test_data = b"SELECT * FROM users WHERE id = 1 UNION SELECT * FROM passwords";

        group.bench_with_input(BenchmarkId::from_parameter(mode), &mode, |b, _| {
            b.iter(|| scanner.enhanced_scan(test_data).unwrap());
        });
    }

    group.finish();
}

fn bench_correlation_sync(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_sync");
    group.measurement_time(Duration::from_secs(5));

    let rt = tokio::runtime::Runtime::new().unwrap();

    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";
        let config = create_test_config(enhanced);
        let manager = ComponentManager::new(&config).unwrap();
        let correlation_engine = manager.correlation_engine();

        // Create a pattern of events
        let events: Vec<SecurityEvent> = (0..20)
            .map(|i| SecurityEvent {
                event_type: if i % 3 == 0 {
                    "auth_failure"
                } else {
                    "request"
                }
                .to_string(),
                client_id: "suspicious_client".to_string(),
                timestamp: i,
                metadata: serde_json::json!({}),
            })
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(mode), &mode, |b, _| {
            b.iter(|| rt.block_on(async { correlation_engine.correlate(&events).await.unwrap() }));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_event_processing_sync,
    bench_rate_limiting_sync,
    bench_scanner_sync,
    bench_correlation_sync
);
criterion_main!(benches);
