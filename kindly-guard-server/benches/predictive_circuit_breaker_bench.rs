//! Benchmarks for Predictive Circuit Breaker
//!
//! Run with: cargo bench --features enhanced predictive_circuit_breaker

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use kindly_guard_server::config::Config;
use kindly_guard_server::enhanced_impl::resilience::predictive_circuit_breaker::PredictiveCircuitBreaker;
use kindly_guard_server::resilience::standard::StandardCircuitBreaker;
use kindly_guard_server::resilience::circuit_breaker::CircuitBreakerConfig;
use kindly_guard_server::traits::CircuitBreakerTrait;
use std::time::Duration;
use tokio::runtime::Runtime;

fn create_config() -> Config {
    let mut config = Config::default();
    config.resilience.circuit_breaker.failure_threshold = 5;
    config.resilience.circuit_breaker.recovery_timeout = Duration::from_secs(30);
    config.resilience.circuit_breaker.predictive = Some(true);
    config
}

fn create_standard_config() -> CircuitBreakerConfig {
    CircuitBreakerConfig {
        failure_threshold: 5,
        failure_window: Duration::from_secs(60),
        success_threshold: 0.8,
        recovery_timeout: Duration::from_secs(30),
        request_timeout: Duration::from_secs(10),
        half_open_max_requests: 3,
    }
}

fn bench_successful_calls(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = create_config();
    
    let mut group = c.benchmark_group("successful_calls");
    
    // Benchmark standard circuit breaker
    group.bench_function("standard", |b| {
        let cb = StandardCircuitBreaker::new(create_standard_config());
        b.to_async(&rt).iter(|| async {
            cb.call("bench", || async {
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(black_box(42))
            }).await
        });
    });
    
    // Benchmark predictive circuit breaker
    #[cfg(feature = "enhanced")]
    group.bench_function("predictive", |b| {
        let cb = PredictiveCircuitBreaker::new(&config);
        b.to_async(&rt).iter(|| async {
            cb.call("bench", || async {
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(black_box(42))
            }).await
        });
    });
    
    group.finish();
}

fn bench_mixed_workload(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = create_config();
    
    let mut group = c.benchmark_group("mixed_workload");
    
    // 20% failure rate
    let failure_rate = 0.2;
    
    group.bench_function("standard", |b| {
        let cb = StandardCircuitBreaker::new(create_standard_config());
        let mut counter = 0;
        b.to_async(&rt).iter(|| async {
            counter += 1;
            cb.call("bench", || async move {
                if counter % 5 == 0 {
                    Err::<i32, _>("error".into())
                } else {
                    Ok(black_box(42))
                }
            }).await
        });
    });
    
    #[cfg(feature = "enhanced")]
    group.bench_function("predictive", |b| {
        let cb = PredictiveCircuitBreaker::new(&config);
        let mut counter = 0;
        b.to_async(&rt).iter(|| async {
            counter += 1;
            cb.call("bench", || async move {
                if counter % 5 == 0 {
                    Err::<i32, _>("error".into())
                } else {
                    Ok(black_box(42))
                }
            }).await
        });
    });
    
    group.finish();
}

#[cfg(feature = "enhanced")]
fn bench_prediction_overhead(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = create_config();
    let cb = PredictiveCircuitBreaker::new(&config);
    
    // Warm up with some data
    rt.block_on(async {
        for i in 0..100 {
            let _ = cb.call("warmup", || async move {
                if i % 10 == 0 {
                    Err::<i32, _>("error".into())
                } else {
                    Ok(i)
                }
            }).await;
        }
    });
    
    let mut group = c.benchmark_group("prediction_overhead");
    
    group.bench_function("confidence_check", |b| {
        b.iter(|| {
            black_box(cb.prediction_confidence())
        });
    });
    
    group.bench_function("probability_check", |b| {
        b.iter(|| {
            black_box(cb.failure_probability())
        });
    });
    
    group.bench_function("stats_retrieval", |b| {
        b.iter(|| {
            black_box(cb.feature_stats())
        });
    });
    
    group.finish();
}

fn bench_circuit_state_transitions(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let config = create_config();
    
    let mut group = c.benchmark_group("state_transitions");
    
    // Benchmark opening circuit (consecutive failures)
    group.bench_function("circuit_opening", |b| {
        b.to_async(&rt).iter_custom(|iters| {
            let cb = PredictiveCircuitBreaker::new(&config);
            async move {
                let start = std::time::Instant::now();
                for _ in 0..iters {
                    // Reset state
                    cb.reset("bench").await;
                    
                    // Cause failures to open circuit
                    for _ in 0..5 {
                        let _ = cb.call("bench", || async {
                            Err::<i32, _>("error".into())
                        }).await;
                    }
                }
                start.elapsed()
            }
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_successful_calls,
    bench_mixed_workload,
    bench_circuit_state_transitions
);

#[cfg(feature = "enhanced")]
criterion_group!(
    enhanced_benches,
    bench_prediction_overhead
);

#[cfg(not(feature = "enhanced"))]
criterion_main!(benches);

#[cfg(feature = "enhanced")]
criterion_main!(benches, enhanced_benches);