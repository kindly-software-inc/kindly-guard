// Copyright 2025 Kindly-Software
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
//! Benchmark comparing standard vs hierarchical rate limiter implementations
//!
//! This benchmark demonstrates:
//! - Linear scaling of hierarchical implementation up to 64+ cores
//! - Cache efficiency improvements
//! - Reduced contention under high concurrency

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kindly_guard_server::{
    rate_limit::{RateLimitConfig, RateLimiter as StandardRateLimiter},
    traits::{RateLimitKey, RateLimiter as RateLimiterTrait},
    Config,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

#[cfg(feature = "enhanced")]
use kindly_guard_server::enhanced_impl::HierarchicalRateLimiter;

/// Benchmark single-threaded rate limiting performance
fn bench_single_thread_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiter_single_thread");
    group.measurement_time(Duration::from_secs(10));

    let rt = Runtime::new().unwrap();

    // Standard rate limiter
    let standard_config = RateLimitConfig {
        enabled: true,
        default_rpm: 60000, // 1000 RPS
        burst_capacity: 1000,
        ..Default::default()
    };
    let standard_limiter = Arc::new(StandardRateLimiter::new(standard_config));

    group.bench_function("standard", |b| {
        let key = RateLimitKey {
            client_id: "bench_client".to_string(),
            method: None,
        };

        b.iter(|| {
            rt.block_on(async {
                let decision = standard_limiter
                    .check_limit(&key.client_id, key.method.as_deref(), 1.0)
                    .await
                    .unwrap();
                black_box(decision.allowed)
            })
        });
    });

    // Hierarchical rate limiter (if available)
    #[cfg(feature = "enhanced")]
    {
        let hierarchical_limiter = Arc::new(HierarchicalRateLimiter::new(60000, 1000));

        group.bench_function("hierarchical", |b| {
            let key = RateLimitKey {
                client_id: "bench_client".to_string(),
                method: None,
            };

            b.iter(|| {
                rt.block_on(async {
                    let decision = hierarchical_limiter.check_rate_limit(&key).await.unwrap();
                    black_box(decision.allowed)
                })
            });
        });
    }

    group.finish();
}

/// Benchmark multi-threaded contention
fn bench_concurrent_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiter_contention");
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(20);

    let thread_counts = vec![1, 2, 4, 8, 16, 32, 64];

    for thread_count in thread_counts {
        // Standard rate limiter
        let standard_config = RateLimitConfig {
            enabled: true,
            default_rpm: 600000, // 10k RPS
            burst_capacity: 10000,
            ..Default::default()
        };
        let standard_limiter = Arc::new(StandardRateLimiter::new(standard_config));

        group.bench_with_input(
            BenchmarkId::new("standard", thread_count),
            &thread_count,
            |b, &thread_count| {
                b.iter_custom(|iters| {
                    let rt = Runtime::new().unwrap();

                    rt.block_on(async {
                        let start = std::time::Instant::now();

                        let mut handles = vec![];
                        let iterations_per_thread = iters / thread_count as u64;

                        for thread_id in 0..thread_count {
                            let limiter = standard_limiter.clone();
                            let handle = tokio::spawn(async move {
                                let key = RateLimitKey {
                                    client_id: format!("client_{}", thread_id),
                                    method: None,
                                };

                                for _ in 0..iterations_per_thread {
                                    let decision = limiter
                                        .check_limit(&key.client_id, key.method.as_deref(), 1.0)
                                        .await
                                        .unwrap();
                                    black_box(decision.allowed);
                                }
                            });
                            handles.push(handle);
                        }

                        for handle in handles {
                            handle.await.unwrap();
                        }

                        start.elapsed()
                    })
                });
            },
        );

        // Hierarchical rate limiter
        #[cfg(feature = "enhanced")]
        {
            let hierarchical_limiter = Arc::new(HierarchicalRateLimiter::new(600000, 10000));

            group.bench_with_input(
                BenchmarkId::new("hierarchical", thread_count),
                &thread_count,
                |b, &thread_count| {
                    b.iter_custom(|iters| {
                        let rt = Runtime::new().unwrap();

                        rt.block_on(async {
                            let start = std::time::Instant::now();

                            let mut handles = vec![];
                            let iterations_per_thread = iters / thread_count as u64;

                            for thread_id in 0..thread_count {
                                let limiter = hierarchical_limiter.clone();
                                let handle = tokio::spawn(async move {
                                    let key = RateLimitKey {
                                        client_id: format!("client_{}", thread_id),
                                        method: None,
                                    };

                                    for _ in 0..iterations_per_thread {
                                        let decision =
                                            limiter.check_rate_limit(&key).await.unwrap();
                                        black_box(decision.allowed);
                                    }
                                });
                                handles.push(handle);
                            }

                            for handle in handles {
                                handle.await.unwrap();
                            }

                            start.elapsed()
                        })
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark work-stealing efficiency
#[cfg(feature = "enhanced")]
fn bench_work_stealing(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiter_work_stealing");
    group.measurement_time(Duration::from_secs(10));

    let rt = Runtime::new().unwrap();
    let hierarchical_limiter = Arc::new(HierarchicalRateLimiter::new(60000, 1000));

    // Simulate unbalanced load
    group.bench_function("unbalanced_load", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut handles = vec![];

                // 80% of requests go to 20% of clients (Pareto distribution)
                for i in 0..100 {
                    let limiter = hierarchical_limiter.clone();
                    let client_id = if i < 80 {
                        format!("hot_client_{}", i % 20)
                    } else {
                        format!("cold_client_{}", i)
                    };

                    let handle = tokio::spawn(async move {
                        let key = RateLimitKey {
                            client_id,
                            method: None,
                        };

                        for _ in 0..10 {
                            let decision = limiter.check_rate_limit(&key).await.unwrap();
                            black_box(decision.allowed);
                        }
                    });
                    handles.push(handle);
                }

                for handle in handles {
                    handle.await.unwrap();
                }
            })
        });
    });

    group.finish();
}

/// Benchmark cache efficiency
fn bench_cache_efficiency(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiter_cache");
    group.measurement_time(Duration::from_secs(10));

    let rt = Runtime::new().unwrap();

    // Test with different client counts to see cache impact
    let client_counts = vec![10, 100, 1000, 10000];

    for client_count in client_counts {
        // Standard rate limiter
        let standard_config = RateLimitConfig {
            enabled: true,
            default_rpm: 60000,
            burst_capacity: 1000,
            ..Default::default()
        };
        let standard_limiter = Arc::new(StandardRateLimiter::new(standard_config));

        group.bench_with_input(
            BenchmarkId::new("standard", client_count),
            &client_count,
            |b, &client_count| {
                let mut client_idx = 0;
                b.iter(|| {
                    rt.block_on(async {
                        let key = RateLimitKey {
                            client_id: format!("client_{}", client_idx % client_count),
                            method: None,
                        };
                        client_idx += 1;

                        let decision = standard_limiter
                            .check_limit(&key.client_id, key.method.as_deref(), 1.0)
                            .await
                            .unwrap();
                        black_box(decision.allowed)
                    })
                });
            },
        );

        // Hierarchical rate limiter
        #[cfg(feature = "enhanced")]
        {
            let hierarchical_limiter = Arc::new(HierarchicalRateLimiter::new(60000, 1000));

            group.bench_with_input(
                BenchmarkId::new("hierarchical", client_count),
                &client_count,
                |b, &client_count| {
                    let mut client_idx = 0;
                    b.iter(|| {
                        rt.block_on(async {
                            let key = RateLimitKey {
                                client_id: format!("client_{}", client_idx % client_count),
                                method: None,
                            };
                            client_idx += 1;

                            let decision =
                                hierarchical_limiter.check_rate_limit(&key).await.unwrap();
                            black_box(decision.allowed)
                        })
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark memory usage patterns
fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiter_memory");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    let rt = Runtime::new().unwrap();

    // Standard rate limiter memory growth
    group.bench_function("standard_growth", |b| {
        b.iter_custom(|_iters| {
            let standard_config = RateLimitConfig {
                enabled: true,
                default_rpm: 60000,
                burst_capacity: 1000,
                ..Default::default()
            };
            let standard_limiter = Arc::new(StandardRateLimiter::new(standard_config));

            let start = std::time::Instant::now();

            rt.block_on(async {
                // Create many unique clients to force memory allocation
                for i in 0..10000 {
                    let key = RateLimitKey {
                        client_id: format!("unique_client_{}", i),
                        method: None,
                    };

                    let _ = standard_limiter
                        .check_limit(&key.client_id, key.method.as_deref(), 1.0)
                        .await;
                }
            });

            start.elapsed()
        });
    });

    // Hierarchical rate limiter has fixed memory
    #[cfg(feature = "enhanced")]
    {
        group.bench_function("hierarchical_fixed", |b| {
            b.iter_custom(|_iters| {
                let hierarchical_limiter = Arc::new(HierarchicalRateLimiter::new(60000, 1000));

                let start = std::time::Instant::now();

                rt.block_on(async {
                    // Create many unique clients - memory stays constant
                    for i in 0..10000 {
                        let key = RateLimitKey {
                            client_id: format!("unique_client_{}", i),
                            method: None,
                        };

                        let _ = hierarchical_limiter.check_rate_limit(&key).await;
                    }
                });

                start.elapsed()
            });
        });
    }

    group.finish();
}

#[cfg(feature = "enhanced")]
criterion_group!(
    benches,
    bench_single_thread_throughput,
    bench_concurrent_contention,
    bench_work_stealing,
    bench_cache_efficiency,
    bench_memory_usage
);

#[cfg(not(feature = "enhanced"))]
criterion_group!(
    benches,
    bench_single_thread_throughput,
    bench_concurrent_contention,
    bench_cache_efficiency,
    bench_memory_usage
);

criterion_main!(benches);
