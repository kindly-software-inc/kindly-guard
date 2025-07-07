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
//! Comparative benchmarks for standard vs atomic event buffer implementations
//!
//! These benchmarks measure the performance difference between:
//! - SimpleEventBuffer: Standard in-memory implementation
//! - AtomicEventBufferAdapter: High-performance lock-free implementation

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kindly_guard_server::{
    config::Config,
    event_processor::{EventProcessorConfig, SecurityEventProcessor, SimpleEventBuffer},
    traits::{EventBufferTrait, Priority},
};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[cfg(feature = "enhanced")]
use kindly_guard_server::enhanced_impl::atomic_event_buffer::AtomicEventBufferAdapter;

/// Test data sizes for benchmarking
const SMALL_BATCH: usize = 100;
const MEDIUM_BATCH: usize = 1_000;
const LARGE_BATCH: usize = 10_000;
const XLARGE_BATCH: usize = 100_000;

/// Thread counts for concurrent benchmarks
const THREAD_COUNTS: &[usize] = &[1, 2, 4, 8, 16];

/// Buffer sizes to test (in MB)
const BUFFER_SIZES: &[usize] = &[1, 10, 50, 100];

/// Generate test event data of various sizes
fn generate_event_data(size: usize) -> Vec<u8> {
    vec![0xAB; size]
}

/// Benchmark single-threaded event enqueueing
fn bench_single_thread_enqueue(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_buffer/single_thread_enqueue");

    for buffer_mb in BUFFER_SIZES {
        for batch_size in &[SMALL_BATCH, MEDIUM_BATCH, LARGE_BATCH] {
            let event_data = generate_event_data(256); // 256 byte events

            // Benchmark standard implementation
            group.throughput(Throughput::Elements(*batch_size as u64));
            group.bench_function(
                BenchmarkId::new(format!("standard/{}mb", buffer_mb), batch_size),
                |b| {
                    let buffer = Arc::new(SimpleEventBuffer::new());
                    
                    b.iter(|| {
                        for i in 0..*batch_size {
                            let endpoint_id = (i % 100) as u32;
                            let priority = if i % 10 == 0 {
                                Priority::High
                            } else {
                                Priority::Normal
                            };
                            
                            let _ = buffer.enqueue_event(
                                black_box(endpoint_id),
                                black_box(&event_data),
                                black_box(priority),
                            );
                        }
                    });
                },
            );

            // Benchmark atomic implementation
            #[cfg(feature = "enhanced")]
            {
                group.bench_function(
                    BenchmarkId::new(format!("atomic/{}mb", buffer_mb), batch_size),
                    |b| {
                        let buffer = Arc::new(
                            AtomicEventBufferAdapter::new(*buffer_mb, 1000).unwrap()
                        );
                        
                        b.iter(|| {
                            for i in 0..*batch_size {
                                let endpoint_id = (i % 100) as u32;
                                let priority = if i % 10 == 0 {
                                    Priority::High
                                } else {
                                    Priority::Normal
                                };
                                
                                let _ = buffer.enqueue_event(
                                    black_box(endpoint_id),
                                    black_box(&event_data),
                                    black_box(priority),
                                );
                            }
                        });
                    },
                );
            }
        }
    }

    group.finish();
}

/// Benchmark concurrent event enqueueing
fn bench_concurrent_enqueue(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_buffer/concurrent_enqueue");
    group.sample_size(10); // Reduce sample size for concurrent benchmarks

    let buffer_mb = 50; // Fixed buffer size for concurrent tests
    let events_per_thread = 1000;

    for thread_count in THREAD_COUNTS {
        let event_data = generate_event_data(256);
        
        // Benchmark standard implementation
        group.throughput(Throughput::Elements((*thread_count * events_per_thread) as u64));
        group.bench_function(
            BenchmarkId::new("standard", thread_count),
            |b| {
                b.iter_custom(|iters| {
                    let buffer = Arc::new(SimpleEventBuffer::new());
                    
                    let start = std::time::Instant::now();
                    
                    let mut handles = vec![];
                    for thread_id in 0..*thread_count {
                        let buffer_clone = buffer.clone();
                        let event_data_clone = event_data.clone();
                        let iterations = iters;
                        
                        let handle = thread::spawn(move || {
                            for i in 0..events_per_thread {
                                for _ in 0..iterations {
                                    let endpoint_id = ((thread_id * 100 + i) % 1000) as u32;
                                    let priority = if i % 10 == 0 {
                                        Priority::High
                                    } else {
                                        Priority::Normal
                                    };
                                    
                                    let _ = buffer_clone.enqueue_event(
                                        endpoint_id,
                                        &event_data_clone,
                                        priority,
                                    );
                                }
                            }
                        });
                        
                        handles.push(handle);
                    }
                    
                    for handle in handles {
                        handle.join().unwrap();
                    }
                    
                    start.elapsed()
                });
            },
        );

        // Benchmark atomic implementation
        #[cfg(feature = "enhanced")]
        {
            group.bench_function(
                BenchmarkId::new("atomic", thread_count),
                |b| {
                    b.iter_custom(|iters| {
                        let buffer = Arc::new(
                            AtomicEventBufferAdapter::new(buffer_mb, 1000).unwrap()
                        );
                        
                        let start = std::time::Instant::now();
                        
                        let mut handles = vec![];
                        for thread_id in 0..*thread_count {
                            let buffer_clone = buffer.clone();
                            let event_data_clone = event_data.clone();
                            let iterations = iters;
                            
                            let handle = thread::spawn(move || {
                                for i in 0..events_per_thread {
                                    for _ in 0..iterations {
                                        let endpoint_id = ((thread_id * 100 + i) % 1000) as u32;
                                        let priority = if i % 10 == 0 {
                                            Priority::High
                                        } else {
                                            Priority::Normal
                                        };
                                        
                                        let _ = buffer_clone.enqueue_event(
                                            endpoint_id,
                                            &event_data_clone,
                                            priority,
                                        );
                                    }
                                }
                            });
                            
                            handles.push(handle);
                        }
                        
                        for handle in handles {
                            handle.join().unwrap();
                        }
                        
                        start.elapsed()
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark mixed operations (enqueue + stats)
fn bench_mixed_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_buffer/mixed_operations");
    
    let buffer_mb = 50;
    let operation_count = 10000;
    
    // Benchmark standard implementation
    group.throughput(Throughput::Elements(operation_count as u64));
    group.bench_function("standard", |b| {
        let buffer = Arc::new(SimpleEventBuffer::new());
        let event_data = generate_event_data(256);
        
        b.iter(|| {
            for i in 0..operation_count {
                let endpoint_id = (i % 100) as u32;
                
                // Mix of enqueue and stats operations
                if i % 5 == 0 {
                    // Get stats every 5th operation
                    let _ = buffer.get_endpoint_stats(black_box(endpoint_id));
                } else {
                    // Enqueue event
                    let priority = if i % 10 == 0 {
                        Priority::High
                    } else {
                        Priority::Normal
                    };
                    
                    let _ = buffer.enqueue_event(
                        black_box(endpoint_id),
                        black_box(&event_data),
                        black_box(priority),
                    );
                }
            }
        });
    });

    // Benchmark atomic implementation
    #[cfg(feature = "enhanced")]
    {
        group.bench_function("atomic", |b| {
            let buffer = Arc::new(
                AtomicEventBufferAdapter::new(buffer_mb, 1000).unwrap()
            );
            let event_data = generate_event_data(256);
            
            b.iter(|| {
                for i in 0..operation_count {
                    let endpoint_id = (i % 100) as u32;
                    
                    // Mix of enqueue and stats operations
                    if i % 5 == 0 {
                        // Get stats every 5th operation
                        let _ = buffer.get_endpoint_stats(black_box(endpoint_id));
                    } else {
                        // Enqueue event
                        let priority = if i % 10 == 0 {
                            Priority::High
                        } else {
                            Priority::Normal
                        };
                        
                        let _ = buffer.enqueue_event(
                            black_box(endpoint_id),
                            black_box(&event_data),
                            black_box(priority),
                        );
                    }
                }
            });
        });
    }

    group.finish();
}

/// Benchmark different event sizes
fn bench_event_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_buffer/event_sizes");
    
    let buffer_mb = 50;
    let event_sizes = vec![64, 256, 1024, 4096, 16384]; // Various event sizes in bytes
    let events_per_size = 1000;
    
    for event_size in &event_sizes {
        let event_data = generate_event_data(*event_size);
        
        // Benchmark standard implementation
        group.throughput(Throughput::Bytes((*event_size * events_per_size) as u64));
        group.bench_function(
            BenchmarkId::new("standard", event_size),
            |b| {
                let buffer = Arc::new(SimpleEventBuffer::new());
                
                b.iter(|| {
                    for i in 0..events_per_size {
                        let endpoint_id = (i % 100) as u32;
                        let _ = buffer.enqueue_event(
                            black_box(endpoint_id),
                            black_box(&event_data),
                            black_box(Priority::Normal),
                        );
                    }
                });
            },
        );

        // Benchmark atomic implementation
        #[cfg(feature = "enhanced")]
        {
            group.bench_function(
                BenchmarkId::new("atomic", event_size),
                |b| {
                    let buffer = Arc::new(
                        AtomicEventBufferAdapter::new(buffer_mb, 1000).unwrap()
                    );
                    
                    b.iter(|| {
                        for i in 0..events_per_size {
                            let endpoint_id = (i % 100) as u32;
                            let _ = buffer.enqueue_event(
                                black_box(endpoint_id),
                                black_box(&event_data),
                                black_box(Priority::Normal),
                            );
                        }
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark priority handling
fn bench_priority_handling(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_buffer/priority_handling");
    
    let buffer_mb = 50;
    let event_data = generate_event_data(256);
    let events_per_priority = 1000;
    
    let priorities = vec![
        ("all_normal", vec![Priority::Normal; events_per_priority]),
        ("all_high", vec![Priority::High; events_per_priority]),
        ("mixed", {
            let mut p = Vec::with_capacity(events_per_priority);
            for i in 0..events_per_priority {
                p.push(if i % 10 == 0 { Priority::High } else { Priority::Normal });
            }
            p
        }),
    ];
    
    for (name, priority_list) in &priorities {
        // Benchmark standard implementation
        group.throughput(Throughput::Elements(events_per_priority as u64));
        group.bench_function(
            BenchmarkId::new("standard", name),
            |b| {
                let buffer = Arc::new(SimpleEventBuffer::new());
                
                b.iter(|| {
                    for (i, priority) in priority_list.iter().enumerate() {
                        let endpoint_id = (i % 100) as u32;
                        let _ = buffer.enqueue_event(
                            black_box(endpoint_id),
                            black_box(&event_data),
                            black_box(*priority),
                        );
                    }
                });
            },
        );

        // Benchmark atomic implementation
        #[cfg(feature = "enhanced")]
        {
            group.bench_function(
                BenchmarkId::new("atomic", name),
                |b| {
                    let buffer = Arc::new(
                        AtomicEventBufferAdapter::new(buffer_mb, 1000).unwrap()
                    );
                    
                    b.iter(|| {
                        for (i, priority) in priority_list.iter().enumerate() {
                            let endpoint_id = (i % 100) as u32;
                            let _ = buffer.enqueue_event(
                                black_box(endpoint_id),
                                black_box(&event_data),
                                black_box(*priority),
                            );
                        }
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark full event processor integration
fn bench_event_processor_integration(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_buffer/processor_integration");
    
    let event_count = 10000;
    
    // Benchmark standard processor
    group.throughput(Throughput::Elements(event_count as u64));
    group.bench_function("standard", |b| {
        let mut config = EventProcessorConfig::default();
        config.enabled = true;
        config.enhanced_mode = Some(false); // Force standard implementation
        config.buffer_size_mb = 50;
        
        let processor = SecurityEventProcessor::new(config).unwrap();
        
        b.iter(|| {
            for i in 0..event_count {
                let client_id = format!("client_{}", i % 100);
                let event = SecurityEventProcessor::auth_event(
                    black_box(&client_id),
                    black_box(i % 2 == 0), // Alternate success/failure
                    None,
                );
                let _ = processor.track_event(black_box(event));
            }
        });
    });

    // Benchmark enhanced processor
    #[cfg(feature = "enhanced")]
    {
        group.bench_function("enhanced", |b| {
            let mut config = EventProcessorConfig::default();
            config.enabled = true;
            config.enhanced_mode = Some(true); // Force atomic implementation
            config.buffer_size_mb = 50;
            
            let processor = SecurityEventProcessor::new(config).unwrap();
            
            b.iter(|| {
                for i in 0..event_count {
                    let client_id = format!("client_{}", i % 100);
                    let event = SecurityEventProcessor::auth_event(
                        black_box(&client_id),
                        black_box(i % 2 == 0), // Alternate success/failure
                        None,
                    );
                    let _ = processor.track_event(black_box(event));
                }
            });
        });
    }

    group.finish();
}

/// Generate comparison report
fn generate_comparison_report() {
    println!("\n=== Event Buffer Performance Comparison Report ===\n");
    println!("This report compares the performance of standard vs atomic event buffer implementations.");
    println!("The atomic implementation uses lock-free data structures for improved concurrency.\n");

    println!("Key Performance Characteristics:");
    println!("1. Single-threaded Performance:");
    println!("   - Standard: Baseline performance with simple in-memory storage");
    println!("   - Atomic: May have slight overhead but provides better guarantees\n");

    println!("2. Multi-threaded Performance:");
    println!("   - Standard: May experience contention under high concurrency");
    println!("   - Atomic: Lock-free design scales better with thread count\n");

    println!("3. Event Size Impact:");
    println!("   - Both implementations handle various event sizes");
    println!("   - Atomic may show better cache locality for larger events\n");

    println!("4. Priority Handling:");
    println!("   - Standard: Simple priority processing");
    println!("   - Atomic: Optimized priority queue with minimal contention\n");

    println!("Expected Results:");
    println!("- Atomic implementation should show significant improvement at high thread counts");
    println!("- Single-threaded performance should be comparable");
    println!("- Mixed operations benefit from atomic's non-blocking design\n");

    println!("For detailed results, see the criterion report in target/criterion/");
}

// Configure criterion
criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(100)
        .measurement_time(Duration::from_secs(10))
        .warm_up_time(Duration::from_secs(3))
        .with_profiler(criterion::profiler::perf::PerfProfiler);
    targets =
        bench_single_thread_enqueue,
        bench_concurrent_enqueue,
        bench_mixed_operations,
        bench_event_sizes,
        bench_priority_handling,
        bench_event_processor_integration
}

criterion_main!(benches);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_data_generation() {
        let data = generate_event_data(256);
        assert_eq!(data.len(), 256);
        assert!(data.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_buffer_creation() {
        // Test standard buffer
        let standard = SimpleEventBuffer::new();
        let result = standard.enqueue_event(1, &[1, 2, 3], Priority::Normal);
        assert!(result.is_ok());

        // Test atomic buffer
        #[cfg(feature = "enhanced")]
        {
            let atomic = AtomicEventBufferAdapter::new(1, 100).unwrap();
            let result = atomic.enqueue_event(1, &[1, 2, 3], Priority::Normal);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_processor_integration() {
        // Test standard processor
        let mut config = EventProcessorConfig::default();
        config.enabled = true;
        config.enhanced_mode = Some(false);
        
        let processor = SecurityEventProcessor::new(config).unwrap();
        let event = SecurityEventProcessor::auth_event("test-client", true, None);
        let result = processor.track_event(event);
        assert!(result.is_ok());

        // Test enhanced processor
        #[cfg(feature = "enhanced")]
        {
            let mut config = EventProcessorConfig::default();
            config.enabled = true;
            config.enhanced_mode = Some(true);
            
            let processor = SecurityEventProcessor::new(config).unwrap();
            let event = SecurityEventProcessor::auth_event("test-client", true, None);
            let result = processor.track_event(event);
            assert!(result.is_ok());
        }
    }
}