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
//! Benchmarks for atomic event buffer performance

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use kindly_guard_server::event_processor::{EventProcessorConfig, SecurityEventProcessor};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn benchmark_event_enqueue(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_enqueue");
    
    // Test different buffer sizes
    for buffer_mb in [1, 10, 50].iter() {
        // Benchmark simple implementation
        group.bench_with_input(
            BenchmarkId::new("simple", buffer_mb),
            buffer_mb,
            |b, &buffer_mb| {
                let mut config = EventProcessorConfig::default();
                config.enabled = true;
                config.enhanced_mode = Some(false); // Force simple implementation
                config.buffer_size_mb = buffer_mb;
                
                let processor = SecurityEventProcessor::new(config).unwrap();
                
                b.iter(|| {
                    let event = SecurityEventProcessor::auth_event("bench-client", true, None);
                    processor.track_event(black_box(event)).unwrap();
                });
            },
        );
        
        #[cfg(feature = "enhanced")]
        {
            // Benchmark atomic implementation
            group.bench_with_input(
                BenchmarkId::new("atomic", buffer_mb),
                buffer_mb,
                |b, &buffer_mb| {
                    let mut config = EventProcessorConfig::default();
                    config.enabled = true;
                    config.enhanced_mode = Some(true); // Force atomic implementation
                    config.buffer_size_mb = buffer_mb;
                    
                    let processor = SecurityEventProcessor::new(config).unwrap();
                    
                    b.iter(|| {
                        let event = SecurityEventProcessor::auth_event("bench-client", true, None);
                        processor.track_event(black_box(event)).unwrap();
                    });
                },
            );
        }
    }
    
    group.finish();
}

fn benchmark_concurrent_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_access");
    group.sample_size(10); // Reduce sample size for concurrent benchmarks
    
    for thread_count in [1, 4, 8, 16].iter() {
        // Benchmark simple implementation
        group.throughput(Throughput::Elements(*thread_count as u64 * 1000));
        group.bench_with_input(
            BenchmarkId::new("simple", thread_count),
            thread_count,
            |b, &thread_count| {
                b.iter_custom(|iters| {
                    let mut config = EventProcessorConfig::default();
                    config.enabled = true;
                    config.enhanced_mode = Some(false);
                    config.buffer_size_mb = 20;
                    config.max_endpoints = 1000;
                    
                    let processor = Arc::new(SecurityEventProcessor::new(config).unwrap());
                    
                    let start = std::time::Instant::now();
                    
                    let mut handles = vec![];
                    for thread_id in 0..thread_count {
                        let processor_clone = processor.clone();
                        let events_per_thread = (iters / thread_count as u64).max(1);
                        
                        let handle = thread::spawn(move || {
                            for i in 0..events_per_thread {
                                let client_id = format!("client-{}-{}", thread_id, i % 10);
                                let event = SecurityEventProcessor::auth_event(&client_id, true, None);
                                let _ = processor_clone.track_event(event);
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
        
        #[cfg(feature = "enhanced")]
        {
            // Benchmark atomic implementation
            group.bench_with_input(
                BenchmarkId::new("atomic", thread_count),
                thread_count,
                |b, &thread_count| {
                    b.iter_custom(|iters| {
                        let mut config = EventProcessorConfig::default();
                        config.enabled = true;
                        config.enhanced_mode = Some(true);
                        config.buffer_size_mb = 20;
                        config.max_endpoints = 1000;
                        
                        let processor = Arc::new(SecurityEventProcessor::new(config).unwrap());
                        
                        let start = std::time::Instant::now();
                        
                        let mut handles = vec![];
                        for thread_id in 0..thread_count {
                            let processor_clone = processor.clone();
                            let events_per_thread = (iters / thread_count as u64).max(1);
                            
                            let handle = thread::spawn(move || {
                                for i in 0..events_per_thread {
                                    let client_id = format!("client-{}-{}", thread_id, i % 10);
                                    let event = SecurityEventProcessor::auth_event(&client_id, true, None);
                                    let _ = processor_clone.track_event(event);
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

fn benchmark_get_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_stats");
    
    // Benchmark simple implementation
    group.bench_function("simple", |b| {
        let mut config = EventProcessorConfig::default();
        config.enabled = true;
        config.enhanced_mode = Some(false);
        
        let processor = SecurityEventProcessor::new(config).unwrap();
        
        // Pre-populate with some events
        for i in 0..100 {
            let event = SecurityEventProcessor::auth_event(&format!("client-{}", i), true, None);
            processor.track_event(event).unwrap();
        }
        
        b.iter(|| {
            processor.get_endpoint_stats(black_box("auth:client-50"))
        });
    });
    
    #[cfg(feature = "enhanced")]
    {
        // Benchmark atomic implementation
        group.bench_function("atomic", |b| {
            let mut config = EventProcessorConfig::default();
            config.enabled = true;
            config.enhanced_mode = Some(true);
            
            let processor = SecurityEventProcessor::new(config).unwrap();
            
            // Pre-populate with some events
            for i in 0..100 {
                let event = SecurityEventProcessor::auth_event(&format!("client-{}", i), true, None);
                processor.track_event(event).unwrap();
            }
            
            b.iter(|| {
                processor.get_endpoint_stats(black_box("auth:client-50"))
            });
        });
    }
    
    group.finish();
}

fn benchmark_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");
    group.sample_size(10);
    
    for endpoint_count in [100, 1000, 10000].iter() {
        #[cfg(feature = "enhanced")]
        {
            group.bench_with_input(
                BenchmarkId::new("atomic", endpoint_count),
                endpoint_count,
                |b, &endpoint_count| {
                    b.iter_custom(|_iters| {
                        let mut config = EventProcessorConfig::default();
                        config.enabled = true;
                        config.enhanced_mode = Some(true);
                        config.max_endpoints = endpoint_count;
                        config.buffer_size_mb = 50;
                        
                        let start = std::time::Instant::now();
                        
                        let processor = SecurityEventProcessor::new(config).unwrap();
                        
                        // Track events across many endpoints
                        for i in 0..endpoint_count {
                            let event = SecurityEventProcessor::auth_event(
                                &format!("client-{}", i), 
                                true, 
                                None
                            );
                            let _ = processor.track_event(event);
                        }
                        
                        start.elapsed()
                    });
                },
            );
        }
    }
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_event_enqueue,
    benchmark_concurrent_access,
    benchmark_get_stats,
    benchmark_memory_usage
);
criterion_main!(benches);