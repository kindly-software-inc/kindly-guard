#![no_main]

use libfuzzer_sys::fuzz_target;
use kindly_guard_core::{AtomicEventBuffer, Priority};
use arbitrary::{Arbitrary, Unstructured};
use std::sync::Arc;
use std::thread;

#[derive(Arbitrary, Debug)]
struct EventBufferTestCase {
    // Buffer configuration
    size_mb: u8,
    num_endpoints: u8,
    rate_limit: f64,
    failure_threshold: u8,
    
    // Operations to perform
    operations: Vec<Operation>,
}

#[derive(Arbitrary, Debug, Clone)]
enum Operation {
    Enqueue {
        endpoint_id: u8,
        data: Vec<u8>,
        priority: PriorityWrapper,
    },
    Dequeue {
        priority: PriorityWrapper,
    },
    RecordDelivery {
        endpoint_id: u8,
        success: bool,
    },
    ConcurrentAccess {
        num_threads: u8,
        operations_per_thread: u8,
    },
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct PriorityWrapper(u8);

impl From<PriorityWrapper> for Priority {
    fn from(p: PriorityWrapper) -> Self {
        match p.0 % 3 {
            0 => Priority::Low,
            1 => Priority::Normal,
            _ => Priority::High,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // Try to generate structured test case
    let test_case = match Unstructured::new(data).arbitrary::<EventBufferTestCase>() {
        Ok(tc) => tc,
        Err(_) => {
            // Fall back to basic testing
            test_basic_operations(data);
            return;
        }
    };

    // Sanitize inputs
    let size_mb = test_case.size_mb.max(1).min(100);
    let num_endpoints = test_case.num_endpoints.max(1).min(100);
    let rate_limit = test_case.rate_limit.max(1.0).min(1_000_000.0);
    let failure_threshold = test_case.failure_threshold.max(1).min(100);

    // Create event buffer
    let buffer = Arc::new(AtomicEventBuffer::new(
        size_mb as usize,
        num_endpoints as usize,
        rate_limit,
        failure_threshold as usize,
    ));

    // Execute operations
    for op in test_case.operations.iter().take(1000) {
        match op {
            Operation::Enqueue { endpoint_id, data, priority } => {
                let endpoint_id = (*endpoint_id as usize) % (num_endpoints as usize);
                let data_slice = if data.len() > 1024 {
                    &data[..1024]
                } else {
                    data
                };
                let _ = buffer.enqueue_event(endpoint_id, data_slice, (*priority).into());
            }
            Operation::Dequeue { priority } => {
                let _ = buffer.dequeue_event((*priority).into());
            }
            Operation::RecordDelivery { endpoint_id, success } => {
                let endpoint_id = (*endpoint_id as usize) % (num_endpoints as usize);
                buffer.record_delivery(endpoint_id, *success);
            }
            Operation::ConcurrentAccess { num_threads, operations_per_thread } => {
                test_concurrent_access(
                    buffer.clone(),
                    (*num_threads).min(10),
                    (*operations_per_thread).min(100),
                    num_endpoints,
                );
            }
        }
    }

    // Test edge cases
    test_edge_cases(buffer.clone(), num_endpoints);
});

fn test_basic_operations(data: &[u8]) {
    let buffer = AtomicEventBuffer::new(1, 10, 100.0, 3);
    
    // Use fuzzer data for operations
    for chunk in data.chunks(4) {
        if chunk.len() < 2 {
            continue;
        }
        
        let op = chunk[0] % 3;
        let endpoint_id = (chunk[1] % 10) as usize;
        
        match op {
            0 => {
                let _ = buffer.enqueue_event(endpoint_id, chunk, Priority::Normal);
            }
            1 => {
                let _ = buffer.dequeue_event(Priority::Normal);
            }
            2 => {
                buffer.record_delivery(endpoint_id, chunk[1] % 2 == 0);
            }
            _ => {}
        }
    }
}

fn test_concurrent_access(
    buffer: Arc<AtomicEventBuffer>,
    num_threads: u8,
    operations_per_thread: u8,
    num_endpoints: u8,
) {
    let mut handles = vec![];
    
    for thread_id in 0..num_threads {
        let buffer_clone = buffer.clone();
        let handle = thread::spawn(move || {
            for i in 0..operations_per_thread {
                let endpoint_id = ((thread_id as usize) + (i as usize)) % (num_endpoints as usize);
                let data = vec![thread_id, i];
                
                // Mix of operations
                match i % 4 {
                    0 => {
                        let _ = buffer_clone.enqueue_event(endpoint_id, &data, Priority::Normal);
                    }
                    1 => {
                        let _ = buffer_clone.dequeue_event(Priority::Normal);
                    }
                    2 => {
                        buffer_clone.record_delivery(endpoint_id, i % 2 == 0);
                    }
                    3 => {
                        // Try high priority
                        let _ = buffer_clone.enqueue_event(endpoint_id, &data, Priority::High);
                        let _ = buffer_clone.dequeue_event(Priority::High);
                    }
                    _ => {}
                }
            }
        });
        handles.push(handle);
    }
    
    // Wait for all threads
    for handle in handles {
        let _ = handle.join();
    }
}

fn test_edge_cases(buffer: Arc<AtomicEventBuffer>, num_endpoints: u8) {
    // Test empty buffer dequeue
    for _ in 0..10 {
        let _ = buffer.dequeue_event(Priority::Normal);
        let _ = buffer.dequeue_event(Priority::High);
        let _ = buffer.dequeue_event(Priority::Low);
    }
    
    // Test circuit breaker by recording many failures
    for endpoint_id in 0..num_endpoints {
        for _ in 0..20 {
            buffer.record_delivery(endpoint_id as usize, false);
        }
        // Should reject new events when circuit is open
        let result = buffer.enqueue_event(endpoint_id as usize, b"test", Priority::Normal);
        let _ = result; // Don't assert, just ensure no panic
    }
    
    // Test large data
    let large_data = vec![0u8; 10_000];
    for i in 0..num_endpoints {
        let _ = buffer.enqueue_event(i as usize, &large_data, Priority::Low);
    }
    
    // Test priority ordering
    let _ = buffer.enqueue_event(0, b"low", Priority::Low);
    let _ = buffer.enqueue_event(0, b"high", Priority::High);
    let _ = buffer.enqueue_event(0, b"normal", Priority::Normal);
    
    // High priority should come first
    let _ = buffer.dequeue_event(Priority::High);
    let _ = buffer.dequeue_event(Priority::Normal);
    let _ = buffer.dequeue_event(Priority::Low);
}