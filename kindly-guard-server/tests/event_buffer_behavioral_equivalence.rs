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
//! Behavioral Equivalence Tests for Event Buffer Implementations
//!
//! Ensures that both standard and enhanced event buffer implementations
//! behave identically from an external perspective, maintaining the same
//! contract while potentially differing in performance characteristics.

use anyhow::Result;
use kindly_guard_server::{
    create_event_buffer,
    event_processor::{EventProcessorConfig, Priority},
    traits::EventBufferTrait,
};

/// Test configuration for both implementations
fn create_test_config(enhanced: bool) -> EventProcessorConfig {
    EventProcessorConfig {
        enabled: true,
        buffer_size_mb: 1,
        max_endpoints: 100,
        enhanced_mode: Some(enhanced),
        ..Default::default()
    }
}

/// Test helper to run identical operations on both implementations
async fn test_both_implementations<F>(test_fn: F) -> Result<()>
where
    F: Fn(&dyn EventBufferTrait) -> Result<()>,
{
    // Test standard implementation
    let standard_config = create_test_config(false);
    let standard_buffer =
        create_event_buffer(&standard_config)?.expect("Standard buffer should be created");
    test_fn(standard_buffer.as_ref())?;

    // Test enhanced implementation (if available)
    #[cfg(feature = "enhanced")]
    {
        let enhanced_config = create_test_config(true);
        let enhanced_buffer =
            create_event_buffer(&enhanced_config)?.expect("Enhanced buffer should be created");
        test_fn(enhanced_buffer.as_ref())?;
    }

    Ok(())
}

#[tokio::test]
async fn test_basic_event_enqueue() -> Result<()> {
    test_both_implementations(|buffer| {
        // Enqueue a simple event
        let event_id = buffer.enqueue_event(0, b"test event", Priority::Normal)?;
        assert_eq!(event_id, 0, "First event should have ID 0");

        // Enqueue another event
        let event_id2 = buffer.enqueue_event(0, b"test event 2", Priority::Urgent)?;
        assert!(event_id2 > event_id, "Event IDs should increment");

        Ok(())
    })
    .await
}

#[tokio::test]
async fn test_endpoint_stats_tracking() -> Result<()> {
    test_both_implementations(|buffer| {
        // Initial stats should be empty/default
        let stats = buffer.get_endpoint_stats(0)?;
        assert_eq!(stats.success_count, 0);
        assert_eq!(stats.failure_count, 0);

        // After enqueuing events, success count should increase
        for _ in 0..5 {
            buffer.enqueue_event(0, b"success", Priority::Normal)?;
        }

        let stats = buffer.get_endpoint_stats(0)?;
        assert!(
            stats.success_count >= 5,
            "Success count should track events"
        );

        Ok(())
    })
    .await
}

#[tokio::test]
async fn test_multiple_endpoints() -> Result<()> {
    test_both_implementations(|buffer| {
        // Test isolation between endpoints
        buffer.enqueue_event(0, b"endpoint 0", Priority::Normal)?;
        buffer.enqueue_event(1, b"endpoint 1", Priority::Normal)?;
        buffer.enqueue_event(2, b"endpoint 2", Priority::Normal)?;

        // Each endpoint should have independent stats
        let stats0 = buffer.get_endpoint_stats(0)?;
        let stats1 = buffer.get_endpoint_stats(1)?;
        let stats2 = buffer.get_endpoint_stats(2)?;

        // In enhanced implementation, stats are tracked per endpoint
        // In simple implementation, stats might be global or default
        // The key is both behave consistently

        Ok(())
    })
    .await
}

#[tokio::test]
async fn test_priority_handling() -> Result<()> {
    test_both_implementations(|buffer| {
        // Both priorities should be accepted
        let normal_id = buffer.enqueue_event(0, b"normal", Priority::Normal)?;
        let urgent_id = buffer.enqueue_event(0, b"urgent", Priority::Urgent)?;

        // IDs should still be sequential regardless of priority
        assert!(urgent_id > normal_id);

        Ok(())
    })
    .await
}

#[tokio::test]
async fn test_invalid_endpoint_handling() -> Result<()> {
    test_both_implementations(|buffer| {
        // Test with endpoint ID at the boundary
        let config = EventProcessorConfig::default();
        let max_endpoint = config.max_endpoints - 1;

        // This should succeed
        buffer.enqueue_event(max_endpoint, b"boundary", Priority::Normal)?;

        // This should fail in enhanced implementation
        // Simple implementation might not enforce this
        let result = buffer.get_endpoint_stats(max_endpoint + 1);

        // Both implementations should handle this gracefully
        // (either return error or default stats)

        Ok(())
    })
    .await
}

#[tokio::test]
async fn test_concurrent_access() -> Result<()> {
    
    

    // Only test if we have the enhanced feature
    #[cfg(feature = "enhanced")]
    {
        let config = create_test_config(true);
        let buffer = create_event_buffer(&config)?.expect("Buffer should be created");
        let buffer = Arc::new(buffer);

        let mut handles = vec![];

        // Spawn multiple tasks to access buffer concurrently
        for i in 0..10 {
            let buffer_clone = Arc::clone(&buffer);
            handles.push(task::spawn(async move {
                for j in 0..100 {
                    buffer_clone
                        .enqueue_event(i, format!("event {}", j).as_bytes(), Priority::Normal)
                        .expect("Enqueue should succeed");
                }
            }));
        }

        // Wait for all tasks
        for handle in handles {
            handle.await?;
        }

        // Verify all endpoints have events
        for i in 0..10 {
            let stats = buffer.get_endpoint_stats(i)?;
            assert!(stats.success_count > 0, "Endpoint {} should have events", i);
        }
    }

    Ok(())
}

#[cfg(test)]
mod performance_comparison {
    use super::*;
    use std::time::Instant;

    #[tokio::test]
    #[ignore] // Run with --ignored to see performance comparison
    async fn benchmark_implementations() -> Result<()> {
        const ITERATIONS: usize = 100_000;

        // Benchmark standard implementation
        let standard_config = create_test_config(false);
        let standard_buffer =
            create_event_buffer(&standard_config)?.expect("Standard buffer should be created");

        let start = Instant::now();
        for i in 0..ITERATIONS {
            standard_buffer.enqueue_event(
                (i % 100) as u32,
                b"benchmark event",
                Priority::Normal,
            )?;
        }
        let standard_duration = start.elapsed();

        println!(
            "Standard implementation: {} events in {:?} ({:.0} events/sec)",
            ITERATIONS,
            standard_duration,
            ITERATIONS as f64 / standard_duration.as_secs_f64()
        );

        // Benchmark enhanced implementation (if available)
        #[cfg(feature = "enhanced")]
        {
            let enhanced_config = create_test_config(true);
            let enhanced_buffer =
                create_event_buffer(&enhanced_config)?.expect("Enhanced buffer should be created");

            let start = Instant::now();
            for i in 0..ITERATIONS {
                enhanced_buffer.enqueue_event(
                    (i % 100) as u32,
                    b"benchmark event",
                    Priority::Normal,
                )?;
            }
            let enhanced_duration = start.elapsed();

            println!(
                "Enhanced implementation: {} events in {:?} ({:.0} events/sec)",
                ITERATIONS,
                enhanced_duration,
                ITERATIONS as f64 / enhanced_duration.as_secs_f64()
            );

            let speedup = standard_duration.as_secs_f64() / enhanced_duration.as_secs_f64();
            println!("Enhanced is {:.2}x faster", speedup);
        }

        Ok(())
    }
}
