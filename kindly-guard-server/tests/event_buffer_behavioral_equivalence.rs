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
//! Event Buffer Behavioral Equivalence Tests
//!
//! These tests ensure that both standard (SimpleEventBuffer) and enhanced
//! (AtomicEventBufferAdapter) implementations produce functionally equivalent
//! results for all security event operations.
//!
//! IMPORTANT: These tests only run when the enhanced feature is enabled
//! to allow comparison between implementations.

#![cfg(all(test, feature = "enhanced"))]

use kindly_guard_server::{
    config::Config,
    create_event_buffer,
    event_processor::{EventProcessorConfig, SimpleEventBuffer},
    traits::{CircuitState, EndpointStats, EventBufferTrait, Priority},
};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Helper to create both standard and enhanced versions of event buffer
fn create_both_buffers() -> (Box<dyn EventBufferTrait>, Box<dyn EventBufferTrait>) {
    // Create standard version (SimpleEventBuffer)
    let standard = Box::new(SimpleEventBuffer::new()) as Box<dyn EventBufferTrait>;

    // Create enhanced version (AtomicEventBufferAdapter)
    let mut config = EventProcessorConfig::default();
    config.enabled = true;
    config.enhanced_mode = Some(true);
    config.buffer_size_mb = 10;
    config.max_endpoints = 1000;

    let enhanced = create_event_buffer(&config)
        .expect("Should create enhanced buffer")
        .expect("Buffer should be Some when enabled");

    (standard, enhanced)
}

/// Generate test event data with various sizes and patterns
fn generate_test_events() -> Vec<(u32, Vec<u8>, Priority, String)> {
    vec![
        // Small events
        (1, b"small event".to_vec(), Priority::Normal, "Small normal event".to_string()),
        (1, b"urgent!".to_vec(), Priority::Urgent, "Small urgent event".to_string()),
        
        // Medium events
        (2, vec![0xAB; 100], Priority::Normal, "Medium binary event".to_string()),
        (2, b"x".repeat(256).to_vec(), Priority::Urgent, "Medium text event".to_string()),
        
        // Large events
        (3, vec![0xFF; 1024], Priority::Normal, "Large binary event".to_string()),
        (3, b"security_event_data".repeat(100).to_vec(), Priority::Urgent, "Large text event".to_string()),
        
        // Edge cases
        (0, vec![], Priority::Normal, "Empty event".to_string()),
        (u32::MAX, b"max_endpoint".to_vec(), Priority::Urgent, "Max endpoint ID".to_string()),
        (100, vec![0; 4096], Priority::Normal, "Zero-filled event".to_string()),
        
        // Special patterns
        (10, b"\x00\x01\x02\x03\xFF\xFE\xFD".to_vec(), Priority::Urgent, "Binary pattern".to_string()),
        (11, b"SQL injection: ' OR 1=1 --".to_vec(), Priority::Urgent, "SQL injection pattern".to_string()),
        (12, b"<script>alert('XSS')</script>".to_vec(), Priority::Urgent, "XSS pattern".to_string()),
    ]
}

#[test]
fn test_basic_enqueue_operations() {
    let (standard, enhanced) = create_both_buffers();
    let test_events = generate_test_events();

    for (endpoint_id, data, priority, description) in test_events {
        // Test with standard implementation
        let std_result = standard.enqueue_event(endpoint_id, &data, priority);
        
        // Test with enhanced implementation
        let enh_result = enhanced.enqueue_event(endpoint_id, &data, priority);

        // Both should succeed for basic operations
        assert!(
            std_result.is_ok(),
            "Standard enqueue failed for {}: {:?}",
            description, std_result
        );
        
        // Enhanced might fail for some edge cases (e.g., invalid endpoint)
        // but should succeed for normal operations
        if endpoint_id < 1000 && !data.is_empty() {
            assert!(
                enh_result.is_ok(),
                "Enhanced enqueue failed for {}: {:?}",
                description, enh_result
            );
        }
    }
}

#[test]
fn test_endpoint_stats_consistency() {
    let (standard, enhanced) = create_both_buffers();
    
    // Test various endpoint IDs
    let test_endpoints = vec![0, 1, 10, 100, 999, 1000, u32::MAX];
    
    for endpoint_id in test_endpoints {
        let std_stats = standard.get_endpoint_stats(endpoint_id);
        let enh_stats = enhanced.get_endpoint_stats(endpoint_id);
        
        // Both should return stats (even if default/empty)
        assert!(std_stats.is_ok(), "Standard stats failed for endpoint {}", endpoint_id);
        
        // Enhanced might fail for invalid endpoints
        if endpoint_id < 1000 {
            assert!(enh_stats.is_ok(), "Enhanced stats failed for endpoint {}", endpoint_id);
            
            // Compare initial stats (should be similar)
            let std_stats = std_stats.unwrap();
            let enh_stats = enh_stats.unwrap();
            
            // Initial state should be closed for both
            assert_eq!(
                std_stats.circuit_state, CircuitState::Closed,
                "Standard should start with closed circuit"
            );
            assert_eq!(
                enh_stats.circuit_state, CircuitState::Closed,
                "Enhanced should start with closed circuit"
            );
        }
    }
}

#[test]
fn test_priority_handling() {
    let (standard, enhanced) = create_both_buffers();
    
    let endpoint_id = 5;
    let normal_data = b"normal priority event";
    let urgent_data = b"urgent priority event";
    
    // Enqueue events with different priorities
    let std_normal = standard.enqueue_event(endpoint_id, normal_data, Priority::Normal);
    let std_urgent = standard.enqueue_event(endpoint_id, urgent_data, Priority::Urgent);
    
    let enh_normal = enhanced.enqueue_event(endpoint_id, normal_data, Priority::Normal);
    let enh_urgent = enhanced.enqueue_event(endpoint_id, urgent_data, Priority::Urgent);
    
    // All should succeed
    assert!(std_normal.is_ok(), "Standard normal priority failed");
    assert!(std_urgent.is_ok(), "Standard urgent priority failed");
    assert!(enh_normal.is_ok(), "Enhanced normal priority failed");
    assert!(enh_urgent.is_ok(), "Enhanced urgent priority failed");
}

#[test]
fn test_concurrent_operations() {
    let (standard, enhanced) = create_both_buffers();
    
    // Wrap in Arc for thread sharing
    let std_buffer = Arc::new(standard);
    let enh_buffer = Arc::new(enhanced);
    
    let num_threads = 4;
    let events_per_thread = 25;
    
    // Spawn threads for concurrent operations
    let mut handles = vec![];
    
    for thread_id in 0..num_threads {
        let std_clone = Arc::clone(&std_buffer);
        let enh_clone = Arc::clone(&enh_buffer);
        
        let handle = thread::spawn(move || {
            for event_id in 0..events_per_thread {
                let endpoint_id = (thread_id % 10) as u32;
                let data = format!("Thread {} Event {}", thread_id, event_id).into_bytes();
                let priority = if event_id % 2 == 0 { Priority::Normal } else { Priority::Urgent };
                
                // Both implementations should handle concurrent access
                let _std_result = std_clone.enqueue_event(endpoint_id, &data, priority);
                let _enh_result = enh_clone.enqueue_event(endpoint_id, &data, priority);
            }
        });
        
        handles.push(handle);
    }
    
    // Wait for all threads to complete
    for handle in handles {
        handle.join().expect("Thread should complete");
    }
    
    // Check stats after concurrent operations
    for endpoint_id in 0..10 {
        let _std_stats = std_buffer.get_endpoint_stats(endpoint_id);
        let _enh_stats = enh_buffer.get_endpoint_stats(endpoint_id);
        
        // Both should still return valid stats
        assert!(_std_stats.is_ok(), "Standard stats should be available after concurrent ops");
        assert!(_enh_stats.is_ok(), "Enhanced stats should be available after concurrent ops");
    }
}

#[test]
fn test_large_data_handling() {
    let (standard, enhanced) = create_both_buffers();
    
    // Test with increasingly large data sizes
    let sizes = vec![
        1,          // 1 byte
        100,        // 100 bytes
        1024,       // 1 KB
        10240,      // 10 KB
        102400,     // 100 KB
        1048576,    // 1 MB
    ];
    
    for size in sizes {
        let data = vec![0xAB; size];
        let endpoint_id = 1;
        
        let std_result = standard.enqueue_event(endpoint_id, &data, Priority::Normal);
        let enh_result = enhanced.enqueue_event(endpoint_id, &data, Priority::Normal);
        
        // Standard should always succeed (simple implementation)
        assert!(
            std_result.is_ok(),
            "Standard failed with {} byte data",
            size
        );
        
        // Enhanced may have size limits but should handle reasonable sizes
        if size <= 102400 { // Up to 100KB should work
            assert!(
                enh_result.is_ok(),
                "Enhanced failed with {} byte data: {:?}",
                size, enh_result
            );
        }
    }
}

#[test]
fn test_error_conditions() {
    let (standard, enhanced) = create_both_buffers();
    
    // Test various error conditions
    
    // 1. Invalid endpoint (beyond max_endpoints for enhanced)
    let invalid_endpoint = 2000;
    let data = b"test data";
    
    let std_result = standard.enqueue_event(invalid_endpoint, data, Priority::Normal);
    let enh_result = enhanced.enqueue_event(invalid_endpoint, data, Priority::Normal);
    
    // Standard always succeeds (simple implementation)
    assert!(std_result.is_ok(), "Standard should handle any endpoint ID");
    
    // Enhanced should fail for invalid endpoint
    assert!(
        enh_result.is_err(),
        "Enhanced should fail for endpoint beyond max_endpoints"
    );
    
    // 2. Empty data handling
    let empty_data = &[];
    let std_empty = standard.enqueue_event(1, empty_data, Priority::Normal);
    let enh_empty = enhanced.enqueue_event(1, empty_data, Priority::Normal);
    
    // Both should handle empty data gracefully
    assert!(std_empty.is_ok(), "Standard should handle empty data");
    // Enhanced might reject empty data or accept it
    // The important thing is it doesn't panic
}

#[test]
fn test_stats_after_operations() {
    let (standard, enhanced) = create_both_buffers();
    
    let endpoint_id = 7;
    let num_events = 10;
    
    // Enqueue multiple events
    for i in 0..num_events {
        let data = format!("Event {}", i).into_bytes();
        let priority = if i % 3 == 0 { Priority::Urgent } else { Priority::Normal };
        
        let _std = standard.enqueue_event(endpoint_id, &data, priority);
        let _enh = enhanced.enqueue_event(endpoint_id, &data, priority);
    }
    
    // Get stats after operations
    let std_stats = standard.get_endpoint_stats(endpoint_id).unwrap();
    let enh_stats = enhanced.get_endpoint_stats(endpoint_id).unwrap();
    
    // Both should still report closed circuit (no failures)
    assert_eq!(
        std_stats.circuit_state, CircuitState::Closed,
        "Standard circuit should remain closed"
    );
    assert_eq!(
        enh_stats.circuit_state, CircuitState::Closed,
        "Enhanced circuit should remain closed"
    );
    
    // Token counts might differ but should be positive
    assert!(
        std_stats.available_tokens > 0,
        "Standard should have available tokens"
    );
    assert!(
        enh_stats.available_tokens > 0,
        "Enhanced should have available tokens"
    );
}

#[test]
fn test_rapid_fire_events() {
    let (standard, enhanced) = create_both_buffers();
    
    let endpoint_id = 3;
    let num_events = 1000;
    
    // Rapidly enqueue many events
    let start = std::time::Instant::now();
    
    for i in 0..num_events {
        let data = vec![i as u8; 10];
        let priority = Priority::Normal;
        
        let std_result = standard.enqueue_event(endpoint_id, &data, priority);
        let enh_result = enhanced.enqueue_event(endpoint_id, &data, priority);
        
        // Standard should always succeed
        assert!(std_result.is_ok(), "Standard failed at event {}", i);
        
        // Enhanced might hit rate limits but shouldn't panic
        if enh_result.is_err() {
            // If we hit rate limit, that's expected behavior
            if let Err(e) = enh_result {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("Rate limit") || error_msg.contains("Back pressure"),
                    "Unexpected error: {}",
                    error_msg
                );
            }
        }
    }
    
    let elapsed = start.elapsed();
    println!("Processed {} events in {:?}", num_events, elapsed);
}

#[test]
fn test_multiple_endpoints() {
    let (standard, enhanced) = create_both_buffers();
    
    // Test operations across multiple endpoints
    let endpoints = vec![0, 1, 5, 10, 50, 100, 500, 999];
    
    for endpoint_id in &endpoints {
        let data = format!("Data for endpoint {}", endpoint_id).into_bytes();
        
        // Enqueue event
        let std_result = standard.enqueue_event(*endpoint_id, &data, Priority::Normal);
        let enh_result = enhanced.enqueue_event(*endpoint_id, &data, Priority::Normal);
        
        assert!(std_result.is_ok(), "Standard failed for endpoint {}", endpoint_id);
        assert!(enh_result.is_ok(), "Enhanced failed for endpoint {}", endpoint_id);
        
        // Get stats
        let std_stats = standard.get_endpoint_stats(*endpoint_id);
        let enh_stats = enhanced.get_endpoint_stats(*endpoint_id);
        
        assert!(std_stats.is_ok(), "Standard stats failed for endpoint {}", endpoint_id);
        assert!(enh_stats.is_ok(), "Enhanced stats failed for endpoint {}", endpoint_id);
    }
}

#[test]
fn test_behavioral_consistency_under_load() {
    let (standard, enhanced) = create_both_buffers();
    
    // Simulate load with mixed operations
    let operations = vec![
        (1, b"auth_success".to_vec(), Priority::Normal),
        (1, b"auth_failure".to_vec(), Priority::Urgent),
        (2, b"rate_limit_check".to_vec(), Priority::Normal),
        (2, b"rate_limit_exceeded".to_vec(), Priority::Urgent),
        (3, b"threat_detected".to_vec(), Priority::Urgent),
        (4, b"circuit_opened".to_vec(), Priority::Urgent),
        (5, b"normal_request".to_vec(), Priority::Normal),
    ];
    
    // Execute operations multiple times
    for _ in 0..10 {
        for (endpoint_id, data, priority) in &operations {
            let _std = standard.enqueue_event(*endpoint_id, data, *priority);
            let _enh = enhanced.enqueue_event(*endpoint_id, data, *priority);
        }
    }
    
    // Verify endpoints are still accessible
    for i in 1..=5 {
        let std_stats = standard.get_endpoint_stats(i);
        let enh_stats = enhanced.get_endpoint_stats(i);
        
        assert!(std_stats.is_ok(), "Standard stats should be available");
        assert!(enh_stats.is_ok(), "Enhanced stats should be available");
    }
}

#[test]
fn test_edge_case_endpoint_ids() {
    let (standard, enhanced) = create_both_buffers();
    
    // Test boundary endpoint IDs
    let edge_cases = vec![
        (0, "Zero endpoint ID"),
        (1, "One endpoint ID"),
        (999, "Max valid endpoint for enhanced"),
        (1000, "Just beyond max for enhanced"),
        (u32::MAX / 2, "Half of u32::MAX"),
        (u32::MAX - 1, "u32::MAX - 1"),
        (u32::MAX, "u32::MAX"),
    ];
    
    for (endpoint_id, description) in edge_cases {
        let data = b"edge case test";
        
        let std_result = standard.enqueue_event(endpoint_id, data, Priority::Normal);
        let enh_result = enhanced.enqueue_event(endpoint_id, data, Priority::Normal);
        
        // Standard should handle all endpoint IDs
        assert!(
            std_result.is_ok(),
            "Standard failed for {}: {:?}",
            description, std_result
        );
        
        // Enhanced has limits
        if endpoint_id < 1000 {
            assert!(
                enh_result.is_ok(),
                "Enhanced should handle {} ({})",
                description, endpoint_id
            );
        } else {
            assert!(
                enh_result.is_err(),
                "Enhanced should reject {} ({})",
                description, endpoint_id
            );
        }
    }
}

#[test]
fn test_enhanced_feature_enabled() {
    // This test ensures we're actually testing with enhanced feature
    #[cfg(not(feature = "enhanced"))]
    panic!("Event buffer behavioral equivalence tests require 'enhanced' feature");

    #[cfg(feature = "enhanced")]
    println!("Enhanced feature is enabled - event buffer behavioral equivalence tests will run");
}

/// Helper function to verify behavioral equivalence
fn assert_behavioral_equivalence(
    std_result: &Result<u64, anyhow::Error>,
    enh_result: &Result<u64, anyhow::Error>,
    context: &str,
) {
    match (std_result, enh_result) {
        (Ok(_), Ok(_)) => {
            // Both succeeded - good
        }
        (Err(_), Err(_)) => {
            // Both failed - also acceptable if for same reason
        }
        (Ok(_), Err(e)) => {
            // Enhanced failed where standard succeeded
            // This is acceptable if it's due to enhanced safety checks
            let error_msg = e.to_string();
            assert!(
                error_msg.contains("Rate limit") || 
                error_msg.contains("Circuit") ||
                error_msg.contains("Back pressure") ||
                error_msg.contains("Invalid endpoint"),
                "Unexpected enhanced failure in {}: {}",
                context, error_msg
            );
        }
        (Err(_), Ok(_)) => {
            // Standard failed where enhanced succeeded - unexpected
            panic!("Standard implementation failed where enhanced succeeded in {}", context);
        }
    }
}

#[test]
fn test_comprehensive_behavioral_equivalence() {
    let (standard, enhanced) = create_both_buffers();
    
    // Test comprehensive scenarios
    let scenarios = vec![
        // Normal operations
        (1, vec![1, 2, 3], Priority::Normal, "Normal small event"),
        (2, vec![0xFF; 100], Priority::Urgent, "Urgent medium event"),
        
        // Edge cases
        (0, vec![], Priority::Normal, "Empty event on endpoint 0"),
        (999, vec![0; 1024], Priority::Urgent, "Large event on max endpoint"),
        
        // Security patterns
        (10, b"SELECT * FROM users".to_vec(), Priority::Urgent, "SQL-like pattern"),
        (11, b"<img src=x>".to_vec(), Priority::Urgent, "HTML-like pattern"),
        (12, b"../../etc/passwd".to_vec(), Priority::Urgent, "Path traversal pattern"),
    ];
    
    for (endpoint_id, data, priority, context) in scenarios {
        let std_result = standard.enqueue_event(endpoint_id, &data, priority);
        let enh_result = enhanced.enqueue_event(endpoint_id, &data, priority);
        
        assert_behavioral_equivalence(&std_result, &enh_result, context);
    }
}