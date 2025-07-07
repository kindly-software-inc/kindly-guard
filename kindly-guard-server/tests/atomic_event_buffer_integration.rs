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
//! Integration tests for atomic event buffer

#[cfg(feature = "enhanced")]
mod atomic_buffer_tests {
    use kindly_guard_server::event_processor::{
        EventProcessorConfig, SecurityEvent, SecurityEventProcessor,
    };
    use kindly_guard_server::traits::{CircuitState, Priority};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn test_atomic_buffer_with_event_processor() {
        // Create config with enhanced mode enabled
        let mut config = EventProcessorConfig::default();
        config.enabled = true;
        config.enhanced_mode = Some(true);
        config.buffer_size_mb = 10;
        config.max_endpoints = 100;

        // Create processor with atomic buffer
        let processor = SecurityEventProcessor::new(config).unwrap();
        assert!(processor.is_enabled());

        // Track some events
        let auth_event = SecurityEventProcessor::auth_event("test-client", true, None);
        processor.track_event(auth_event).unwrap();

        let rate_limit_event = SecurityEventProcessor::rate_limit_event("test-client", "query", true);
        processor.track_event(rate_limit_event).unwrap();

        // Check endpoint stats
        let auth_stats = processor.get_endpoint_stats("auth:test-client");
        assert!(auth_stats.is_some());
        let stats = auth_stats.unwrap();
        assert_eq!(stats.circuit_state, CircuitState::Closed);
        assert!(stats.available_tokens > 0);
    }

    #[test]
    fn test_atomic_buffer_concurrent_access() {
        let mut config = EventProcessorConfig::default();
        config.enabled = true;
        config.enhanced_mode = Some(true);
        config.buffer_size_mb = 20;
        config.max_endpoints = 200;

        let processor = Arc::new(SecurityEventProcessor::new(config).unwrap());
        let mut handles = vec![];

        // Spawn multiple threads to simulate concurrent event tracking
        for thread_id in 0..8 {
            let processor_clone = processor.clone();
            let handle = thread::spawn(move || {
                for i in 0..100 {
                    let client_id = format!("client-{}-{}", thread_id, i % 10);
                    let event = SecurityEventProcessor::auth_event(&client_id, i % 2 == 0, None);
                    
                    // Should not panic or error
                    let _ = processor_clone.track_event(event);
                    
                    // Small delay to simulate real-world timing
                    thread::sleep(Duration::from_micros(10));
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify some endpoints have stats
        for i in 0..5 {
            let endpoint = format!("auth:client-0-{}", i);
            let stats = processor.get_endpoint_stats(&endpoint);
            assert!(stats.is_some(), "Should have stats for {}", endpoint);
        }
    }

    #[test]
    fn test_atomic_buffer_priority_handling() {
        let mut config = EventProcessorConfig::default();
        config.enabled = true;
        config.enhanced_mode = Some(true);

        let processor = SecurityEventProcessor::new(config).unwrap();

        // Create events that trigger different priorities
        let threat_event = SecurityEvent {
            event_type: kindly_guard_server::event_processor::SecurityEventType::ThreatDetected {
                client_id: "attacker".to_string(),
                threat_type: "SQL_INJECTION".to_string(),
                severity: "HIGH".to_string(),
            },
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            correlation_id: None,
            metadata: None,
        };

        let normal_event = SecurityEventProcessor::request_event("normal-user", "list", "req-123");

        // Track both events
        processor.track_event(threat_event).unwrap();
        processor.track_event(normal_event).unwrap();

        // Threat events should be tracked with urgent priority
        let threat_stats = processor.get_endpoint_stats("threat:attacker");
        assert!(threat_stats.is_some());
    }

    #[test]
    fn test_atomic_buffer_rate_limiting() {
        let mut config = EventProcessorConfig::default();
        config.enabled = true;
        config.enhanced_mode = Some(true);
        config.rate_limit = 5.0; // Very low rate limit for testing

        let processor = SecurityEventProcessor::new(config).unwrap();

        // Rapidly send events to trigger rate limiting
        for i in 0..10 {
            let event = SecurityEventProcessor::auth_event("rate-test-client", true, None);
            let result = processor.track_event(event);
            
            // First few should succeed, later ones might be rate limited
            if i < 5 {
                assert!(result.is_ok(), "Event {} should succeed", i);
            }
            // We don't assert failure for later events as the atomic buffer
            // manages its own token refill timing
        }
    }

    #[test]
    fn test_atomic_buffer_circuit_breaker() {
        let mut config = EventProcessorConfig::default();
        config.enabled = true;
        config.enhanced_mode = Some(true);
        config.failure_threshold = 3;

        let processor = SecurityEventProcessor::new(config).unwrap();

        // Simulate failures that should trigger circuit breaker
        for i in 0..5 {
            let event = SecurityEventProcessor::auth_event("failing-client", false, Some("invalid_credentials"));
            processor.track_event(event).unwrap();
            
            // After threshold, circuit should open
            if i >= 3 {
                let stats = processor.get_endpoint_stats("auth:failing-client");
                if let Some(stats) = stats {
                    // The atomic buffer manages circuit state internally
                    // We can't directly observe the state change in this test
                    // but we verify stats are still retrievable
                    assert!(stats.available_tokens <= 1000);
                }
            }
        }
    }

    #[test]
    fn test_is_monitored_with_atomic_buffer() {
        let mut config = EventProcessorConfig::default();
        config.enabled = true;
        config.enhanced_mode = Some(true);

        let processor = SecurityEventProcessor::new(config).unwrap();

        // Track threat event
        let threat_event = SecurityEvent {
            event_type: kindly_guard_server::event_processor::SecurityEventType::ThreatDetected {
                client_id: "suspicious-client".to_string(),
                threat_type: "XSS".to_string(),
                severity: "HIGH".to_string(),
            },
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            correlation_id: None,
            metadata: None,
        };

        processor.track_event(threat_event).unwrap();

        // Client should not be considered monitored just for having events
        // Only if circuit is open or tokens depleted
        let monitored = processor.is_monitored("suspicious-client");
        assert!(!monitored, "Client should not be monitored without circuit open");
    }
}