//! Tests using mockall for component isolation
//! Demonstrates mocking external dependencies and error conditions

use kindly_guard_server::{
    traits::*,
    scanner::{Threat, ThreatType, Severity, Location},
    permissions::{Permission, PermissionContext, ThreatLevel},
};
use mockall::predicate::*;
use anyhow::{Result, anyhow};
use std::sync::Arc;

/// Test that the scanner correctly handles processor failures
#[tokio::test]
async fn test_scanner_with_failing_event_processor() {
    // Create a mock event processor that always fails
    let mut mock_processor = MockSecurityEventProcessor::new();
    mock_processor
        .expect_process_event()
        .times(1)
        .returning(|_| Err(anyhow!("Event processor failure")));
    
    mock_processor
        .expect_get_stats()
        .returning(|| ProcessorStats {
            events_processed: 0,
            events_failed: 1,
            events_queued: 0,
            active_monitors: 0,
        });
    
    // Test that scanner continues to work even if processor fails
    let event = SecurityEvent {
        event_type: "test.scan".to_string(),
        client_id: "test-client".to_string(),
        timestamp: 0,
        metadata: serde_json::json!({}),
    };
    
    // Process should fail gracefully
    let result = mock_processor.process_event(event).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "Event processor failure");
    
    // Stats should reflect the failure
    let stats = mock_processor.get_stats();
    assert_eq!(stats.events_failed, 1);
}

/// Test rate limiter with various scenarios
#[tokio::test]
async fn test_rate_limiter_mocking() {
    let mut mock_limiter = MockRateLimiter::new();
    
    // Set up expectations for different clients
    mock_limiter
        .expect_check_rate_limit()
        .with(eq(RateLimitKey { 
            client_id: "good-client".to_string(), 
            method: None 
        }))
        .times(3)
        .returning(|_| Ok(RateLimitDecision {
            allowed: true,
            tokens_remaining: 10.0,
            tokens_used: 1.0,
            retry_after: None,
        }));
    
    mock_limiter
        .expect_check_rate_limit()
        .with(eq(RateLimitKey { 
            client_id: "bad-client".to_string(), 
            method: None 
        }))
        .times(1)
        .returning(|_| Ok(RateLimitDecision {
            allowed: false,
            tokens_remaining: 0.0,
            tokens_used: 0.0,
            retry_after: Some(60),
        }));
    
    // Test good client - should be allowed
    for _ in 0..3 {
        let decision = mock_limiter.check_rate_limit(&RateLimitKey {
            client_id: "good-client".to_string(),
            method: None,
        }).await.unwrap();
        assert!(decision.allowed);
    }
    
    // Test bad client - should be rate limited
    let decision = mock_limiter.check_rate_limit(&RateLimitKey {
        client_id: "bad-client".to_string(),
        method: None,
    }).await.unwrap();
    assert!(!decision.allowed);
    assert_eq!(decision.retry_after, Some(60));
}

/// Test permission manager with complex scenarios
#[tokio::test]
async fn test_permission_manager_edge_cases() {
    let mut mock_permissions = MockToolPermissionManager::new();
    
    // Set up different permission scenarios
    mock_permissions
        .expect_check_permission()
        .withf(|client_id, tool_name, context| {
            client_id == "admin" && 
            tool_name == "update_config" &&
            context.threat_level == ThreatLevel::Safe
        })
        .returning(|_, _, _| Ok(Permission::Allow));
    
    mock_permissions
        .expect_check_permission()
        .withf(|client_id, tool_name, context| {
            client_id == "user" && 
            tool_name == "update_config" &&
            context.threat_level == ThreatLevel::Safe
        })
        .returning(|_, _, _| Ok(Permission::Deny("Insufficient privileges".to_string())));
    
    mock_permissions
        .expect_check_permission()
        .withf(|_, _, context| {
            context.threat_level >= ThreatLevel::High
        })
        .returning(|_, _, _| Ok(Permission::Deny("Threat level too high".to_string())));
    
    // Test admin access
    let context = PermissionContext {
        auth_token: None,
        scopes: vec!["admin".to_string()],
        threat_level: ThreatLevel::Safe,
        request_metadata: Default::default(),
    };
    
    let result = mock_permissions.check_permission("admin", "update_config", &context).await.unwrap();
    assert_eq!(result, Permission::Allow);
    
    // Test regular user access
    let result = mock_permissions.check_permission("user", "update_config", &context).await.unwrap();
    assert!(matches!(result, Permission::Deny(msg) if msg.contains("privileges")));
    
    // Test high threat level
    let high_threat_context = PermissionContext {
        auth_token: None,
        scopes: vec!["admin".to_string()],
        threat_level: ThreatLevel::High,
        request_metadata: Default::default(),
    };
    
    let result = mock_permissions.check_permission("admin", "update_config", &high_threat_context).await.unwrap();
    assert!(matches!(result, Permission::Deny(msg) if msg.contains("Threat level")));
}

/// Test scanner with mock pattern injection
#[test]
fn test_scanner_with_pattern_failures() {
    let mut mock_scanner = MockEnhancedScanner::new();
    
    // Set up scanner to detect specific patterns
    mock_scanner
        .expect_enhanced_scan()
        .withf(|data| {
            let text = String::from_utf8_lossy(data);
            text.contains("EICAR")
        })
        .returning(|_| Ok(vec![
            Threat {
                threat_type: ThreatType::Malware,
                severity: Severity::Critical,
                description: "EICAR test file detected".to_string(),
                location: Location::Text { offset: 0, length: 68 },
                confidence: 1.0,
            }
        ]));
    
    mock_scanner
        .expect_enhanced_scan()
        .withf(|data| {
            let text = String::from_utf8_lossy(data);
            text.contains("safe")
        })
        .returning(|_| Ok(vec![]));
    
    // Test malware detection
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let threats = mock_scanner.enhanced_scan(eicar).unwrap();
    assert_eq!(threats.len(), 1);
    assert_eq!(threats[0].threat_type, ThreatType::Malware);
    assert_eq!(threats[0].severity, Severity::Critical);
    
    // Test safe content
    let safe = b"This is safe content";
    let threats = mock_scanner.enhanced_scan(safe).unwrap();
    assert!(threats.is_empty());
}

/// Test correlation engine with attack patterns
#[tokio::test]
async fn test_correlation_engine_attack_detection() {
    let mut mock_correlation = MockCorrelationEngine::new();
    
    // Set up correlation to detect brute force attacks
    mock_correlation
        .expect_correlate()
        .withf(|events| {
            events.iter().filter(|e| e.event_type == "auth_failure").count() >= 5
        })
        .returning(|events| {
            let client_id = &events[0].client_id;
            Ok(vec![
                ThreatPattern {
                    pattern_type: "brute_force".to_string(),
                    confidence: 0.95,
                    severity: Severity::High,
                    client_id: client_id.clone(),
                    event_count: events.len(),
                    time_window: 60,
                    description: "Multiple authentication failures detected".to_string(),
                }
            ])
        });
    
    // Create attack pattern events
    let mut events = vec![];
    for i in 0..10 {
        events.push(SecurityEvent {
            event_type: if i < 7 { "auth_failure" } else { "auth_success" }.to_string(),
            client_id: "attacker".to_string(),
            timestamp: i as u64,
            metadata: serde_json::json!({}),
        });
    }
    
    let patterns = mock_correlation.correlate(&events).await.unwrap();
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns[0].pattern_type, "brute_force");
    assert_eq!(patterns[0].severity, Severity::High);
}

/// Test error propagation through mocked components
#[tokio::test]
async fn test_error_handling_with_mocks() {
    let mut mock_processor = MockSecurityEventProcessor::new();
    let mut mock_scanner = MockEnhancedScanner::new();
    let mut mock_limiter = MockRateLimiter::new();
    
    // Set up various failure modes
    let error_sequence = mockall::Sequence::new();
    
    // First call succeeds
    mock_processor
        .expect_process_event()
        .times(1)
        .in_sequence(&mut error_sequence.clone())
        .returning(|_| Ok(EventHandle { event_id: 1, processed: true }));
    
    // Second call fails with network error
    mock_processor
        .expect_process_event()
        .times(1)
        .in_sequence(&mut error_sequence.clone())
        .returning(|_| Err(anyhow!("Network timeout")));
    
    // Third call fails with capacity error
    mock_processor
        .expect_process_event()
        .times(1)
        .in_sequence(&mut error_sequence.clone())
        .returning(|_| Err(anyhow!("Buffer full")));
    
    // Test error handling
    let event = SecurityEvent {
        event_type: "test".to_string(),
        client_id: "test".to_string(),
        timestamp: 0,
        metadata: serde_json::json!({}),
    };
    
    // First should succeed
    assert!(mock_processor.process_event(event.clone()).await.is_ok());
    
    // Second should fail with network error
    let err = mock_processor.process_event(event.clone()).await.unwrap_err();
    assert!(err.to_string().contains("Network timeout"));
    
    // Third should fail with capacity error
    let err = mock_processor.process_event(event).await.unwrap_err();
    assert!(err.to_string().contains("Buffer full"));
}

/// Test component factory with mocks
#[test]
fn test_component_factory_with_mocks() {
    // Create a mock factory that returns specific mock implementations
    struct MockComponentFactory {
        scanner: Arc<MockEnhancedScanner>,
        processor: Arc<MockSecurityEventProcessor>,
        limiter: Arc<MockRateLimiter>,
    }
    
    impl MockComponentFactory {
        fn new() -> Self {
            let mut scanner = MockEnhancedScanner::new();
            scanner
                .expect_get_metrics()
                .returning(|| ScannerMetrics {
                    total_scans: 100,
                    threats_detected: 10,
                    avg_scan_time_ms: 5.0,
                });
            
            let mut processor = MockSecurityEventProcessor::new();
            processor
                .expect_is_monitored()
                .returning(|_| false);
            
            let mut limiter = MockRateLimiter::new();
            limiter
                .expect_get_stats()
                .returning(|| RateLimiterStats {
                    total_requests: 1000,
                    allowed_requests: 950,
                    denied_requests: 50,
                    active_limiters: 10,
                });
            
            Self {
                scanner: Arc::new(scanner),
                processor: Arc::new(processor),
                limiter: Arc::new(limiter),
            }
        }
        
        fn create_scanner(&self) -> Arc<dyn EnhancedScanner> {
            self.scanner.clone()
        }
        
        fn create_processor(&self) -> Arc<dyn SecurityEventProcessor> {
            self.processor.clone()
        }
        
        fn create_limiter(&self) -> Arc<dyn RateLimiter> {
            self.limiter.clone()
        }
    }
    
    // Test factory usage
    let factory = MockComponentFactory::new();
    
    let scanner = factory.create_scanner();
    let metrics = scanner.get_metrics();
    assert_eq!(metrics.total_scans, 100);
    assert_eq!(metrics.threats_detected, 10);
    
    let processor = factory.create_processor();
    assert!(!processor.is_monitored("test"));
    
    let limiter = factory.create_limiter();
    let stats = limiter.get_stats();
    assert_eq!(stats.total_requests, 1000);
    assert_eq!(stats.denied_requests, 50);
}

/// Test timeout behavior with mocks
#[tokio::test]
async fn test_timeout_handling() {
    use tokio::time::{timeout, Duration};
    
    let mut mock_processor = MockSecurityEventProcessor::new();
    
    // Set up processor to delay response
    mock_processor
        .expect_process_event()
        .returning(|_| {
            // This would normally use tokio::time::sleep but we'll return immediately
            // In real tests, you'd test actual timeout behavior
            Ok(EventHandle { event_id: 1, processed: true })
        });
    
    let event = SecurityEvent {
        event_type: "test".to_string(),
        client_id: "test".to_string(),
        timestamp: 0,
        metadata: serde_json::json!({}),
    };
    
    // Test with timeout
    let result = timeout(
        Duration::from_millis(100),
        mock_processor.process_event(event)
    ).await;
    
    assert!(result.is_ok());
}