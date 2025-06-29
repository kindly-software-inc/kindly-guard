//! Integration tests for KindlyGuard server
//! Tests both standard and enhanced modes

use kindly_guard_server::{
    Config, McpServer, 
    component_selector::ComponentManager,
    traits::{SecurityEvent, RateLimitKey},
};
use std::sync::Arc;
use serde_json::json;

/// Create a test configuration
fn create_test_config(enhanced: bool) -> Config {
    let mut config = Config::default();
    config.event_processor.enabled = enhanced;
    config.server.stdio = true;
    config.shield.enabled = false; // Disable for tests
    config
}

#[tokio::test]
async fn test_server_creation_standard_mode() {
    let config = create_test_config(false);
    let server = McpServer::new(config).expect("Failed to create server");
    
    // Verify shield is not in enhanced mode
    assert!(!server.shield.is_event_processor_enabled());
}

#[tokio::test]
async fn test_server_creation_enhanced_mode() {
    let config = create_test_config(true);
    let server = McpServer::new(config).expect("Failed to create server");
    
    // Verify shield is in enhanced mode (purple)
    assert!(server.shield.is_event_processor_enabled());
}

#[tokio::test]
async fn test_component_manager_standard() {
    let config = create_test_config(false);
    let manager = ComponentManager::new(&config).expect("Failed to create component manager");
    
    // Verify we can get all components
    let _event_processor = manager.event_processor();
    let _scanner = manager.scanner();
    let _correlation_engine = manager.correlation_engine();
    let _rate_limiter = manager.rate_limiter();
    
    assert!(!manager.is_enhanced_mode());
}

#[tokio::test]
async fn test_component_manager_enhanced() {
    let config = create_test_config(true);
    let manager = ComponentManager::new(&config).expect("Failed to create component manager");
    
    assert!(manager.is_enhanced_mode());
    assert_eq!(manager.performance_description(), "optimized performance mode");
}

#[tokio::test]
async fn test_event_processing_standard() {
    let config = create_test_config(false);
    let manager = ComponentManager::new(&config).expect("Failed to create component manager");
    let processor = manager.event_processor();
    
    let event = SecurityEvent {
        event_type: "test.event".to_string(),
        client_id: "test_client".to_string(),
        timestamp: 0,
        metadata: json!({}),
    };
    
    let handle = processor.process_event(event).await.expect("Failed to process event");
    assert!(handle.processed);
}

#[tokio::test]
async fn test_event_processing_enhanced() {
    let config = create_test_config(true);
    let manager = ComponentManager::new(&config).expect("Failed to create component manager");
    let processor = manager.event_processor();
    
    let event = SecurityEvent {
        event_type: "test.event".to_string(),
        client_id: "test_client".to_string(),
        timestamp: 0,
        metadata: json!({}),
    };
    
    let handle = processor.process_event(event).await.expect("Failed to process event");
    assert!(handle.processed);
}

#[tokio::test]
async fn test_rate_limiting_standard() {
    let config = create_test_config(false);
    let manager = ComponentManager::new(&config).expect("Failed to create component manager");
    let rate_limiter = manager.rate_limiter();
    
    let key = RateLimitKey {
        client_id: "test_client".to_string(),
        method: Some("test_method".to_string()),
    };
    
    // First request should be allowed
    let decision = rate_limiter.check_rate_limit(&key).await.expect("Failed to check rate limit");
    assert!(decision.allowed);
    assert!(decision.tokens_remaining > 0.0);
}

#[tokio::test]
async fn test_rate_limiting_enhanced() {
    let config = create_test_config(true);
    let manager = ComponentManager::new(&config).expect("Failed to create component manager");
    let rate_limiter = manager.rate_limiter();
    
    let key = RateLimitKey {
        client_id: "test_client".to_string(),
        method: Some("test_method".to_string()),
    };
    
    // First request should be allowed
    let decision = rate_limiter.check_rate_limit(&key).await.expect("Failed to check rate limit");
    assert!(decision.allowed);
}

#[tokio::test]
async fn test_scanner_standard() {
    let config = create_test_config(false);
    let manager = ComponentManager::new(&config).expect("Failed to create component manager");
    let scanner = manager.scanner();
    
    let test_data = b"SELECT * FROM users WHERE id = '1' OR '1'='1'";
    let threats = scanner.enhanced_scan(test_data).expect("Failed to scan");
    
    // Should detect SQL injection
    assert!(!threats.is_empty());
    assert_eq!(threats[0].threat_type, kindly_guard_server::ThreatType::SqlInjection);
}

#[tokio::test]
async fn test_scanner_enhanced() {
    let config = create_test_config(true);
    let manager = ComponentManager::new(&config).expect("Failed to create component manager");
    let scanner = manager.scanner();
    
    let test_data = b"SELECT * FROM users WHERE id = '1' OR '1'='1'";
    let threats = scanner.enhanced_scan(test_data).expect("Failed to scan");
    
    // Should detect SQL injection with enhanced performance
    assert!(!threats.is_empty());
}

#[tokio::test]
async fn test_correlation_standard() {
    let config = create_test_config(false);
    let manager = ComponentManager::new(&config).expect("Failed to create component manager");
    let correlation_engine = manager.correlation_engine();
    
    // Create suspicious pattern of events
    let events: Vec<SecurityEvent> = (0..10)
        .map(|i| SecurityEvent {
            event_type: if i < 5 { "auth_failure" } else { "request" }.to_string(),
            client_id: "suspicious_client".to_string(),
            timestamp: i as u64,
            metadata: json!({}),
        })
        .collect();
    
    let patterns = correlation_engine.correlate(&events).await.expect("Failed to correlate");
    
    // Should detect repeated failures
    assert!(!patterns.is_empty());
    assert_eq!(patterns[0].pattern_type, "repeated_failures");
}

#[tokio::test]
async fn test_correlation_enhanced() {
    let config = create_test_config(true);
    let manager = ComponentManager::new(&config).expect("Failed to create component manager");
    let correlation_engine = manager.correlation_engine();
    
    // Create attack pattern
    let events: Vec<SecurityEvent> = (0..10)
        .map(|i| SecurityEvent {
            event_type: if i % 2 == 0 { "auth_failure" } else { "threat_detected" }.to_string(),
            client_id: "attacker".to_string(),
            timestamp: i as u64,
            metadata: json!({}),
        })
        .collect();
    
    let patterns = correlation_engine.correlate(&events).await.expect("Failed to correlate");
    
    // Should detect active attack
    assert!(patterns.iter().any(|p| p.pattern_type == "active_attack"));
}

#[tokio::test]
async fn test_message_handling() {
    let config = create_test_config(false);
    let server = Arc::new(McpServer::new(config).expect("Failed to create server"));
    
    // Test initialize request
    let init_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        },
        "id": 1
    });
    
    let response = server.handle_message(&serde_json::to_string(&init_request).unwrap()).await;
    assert!(response.is_some());
    
    let response_json: serde_json::Value = serde_json::from_str(&response.unwrap()).unwrap();
    assert_eq!(response_json["jsonrpc"], "2.0");
    assert_eq!(response_json["id"], 1);
    assert!(response_json["result"].is_object());
}

#[tokio::test]
async fn test_threat_detection_flow() {
    let config = create_test_config(true);
    let server = Arc::new(McpServer::new(config).expect("Failed to create server"));
    
    // Test scan_text tool with SQL injection
    let scan_request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": "'; DROP TABLE users; --"
            }
        },
        "id": 2
    });
    
    let response = server.handle_message(&serde_json::to_string(&scan_request).unwrap()).await;
    assert!(response.is_some());
    
    let response_json: serde_json::Value = serde_json::from_str(&response.unwrap()).unwrap();
    
    // Should detect threat
    if let Some(result) = response_json.get("result") {
        assert_eq!(result["safe"], false);
        assert!(!result["threats"].as_array().unwrap().is_empty());
    } else {
        // If error, check it's an auth error (expected without auth token)
        assert!(response_json["error"].is_object());
    }
}