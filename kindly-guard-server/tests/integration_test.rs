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
//! Integration tests for storage and plugin systems

use kindly_guard_server::{
    component_selector::ComponentManager, Config, ScannerConfig, SecurityScanner, ThreatType,
};
use std::sync::Arc;

#[tokio::test]
async fn test_storage_integration() {
    // Create config
    let mut config = Config::default();
    config.storage.enabled = true;

    // Create component manager
    let component_manager = Arc::new(ComponentManager::new(&config).unwrap());

    // Get storage provider
    let storage = component_manager.storage_provider();

    // Store an event
    let event = kindly_guard_server::traits::SecurityEvent {
        event_type: "test_threat".to_string(),
        client_id: "test_client".to_string(),
        timestamp: 1234567890,
        metadata: serde_json::json!({
            "severity": "high",
            "description": "Test threat"
        }),
    };

    // Store event
    let event_id = storage.store_event(&event).await.unwrap();
    assert!(!event_id.0.is_empty());

    // Query events
    use kindly_guard_server::storage::EventFilter;
    let filter = EventFilter {
        client_id: Some("test_client".to_string()),
        ..Default::default()
    };

    let events = storage.query_events(filter).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].client_id, "test_client");
}

#[test]
fn test_scanner_without_plugins() {
    // Create scanner without plugins
    let config = ScannerConfig {
        unicode_detection: true,
        injection_detection: true,
        path_traversal_detection: true,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
        xss_detection: Some(true),
        enhanced_mode: Some(false),
        crypto_detection: true,
        max_content_size: 5 * 1024 * 1024, // 5MB
            max_input_size: None,
    };
    let scanner = SecurityScanner::new(config).unwrap();

    // Test SQL injection detection
    let threats = scanner
        .scan_text("SELECT * FROM users WHERE id = '1' OR '1'='1'")
        .unwrap();
    assert!(!threats.is_empty());

    let sql_threats: Vec<_> = threats
        .iter()
        .filter(|t| matches!(t.threat_type, ThreatType::SqlInjection))
        .collect();
    assert!(!sql_threats.is_empty());
}

#[test]
fn test_scanner_threat_detection() {
    let config = ScannerConfig {
        unicode_detection: true,
        injection_detection: true,
        path_traversal_detection: true,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
        xss_detection: Some(true),
        enhanced_mode: Some(false),
        crypto_detection: true,
        max_content_size: 5 * 1024 * 1024, // 5MB
            max_input_size: None,
    };
    let scanner = SecurityScanner::new(config).unwrap();

    // Test various threats
    let test_cases = vec![
        ("Hello\u{202E}World", ThreatType::UnicodeBiDi),
        ("rm -rf /; echo done", ThreatType::CommandInjection),
        ("../../etc/passwd", ThreatType::PathTraversal),
    ];

    for (input, expected_type) in test_cases {
        let threats = scanner.scan_text(input).unwrap();
        assert!(!threats.is_empty(), "Expected threats for input: {input}");

        let has_expected = threats.iter().any(|t| t.threat_type == expected_type);
        assert!(
            has_expected,
            "Expected {expected_type:?} threat for input: {input}"
        );
    }
}

#[tokio::test]
async fn test_component_manager_creation() {
    // Test that all components can be created successfully
    let config = Config::default();
    let component_manager = ComponentManager::new(&config).unwrap();

    // Verify all components are accessible
    assert!(!component_manager.event_processor().is_monitored("test"));
    assert_eq!(component_manager.scanner().get_metrics().scans_performed, 0);
    assert_eq!(
        component_manager
            .rate_limiter()
            .get_stats()
            .requests_allowed,
        0
    );

    // Check storage
    let storage_stats = component_manager
        .storage_provider()
        .get_stats()
        .await
        .unwrap();
    assert_eq!(storage_stats.event_count, 0);

    // Check plugin manager (should be no-op when disabled)
    let plugins = component_manager
        .plugin_manager()
        .list_plugins()
        .await
        .unwrap();
    assert!(plugins.is_empty());
}

#[test]
fn test_json_scanning() {
    let config = ScannerConfig {
        unicode_detection: true,
        injection_detection: true,
        path_traversal_detection: true,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
        xss_detection: Some(true),
        enhanced_mode: Some(false),
        crypto_detection: true,
        max_content_size: 5 * 1024 * 1024, // 5MB
            max_input_size: None,
    };
    let scanner = SecurityScanner::new(config).unwrap();

    let json = serde_json::json!({
        "user": "admin' OR '1'='1",
        "command": "ls; cat /etc/passwd",
        "path": "../../../etc/shadow",
        "script": "<img src=x onerror=alert('xss')>"
    });

    let threats = scanner.scan_json(&json).unwrap();
    assert!(
        threats.len() >= 3,
        "Expected at least 3 threats, got {}",
        threats.len()
    );

    // Verify threat locations are JSON paths
    for threat in &threats {
        match &threat.location {
            kindly_guard_server::scanner::Location::Json { path } => {
                assert!(path.starts_with('$'), "JSON path should start with $");
            }
            _ => panic!("Expected JSON location for JSON scanning"),
        }
    }
}

#[tokio::test]
async fn test_audit_logger_integration() {
    use kindly_guard_server::audit::{AuditEvent, AuditEventType, AuditFilter, AuditSeverity};

    // Create config with audit enabled
    let mut config = Config::default();
    config.audit.enabled = true;
    config.audit.backend = kindly_guard_server::audit::AuditBackend::Memory;

    // Create component manager
    let component_manager = Arc::new(ComponentManager::new(&config).unwrap());

    // Get audit logger
    let audit_logger = component_manager.audit_logger();

    // Log some events
    let event1 = AuditEvent::new(
        AuditEventType::AuthSuccess {
            user_id: "test_user".to_string(),
        },
        AuditSeverity::Info,
    )
    .with_client_id("client123".to_string());

    let event2 = AuditEvent::new(
        AuditEventType::ThreatDetected {
            client_id: "client123".to_string(),
            threat_count: 3,
        },
        AuditSeverity::Warning,
    )
    .with_client_id("client123".to_string());

    let event3 = AuditEvent::new(
        AuditEventType::RateLimitTriggered {
            client_id: "client456".to_string(),
            limit_type: "request".to_string(),
        },
        AuditSeverity::Warning,
    )
    .with_client_id("client456".to_string());

    // Log events
    let id1 = audit_logger.log(event1).await.unwrap();
    let id2 = audit_logger.log(event2).await.unwrap();
    let id3 = audit_logger.log(event3).await.unwrap();

    // Query all events
    let all_events = audit_logger.query(AuditFilter::default()).await.unwrap();
    assert_eq!(all_events.len(), 3);

    // Query by client ID
    let filter = AuditFilter {
        client_id: Some("client123".to_string()),
        ..Default::default()
    };
    let client_events = audit_logger.query(filter).await.unwrap();
    assert_eq!(client_events.len(), 2);

    // Query by severity
    let filter = AuditFilter {
        min_severity: Some(AuditSeverity::Warning),
        ..Default::default()
    };
    let warning_events = audit_logger.query(filter).await.unwrap();
    // Should include Warning and higher severity events (Warning, Error, Critical)
    assert_eq!(warning_events.len(), 2);

    // Get specific event
    let event = audit_logger.get_event(&id1).await.unwrap();
    assert!(event.is_some());

    // Check stats
    let stats = audit_logger.get_stats().await.unwrap();
    assert_eq!(stats.total_events, 3);
    assert_eq!(stats.events_by_severity.get("Warning"), Some(&2));
    assert_eq!(stats.events_by_severity.get("Info"), Some(&1));
}
