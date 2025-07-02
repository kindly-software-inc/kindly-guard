//! Snapshot tests for regression prevention
#![allow(missing_docs)] // Test module

use insta::assert_snapshot;
use kindly_guard_server::shield::{Shield, UniversalDisplay, UniversalDisplayConfig};
use kindly_guard_server::shield::universal_display::DisplayFormat;
use kindly_guard_server::scanner::{Threat, ThreatType, Severity, Location};
use std::sync::Arc;

fn create_test_shield() -> Arc<Shield> {
    let shield = Arc::new(Shield::new());
    
    // Add various threats for comprehensive snapshot
    shield.record_threat(Threat {
        threat_type: ThreatType::UnicodeInvisible,
        severity: Severity::High,
        description: "Invisible Unicode character detected".to_string(),
        location: Location::Text { offset: 42, length: 1 },
        confidence: 0.95,
    });
    
    shield.record_threat(Threat {
        threat_type: ThreatType::SqlInjection,
        severity: Severity::Critical,
        description: "SQL injection attempt detected".to_string(),
        location: Location::Text { offset: 100, length: 20 },
        confidence: 0.99,
    });
    
    shield.record_threat(Threat {
        threat_type: ThreatType::PathTraversal,
        severity: Severity::High,
        description: "Path traversal attempt detected".to_string(),
        location: Location::Text { offset: 200, length: 10 },
        confidence: 0.90,
    });
    
    shield
}

#[test]
fn test_minimal_format_snapshot() {
    let shield = create_test_shield();
    let config = UniversalDisplayConfig {
        color: false,
        detailed: false,
        format: DisplayFormat::Minimal,
        status_file: None,
    };
    
    let display = UniversalDisplay::new(shield, config);
    assert_snapshot!("minimal_format", display.render());
}

#[test]
fn test_compact_format_snapshot() {
    let shield = create_test_shield();
    let config = UniversalDisplayConfig {
        color: false,
        detailed: true,
        format: DisplayFormat::Compact,
        status_file: None,
    };
    
    let display = UniversalDisplay::new(shield, config);
    assert_snapshot!("compact_format", display.render());
}

#[test]
fn test_dashboard_format_snapshot() {
    let shield = create_test_shield();
    let config = UniversalDisplayConfig {
        color: false,
        detailed: true,
        format: DisplayFormat::Dashboard,
        status_file: None,
    };
    
    let display = UniversalDisplay::new(shield, config);
    assert_snapshot!("dashboard_format", display.render());
}

#[test]
fn test_enhanced_mode_snapshot() {
    let shield = create_test_shield();
    shield.set_event_processor_enabled(true);
    
    let config = UniversalDisplayConfig {
        color: false,
        detailed: true,
        format: DisplayFormat::Compact,
        status_file: None,
    };
    
    let display = UniversalDisplay::new(shield, config);
    assert_snapshot!("enhanced_mode_compact", display.render());
}

#[test]
fn test_json_format_structure() {
    let shield = create_test_shield();
    let config = UniversalDisplayConfig {
        color: false,
        detailed: true,
        format: DisplayFormat::Json,
        status_file: None,
    };
    
    let display = UniversalDisplay::new(shield, config);
    let json_output = display.render();
    
    // Parse and re-serialize to ensure consistent formatting
    let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
    let formatted = serde_json::to_string_pretty(&parsed).unwrap();
    
    assert_snapshot!("json_format", formatted);
}