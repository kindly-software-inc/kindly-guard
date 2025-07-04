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
//! Integration tests for universal display functionality

use kindly_guard_server::scanner::{Location, Severity, Threat, ThreatType};
use kindly_guard_server::shield::universal_display::{DisplayFormat, UniversalShieldStatus};
use kindly_guard_server::shield::{Shield, UniversalDisplay, UniversalDisplayConfig};
use std::sync::Arc;
use tempfile::tempdir;

/// Helper to create a test shield with predefined stats
fn create_test_shield(threats: u64, enhanced: bool) -> Arc<Shield> {
    let shield = Arc::new(Shield::new());

    // Set up test data
    for _ in 0..threats {
        shield.record_threats(&[Threat {
            threat_type: ThreatType::UnicodeInvisible,
            severity: Severity::High,
            description: "Test threat".to_string(),
            location: Location::Text {
                offset: 0,
                length: 1,
            },
            remediation: None,
        }]);
    }

    shield.set_event_processor_enabled(enhanced);
    shield
}

#[test]
fn test_minimal_format_basic() {
    let shield = create_test_shield(42, false);
    let config = UniversalDisplayConfig {
        color: false,
        detailed: false,
        format: DisplayFormat::Minimal,
        status_file: None,
    };

    let display = UniversalDisplay::new(shield, config);
    let output = display.render();

    // Verify minimal format contains key elements
    assert!(output.contains("KindlyGuard"));
    assert!(output.contains("Status: Active"));
    assert!(output.contains("Threats: 42"));
    assert!(output.contains("Uptime:"));
    assert!(!output.contains('\n')); // Single line
}

#[test]
fn test_json_format_validity() {
    let shield = create_test_shield(99, true);
    let config = UniversalDisplayConfig {
        color: false,
        detailed: true,
        format: DisplayFormat::Json,
        status_file: None,
    };

    let display = UniversalDisplay::new(shield, config);
    let output = display.render();

    // Parse JSON to verify validity
    let status: UniversalShieldStatus =
        serde_json::from_str(&output).expect("JSON output should be valid");

    assert_eq!(status.threats_blocked, 99);
    assert!(status.enhanced_mode);
    assert_eq!(status.mode_name, "Enhanced");
    assert_eq!(status.status_emoji, "🛡️");
    assert_eq!(status.threat_breakdown.unicode_attacks, 99);
}

#[test]
fn test_status_file_writing() {
    let dir = tempdir().unwrap();
    let status_file = dir.path().join("test-status.json");

    let shield = create_test_shield(50, false);
    let config = UniversalDisplayConfig {
        color: false,
        detailed: false,
        format: DisplayFormat::Compact,
        status_file: Some(status_file.to_str().unwrap().to_string()),
    };

    let display = UniversalDisplay::new(shield, config);
    display
        .write_status_file()
        .expect("Should write status file");

    // Verify file exists and contains valid JSON
    assert!(status_file.exists());
    let content = std::fs::read_to_string(&status_file).unwrap();
    let status: UniversalShieldStatus = serde_json::from_str(&content).unwrap();
    assert_eq!(status.threats_blocked, 50);
}
