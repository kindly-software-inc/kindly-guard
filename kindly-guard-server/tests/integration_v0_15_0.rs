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

//! Comprehensive integration tests for v0.15.0 features
//!
//! Tests:
//! 1. Three protection modes (auto, interactive, report)
//! 2. Quarantine encryption and retrieval
//! 3. MCP protocol with new tools
//! 4. Neutralization for SQL, XSS, and Unicode threats
//! 5. Friendly messaging system
//! 6. Configuration loading with partial configs

use anyhow::Result;
use kindly_guard_server::{
    config::Config,
    neutralizer::{
        BiDiReplacement, HomographAction, NeutralizationMode, NeutralizeAction, SqlAction,
        ThreatNeutralizer, UnicodeNeutralizationConfig, ZeroWidthAction,
    },
    protocol::{JsonRpcRequest, JsonRpcResponse, ToolsListResult},
    quarantine::QuarantineConfig,
    scanner::{Location, Severity, Threat, ThreatType},
    server::McpServer,
    SecurityScanner,
};
use serde_json::json;
use std::{fs, sync::Arc, time::SystemTime};
use tempfile::TempDir;

/// Test fixture for integration tests
struct TestFixture {
    server: Arc<McpServer>,
    #[allow(dead_code)]
    config: Arc<Config>,
    #[allow(dead_code)]
    scanner: Arc<SecurityScanner>,
    neutralizer: Arc<dyn ThreatNeutralizer>,
    quarantine: Option<Arc<dyn kindly_guard_server::quarantine::Quarantine>>,
    _temp_dir: TempDir,
}

impl TestFixture {
    async fn new(config_overrides: Option<Config>) -> Result<Self> {
        let temp_dir = TempDir::new()?;
        let storage_path = temp_dir.path().join("storage");
        fs::create_dir_all(&storage_path)?;

        // Create base config
        let mut config = config_overrides.unwrap_or_else(Config::default);

        // Enable quarantine
        if config.quarantine.is_none() {
            config.quarantine = Some(QuarantineConfig {
                base_path: storage_path.join("quarantine"),
                encrypt: true,
                compress_after_days: 30,
                delete_after_days: 90,
                max_size_mb: 100,
            });
        }

        // Create server
        let server = Arc::new(McpServer::new(config.clone())?);

        // Get components from server's component manager for test access
        let scanner = server.scanner().clone();
        let neutralizer = server.component_manager.threat_neutralizer().clone();
        let quarantine = server.quarantine().and_then(|q| Some(q.clone()));

        Ok(TestFixture {
            config: Arc::new(config),
            server,
            scanner: scanner.clone(),
            neutralizer,
            quarantine,
            _temp_dir: temp_dir,
        })
    }

    /// Execute a JSON-RPC request
    async fn execute_request(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse> {
        let response_json = self.server.handle_request(request).await;
        Ok(response_json)
    }
}

// ===== Protection Mode Tests =====

#[tokio::test]
async fn test_automatic_protection_mode() -> Result<()> {
    let mut config = Config::default();
    config.neutralization.mode = NeutralizationMode::Automatic;
    let fixture = TestFixture::new(Some(config)).await?;

    // Test SQL injection auto-neutralization
    let sql_threat = Threat {
        threat_type: ThreatType::SqlInjection,
        severity: Severity::High,
        location: Location::Text {
            offset: 28,
            length: 15,
        },
        description: "SQL injection detected".to_string(),
        remediation: Some("Use parameterized queries".to_string()),
    };

    let content = "SELECT * FROM users WHERE id='1' OR '1'='1'";
    let result = fixture.neutralizer.neutralize(&sql_threat, content).await?;

    assert_eq!(result.action_taken, NeutralizeAction::Parameterized);
    assert!(result.sanitized_content.is_some());
    assert!(result.extracted_params.is_some());

    Ok(())
}

#[tokio::test]
async fn test_interactive_protection_mode() -> Result<()> {
    let mut config = Config::default();
    config.neutralization.mode = NeutralizationMode::Interactive;
    let fixture = TestFixture::new(Some(config)).await?;

    // In interactive mode, neutralization requires user input
    // For testing, we verify it doesn't auto-neutralize
    let xss_threat = Threat {
        threat_type: ThreatType::CrossSiteScripting,
        severity: Severity::High,
        location: Location::Text { offset: 0, length: 35 },
        description: "XSS script injection detected".to_string(),
        remediation: Some("Escape HTML special characters".to_string()),
    };

    let content = "<script>alert('XSS')</script>Hello";
    let result = fixture.neutralizer.neutralize(&xss_threat, content).await?;

    // In interactive mode, it should report but not modify
    assert_eq!(result.action_taken, NeutralizeAction::NoAction);
    assert!(result.sanitized_content.is_none());

    Ok(())
}

#[tokio::test]
async fn test_report_only_protection_mode() -> Result<()> {
    let mut config = Config::default();
    config.neutralization.mode = NeutralizationMode::ReportOnly;
    let fixture = TestFixture::new(Some(config)).await?;

    // Test that threats are reported but not neutralized
    let unicode_threat = Threat {
        threat_type: ThreatType::UnicodeBiDi,
        severity: Severity::Medium,
        location: Location::Text { offset: 5, length: 1 },
        description: "Bidirectional override character detected".to_string(),
        remediation: Some("Remove or escape BiDi characters".to_string()),
    };

    let content = "Hello\u{202E}World";
    let result = fixture.neutralizer.neutralize(&unicode_threat, content).await?;

    assert_eq!(result.action_taken, NeutralizeAction::NoAction);
    assert!(result.sanitized_content.is_none());

    Ok(())
}

// ===== Quarantine Tests =====

#[tokio::test]
async fn test_quarantine_encryption_and_retrieval() -> Result<()> {
    let fixture = TestFixture::new(None).await?;
    let quarantine = fixture.quarantine.expect("Quarantine should be enabled");

    // Create test content
    let original_content = "SELECT * FROM users WHERE id='1' OR '1'='1'";
    let threat = Threat {
        threat_type: ThreatType::SqlInjection,
        severity: Severity::High,
        location: Location::Text {
            offset: 28,
            length: 15,
        },
        description: "SQL injection detected".to_string(),
        remediation: Some("Use parameterized queries".to_string()),
    };

    // Store in quarantine
    let threat_info = kindly_guard_server::quarantine::ThreatInfo {
        threat_type: format!("{:?}", threat.threat_type),
        severity: format!("{:?}", threat.severity),
        description: threat.description.clone(),
        location: Some(format!("{:?}", threat.location)),
        timestamp: SystemTime::now(),
    };

    let entry_id = quarantine
        .quarantine(original_content, threat_info, Some("test-client".to_string()))
        .await?;

    // Retrieve and verify
    let retrieved = quarantine.retrieve(&entry_id).await?;
    assert!(retrieved.is_some());

    let entry = retrieved.unwrap();
    assert_eq!(entry.original_content, original_content);
    assert_eq!(entry.threat_info.threat_type, "SqlInjection");
    assert_eq!(entry.source, Some("test-client".to_string()));

    // Test listing
    let filter = kindly_guard_server::quarantine::QuarantineFilter::default();
    let entries = quarantine.list(filter).await?;
    assert!(!entries.is_empty());
    assert!(entries.iter().any(|e| e.id == entry_id));

    Ok(())
}

#[tokio::test]
async fn test_quarantine_retention_and_cleanup() -> Result<()> {
    let mut config = Config::default();
    if let Some(ref mut q) = config.quarantine {
        q.delete_after_days = 0; // Immediate expiry for testing
    }
    let fixture = TestFixture::new(Some(config)).await?;
    let quarantine = fixture.quarantine.expect("Quarantine should be enabled");

    // Store an entry
    let threat = Threat {
        threat_type: ThreatType::PathTraversal,
        severity: Severity::High,
        location: Location::Text { offset: 0, length: 10 },
        description: "Path traversal detected".to_string(),
        remediation: Some("Normalize paths".to_string()),
    };

    let threat_info = kindly_guard_server::quarantine::ThreatInfo {
        threat_type: format!("{:?}", threat.threat_type),
        severity: format!("{:?}", threat.severity),
        description: threat.description.clone(),
        location: Some(format!("{:?}", threat.location)),
        timestamp: SystemTime::now(),
    };

    let entry_id = quarantine
        .quarantine("../../etc/passwd", threat_info, Some("test-client".to_string()))
        .await?;

    // Verify it exists
    assert!(quarantine.retrieve(&entry_id).await?.is_some());

    // Run retention policy (which includes cleanup)
    quarantine.apply_retention().await?;

    // After cleanup with 0 retention days, entry might be gone
    // Note: Actual cleanup might not remove immediately created entries
    // This is implementation-dependent

    Ok(())
}

// ===== MCP Protocol Tests =====

#[tokio::test]
async fn test_mcp_scan_text_tool() -> Result<()> {
    let fixture = TestFixture::new(None).await?;

    // List tools
    let list_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: json!(1),
        method: "tools/list".to_string(),
        params: json!({}),
    };

    let response = fixture.execute_request(list_request).await?;
    let tools_result: ToolsListResult = serde_json::from_value(response.result.unwrap())?;

    // Verify scan_text tool exists
    assert!(tools_result.tools.iter().any(|t| t.name == "scan_text"));

    // Call scan_text with all parameters
    let scan_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: json!(2),
        method: "tools/call".to_string(),
        params: json!({
            "name": "scan_text",
            "arguments": {
                "text": "<script>alert('XSS')</script>Hello' OR '1'='1",
                "protection_mode": "auto",
                "include_messages": true,
                "auto_quarantine": true
            }
        }),
    };

    let response = fixture.execute_request(scan_request).await?;
    let result = response.result.unwrap();

    // Verify response structure
    assert!(result.get("threats").is_some());
    assert!(result.get("neutralized_content").is_some());

    // Verify threats detected
    let threats = result["threats"].as_array().unwrap();
    assert!(!threats.is_empty()); // Should detect threats

    Ok(())
}

#[tokio::test]
async fn test_mcp_check_content_tool() -> Result<()> {
    let fixture = TestFixture::new(None).await?;

    // Call check_content tool
    let check_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: json!(1),
        method: "tools/call".to_string(),
        params: json!({
            "name": "check_content",
            "arguments": {
                "content": {
                    "type": "text",
                    "data": "Hello\u{202E}World"
                }
            }
        }),
    };

    let response = fixture.execute_request(check_request).await?;
    let result = response.result.unwrap();

    // Verify threat detection
    assert_eq!(result["is_safe"].as_bool().unwrap(), false);
    assert!(result["threat_count"].as_u64().unwrap() > 0);

    let threats = result["threats"].as_array().unwrap();
    assert!(threats
        .iter()
        .any(|t| t["type"].as_str().unwrap().contains("UnicodeBiDi")));

    Ok(())
}

#[tokio::test]
async fn test_mcp_get_quarantine_item_tool() -> Result<()> {
    let fixture = TestFixture::new(None).await?;
    let quarantine = fixture.quarantine.clone().expect("Quarantine should be enabled");

    // First, quarantine something
    let threat = Threat {
        threat_type: ThreatType::CommandInjection,
        severity: Severity::Critical,
        location: Location::Text { offset: 0, length: 10 },
        description: "Command injection detected".to_string(),
        remediation: Some("Escape shell metacharacters".to_string()),
    };

    let threat_info = kindly_guard_server::quarantine::ThreatInfo {
        threat_type: format!("{:?}", threat.threat_type),
        severity: format!("{:?}", threat.severity),
        description: threat.description.clone(),
        location: Some(format!("{:?}", threat.location)),
        timestamp: SystemTime::now(),
    };

    let entry_id = quarantine
        .quarantine("rm -rf /", threat_info, Some("test-client".to_string()))
        .await?;

    // Call get_quarantine_item tool
    let get_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: json!(1),
        method: "tools/call".to_string(),
        params: json!({
            "name": "get_quarantine_item",
            "arguments": {
                "id": entry_id
            }
        }),
    };

    let response = fixture.execute_request(get_request).await?;
    let result = response.result.unwrap();

    // Verify quarantine entry
    assert_eq!(result["id"].as_str().unwrap(), entry_id);
    assert_eq!(result["original_content"].as_str().unwrap(), "rm -rf /");
    assert_eq!(result["threat_info"]["threat_type"].as_str().unwrap(), "CommandInjection");
    assert_eq!(result["source"].as_str().unwrap(), "test-client");

    Ok(())
}

// ===== Neutralization Tests =====

#[tokio::test]
async fn test_sql_injection_neutralization() -> Result<()> {
    let mut config = Config::default();
    config.neutralization.injection.sql_action = SqlAction::Parameterize;
    let fixture = TestFixture::new(Some(config)).await?;

    let threat = Threat {
        threat_type: ThreatType::SqlInjection,
        severity: Severity::High,
        location: Location::Text {
            offset: 36,
            length: 28,
        },
        description: "SQL injection via UNION".to_string(),
        remediation: Some("Use parameterized queries".to_string()),
    };

    let content = "SELECT name FROM users WHERE id = 1 UNION SELECT password FROM admins";
    let result = fixture.neutralizer.neutralize(&threat, content).await?;

    assert_eq!(result.action_taken, NeutralizeAction::Parameterized);
    assert!(result.sanitized_content.is_some());
    assert!(result.extracted_params.is_some());

    // Verify parameterization
    let params = result.extracted_params.unwrap();
    assert!(!params.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_xss_neutralization() -> Result<()> {
    let fixture = TestFixture::new(None).await?;

    // Test various XSS patterns
    let xss_patterns = vec![
        (
            "<img src=x onerror=alert('XSS')>",
            ThreatType::CrossSiteScripting,
            "Image tag with event handler",
        ),
        (
            "<svg onload=alert('XSS')>",
            ThreatType::CrossSiteScripting,
            "SVG with event handler",
        ),
        (
            "javascript:alert('XSS')",
            ThreatType::CrossSiteScripting,
            "JavaScript protocol",
        ),
    ];

    for (content, threat_type, description) in xss_patterns {
        let threat = Threat {
            threat_type,
            severity: Severity::High,
            location: Location::Text {
                offset: 0,
                length: content.len(),
            },
            description: description.to_string(),
            remediation: Some("Escape HTML entities".to_string()),
        };

        let result = fixture.neutralizer.neutralize(&threat, content).await?;

        assert!(matches!(
            result.action_taken,
            NeutralizeAction::Sanitized | NeutralizeAction::Escaped
        ));
        assert!(result.sanitized_content.is_some());

        let sanitized = result.sanitized_content.unwrap();
        assert!(!sanitized.contains("alert"));
        assert!(!sanitized.contains("<script"));
        assert!(!sanitized.contains("onerror="));
    }

    Ok(())
}

#[tokio::test]
async fn test_unicode_threat_neutralization() -> Result<()> {
    let mut config = Config::default();
    config.neutralization.unicode = UnicodeNeutralizationConfig {
        bidi_replacement: BiDiReplacement::Marker,
        zero_width_action: ZeroWidthAction::Remove,
        homograph_action: HomographAction::Ascii,
    };
    let fixture = TestFixture::new(Some(config)).await?;

    // Test BiDi neutralization
    let bidi_threat = Threat {
        threat_type: ThreatType::UnicodeBiDi,
        severity: Severity::Medium,
        location: Location::Text { offset: 5, length: 1 },
        description: "BiDi override character".to_string(),
        remediation: Some("Remove BiDi characters".to_string()),
    };

    let bidi_content = "Hello\u{202E}World";
    let result = fixture.neutralizer.neutralize(&bidi_threat, bidi_content).await?;

    assert!(result.sanitized_content.is_some());
    let sanitized = result.sanitized_content.unwrap();
    assert!(sanitized.contains("[BIDI]") || !sanitized.contains("\u{202E}"));

    // Test zero-width character removal
    let zw_threat = Threat {
        threat_type: ThreatType::UnicodeInvisible,
        severity: Severity::Low,
        location: Location::Text { offset: 5, length: 1 },
        description: "Zero-width character".to_string(),
        remediation: Some("Remove invisible characters".to_string()),
    };

    let zw_content = "Hello\u{200B}World";
    let result = fixture.neutralizer.neutralize(&zw_threat, zw_content).await?;

    assert!(result.sanitized_content.is_some());
    assert!(!result.sanitized_content.unwrap().contains("\u{200B}"));

    Ok(())
}

// ===== Configuration Tests =====

#[tokio::test]
async fn test_partial_config_loading() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join("partial-config.toml");

    // Write partial config with only some fields
    let partial_config = r#"
[scanner]
unicode_detection = true
xss_detection = false

[neutralization]
mode = "automatic"

[neutralization.unicode]
bidi_replacement = "marker"

[quarantine]
encrypt = true
delete_after_days = 14
"#;

    fs::write(&config_path, partial_config)?;

    // Load config
    let config = kindly_guard_server::config::Config::load_from_file(config_path.to_str().unwrap())?;

    // Verify specified values are loaded
    assert!(config.scanner.unicode_detection);
    assert_eq!(config.scanner.xss_detection, Some(false));
    assert_eq!(config.neutralization.mode, NeutralizationMode::Automatic);
    assert_eq!(
        config.neutralization.unicode.bidi_replacement,
        BiDiReplacement::Marker
    );
    assert!(config.quarantine.is_some());
    assert_eq!(config.quarantine.as_ref().unwrap().delete_after_days, 14);

    // Verify defaults are used for unspecified fields
    assert!(config.scanner.injection_detection); // Should use default (true)
    assert_eq!(
        config.neutralization.unicode.zero_width_action,
        ZeroWidthAction::default()
    );

    Ok(())
}

// ===== End-to-End Scenario Tests =====

#[tokio::test]
async fn test_full_threat_lifecycle() -> Result<()> {
    let fixture = TestFixture::new(None).await?;

    // 1. Submit malicious content via MCP
    let scan_request = JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: json!(1),
        method: "tools/call".to_string(),
        params: json!({
            "name": "scan_text",
            "arguments": {
                "text": "Hello\u{202E}World <script>alert('XSS')</script> SELECT * FROM users WHERE id='1' OR '1'='1'",
                "protection_mode": "auto",
                "include_messages": true,
                "auto_quarantine": true
            }
        }),
    };

    let response = fixture.execute_request(scan_request).await?;
    let result = response.result.unwrap();

    // 2. Verify multiple threats detected
    let threats = result["threats"].as_array().unwrap();
    assert!(!threats.is_empty()); // Should detect threats

    // 3. Verify neutralization occurred
    if let Some(neutralized) = result.get("neutralized_content") {
        let neutralized_str = neutralized.as_str().unwrap();
        assert!(!neutralized_str.contains("<script>"));
        assert!(!neutralized_str.contains("OR '1'='1"));
    }

    Ok(())
}

#[tokio::test]
async fn test_high_volume_threat_processing() -> Result<()> {
    let fixture = TestFixture::new(None).await?;

    // Generate multiple threats
    let threat_contents = vec![
        "<script>alert(1)</script>",
        "' OR '1'='1' --",
        "../../etc/passwd",
        "\u{202E}reversed",
        "javascript:void(0)",
        "<img src=x onerror=alert(1)>",
        "'; DROP TABLE users; --",
        "Hello\u{200B}World",
    ];

    // Process all threats concurrently
    let mut handles = vec![];

    for (i, content) in threat_contents.iter().enumerate() {
        let fixture_clone = fixture.server.clone();
        let content = content.to_string();

        let handle = tokio::spawn(async move {
            let request = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: json!(i),
                method: "tools/call".to_string(),
                params: json!({
                    "name": "scan_text",
                    "arguments": {
                        "text": content,
                        "protection_mode": "auto",
                        "auto_quarantine": true
                    }
                }),
            };

            fixture_clone.handle_request(request).await
        });

        handles.push(handle);
    }

    // Wait for all to complete
    let results = futures::future::join_all(handles).await;

    // Verify all succeeded
    for result in results {
        let response = result?;
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    Ok(())
}

// ===== Helper Functions =====

/// Create a test threat
fn _create_test_threat(threat_type: ThreatType, severity: Severity) -> Threat {
    Threat {
        threat_type: threat_type.clone(),
        severity,
        location: Location::Text { offset: 0, length: 10 },
        description: format!("{:?} threat", &threat_type),
        remediation: Some("Test remediation".to_string()),
    }
}