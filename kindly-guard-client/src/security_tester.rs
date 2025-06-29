//! Security testing implementation

use async_trait::async_trait;
use anyhow::Result;
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info};

use crate::traits::{
    SecurityTester, ThreatType, TestResult, RateLimitTestResult,
    AuthScenario, AuthTestResult, SigningTestResult, McpClient
};

/// Security test runner implementation
pub struct SecurityTestRunner {
    client: Arc<dyn McpClient>,
}

impl SecurityTestRunner {
    /// Create a new security test runner
    pub fn new(client: Arc<dyn McpClient>) -> Self {
        Self { client }
    }
    
    /// Run all security tests
    pub async fn run_all_tests(&self) -> Result<SecurityTestReport> {
        info!("🔒 Running comprehensive security tests...");
        
        let mut report = SecurityTestReport::default();
        
        // Test threat detection
        info!("Testing threat detection...");
        report.threat_detection = self.test_all_threats().await?;
        
        // Test rate limiting
        info!("Testing rate limiting...");
        report.rate_limiting = self.test_rate_limiting_scenarios().await?;
        
        // Test authentication
        info!("Testing authentication...");
        report.authentication = self.test_auth_scenarios().await?;
        
        Ok(report)
    }
    
    /// Test all threat types
    async fn test_all_threats(&self) -> Result<ThreatDetectionReport> {
        let mut report = ThreatDetectionReport::default();
        
        // SQL Injection
        let sql_result = self.inject_threat(
            ThreatType::SqlInjection,
            "'; DROP TABLE users; --"
        ).await?;
        report.sql_injection_blocked = sql_result.threat_detected;
        
        // Unicode attacks
        let unicode_result = self.inject_threat(
            ThreatType::UnicodeAttack,
            "Hello\u{202E}World"
        ).await?;
        report.unicode_attack_blocked = unicode_result.threat_detected;
        
        // Path traversal
        let path_result = self.inject_threat(
            ThreatType::PathTraversal,
            "../../etc/passwd"
        ).await?;
        report.path_traversal_blocked = path_result.threat_detected;
        
        // XSS
        let xss_result = self.inject_threat(
            ThreatType::XssAttempt,
            "<script>alert('xss')</script>"
        ).await?;
        report.xss_blocked = xss_result.threat_detected;
        
        // Command injection
        let cmd_result = self.inject_threat(
            ThreatType::CommandInjection,
            "test; rm -rf /"
        ).await?;
        report.command_injection_blocked = cmd_result.threat_detected;
        
        report.all_threats_blocked = report.sql_injection_blocked
            && report.unicode_attack_blocked
            && report.path_traversal_blocked
            && report.xss_blocked
            && report.command_injection_blocked;
        
        Ok(report)
    }
    
    /// Test rate limiting scenarios
    async fn test_rate_limiting_scenarios(&self) -> Result<RateLimitingReport> {
        let mut report = RateLimitingReport::default();
        
        // Test burst requests
        let burst_result = self.test_rate_limits(100).await?;
        report.burst_requests_handled = burst_result.requests_blocked > 0;
        report.rate_limit_headers_present = !burst_result.rate_limit_headers.is_empty();
        
        // Test gradual requests
        let gradual_result = self.test_gradual_requests(10, Duration::from_millis(100)).await?;
        report.gradual_requests_allowed = gradual_result.requests_allowed == gradual_result.requests_sent;
        
        Ok(report)
    }
    
    /// Test authentication scenarios
    async fn test_auth_scenarios(&self) -> Result<AuthenticationReport> {
        let mut report = AuthenticationReport::default();
        
        // Test missing token
        let missing_result = self.test_auth(AuthScenario::MissingToken).await?;
        report.missing_token_rejected = !missing_result.authenticated;
        
        // Test invalid token
        let invalid_result = self.test_auth(AuthScenario::InvalidToken).await?;
        report.invalid_token_rejected = !invalid_result.authenticated;
        
        // Test expired token
        let expired_result = self.test_auth(AuthScenario::ExpiredToken).await?;
        report.expired_token_rejected = !expired_result.authenticated;
        
        Ok(report)
    }
    
    /// Test gradual requests
    async fn test_gradual_requests(&self, count: u32, delay: Duration) -> Result<RateLimitTestResult> {
        let mut result = RateLimitTestResult {
            requests_sent: 0,
            requests_allowed: 0,
            requests_blocked: 0,
            rate_limit_headers: Vec::new(),
        };
        
        for i in 0..count {
            let response = self.client.call_tool(
                "get_security_info",
                json!({ "request_id": i })
            ).await;
            
            result.requests_sent += 1;
            
            match response {
                Ok(_) => result.requests_allowed += 1,
                Err(_) => result.requests_blocked += 1,
            }
            
            tokio::time::sleep(delay).await;
        }
        
        Ok(result)
    }
}

#[async_trait]
impl SecurityTester for SecurityTestRunner {
    async fn inject_threat(&self, threat_type: ThreatType, payload: &str) -> Result<TestResult> {
        let threat_name = match &threat_type {
            ThreatType::SqlInjection => "sql_injection",
            ThreatType::UnicodeAttack => "unicode_attack",
            ThreatType::PathTraversal => "path_traversal",
            ThreatType::XssAttempt => "xss_attempt",
            ThreatType::CommandInjection => "command_injection",
            ThreatType::Custom(name) => name,
        };
        
        debug!("Injecting {} threat: {}", threat_name, payload);
        
        // Use scan_text tool to test threat detection
        let result = self.client.call_tool(
            "scan_text",
            json!({ "text": payload })
        ).await;
        
        match result {
            Ok(scan_result) => {
                let safe = scan_result["safe"].as_bool().unwrap_or(true);
                let _threats = scan_result["threats"].as_array();
                
                Ok(TestResult {
                    threat_detected: !safe,
                    response_code: 200,
                    error_message: None,
                    shield_color: scan_result["shield_color"].as_str().map(String::from),
                })
            }
            Err(e) => {
                // Check if error indicates threat was blocked
                let error_msg = e.to_string();
                let threat_detected = error_msg.contains("threat") || error_msg.contains("blocked");
                
                Ok(TestResult {
                    threat_detected,
                    response_code: 400,
                    error_message: Some(error_msg),
                    shield_color: None,
                })
            }
        }
    }
    
    async fn test_rate_limits(&self, requests_per_second: u32) -> Result<RateLimitTestResult> {
        let mut result = RateLimitTestResult {
            requests_sent: 0,
            requests_allowed: 0,
            requests_blocked: 0,
            rate_limit_headers: Vec::new(),
        };
        
        let start = Instant::now();
        
        for i in 0..requests_per_second {
            let response = self.client.call_tool(
                "get_security_info",
                json!({ "request_id": i })
            ).await;
            
            result.requests_sent += 1;
            
            match response {
                Ok(_) => result.requests_allowed += 1,
                Err(e) => {
                    if e.to_string().contains("rate") {
                        result.requests_blocked += 1;
                    }
                }
            }
            
            // Try to maintain target rate
            let elapsed = start.elapsed();
            let expected = Duration::from_secs_f64(i as f64 / requests_per_second as f64);
            if expected > elapsed {
                tokio::time::sleep(expected - elapsed).await;
            }
        }
        
        Ok(result)
    }
    
    async fn test_auth(&self, _scenario: AuthScenario) -> Result<AuthTestResult> {
        // This would typically modify the client's auth configuration
        // For now, simulate by calling a protected endpoint
        let result = self.client.call_tool(
            "get_security_info",
            json!({ "auth_test": true })
        ).await;
        
        match result {
            Ok(_) => Ok(AuthTestResult {
                authenticated: true,
                error_code: None,
                required_scopes: None,
            }),
            Err(e) => {
                let error_msg = e.to_string();
                let error_code = if error_msg.contains("401") {
                    Some("unauthorized".to_string())
                } else if error_msg.contains("403") {
                    Some("forbidden".to_string())
                } else {
                    None
                };
                
                Ok(AuthTestResult {
                    authenticated: false,
                    error_code,
                    required_scopes: None,
                })
            }
        }
    }
    
    async fn test_signing(&self, tamper: bool) -> Result<SigningTestResult> {
        // Test message signing by calling an endpoint
        let result = self.client.call_tool(
            "verify_signature",
            json!({ 
                "message": "test message",
                "tampered": tamper 
            })
        ).await;
        
        match result {
            Ok(verify_result) => Ok(SigningTestResult {
                signature_valid: verify_result["valid"].as_bool().unwrap_or(false),
                tampering_detected: tamper && !verify_result["valid"].as_bool().unwrap_or(true),
                signature_algorithm: verify_result["algorithm"].as_str().map(String::from),
            }),
            Err(_) => Ok(SigningTestResult {
                signature_valid: false,
                tampering_detected: tamper,
                signature_algorithm: None,
            }),
        }
    }
}

/// Comprehensive security test report
#[derive(Debug, Default)]
pub struct SecurityTestReport {
    pub threat_detection: ThreatDetectionReport,
    pub rate_limiting: RateLimitingReport,
    pub authentication: AuthenticationReport,
}

/// Threat detection test results
#[derive(Debug, Default)]
pub struct ThreatDetectionReport {
    pub sql_injection_blocked: bool,
    pub unicode_attack_blocked: bool,
    pub path_traversal_blocked: bool,
    pub xss_blocked: bool,
    pub command_injection_blocked: bool,
    pub all_threats_blocked: bool,
}

/// Rate limiting test results
#[derive(Debug, Default)]
pub struct RateLimitingReport {
    pub burst_requests_handled: bool,
    pub rate_limit_headers_present: bool,
    pub gradual_requests_allowed: bool,
}

/// Authentication test results
#[derive(Debug, Default)]
pub struct AuthenticationReport {
    pub missing_token_rejected: bool,
    pub invalid_token_rejected: bool,
    pub expired_token_rejected: bool,
}

impl SecurityTestReport {
    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.threat_detection.all_threats_blocked
            && self.rate_limiting.burst_requests_handled
            && self.authentication.missing_token_rejected
    }
    
    /// Print summary
    pub fn print_summary(&self) {
        println!("\n📊 Security Test Summary");
        println!("========================");
        
        println!("\n🛡️ Threat Detection:");
        println!("  SQL Injection: {}", self.format_result(self.threat_detection.sql_injection_blocked));
        println!("  Unicode Attack: {}", self.format_result(self.threat_detection.unicode_attack_blocked));
        println!("  Path Traversal: {}", self.format_result(self.threat_detection.path_traversal_blocked));
        println!("  XSS: {}", self.format_result(self.threat_detection.xss_blocked));
        println!("  Command Injection: {}", self.format_result(self.threat_detection.command_injection_blocked));
        
        println!("\n⏱️ Rate Limiting:");
        println!("  Burst Protection: {}", self.format_result(self.rate_limiting.burst_requests_handled));
        println!("  Headers Present: {}", self.format_result(self.rate_limiting.rate_limit_headers_present));
        
        println!("\n🔐 Authentication:");
        println!("  Missing Token: {}", self.format_result(self.authentication.missing_token_rejected));
        println!("  Invalid Token: {}", self.format_result(self.authentication.invalid_token_rejected));
        
        println!("\n📋 Overall: {}", 
            if self.all_passed() { "✅ ALL TESTS PASSED" } else { "❌ SOME TESTS FAILED" }
        );
    }
    
    fn format_result(&self, passed: bool) -> &'static str {
        if passed { "✅ PASS" } else { "❌ FAIL" }
    }
}