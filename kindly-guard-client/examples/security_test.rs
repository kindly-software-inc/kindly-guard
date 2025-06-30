//! Comprehensive security testing example

use anyhow::Result;
use kindly_guard_client::{
    ClientConfiguration, TestClient, SecurityTestRunner,
    ThreatType, AuthScenario,
};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::io::Write;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("🔒 Starting KindlyGuard security test suite");

    // Test both standard and enhanced modes
    for enhanced in [false, true] {
        let mode = if enhanced { "ENHANCED" } else { "STANDARD" };
        info!("\n{}", "=".repeat(50));
        info!("Testing {} mode", mode);
        info!("{}\n", "=".repeat(50));

        // Create config file for the mode
        let config_content = format!(
            r#"[event_processor]
enabled = {}

[shield]
enabled = false

[server]
stdio = true
"#,
            enhanced
        );
        
        let config_dir = tempfile::tempdir()?;
        let config_path = config_dir.path().join("config.toml");
        std::fs::write(&config_path, config_content)?;
        
        // Create client configuration
        let client_config = ClientConfiguration {
            endpoint: "stdio".to_string(),
            auth_token: Some("test-token-12345".to_string()),
            enable_signing: true,
            client_id: "security-tester".to_string(),
            signing_key: Some("test-signing-key".to_string()),
        };

        // Path to server
        let server_path = std::env::var("KINDLY_GUARD_SERVER")
            .unwrap_or_else(|_| "../target/release/kindly-guard".to_string());

        // Create client with custom config
        std::env::set_var("KINDLY_GUARD_CONFIG", config_path.to_str().unwrap());
        let mut client = TestClient::stdio(&server_path, client_config).await?;
        client.connect().await?;

        // Check if enhanced mode is active
        let capabilities = client.get_capabilities().await?;
        info!("Enhanced mode active: {}", capabilities.security_features.enhanced_mode);

        // Create security test runner
        let test_runner = SecurityTestRunner::new(Arc::new(client));

        // Run specific threat tests
        info!("\n🛡️ Testing threat detection...");
        
        // SQL Injection
        let sql_threat = test_runner.inject_threat(
            ThreatType::SqlInjection,
            "SELECT * FROM users WHERE id = '1' OR '1'='1'"
        ).await?;
        info!("SQL Injection - Detected: {}, Shield: {:?}", 
            sql_threat.threat_detected, 
            sql_threat.shield_color);

        // Unicode attack
        let unicode_threat = test_runner.inject_threat(
            ThreatType::UnicodeAttack,
            "Normal\u{202E}Reversed"
        ).await?;
        info!("Unicode Attack - Detected: {}", unicode_threat.threat_detected);

        // Custom threat
        let custom_threat = test_runner.inject_threat(
            ThreatType::Custom("buffer_overflow".to_string()),
            &"A".repeat(10000)
        ).await?;
        info!("Buffer Overflow - Detected: {}", custom_threat.threat_detected);

        // Test rate limiting
        info!("\n⏱️ Testing rate limiting...");
        let rate_result = test_runner.test_rate_limits(50).await?;
        info!("Rate limiting - Sent: {}, Allowed: {}, Blocked: {}", 
            rate_result.requests_sent,
            rate_result.requests_allowed,
            rate_result.requests_blocked);

        // Test authentication scenarios
        info!("\n🔐 Testing authentication...");
        
        let auth_scenarios = vec![
            (AuthScenario::ValidToken, "Valid Token"),
            (AuthScenario::ExpiredToken, "Expired Token"),
            (AuthScenario::MissingToken, "Missing Token"),
        ];

        for (scenario, name) in auth_scenarios {
            let auth_result = test_runner.test_auth(scenario).await?;
            info!("{} - Authenticated: {}, Error: {:?}", 
                name,
                auth_result.authenticated,
                auth_result.error_code);
        }

        // Run comprehensive test suite
        info!("\n📊 Running comprehensive security test suite...");
        let report = test_runner.run_all_tests().await?;
        report.print_summary();

        // Performance comparison
        if enhanced {
            info!("\n⚡ Performance notes:");
            info!("  - Event processing should be significantly faster");
            info!("  - Shield should show purple when threats detected");
        }
    }

    info!("\n✅ Security testing completed");
    Ok(())
}