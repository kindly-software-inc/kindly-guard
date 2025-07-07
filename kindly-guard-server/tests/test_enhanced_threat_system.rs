//! Integration tests for the enhanced threat system

use kindly_guard_server::{
    cli::enhanced_commands::{ProtectionMode, EnhancedScanCommand},
    config::{Config, NeutralizationConfig, NeutralizationMode},
    messages::{MessageService, MessageType},
    neutralizer::{create_neutralizer, quarantine_aware::QuarantineAwareNeutralizer, verifying::VerifyingNeutralizer},
    quarantine::{create_quarantine, QuarantineConfig, QuarantineFilter},
    scanner::{SecurityScanner, ThreatType},
};
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test]
async fn test_auto_protection_mode_full_flow() {
    // Setup
    let temp_dir = TempDir::new().unwrap();
    let quarantine_config = QuarantineConfig {
        base_path: temp_dir.path().join("quarantine"),
        encrypt: true,
        compress_after_days: 30,
        delete_after_days: 90,
        max_size_mb: 100,
    };
    
    let mut config = Config::default();
    config.neutralization.mode = NeutralizationMode::Automatic;
    config.quarantine = Some(quarantine_config.clone());
    
    let scanner = Arc::new(SecurityScanner::new(config.scanner.clone()).unwrap());
    let quarantine = create_quarantine(&quarantine_config);
    let messages = MessageService::new();
    
    // Test content with multiple threats
    let malicious_content = r#"
        SELECT * FROM users WHERE id='1' OR '1'='1';
        <script>alert('XSS')</script>
        Hello\u{202E}World
        ../../../etc/passwd
    "#;
    
    // Step 1: Scan for threats
    let threats = scanner.scan_text(malicious_content).unwrap();
    assert!(!threats.is_empty(), "Should detect threats");
    println!("Found {} threats", threats.len());
    
    // Step 2: Show friendly protection message
    let protection_msg = messages.protection_engaged(threats.len());
    println!("{}", protection_msg.content);
    assert!(protection_msg.message_type == MessageType::ThreatNeutralized);
    
    // Step 3: Create neutralizer with quarantine and verification
    let base_neutralizer = create_neutralizer(&config.neutralization, None);
    let quarantine_neutralizer = Arc::new(
        QuarantineAwareNeutralizer::new(base_neutralizer, quarantine.clone())
    );
    let verifying_neutralizer = VerifyingNeutralizer::new(quarantine_neutralizer, scanner.clone());
    
    // Step 4: Neutralize threats
    let results = verifying_neutralizer.batch_neutralize(&threats, malicious_content).await.unwrap();
    assert!(!results.is_empty());
    
    // Step 5: Verify content was quarantined
    let quarantine_entries = quarantine.list(QuarantineFilter::default()).await.unwrap();
    assert!(!quarantine_entries.is_empty(), "Content should be quarantined");
    
    let entry = &quarantine_entries[0];
    assert_eq!(entry.original_content, malicious_content);
    assert_eq!(entry.threat_info.threat_type, "multiple");
    
    // Step 6: Verify neutralization worked
    let last_result = results.last().unwrap();
    assert!(last_result.sanitized_content.is_some());
    
    let safe_content = last_result.sanitized_content.as_ref().unwrap();
    
    // Re-scan to ensure it's safe
    let remaining_threats = scanner.scan_text(safe_content).unwrap();
    assert!(
        remaining_threats.is_empty() || 
        remaining_threats.iter().all(|t| t.severity == kindly_guard_server::scanner::Severity::Low),
        "Neutralized content should be safe"
    );
    
    // Step 7: Show success message
    let success_msg = messages.celebrate_success("All threats neutralized");
    println!("{}", success_msg.content);
}

#[tokio::test]
async fn test_interactive_mode_simulation() {
    let temp_dir = TempDir::new().unwrap();
    let quarantine_config = QuarantineConfig {
        base_path: temp_dir.path().join("quarantine"),
        encrypt: false,
        ..Default::default()
    };
    
    let mut config = Config::default();
    config.neutralization.mode = NeutralizationMode::Interactive;
    config.quarantine = Some(quarantine_config.clone());
    
    let scanner = Arc::new(SecurityScanner::new(config.scanner.clone()).unwrap());
    let quarantine = create_quarantine(&quarantine_config);
    let messages = MessageService::new();
    let neutralizer = create_neutralizer(&config.neutralization, None);
    
    // Test content
    let content = "<script>alert('xss')</script> Normal text";
    
    // Scan
    let threats = scanner.scan_text(content).unwrap();
    assert_eq!(threats.len(), 1);
    
    // Simulate interactive prompt
    let prompt = messages.interactive_prompt(&threats[0].threat_type.to_string());
    println!("Interactive: {}", prompt.content);
    assert!(prompt.content.contains("?") || prompt.content.contains("neutralize"));
    
    // Simulate user choosing to neutralize
    let result = neutralizer.neutralize(&threats[0], content).await.unwrap();
    assert!(result.sanitized_content.is_some());
    
    // Quarantine original
    let threat_info = kindly_guard_server::quarantine::ThreatInfo {
        threat_type: threats[0].threat_type.to_string(),
        severity: threats[0].severity.to_string(),
        description: "User chose to neutralize".to_string(),
        location: None,
        timestamp: std::time::SystemTime::now(),
    };
    
    let quarantine_id = quarantine.quarantine(content, threat_info, None).await.unwrap();
    assert!(!quarantine_id.is_empty());
}

#[tokio::test]
async fn test_report_only_mode() {
    let config = Config::default();
    let scanner = Arc::new(SecurityScanner::new(config.scanner.clone()).unwrap());
    let messages = MessageService::new();
    
    // Test content with obvious threat
    let content = "'; DROP TABLE users; --";
    
    // Scan
    let threats = scanner.scan_text(content).unwrap();
    assert!(!threats.is_empty());
    
    // In report-only mode, we just display threats
    println!("Report-only mode:");
    for (i, threat) in threats.iter().enumerate() {
        println!("{}. {} - {}", i + 1, threat.threat_type, threat.severity);
        println!("   {}", threat.description);
    }
    
    // No neutralization or quarantine happens
    // Content remains unchanged
}

#[tokio::test]
async fn test_quarantine_encryption_and_retention() {
    let temp_dir = TempDir::new().unwrap();
    let quarantine_config = QuarantineConfig {
        base_path: temp_dir.path().join("quarantine"),
        encrypt: true,
        compress_after_days: 0, // Compress immediately for testing
        delete_after_days: 0,   // Delete immediately for testing
        max_size_mb: 10,
    };
    
    let quarantine = create_quarantine(&quarantine_config);
    
    // Quarantine sensitive content
    let sensitive_content = "Password: super_secret_123!";
    let threat_info = kindly_guard_server::quarantine::ThreatInfo {
        threat_type: "credential_exposure".to_string(),
        severity: "critical".to_string(),
        description: "Exposed credentials detected".to_string(),
        location: None,
        timestamp: std::time::SystemTime::now(),
    };
    
    let id = quarantine.quarantine(sensitive_content, threat_info, None).await.unwrap();
    
    // Verify file is encrypted on disk
    let file_path = quarantine_config.base_path.join(&id);
    if file_path.exists() {
        let raw_data = tokio::fs::read(&file_path).await.unwrap();
        let raw_str = String::from_utf8(raw_data.clone());
        
        // Should not be readable as plaintext
        assert!(
            raw_str.is_err() || !raw_str.unwrap().contains("super_secret_123"),
            "Quarantine file should be encrypted"
        );
    }
    
    // But we can still retrieve it
    let entry = quarantine.retrieve(&id).await.unwrap().unwrap();
    assert_eq!(entry.original_content, sensitive_content);
    
    // Apply retention policy
    let stats = quarantine.apply_retention().await.unwrap();
    println!("Retention stats: compressed={}, deleted={}", stats.compressed, stats.deleted);
    
    // With our test config, it should be deleted
    assert!(quarantine.retrieve(&id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_message_personality_adaptation() {
    let messages = MessageService::new();
    
    // Test different message types
    let welcome = messages.welcome(Some("Alice"));
    assert!(welcome.content.contains("Alice"));
    
    let all_clear = messages.all_clear();
    assert!(all_clear.content.contains("clean") || all_clear.content.contains("safe"));
    
    let protection = messages.protection_engaged(5);
    assert!(protection.content.contains("5") || protection.content.contains("protect"));
    
    let success = messages.celebrate_success("First scan completed");
    assert!(success.message_type == MessageType::SuccessCelebration);
    
    // Messages should be friendly and encouraging
    for msg in [welcome, all_clear, protection, success] {
        let formatted = msg.format(true, true); // with color and emoji
        println!("Message: {}", formatted);
        
        // Should contain positive language
        let positive_words = ["safe", "protect", "success", "great", "good", "secure"];
        let has_positive = positive_words.iter().any(|word| 
            msg.content.to_lowercase().contains(word)
        );
        assert!(has_positive, "Messages should be positive and encouraging");
    }
}