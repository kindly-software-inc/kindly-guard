//! Integration tests for the quarantine system

use kindly_guard_server::quarantine::{
    create_quarantine, QuarantineConfig, QuarantineFilter, ThreatInfo,
};
use tempfile::TempDir;
use std::time::{Duration, SystemTime};

#[tokio::test]
async fn test_quarantine_lifecycle() {
    let temp_dir = TempDir::new().unwrap();
    let config = QuarantineConfig {
        base_path: temp_dir.path().to_path_buf(),
        encrypt: true,
        compress_after_days: 30,
        delete_after_days: 90,
        max_size_mb: 1000,
    };
    
    let quarantine = create_quarantine(&config);
    
    // Test 1: Quarantine malicious SQL
    let sql_threat = ThreatInfo {
        threat_type: "sql_injection".to_string(),
        severity: "high".to_string(),
        description: "SQL injection attempt detected".to_string(),
        location: Some("query parameter".to_string()),
        timestamp: SystemTime::now(),
    };
    
    let malicious_sql = "SELECT * FROM users WHERE id='1' OR '1'='1'";
    let id1 = quarantine.quarantine(
        malicious_sql,
        sql_threat,
        Some("api_endpoint.rs".to_string()),
    ).await.unwrap();
    
    // Test 2: Quarantine XSS attack
    let xss_threat = ThreatInfo {
        threat_type: "xss".to_string(),
        severity: "medium".to_string(),
        description: "Cross-site scripting attempt".to_string(),
        location: Some("user input field".to_string()),
        timestamp: SystemTime::now(),
    };
    
    let xss_content = "<script>alert('XSS')</script>";
    let id2 = quarantine.quarantine(
        xss_content,
        xss_threat,
        Some("comment_form.rs".to_string()),
    ).await.unwrap();
    
    // Test 3: Retrieve quarantined content
    let entry1 = quarantine.retrieve(&id1).await.unwrap().unwrap();
    assert_eq!(entry1.original_content, malicious_sql);
    assert_eq!(entry1.threat_info.threat_type, "sql_injection");
    assert_eq!(entry1.source, Some("api_endpoint.rs".to_string()));
    
    let entry2 = quarantine.retrieve(&id2).await.unwrap().unwrap();
    assert_eq!(entry2.original_content, xss_content);
    assert_eq!(entry2.threat_info.threat_type, "xss");
    
    // Test 4: List with filters
    let all_entries = quarantine.list(QuarantineFilter::default()).await.unwrap();
    assert_eq!(all_entries.len(), 2);
    
    let sql_only = quarantine.list(QuarantineFilter {
        threat_type: Some("sql_injection".to_string()),
        ..Default::default()
    }).await.unwrap();
    assert_eq!(sql_only.len(), 1);
    assert_eq!(sql_only[0].id, id1);
    
    // Test 5: Delete entry
    assert!(quarantine.delete(&id2).await.unwrap());
    assert!(quarantine.retrieve(&id2).await.unwrap().is_none());
    
    // Test 6: Apply retention (should do nothing since entries are new)
    let stats = quarantine.apply_retention().await.unwrap();
    assert_eq!(stats.compressed, 0);
    assert_eq!(stats.deleted, 0);
    assert_eq!(stats.errors, 0);
}

#[tokio::test]
async fn test_quarantine_encryption() {
    let temp_dir = TempDir::new().unwrap();
    
    // Test with encryption enabled
    let config_encrypted = QuarantineConfig {
        base_path: temp_dir.path().join("encrypted"),
        encrypt: true,
        ..Default::default()
    };
    
    let quarantine_encrypted = create_quarantine(&config_encrypted);
    
    let threat = ThreatInfo {
        threat_type: "test".to_string(),
        severity: "low".to_string(),
        description: "Test threat".to_string(),
        location: None,
        timestamp: SystemTime::now(),
    };
    
    let content = "Sensitive data that should be encrypted";
    let id = quarantine_encrypted.quarantine(content, threat.clone(), None).await.unwrap();
    
    // Verify the file on disk is encrypted (not readable as plaintext)
    let file_path = config_encrypted.base_path.join(&id);
    let raw_data = tokio::fs::read(&file_path).await.unwrap();
    let raw_string = String::from_utf8(raw_data.clone());
    
    // If encryption is working, the raw file should not contain the plaintext
    assert!(raw_string.is_err() || !raw_string.unwrap().contains(content));
    
    // But we should still be able to retrieve it
    let entry = quarantine_encrypted.retrieve(&id).await.unwrap().unwrap();
    assert_eq!(entry.original_content, content);
}

#[tokio::test]
async fn test_quarantine_with_unicode_threats() {
    let temp_dir = TempDir::new().unwrap();
    let config = QuarantineConfig {
        base_path: temp_dir.path().to_path_buf(),
        encrypt: true,
        ..Default::default()
    };
    
    let quarantine = create_quarantine(&config);
    
    // Test with various Unicode threats
    let unicode_threats = vec![
        ("Hello\u{202E}World", "bidi_override", "Right-to-left override detected"),
        ("admin\u{200B}@example.com", "zero_width", "Zero-width character detected"),
        ("раураl.com", "homograph", "Cyrillic homograph detected"), // paypal with Cyrillic 'a'
    ];
    
    let mut ids = Vec::new();
    
    for (content, threat_type, description) in unicode_threats {
        let threat = ThreatInfo {
            threat_type: threat_type.to_string(),
            severity: "high".to_string(),
            description: description.to_string(),
            location: Some("user input".to_string()),
            timestamp: SystemTime::now(),
        };
        
        let id = quarantine.quarantine(content, threat, None).await.unwrap();
        ids.push((id, content));
    }
    
    // Verify all entries can be retrieved correctly
    for (id, original_content) in ids {
        let entry = quarantine.retrieve(&id).await.unwrap().unwrap();
        assert_eq!(entry.original_content, original_content);
    }
}

#[tokio::test]
async fn test_retention_policy() {
    // This test simulates old entries that should be compressed/deleted
    // In a real scenario, we'd need to mock time or wait, but for testing
    // we'll manually create entries with old timestamps
    
    let temp_dir = TempDir::new().unwrap();
    let config = QuarantineConfig {
        base_path: temp_dir.path().to_path_buf(),
        encrypt: false, // Disable for easier testing
        compress_after_days: 0, // Compress immediately for testing
        delete_after_days: 0,   // Delete immediately for testing
        max_size_mb: 1000,
    };
    
    let quarantine = create_quarantine(&config);
    
    let old_threat = ThreatInfo {
        threat_type: "old_threat".to_string(),
        severity: "low".to_string(),
        description: "Old threat for testing".to_string(),
        location: None,
        timestamp: SystemTime::now() - Duration::from_secs(100 * 24 * 60 * 60), // 100 days ago
    };
    
    let id = quarantine.quarantine("Old content", old_threat, None).await.unwrap();
    
    // Apply retention policy
    let stats = quarantine.apply_retention().await.unwrap();
    
    // With our test config, the entry should be deleted
    assert_eq!(stats.deleted, 1);
    assert!(quarantine.retrieve(&id).await.unwrap().is_none());
}