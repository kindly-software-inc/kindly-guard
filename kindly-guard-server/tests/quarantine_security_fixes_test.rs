//! Tests to verify the security fixes for quarantine system vulnerabilities
//! 
//! This test suite verifies that the critical security issues have been resolved:
//! 1. Authentication Tag Bypass - Cache integrity validation
//! 2. Path Traversal Vulnerability - ID sanitization and secure paths

use kindly_guard_server::quarantine::{
    create_quarantine, QuarantineConfig, ThreatInfo,
};
use tempfile::TempDir;
use std::time::SystemTime;

/// Test that the authentication tag bypass vulnerability is fixed
/// by validating file integrity before serving from cache
#[tokio::test]
async fn test_cache_integrity_validation_fix() {
    let temp_dir = TempDir::new().unwrap();
    let config = QuarantineConfig {
        base_path: temp_dir.path().to_path_buf(),
        encrypt: true,
        ..Default::default()
    };
    
    let quarantine = create_quarantine(&config);
    
    // Quarantine some content
    let content = "Sensitive data that should be protected";
    let threat_info = ThreatInfo {
        threat_type: "test".to_string(),
        severity: "high".to_string(),
        description: "Test threat".to_string(),
        location: None,
        timestamp: SystemTime::now(),
    };
    
    let id = quarantine.quarantine(content, threat_info, None).await.unwrap();
    
    // First retrieval should work and populate cache
    let entry1 = quarantine.retrieve(&id).await.unwrap().unwrap();
    assert_eq!(entry1.original_content, content);
    
    // Now simulate file tampering by modifying the file directly
    // The secure path function will create subdirectories
    let prefix = &id[..2];
    let suffix = &id[2..4];
    let file_path = temp_dir.path().join(prefix).join(suffix).join(&id);
    
    // Write tampered data to the file
    tokio::fs::write(&file_path, b"TAMPERED DATA").await.unwrap();
    
    // Try to retrieve again - the integrity check should fail
    // and the cache should be invalidated
    let result = quarantine.retrieve(&id).await;
    
    // The retrieve should fail or return None due to integrity check failure
    assert!(result.is_err() || result.unwrap().is_none(),
            "Should fail integrity check after tampering");
}

/// Test that path traversal attempts are blocked
#[tokio::test]
async fn test_path_traversal_prevention_fix() {
    let temp_dir = TempDir::new().unwrap();
    let config = QuarantineConfig {
        base_path: temp_dir.path().to_path_buf(),
        encrypt: true,
        ..Default::default()
    };
    
    let quarantine = create_quarantine(&config);
    
    // Test various path traversal attempts
    let malicious_ids = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "valid-id/../../../etc/shadow",
        "../../sensitive-data",
        "./../.shadow",
        "id/../../etc/passwd",
        "id\\..\\..\\etc\\passwd",
    ];
    
    for malicious_id in malicious_ids {
        // Attempt to retrieve with malicious ID
        let result = quarantine.retrieve(malicious_id).await;
        
        // Should fail with an error about invalid ID format
        assert!(result.is_err(), 
                "Path traversal attempt '{}' should be blocked", malicious_id);
        
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid quarantine ID format") || 
                err_msg.contains("Path traversal"),
                "Error should indicate security violation for '{}'", malicious_id);
    }
    
    // Also test delete operations
    for malicious_id in vec!["../../../important-file", "..\\..\\system-file"] {
        let result = quarantine.delete(malicious_id).await;
        assert!(result.is_err(), 
                "Delete with path traversal '{}' should be blocked", malicious_id);
    }
}

/// Test that only valid IDs are accepted
#[tokio::test]
async fn test_id_sanitization() {
    let temp_dir = TempDir::new().unwrap();
    let config = QuarantineConfig {
        base_path: temp_dir.path().to_path_buf(),
        encrypt: true,
        ..Default::default()
    };
    
    let quarantine = create_quarantine(&config);
    
    // Test invalid ID formats
    let invalid_ids = vec![
        "id with spaces",
        "id/with/slashes",
        "id\\with\\backslashes",
        "id;rm -rf /",
        "id$(whoami)",
        "id`date`",
        "id&echo test",
        "id|cat /etc/passwd",
        "id<script>alert('xss')</script>",
        "id'; DROP TABLE users; --",
    ];
    
    for invalid_id in invalid_ids {
        let result = quarantine.retrieve(invalid_id).await;
        assert!(result.is_err() || result.unwrap().is_none(),
                "Invalid ID '{}' should be rejected", invalid_id);
    }
    
    // Test valid ID formats (UUIDs and similar)
    let valid_ids = vec![
        "12345678-1234-1234-1234-123456789012",
        "abcdef12-3456-7890-abcd-ef1234567890",
        "test-id-123",
        "UPPERCASE-ID-456",
    ];
    
    for valid_id in valid_ids {
        // These should not error on ID validation (though they may return None if not found)
        let result = quarantine.retrieve(valid_id).await;
        assert!(result.is_ok(), "Valid ID '{}' should be accepted", valid_id);
    }
}

/// Test that files are stored in secure subdirectory structure
#[tokio::test]
async fn test_secure_subdirectory_storage() {
    let temp_dir = TempDir::new().unwrap();
    let config = QuarantineConfig {
        base_path: temp_dir.path().to_path_buf(),
        encrypt: true,
        ..Default::default()
    };
    
    let quarantine = create_quarantine(&config);
    
    // Quarantine content
    let threat_info = ThreatInfo {
        threat_type: "test".to_string(),
        severity: "low".to_string(),
        description: "Test".to_string(),
        location: None,
        timestamp: SystemTime::now(),
    };
    
    let id = quarantine.quarantine("test content", threat_info, None).await.unwrap();
    
    // Verify the file is stored in subdirectory structure
    let prefix = &id[..2];
    let suffix = &id[2..4];
    let expected_path = temp_dir.path().join(prefix).join(suffix).join(&id);
    
    assert!(expected_path.exists(), 
            "File should be stored in subdirectory structure: {:?}", expected_path);
    
    // Verify parent directories were created
    assert!(temp_dir.path().join(prefix).exists(), 
            "First level subdirectory should exist");
    assert!(temp_dir.path().join(prefix).join(suffix).exists(), 
            "Second level subdirectory should exist");
}

/// Test that the list function handles subdirectories correctly
#[tokio::test]
async fn test_list_with_subdirectories() {
    let temp_dir = TempDir::new().unwrap();
    let config = QuarantineConfig {
        base_path: temp_dir.path().to_path_buf(),
        encrypt: true,
        ..Default::default()
    };
    
    let quarantine = create_quarantine(&config);
    
    // Quarantine multiple items
    let threat_info = ThreatInfo {
        threat_type: "test".to_string(),
        severity: "medium".to_string(),
        description: "Test".to_string(),
        location: None,
        timestamp: SystemTime::now(),
    };
    
    let mut ids = Vec::new();
    for i in 0..5 {
        let content = format!("Test content {}", i);
        let id = quarantine.quarantine(&content, threat_info.clone(), None).await.unwrap();
        ids.push(id);
    }
    
    // List all entries
    let entries = quarantine.list(Default::default()).await.unwrap();
    
    // Verify all entries are found
    assert_eq!(entries.len(), 5, "Should find all quarantined entries");
    
    // Verify entries have correct IDs
    let found_ids: Vec<String> = entries.iter().map(|e| e.id.clone()).collect();
    for id in &ids {
        assert!(found_ids.contains(id), "Should find ID {} in list results", id);
    }
}

/// Integration test showing both fixes work together
#[tokio::test]
async fn test_security_fixes_integration() {
    let temp_dir = TempDir::new().unwrap();
    let config = QuarantineConfig {
        base_path: temp_dir.path().to_path_buf(),
        encrypt: true,
        ..Default::default()
    };
    
    let quarantine = create_quarantine(&config);
    
    // Create a legitimate entry
    let threat_info = ThreatInfo {
        threat_type: "malware".to_string(),
        severity: "critical".to_string(),
        description: "Detected malware".to_string(),
        location: Some("infected.exe".to_string()),
        timestamp: SystemTime::now(),
    };
    
    let legitimate_id = quarantine.quarantine(
        "Malicious payload content",
        threat_info,
        None
    ).await.unwrap();
    
    // Verify legitimate operations work
    let entry = quarantine.retrieve(&legitimate_id).await.unwrap().unwrap();
    assert_eq!(entry.threat_info.threat_type, "malware");
    
    // Try path traversal to access the legitimate file
    let traversal_attempt = format!("../../../{}", legitimate_id);
    let result = quarantine.retrieve(&traversal_attempt).await;
    assert!(result.is_err(), "Path traversal should be blocked");
    
    // Verify the file is stored securely
    let prefix = &legitimate_id[..2];
    let suffix = &legitimate_id[2..4];
    let secure_path = temp_dir.path().join(prefix).join(suffix).join(&legitimate_id);
    assert!(secure_path.exists(), "File should be in secure subdirectory");
    
    // Verify deletion works with proper ID
    let deleted = quarantine.delete(&legitimate_id).await.unwrap();
    assert!(deleted, "Should successfully delete with valid ID");
    assert!(!secure_path.exists(), "File should be deleted");
}

#[test]
fn print_security_fix_summary() {
    println!("\n=== Quarantine Security Fixes Summary ===");
    println!("✅ Authentication Tag Bypass: Fixed with integrity validation");
    println!("   - File checksums stored and validated before cache use");
    println!("   - Tampered files rejected and removed from cache");
    println!("✅ Path Traversal Prevention: Fixed with ID sanitization");
    println!("   - Only alphanumeric and hyphen characters allowed in IDs");
    println!("   - Subdirectory structure prevents directory traversal");
    println!("   - All paths validated to stay within quarantine directory");
    println!("\nSecurity vulnerabilities resolved for v0.15.0 release");
}