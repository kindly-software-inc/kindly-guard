//! Quarantine system for safely isolating threats
//! 
//! This module implements the "Kind to you, tough on threats" philosophy by
//! providing a safe space to store original content before neutralization.
//! Features include:
//! - Encrypted storage using ChaCha20Poly1305
//! - Automatic compression after 30 days
//! - Automatic deletion after 90 days
//! - Metadata tracking for audit trail

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use tokio::fs;
use tokio::sync::RwLock;
use uuid::Uuid;
use flate2::Compression;
use flate2::write::{GzEncoder, GzDecoder};
use std::io::Write;

pub mod config;
pub mod manager;
pub mod entry;
pub mod retention;

pub use config::QuarantineConfig;
pub use manager::QuarantineManager;
pub use entry::QuarantineEntry;
pub use retention::RetentionPolicy;

/// Trait for quarantine operations
#[async_trait::async_trait]
pub trait Quarantine: Send + Sync {
    /// Store content in quarantine
    async fn quarantine(
        &self,
        content: &str,
        threat_info: ThreatInfo,
        source: Option<String>,
    ) -> Result<String>; // Returns quarantine ID
    
    /// Retrieve quarantined content
    async fn retrieve(&self, id: &str) -> Result<Option<QuarantineEntry>>;
    
    /// List quarantined items
    async fn list(&self, filter: QuarantineFilter) -> Result<Vec<QuarantineEntry>>;
    
    /// Delete quarantined item
    async fn delete(&self, id: &str) -> Result<bool>;
    
    /// Apply retention policy
    async fn apply_retention(&self) -> Result<RetentionStats>;
}

/// Information about the threat that caused quarantine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub threat_type: String,
    pub severity: String,
    pub description: String,
    pub location: Option<String>,
    pub timestamp: SystemTime,
}

/// Filter for listing quarantine entries
#[derive(Debug, Default)]
pub struct QuarantineFilter {
    pub start_time: Option<SystemTime>,
    pub end_time: Option<SystemTime>,
    pub threat_type: Option<String>,
    pub severity: Option<String>,
    pub source: Option<String>,
}

/// Statistics from retention policy application
#[derive(Debug, Serialize)]
pub struct RetentionStats {
    pub compressed: usize,
    pub deleted: usize,
    pub errors: usize,
}

/// Create a quarantine manager based on configuration
pub fn create_quarantine(config: &QuarantineConfig) -> Arc<dyn Quarantine> {
    Arc::new(QuarantineManager::new(config.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_quarantine_basic() {
        let temp_dir = TempDir::new().unwrap();
        let config = QuarantineConfig {
            base_path: temp_dir.path().to_path_buf(),
            encrypt: true,
            compress_after_days: 30,
            delete_after_days: 90,
            max_size_mb: 1000,
        };
        
        let quarantine = create_quarantine(&config);
        
        let threat_info = ThreatInfo {
            threat_type: "sql_injection".to_string(),
            severity: "high".to_string(),
            description: "SQL injection detected".to_string(),
            location: Some("line 42".to_string()),
            timestamp: SystemTime::now(),
        };
        
        // Quarantine some content
        let id = quarantine.quarantine(
            "SELECT * FROM users WHERE id='1' OR '1'='1'",
            threat_info,
            Some("test.sql".to_string()),
        ).await.unwrap();
        
        // Retrieve it back
        let entry = quarantine.retrieve(&id).await.unwrap().unwrap();
        assert_eq!(entry.original_content, "SELECT * FROM users WHERE id='1' OR '1'='1'");
        assert_eq!(entry.threat_info.threat_type, "sql_injection");
    }
}