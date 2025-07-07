//! Retention policy for quarantine

use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};

/// Retention policy for quarantined items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Compress items older than this duration
    pub compress_after: Duration,
    
    /// Delete items older than this duration
    pub delete_after: Duration,
    
    /// Maximum storage size before oldest items are removed
    pub max_total_size: u64,
}

impl RetentionPolicy {
    /// Check if an item should be compressed
    pub fn should_compress(&self, quarantined_at: SystemTime) -> bool {
        if let Ok(elapsed) = quarantined_at.elapsed() {
            elapsed > self.compress_after
        } else {
            false
        }
    }
    
    /// Check if an item should be deleted
    pub fn should_delete(&self, quarantined_at: SystemTime) -> bool {
        if let Ok(elapsed) = quarantined_at.elapsed() {
            elapsed > self.delete_after
        } else {
            false
        }
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            compress_after: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            delete_after: Duration::from_secs(90 * 24 * 60 * 60),   // 90 days
            max_total_size: 1000 * 1024 * 1024, // 1GB
        }
    }
}