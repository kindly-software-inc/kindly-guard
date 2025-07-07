//! Quarantine entry structure

use super::ThreatInfo;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// A quarantined content entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Unique identifier
    pub id: String,
    
    /// Original content before neutralization
    pub original_content: String,
    
    /// Information about the threat
    pub threat_info: ThreatInfo,
    
    /// Source file or context
    pub source: Option<String>,
    
    /// When this was quarantined
    pub quarantined_at: SystemTime,
    
    /// Whether this is compressed
    pub compressed: bool,
    
    /// Size in bytes
    pub size_bytes: usize,
    
    /// Hash of original content
    pub content_hash: String,
}