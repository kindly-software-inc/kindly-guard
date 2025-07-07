//! Quarantine configuration

use std::path::PathBuf;
use serde::{Deserialize, Serialize};

/// Configuration for the quarantine system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    /// Base directory for quarantine storage
    pub base_path: PathBuf,
    
    /// Whether to encrypt quarantined content
    #[serde(default = "default_encrypt")]
    pub encrypt: bool,
    
    /// Days after which to compress entries
    #[serde(default = "default_compress_days")]
    pub compress_after_days: u32,
    
    /// Days after which to delete entries
    #[serde(default = "default_delete_days")]
    pub delete_after_days: u32,
    
    /// Maximum total size in MB
    #[serde(default = "default_max_size")]
    pub max_size_mb: u64,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from(".kindlyguard/quarantine"),
            encrypt: true,
            compress_after_days: 30,
            delete_after_days: 90,
            max_size_mb: 1000,
        }
    }
}

fn default_encrypt() -> bool { true }
fn default_compress_days() -> u32 { 30 }
fn default_delete_days() -> u32 { 90 }
fn default_max_size() -> u64 { 1000 }