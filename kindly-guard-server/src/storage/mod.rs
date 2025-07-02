//! Storage abstraction layer for persistence
//!
//! This module provides trait-based storage abstractions that allow
//! `KindlyGuard` to persist security events, rate limit states, and
//! correlation data across restarts.

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "enhanced")]
pub mod enhanced;
pub mod memory;

// Re-exports
#[cfg(feature = "enhanced")]
pub use enhanced::EnhancedStorage;
pub use memory::InMemoryStorage;

use crate::traits::{RateLimitKey, SecurityEvent};

/// Unique identifier for stored events
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub String);

/// Unique identifier for snapshots
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotId(pub String);

/// Filter for querying events
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilter {
    /// Filter by client ID
    pub client_id: Option<String>,
    /// Filter by event type
    pub event_type: Option<String>,
    /// Events after this time
    pub from_time: Option<DateTime<Utc>>,
    /// Events before this time
    pub to_time: Option<DateTime<Utc>>,
    /// Maximum number of results
    pub limit: Option<usize>,
    /// Threat severity filter
    pub min_severity: Option<String>,
}

/// Rate limit state that needs persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitState {
    /// Current token count
    pub tokens: f64,
    /// Last refill time
    pub last_refill: DateTime<Utc>,
    /// Number of requests
    pub request_count: u64,
    /// Active penalty multiplier
    pub penalty_multiplier: f64,
}

/// Correlation state for pattern detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationState {
    /// Active correlation windows
    pub windows: Vec<CorrelationWindow>,
    /// Detected patterns
    pub patterns: Vec<DetectedPattern>,
    /// Last update time
    pub last_update: DateTime<Utc>,
}

/// Time window for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationWindow {
    pub id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub events: Vec<EventId>,
}

/// Detected threat pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPattern {
    pub pattern_type: String,
    pub confidence: f64,
    pub events: Vec<EventId>,
    pub detected_at: DateTime<Utc>,
}

/// Storage provider trait for persistence
#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Store a security event
    async fn store_event(&self, event: &SecurityEvent) -> Result<EventId>;

    /// Retrieve an event by ID
    async fn get_event(&self, id: &EventId) -> Result<Option<SecurityEvent>>;

    /// Query events with filters
    async fn query_events(&self, filter: EventFilter) -> Result<Vec<SecurityEvent>>;

    /// Store rate limit state
    async fn store_rate_limit_state(
        &self,
        key: &RateLimitKey,
        state: &RateLimitState,
    ) -> Result<()>;

    /// Get rate limit state
    async fn get_rate_limit_state(&self, key: &RateLimitKey) -> Result<Option<RateLimitState>>;

    /// Clear old rate limit states
    async fn cleanup_rate_limit_states(&self, older_than: Duration) -> Result<u64>;

    /// Store correlation state
    async fn store_correlation_state(
        &self,
        client_id: &str,
        state: &CorrelationState,
    ) -> Result<()>;

    /// Get correlation state
    async fn get_correlation_state(&self, client_id: &str) -> Result<Option<CorrelationState>>;

    /// Create a snapshot
    async fn create_snapshot(&self) -> Result<SnapshotId>;

    /// List available snapshots
    async fn list_snapshots(&self) -> Result<Vec<(SnapshotId, DateTime<Utc>)>>;

    /// Restore from snapshot
    async fn restore_snapshot(&self, id: &SnapshotId) -> Result<()>;

    /// Delete a snapshot
    async fn delete_snapshot(&self, id: &SnapshotId) -> Result<()>;

    /// Get storage statistics
    async fn get_stats(&self) -> Result<StorageStats>;

    /// Compact/optimize storage
    async fn compact(&self) -> Result<()>;
}

/// Extended storage with archival support
#[async_trait]
pub trait ArchivalStorage: StorageProvider {
    /// Archive old events
    async fn archive_events(&self, older_than: Duration) -> Result<u64>;

    /// Query archived events
    async fn query_archived_events(&self, filter: EventFilter) -> Result<Vec<SecurityEvent>>;

    /// Restore events from archive
    async fn restore_from_archive(&self, filter: EventFilter) -> Result<u64>;

    /// Get archive statistics
    async fn get_archive_stats(&self) -> Result<ArchiveStats>;
}

/// Storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total events stored
    pub event_count: u64,
    /// Total storage size in bytes
    pub total_size: u64,
    /// Number of rate limit entries
    pub rate_limit_entries: u64,
    /// Number of correlation states
    pub correlation_states: u64,
    /// Storage type identifier
    pub storage_type: String,
    /// Additional metadata
    pub metadata: serde_json::Value,
}

/// Archive statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveStats {
    /// Total archived events
    pub archived_events: u64,
    /// Archive size in bytes
    pub archive_size: u64,
    /// Oldest archived event
    pub oldest_event: Option<DateTime<Utc>>,
    /// Newest archived event
    pub newest_event: Option<DateTime<Utc>>,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Enable persistence
    pub enabled: bool,
    /// Storage type
    pub storage_type: StorageType,
    /// Data directory (for file-based storage)
    pub data_dir: Option<String>,
    /// Connection string (for remote storage)
    pub connection_string: Option<String>,
    /// Retention period in days
    pub retention_days: u32,
    /// Archive older than days
    pub archive_after_days: Option<u32>,
    /// Maximum storage size in MB
    pub max_storage_mb: Option<u64>,
    /// Enable compression
    pub compression: bool,
    /// Enable encryption at rest
    pub encryption_at_rest: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            storage_type: StorageType::Memory,
            data_dir: None,
            connection_string: None,
            retention_days: 30,
            archive_after_days: None,
            max_storage_mb: Some(1024), // 1GB default
            compression: true,
            encryption_at_rest: false,
        }
    }
}

/// Storage type selection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageType {
    /// In-memory storage (non-persistent)
    Memory,
    /// File-based storage
    File,
    /// `RocksDB` embedded database
    RocksDb,
    /// Redis for distributed cache
    Redis,
    /// `PostgreSQL` for structured queries
    Postgres,
    /// S3-compatible object storage
    S3,
    /// Enhanced storage with performance optimizations
    #[cfg(feature = "enhanced")]
    Enhanced,
}

/// Factory for creating storage providers
pub trait StorageProviderFactory: Send + Sync {
    /// Create a storage provider from configuration
    fn create(&self, config: &StorageConfig) -> Result<Arc<dyn StorageProvider>>;
}

/// Default storage factory
pub struct DefaultStorageFactory;

impl StorageProviderFactory for DefaultStorageFactory {
    fn create(&self, config: &StorageConfig) -> Result<Arc<dyn StorageProvider>> {
        match config.storage_type {
            StorageType::Memory => Ok(Arc::new(InMemoryStorage::new())),
            #[cfg(feature = "enhanced")]
            StorageType::Enhanced => Ok(Arc::new(EnhancedStorage::new(config.clone())?)),
            _ => Ok(Arc::new(InMemoryStorage::new())), // Fallback to memory for now
        }
    }
}
