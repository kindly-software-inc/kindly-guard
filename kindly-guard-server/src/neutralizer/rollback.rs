//! Rollback mechanism for neutralization operations
//!
//! Provides the ability to undo neutralization operations in case of errors
//! or when the user wants to revert changes. Maintains a history of operations
//! with configurable retention.

use anyhow::{bail, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    neutralizer::{NeutralizeAction, NeutralizeResult, ThreatNeutralizer},
    scanner::Threat,
};

/// Configuration for rollback functionality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackConfig {
    /// Enable rollback functionality
    pub enabled: bool,

    /// Maximum number of operations to keep in history
    pub max_history: usize,

    /// How long to retain rollback data (in seconds)
    pub retention_seconds: i64,

    /// Enable automatic cleanup of old entries
    pub auto_cleanup: bool,

    /// Cleanup interval in seconds
    pub cleanup_interval_seconds: u64,
}

impl Default for RollbackConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_history: 1000,
            retention_seconds: 3600, // 1 hour
            auto_cleanup: true,
            cleanup_interval_seconds: 300, // 5 minutes
        }
    }
}

/// A single rollback entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackEntry {
    /// Unique ID for this operation
    pub operation_id: String,

    /// Timestamp of the operation
    pub timestamp: DateTime<Utc>,

    /// The threat that was neutralized
    pub threat: Threat,

    /// Original content before neutralization
    pub original_content: String,

    /// Content after neutralization
    pub neutralized_content: String,

    /// The action that was taken
    pub action: NeutralizeAction,

    /// Client/session ID if available
    pub client_id: Option<String>,

    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Rollback-capable neutralizer wrapper
pub struct RollbackNeutralizer {
    inner: Arc<dyn ThreatNeutralizer>,
    config: RollbackConfig,
    history: Arc<RwLock<VecDeque<RollbackEntry>>>,
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

impl RollbackNeutralizer {
    /// Create a new rollback-capable neutralizer
    pub fn new(neutralizer: Arc<dyn ThreatNeutralizer>, config: RollbackConfig) -> Arc<Self> {
        let history = Arc::new(RwLock::new(VecDeque::with_capacity(config.max_history)));

        let cleanup_handle = if config.enabled && config.auto_cleanup {
            let history_clone = history.clone();
            let retention = config.retention_seconds;
            let interval = config.cleanup_interval_seconds;

            Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval));

                loop {
                    interval.tick().await;
                    Self::cleanup_old_entries(&history_clone, retention).await;
                }
            }))
        } else {
            None
        };

        Arc::new(Self {
            inner: neutralizer,
            config,
            history,
            cleanup_handle,
        })
    }

    /// Rollback a specific operation
    pub async fn rollback(&self, operation_id: &str) -> Result<String> {
        if !self.config.enabled {
            bail!("Rollback functionality is disabled");
        }

        let history = self.history.read().await;

        // Find the operation
        let entry = history
            .iter()
            .find(|e| e.operation_id == operation_id)
            .ok_or_else(|| anyhow::anyhow!("Operation not found in rollback history"))?;

        // Return the original content
        Ok(entry.original_content.clone())
    }

    /// Rollback the most recent operation
    pub async fn rollback_latest(&self) -> Result<String> {
        if !self.config.enabled {
            bail!("Rollback functionality is disabled");
        }

        let history = self.history.read().await;

        let entry = history
            .back()
            .ok_or_else(|| anyhow::anyhow!("No operations in rollback history"))?;

        Ok(entry.original_content.clone())
    }

    /// Get rollback history for a client
    pub async fn get_history(&self, client_id: Option<&str>) -> Vec<RollbackEntry> {
        let history = self.history.read().await;

        if let Some(client) = client_id {
            history
                .iter()
                .filter(|e| e.client_id.as_deref() == Some(client))
                .cloned()
                .collect()
        } else {
            history.iter().cloned().collect()
        }
    }

    /// Clear rollback history
    pub async fn clear_history(&self) {
        let mut history = self.history.write().await;
        history.clear();

        tracing::info!("Rollback history cleared");
    }

    /// Get a specific rollback entry
    pub async fn get_entry(&self, operation_id: &str) -> Option<RollbackEntry> {
        let history = self.history.read().await;
        history
            .iter()
            .find(|e| e.operation_id == operation_id)
            .cloned()
    }

    /// Cleanup old entries based on retention policy
    async fn cleanup_old_entries(
        history: &Arc<RwLock<VecDeque<RollbackEntry>>>,
        retention_seconds: i64,
    ) {
        let mut history = history.write().await;
        let cutoff = Utc::now() - Duration::seconds(retention_seconds);

        // Remove entries older than retention period
        let initial_len = history.len();
        history.retain(|entry| entry.timestamp > cutoff);

        let removed = initial_len - history.len();
        if removed > 0 {
            tracing::debug!("Cleaned up {} old rollback entries", removed);
        }
    }

    /// Add an entry to rollback history
    async fn add_to_history(&self, entry: RollbackEntry) {
        if !self.config.enabled {
            return;
        }

        let mut history = self.history.write().await;

        // Enforce max history size
        while history.len() >= self.config.max_history {
            history.pop_front();
        }

        history.push_back(entry);
    }

    /// Generate a unique operation ID
    fn generate_operation_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

#[async_trait]
impl ThreatNeutralizer for RollbackNeutralizer {
    async fn neutralize(&self, threat: &Threat, content: &str) -> Result<NeutralizeResult> {
        let operation_id = Self::generate_operation_id();
        let original_content = content.to_string();

        // Perform neutralization
        let result = self.inner.neutralize(threat, content).await?;

        // Store in rollback history if neutralization modified content
        if let Some(ref neutralized) = result.sanitized_content {
            if neutralized != content {
                let entry = RollbackEntry {
                    operation_id: operation_id.clone(),
                    timestamp: Utc::now(),
                    threat: threat.clone(),
                    original_content,
                    neutralized_content: neutralized.clone(),
                    action: result.action_taken,
                    client_id: None, // TODO: Get from context
                    metadata: None,
                };

                self.add_to_history(entry).await;

                tracing::debug!(
                    "Stored rollback entry {} for {} neutralization",
                    operation_id,
                    result.action_taken
                );
            }
        }

        Ok(result)
    }

    fn can_neutralize(&self, threat_type: &crate::scanner::ThreatType) -> bool {
        self.inner.can_neutralize(threat_type)
    }

    fn get_capabilities(&self) -> crate::neutralizer::NeutralizerCapabilities {
        let mut capabilities = self.inner.get_capabilities();

        // Add rollback capability
        if self.config.enabled {
            capabilities.rollback_depth = self.config.max_history;
        }

        capabilities
    }
}

impl Drop for RollbackNeutralizer {
    fn drop(&mut self) {
        // Cancel cleanup task if running
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }
    }
}

/// Rollback statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackStats {
    pub total_entries: usize,
    pub oldest_entry: Option<DateTime<Utc>>,
    pub newest_entry: Option<DateTime<Utc>>,
    pub entries_by_action: std::collections::HashMap<String, usize>,
    pub average_content_size: usize,
    pub total_storage_bytes: usize,
}

impl RollbackNeutralizer {
    /// Get rollback statistics
    pub async fn get_stats(&self) -> RollbackStats {
        let history = self.history.read().await;

        let mut entries_by_action = std::collections::HashMap::new();
        let mut total_size = 0;

        for entry in history.iter() {
            let action_str = format!("{:?}", entry.action);
            *entries_by_action.entry(action_str).or_insert(0) += 1;
            total_size += entry.original_content.len() + entry.neutralized_content.len();
        }

        let avg_size = if history.is_empty() {
            0
        } else {
            total_size / history.len()
        };

        RollbackStats {
            total_entries: history.len(),
            oldest_entry: history.front().map(|e| e.timestamp),
            newest_entry: history.back().map(|e| e.timestamp),
            entries_by_action,
            average_content_size: avg_size,
            total_storage_bytes: total_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neutralizer::standard::StandardNeutralizer;
    use crate::neutralizer::NeutralizationConfig;
    use crate::scanner::{Location, Severity, ThreatType};

    fn create_test_threat() -> Threat {
        Threat {
            threat_type: ThreatType::SqlInjection,
            severity: Severity::High,
            location: Location::Text {
                offset: 0,
                length: 10,
            },
            description: "Test threat".to_string(),
            remediation: None,
        }
    }

    #[tokio::test]
    async fn test_rollback_functionality() {
        let config = NeutralizationConfig::default();
        let neutralizer = Arc::new(StandardNeutralizer::new(config));
        let rollback_config = RollbackConfig::default();

        let rollback_neutralizer = RollbackNeutralizer::new(neutralizer, rollback_config);

        // Neutralize some content
        let threat = create_test_threat();
        let original = "SELECT * FROM users WHERE id = '1' OR '1'='1'";

        let result = rollback_neutralizer
            .neutralize(&threat, original)
            .await
            .unwrap();
        assert!(result.sanitized_content.is_some());

        // Check history
        let history = rollback_neutralizer.get_history(None).await;
        assert_eq!(history.len(), 1);

        // Rollback latest
        let rolled_back = rollback_neutralizer.rollback_latest().await.unwrap();
        assert_eq!(rolled_back, original);

        // Rollback by ID
        let entry_id = &history[0].operation_id;
        let rolled_back_by_id = rollback_neutralizer.rollback(entry_id).await.unwrap();
        assert_eq!(rolled_back_by_id, original);
    }

    #[tokio::test]
    async fn test_rollback_history_limit() {
        let config = NeutralizationConfig::default();
        let neutralizer = Arc::new(StandardNeutralizer::new(config));
        let mut rollback_config = RollbackConfig::default();
        rollback_config.max_history = 3;

        let rollback_neutralizer = RollbackNeutralizer::new(neutralizer, rollback_config);

        // Add more entries than the limit
        for i in 0..5 {
            let threat = create_test_threat();
            let content = format!("SELECT * FROM users WHERE id = {}", i);
            let _ = rollback_neutralizer.neutralize(&threat, &content).await;
        }

        // Check that only max_history entries are kept
        let history = rollback_neutralizer.get_history(None).await;
        assert_eq!(history.len(), 3);

        // Verify the oldest entries were removed
        assert!(history.iter().all(|e| e.original_content.contains("2")
            || e.original_content.contains("3")
            || e.original_content.contains("4")));
    }

    #[tokio::test]
    async fn test_rollback_disabled() {
        let config = NeutralizationConfig::default();
        let neutralizer = Arc::new(StandardNeutralizer::new(config));
        let mut rollback_config = RollbackConfig::default();
        rollback_config.enabled = false;

        let rollback_neutralizer = RollbackNeutralizer::new(neutralizer, rollback_config);

        // Neutralize content
        let threat = create_test_threat();
        let _ = rollback_neutralizer.neutralize(&threat, "test").await;

        // History should be empty
        let history = rollback_neutralizer.get_history(None).await;
        assert_eq!(history.len(), 0);

        // Rollback should fail
        let result = rollback_neutralizer.rollback_latest().await;
        assert!(result.is_err());
    }
}
