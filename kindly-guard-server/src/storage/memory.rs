// Copyright 2025 Kindly Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! In-memory storage implementation
//!
//! This provides non-persistent storage for development and testing.
//! All data is lost when the process restarts.

use super::{
    async_trait, Arc, CorrelationState, DateTime, Duration, EventFilter, EventId, RateLimitKey,
    RateLimitState, Result, SecurityEvent, SnapshotId, StorageProvider, StorageStats, Utc,
};
use std::collections::{HashMap, VecDeque};
use tokio::sync::RwLock;
use tracing::{debug, info};
use uuid::Uuid;

/// In-memory storage provider
pub struct InMemoryStorage {
    /// Event storage
    events: Arc<RwLock<HashMap<EventId, SecurityEvent>>>,
    /// Event index by client
    events_by_client: Arc<RwLock<HashMap<String, Vec<EventId>>>>,
    /// Rate limit states
    rate_limits: Arc<RwLock<HashMap<String, RateLimitState>>>,
    /// Correlation states
    correlations: Arc<RwLock<HashMap<String, CorrelationState>>>,
    /// Snapshots
    snapshots: Arc<RwLock<HashMap<SnapshotId, Snapshot>>>,
    /// Event order tracking
    event_order: Arc<RwLock<VecDeque<EventId>>>,
    /// Maximum events to store
    max_events: usize,
}

#[derive(Clone)]
struct Snapshot {
    id: SnapshotId,
    created_at: DateTime<Utc>,
    events: HashMap<EventId, SecurityEvent>,
    rate_limits: HashMap<String, RateLimitState>,
    correlations: HashMap<String, CorrelationState>,
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStorage {
    /// Create new in-memory storage
    pub fn new() -> Self {
        Self::with_capacity(100_000) // 100k events default
    }

    /// Create with specified capacity
    pub fn with_capacity(max_events: usize) -> Self {
        info!(
            "Initializing in-memory storage with capacity: {}",
            max_events
        );
        Self {
            events: Arc::new(RwLock::new(HashMap::new())),
            events_by_client: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            correlations: Arc::new(RwLock::new(HashMap::new())),
            snapshots: Arc::new(RwLock::new(HashMap::new())),
            event_order: Arc::new(RwLock::new(VecDeque::new())),
            max_events,
        }
    }

    /// Evict oldest events when at capacity
    async fn evict_if_needed(&self) {
        let mut order = self.event_order.write().await;
        let mut events = self.events.write().await;

        while order.len() >= self.max_events {
            if let Some(old_id) = order.pop_front() {
                if let Some(old_event) = events.remove(&old_id) {
                    // Also remove from client index
                    let mut by_client = self.events_by_client.write().await;
                    if let Some(client_events) = by_client.get_mut(&old_event.client_id) {
                        client_events.retain(|id| id != &old_id);
                    }
                }
            }
        }
    }
}

#[async_trait]
impl StorageProvider for InMemoryStorage {
    async fn store_event(&self, event: &SecurityEvent) -> Result<EventId> {
        // Evict old events if needed
        self.evict_if_needed().await;

        let id = EventId(Uuid::new_v4().to_string());

        // Store event
        {
            let mut events = self.events.write().await;
            events.insert(id.clone(), event.clone());
        }

        // Update client index
        {
            let mut by_client = self.events_by_client.write().await;
            by_client
                .entry(event.client_id.clone())
                .or_insert_with(Vec::new)
                .push(id.clone());
        }

        // Track order
        {
            let mut order = self.event_order.write().await;
            order.push_back(id.clone());
        }

        debug!("Stored event {} for client {}", id.0, event.client_id);
        Ok(id)
    }

    async fn get_event(&self, id: &EventId) -> Result<Option<SecurityEvent>> {
        let events = self.events.read().await;
        Ok(events.get(id).cloned())
    }

    async fn query_events(&self, filter: EventFilter) -> Result<Vec<SecurityEvent>> {
        let events = self.events.read().await;
        let by_client = self.events_by_client.read().await;

        let mut results = Vec::new();

        // If filtering by client, use index
        if let Some(client_id) = &filter.client_id {
            if let Some(event_ids) = by_client.get(client_id) {
                for event_id in event_ids {
                    if let Some(event) = events.get(event_id) {
                        if Self::matches_filter(event, &filter) {
                            results.push(event.clone());
                        }
                    }
                }
            }
        } else {
            // Full scan
            for event in events.values() {
                if Self::matches_filter(event, &filter) {
                    results.push(event.clone());
                }
            }
        }

        // Sort by timestamp descending
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Apply limit
        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }

        Ok(results)
    }

    async fn store_rate_limit_state(
        &self,
        key: &RateLimitKey,
        state: &RateLimitState,
    ) -> Result<()> {
        let mut rate_limits = self.rate_limits.write().await;
        let key_str = format!("{}:{}", key.client_id, key.method.as_deref().unwrap_or("*"));
        rate_limits.insert(key_str, state.clone());
        Ok(())
    }

    async fn get_rate_limit_state(&self, key: &RateLimitKey) -> Result<Option<RateLimitState>> {
        let rate_limits = self.rate_limits.read().await;
        let key_str = format!("{}:{}", key.client_id, key.method.as_deref().unwrap_or("*"));
        Ok(rate_limits.get(&key_str).cloned())
    }

    async fn cleanup_rate_limit_states(&self, older_than: Duration) -> Result<u64> {
        let mut rate_limits = self.rate_limits.write().await;
        let cutoff = Utc::now() - chrono::Duration::from_std(older_than)?;
        let initial_count = rate_limits.len();

        rate_limits.retain(|_, state| state.last_refill > cutoff);

        let removed = initial_count - rate_limits.len();
        debug!("Cleaned up {} old rate limit states", removed);
        Ok(removed as u64)
    }

    async fn store_correlation_state(
        &self,
        client_id: &str,
        state: &CorrelationState,
    ) -> Result<()> {
        let mut correlations = self.correlations.write().await;
        correlations.insert(client_id.to_string(), state.clone());
        Ok(())
    }

    async fn get_correlation_state(&self, client_id: &str) -> Result<Option<CorrelationState>> {
        let correlations = self.correlations.read().await;
        Ok(correlations.get(client_id).cloned())
    }

    async fn create_snapshot(&self) -> Result<SnapshotId> {
        let id = SnapshotId(Uuid::new_v4().to_string());

        let snapshot = Snapshot {
            id: id.clone(),
            created_at: Utc::now(),
            events: self.events.read().await.clone(),
            rate_limits: self.rate_limits.read().await.clone(),
            correlations: self.correlations.read().await.clone(),
        };

        let mut snapshots = self.snapshots.write().await;
        snapshots.insert(id.clone(), snapshot);

        info!("Created snapshot {}", id.0);
        Ok(id)
    }

    async fn list_snapshots(&self) -> Result<Vec<(SnapshotId, DateTime<Utc>)>> {
        let snapshots = self.snapshots.read().await;
        let mut list: Vec<_> = snapshots
            .values()
            .map(|s| (s.id.clone(), s.created_at))
            .collect();
        list.sort_by(|a, b| b.1.cmp(&a.1)); // Newest first
        Ok(list)
    }

    async fn restore_snapshot(&self, id: &SnapshotId) -> Result<()> {
        let snapshots = self.snapshots.read().await;
        let snapshot = snapshots
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Snapshot not found"))?
            .clone();
        drop(snapshots);

        // Restore all data
        *self.events.write().await = snapshot.events;
        *self.rate_limits.write().await = snapshot.rate_limits;
        *self.correlations.write().await = snapshot.correlations;

        // Rebuild event order and client index
        let mut order = self.event_order.write().await;
        let mut by_client = self.events_by_client.write().await;

        order.clear();
        by_client.clear();

        let events = self.events.read().await;
        let mut event_list: Vec<_> = events.iter().collect();
        event_list.sort_by_key(|(_, event)| event.timestamp);

        for (id, event) in event_list {
            order.push_back(id.clone());
            by_client
                .entry(event.client_id.clone())
                .or_insert_with(Vec::new)
                .push(id.clone());
        }

        info!("Restored from snapshot {}", id.0);
        Ok(())
    }

    async fn delete_snapshot(&self, id: &SnapshotId) -> Result<()> {
        let mut snapshots = self.snapshots.write().await;
        snapshots
            .remove(id)
            .ok_or_else(|| anyhow::anyhow!("Snapshot not found"))?;
        Ok(())
    }

    async fn get_stats(&self) -> Result<StorageStats> {
        let events = self.events.read().await;
        let rate_limits = self.rate_limits.read().await;
        let correlations = self.correlations.read().await;

        // Estimate memory usage
        let event_size = events.len() * std::mem::size_of::<(EventId, SecurityEvent)>();
        let rate_limit_size = rate_limits.len() * std::mem::size_of::<(String, RateLimitState)>();
        let correlation_size =
            correlations.len() * std::mem::size_of::<(String, CorrelationState)>();

        Ok(StorageStats {
            event_count: events.len() as u64,
            total_size: (event_size + rate_limit_size + correlation_size) as u64,
            rate_limit_entries: rate_limits.len() as u64,
            correlation_states: correlations.len() as u64,
            storage_type: "memory".to_string(),
            metadata: serde_json::json!({
                "max_events": self.max_events,
                "snapshots": self.snapshots.read().await.len(),
            }),
        })
    }

    async fn compact(&self) -> Result<()> {
        // For in-memory storage, compaction just shrinks hashmaps
        self.events.write().await.shrink_to_fit();
        self.events_by_client.write().await.shrink_to_fit();
        self.rate_limits.write().await.shrink_to_fit();
        self.correlations.write().await.shrink_to_fit();
        debug!("Compacted in-memory storage");
        Ok(())
    }
}

impl InMemoryStorage {
    /// Check if event matches filter
    fn matches_filter(event: &SecurityEvent, filter: &EventFilter) -> bool {
        // Event type filter
        if let Some(event_type) = &filter.event_type {
            if &event.event_type != event_type {
                return false;
            }
        }

        // Time range filter
        let event_time =
            DateTime::<Utc>::from_timestamp(event.timestamp as i64, 0).unwrap_or_else(Utc::now);

        if let Some(from) = filter.from_time {
            if event_time < from {
                return false;
            }
        }

        if let Some(to) = filter.to_time {
            if event_time > to {
                return false;
            }
        }

        // Severity filter (if present in metadata)
        if let Some(min_severity) = &filter.min_severity {
            if let Some(severity) = event.metadata.get("severity").and_then(|v| v.as_str()) {
                // Simple severity comparison (would be more sophisticated in production)
                let severity_rank = match severity {
                    "low" => 1,
                    "medium" => 2,
                    "high" => 3,
                    "critical" => 4,
                    _ => 0,
                };
                let min_rank = match min_severity.as_str() {
                    "low" => 1,
                    "medium" => 2,
                    "high" => 3,
                    "critical" => 4,
                    _ => 0,
                };
                if severity_rank < min_rank {
                    return false;
                }
            }
        }

        true
    }
}
