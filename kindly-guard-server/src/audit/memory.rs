//! In-memory audit logger implementation

use std::sync::Arc;
use std::collections::{HashMap, VecDeque};
use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use tracing::{debug, warn};

use super::*;

/// In-memory audit logger with configurable retention
pub struct InMemoryAuditLogger {
    config: AuditConfig,
    events: Arc<RwLock<HashMap<AuditEventId, AuditEvent>>>,
    event_order: Arc<RwLock<VecDeque<AuditEventId>>>,
    events_by_client: Arc<RwLock<HashMap<String, Vec<AuditEventId>>>>,
    events_by_type: Arc<RwLock<HashMap<String, Vec<AuditEventId>>>>,
    stats: Arc<RwLock<AuditStats>>,
}

impl InMemoryAuditLogger {
    /// Create a new in-memory audit logger
    pub fn new(config: AuditConfig) -> Result<Self> {
        Ok(Self {
            config,
            events: Arc::new(RwLock::new(HashMap::new())),
            event_order: Arc::new(RwLock::new(VecDeque::new())),
            events_by_client: Arc::new(RwLock::new(HashMap::new())),
            events_by_type: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(AuditStats::default())),
        })
    }
    
    /// Apply retention policy
    async fn apply_retention(&self) -> Result<()> {
        let mut events = self.events.write().await;
        let mut event_order = self.event_order.write().await;
        let mut stats = self.stats.write().await;
        
        // Check max events limit
        if let Some(max_events) = self.config.max_events {
            while event_order.len() > max_events as usize {
                if let Some(oldest_id) = event_order.pop_front() {
                    if let Some(event) = events.remove(&oldest_id) {
                        debug!("Evicting old audit event: {:?}", oldest_id);
                        self.remove_from_indexes(&event).await;
                        stats.total_events = stats.total_events.saturating_sub(1);
                    }
                }
            }
        }
        
        // Check retention period
        let cutoff = Utc::now() - chrono::Duration::days(self.config.retention_days as i64);
        let mut removed = 0;
        
        while let Some(oldest_id) = event_order.front() {
            if let Some(event) = events.get(oldest_id) {
                if event.timestamp < cutoff {
                    let id = oldest_id.clone();
                    event_order.pop_front();
                    if let Some(event) = events.remove(&id) {
                        self.remove_from_indexes(&event).await;
                        removed += 1;
                        stats.total_events = stats.total_events.saturating_sub(1);
                    }
                } else {
                    break;
                }
            } else {
                event_order.pop_front();
            }
        }
        
        if removed > 0 {
            debug!("Removed {} events due to retention policy", removed);
        }
        
        Ok(())
    }
    
    /// Remove event from indexes
    async fn remove_from_indexes(&self, event: &AuditEvent) {
        if let Some(client_id) = &event.client_id {
            let mut by_client = self.events_by_client.write().await;
            if let Some(events) = by_client.get_mut(client_id) {
                events.retain(|id| id != &event.id);
                if events.is_empty() {
                    by_client.remove(client_id);
                }
            }
        }
        
        let type_key = format!("{:?}", event.event_type);
        let mut by_type = self.events_by_type.write().await;
        if let Some(events) = by_type.get_mut(&type_key) {
            events.retain(|id| id != &event.id);
            if events.is_empty() {
                by_type.remove(&type_key);
            }
        }
        
        let mut stats = self.stats.write().await;
        let severity_key = format!("{:?}", event.severity);
        if let Some(count) = stats.events_by_severity.get_mut(&severity_key) {
            *count = count.saturating_sub(1);
        }
        if let Some(count) = stats.events_by_type.get_mut(&type_key) {
            *count = count.saturating_sub(1);
        }
    }
    
    /// Update statistics
    async fn update_stats(&self, event: &AuditEvent) {
        let mut stats = self.stats.write().await;
        stats.total_events += 1;
        
        let severity_key = format!("{:?}", event.severity);
        *stats.events_by_severity.entry(severity_key).or_insert(0) += 1;
        
        let type_key = format!("{:?}", event.event_type);
        *stats.events_by_type.entry(type_key).or_insert(0) += 1;
        
        if stats.oldest_event.is_none() || Some(event.timestamp) < stats.oldest_event {
            stats.oldest_event = Some(event.timestamp);
        }
        
        if stats.newest_event.is_none() || Some(event.timestamp) > stats.newest_event {
            stats.newest_event = Some(event.timestamp);
        }
        
        // Estimate storage size
        stats.storage_size_bytes = stats.total_events * 512; // Rough estimate
    }
}

#[async_trait]
impl AuditLogger for InMemoryAuditLogger {
    async fn log(&self, event: AuditEvent) -> Result<AuditEventId> {
        let id = event.id.clone();
        
        // Update indexes
        if let Some(client_id) = &event.client_id {
            let mut by_client = self.events_by_client.write().await;
            by_client.entry(client_id.clone())
                .or_insert_with(Vec::new)
                .push(id.clone());
        }
        
        let type_key = format!("{:?}", event.event_type);
        {
            let mut by_type = self.events_by_type.write().await;
            by_type.entry(type_key)
                .or_insert_with(Vec::new)
                .push(id.clone());
        }
        
        // Store event
        {
            let mut events = self.events.write().await;
            events.insert(id.clone(), event.clone());
        }
        
        {
            let mut order = self.event_order.write().await;
            order.push_back(id.clone());
        }
        
        // Update stats
        self.update_stats(&event).await;
        
        // Apply retention
        self.apply_retention().await?;
        
        Ok(id)
    }
    
    async fn log_batch(&self, events: Vec<AuditEvent>) -> Result<Vec<AuditEventId>> {
        let mut ids = Vec::with_capacity(events.len());
        
        for event in events {
            ids.push(self.log(event).await?);
        }
        
        Ok(ids)
    }
    
    async fn query(&self, filter: AuditFilter) -> Result<Vec<AuditEvent>> {
        let events = self.events.read().await;
        let event_order = self.event_order.read().await;
        
        let mut results = Vec::new();
        let mut checked = 0;
        
        // Iterate in reverse order (newest first)
        for event_id in event_order.iter().rev() {
            if let Some(limit) = filter.limit {
                if results.len() >= limit {
                    break;
                }
            }
            
            if let Some(offset) = filter.offset {
                if checked < offset {
                    checked += 1;
                    continue;
                }
            }
            
            if let Some(event) = events.get(event_id) {
                // Apply filters
                if let Some(min_severity) = &filter.min_severity {
                    // Info=0, Warning=1, Error=2, Critical=3 - skip if less severe than minimum
                    if (event.severity as u8) < (*min_severity as u8) {
                        continue;
                    }
                }
                
                if let Some(pattern) = &filter.event_type_pattern {
                    let type_str = format!("{:?}", event.event_type);
                    if !type_str.contains(pattern) {
                        continue;
                    }
                }
                
                if let Some(client_id) = &filter.client_id {
                    if event.client_id.as_ref() != Some(client_id) {
                        continue;
                    }
                }
                
                if let Some(ip) = &filter.ip_address {
                    if event.ip_address.as_ref() != Some(ip) {
                        continue;
                    }
                }
                
                if let Some(start) = filter.start_time {
                    if event.timestamp < start {
                        continue;
                    }
                }
                
                if let Some(end) = filter.end_time {
                    if event.timestamp > end {
                        continue;
                    }
                }
                
                if !filter.tags.is_empty() {
                    let has_tag = filter.tags.iter().any(|tag| event.tags.contains(tag));
                    if !has_tag {
                        continue;
                    }
                }
                
                results.push(event.clone());
            }
            
            checked += 1;
        }
        
        Ok(results)
    }
    
    async fn get_event(&self, id: &AuditEventId) -> Result<Option<AuditEvent>> {
        let events = self.events.read().await;
        Ok(events.get(id).cloned())
    }
    
    async fn delete_before(&self, timestamp: DateTime<Utc>) -> Result<u64> {
        let mut events = self.events.write().await;
        let mut event_order = self.event_order.write().await;
        let mut deleted = 0;
        
        let mut to_remove = Vec::new();
        
        for event_id in event_order.iter() {
            if let Some(event) = events.get(event_id) {
                if event.timestamp < timestamp {
                    to_remove.push(event_id.clone());
                    deleted += 1;
                }
            }
        }
        
        for id in to_remove {
            if let Some(event) = events.remove(&id) {
                self.remove_from_indexes(&event).await;
            }
            event_order.retain(|eid| eid != &id);
        }
        
        let mut stats = self.stats.write().await;
        stats.total_events = stats.total_events.saturating_sub(deleted);
        
        Ok(deleted)
    }
    
    async fn get_stats(&self) -> Result<AuditStats> {
        let stats = self.stats.read().await;
        Ok(stats.clone())
    }
    
    async fn export(&self, filter: AuditFilter, format: ExportFormat) -> Result<Vec<u8>> {
        let events = self.query(filter).await?;
        
        match format {
            ExportFormat::Json => {
                let json = serde_json::to_string_pretty(&events)?;
                Ok(json.into_bytes())
            }
            ExportFormat::Csv => {
                let mut wtr = csv::Writer::from_writer(vec![]);
                
                // Write header
                wtr.write_record(&[
                    "id", "timestamp", "event_type", "severity", 
                    "client_id", "ip_address", "user_agent", "tags"
                ])?;
                
                // Write events
                for event in events {
                    wtr.write_record(&[
                        &event.id.0,
                        &event.timestamp.to_rfc3339(),
                        &format!("{:?}", event.event_type),
                        &format!("{:?}", event.severity),
                        &event.client_id.unwrap_or_default(),
                        &event.ip_address.unwrap_or_default(),
                        &event.user_agent.unwrap_or_default(),
                        &event.tags.join(","),
                    ])?;
                }
                
                Ok(wtr.into_inner()?)
            }
            ExportFormat::Syslog => {
                let mut output = Vec::new();
                
                for event in events {
                    let severity = match event.severity {
                        AuditSeverity::Critical => 2,
                        AuditSeverity::Error => 3,
                        AuditSeverity::Warning => 4,
                        AuditSeverity::Info => 6,
                    };
                    
                    let msg = format!(
                        "<{}>{} kindly-guard[{}]: event_type={:?} client={} ip={}\n",
                        16 * 8 + severity, // facility=16 (local0), severity
                        event.timestamp.to_rfc3339(),
                        std::process::id(),
                        event.event_type,
                        event.client_id.as_ref().unwrap_or(&"none".to_string()),
                        event.ip_address.as_ref().unwrap_or(&"none".to_string())
                    );
                    
                    output.extend_from_slice(msg.as_bytes());
                }
                
                Ok(output)
            }
            ExportFormat::Cef => {
                let mut output = Vec::new();
                
                for event in events {
                    let severity = match event.severity {
                        AuditSeverity::Info => 0,
                        AuditSeverity::Warning => 3,
                        AuditSeverity::Error => 7,
                        AuditSeverity::Critical => 10,
                    };
                    
                    let msg = format!(
                        "CEF:0|KindlyGuard|SecurityServer|1.0|{:?}|{:?}|{}|client={} ip={}\n",
                        event.event_type,
                        event.event_type,
                        severity,
                        event.client_id.as_ref().unwrap_or(&"none".to_string()),
                        event.ip_address.as_ref().unwrap_or(&"none".to_string())
                    );
                    
                    output.extend_from_slice(msg.as_bytes());
                }
                
                Ok(output)
            }
        }
    }
    
    async fn verify_integrity(&self) -> Result<IntegrityReport> {
        let events = self.events.read().await;
        let event_order = self.event_order.read().await;
        let mut issues = Vec::new();
        
        // Check order consistency
        for event_id in event_order.iter() {
            if !events.contains_key(event_id) {
                issues.push(format!("Event {} in order but not in storage", event_id.0));
            }
        }
        
        // Check reverse
        for (event_id, _) in events.iter() {
            if !event_order.contains(event_id) {
                issues.push(format!("Event {} in storage but not in order", event_id.0));
            }
        }
        
        Ok(IntegrityReport {
            intact: issues.is_empty(),
            events_checked: events.len() as u64,
            issues,
            verified_at: Utc::now(),
        })
    }
}