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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info};

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Protection is disabled")]
    ProtectionDisabled,
    
    #[error("Invalid threat data")]
    InvalidThreatData,
    
    #[error("Storage error: {0}")]
    StorageError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub id: String,
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub source: String,
    pub details: String,
    pub timestamp: DateTime<Utc>,
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatType {
    UnicodeInvisible,
    UnicodeBiDi,
    UnicodeHomoglyph,
    InjectionAttempt,
    PathTraversal,
    SuspiciousPattern,
    RateLimitViolation,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Statistics {
    pub threats_blocked: u64,
    pub threats_analyzed: u64,
    pub protection_enabled: bool,
    pub uptime_seconds: u64,
    pub last_threat_time: Option<DateTime<Utc>>,
    pub threat_breakdown: ThreatBreakdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatBreakdown {
    pub unicode_invisible: u64,
    pub unicode_bidi: u64,
    pub unicode_homoglyph: u64,
    pub injection_attempt: u64,
    pub path_traversal: u64,
    pub suspicious_pattern: u64,
    pub rate_limit_violation: u64,
    pub unknown: u64,
}

impl Default for ThreatBreakdown {
    fn default() -> Self {
        Self {
            unicode_invisible: 0,
            unicode_bidi: 0,
            unicode_homoglyph: 0,
            injection_attempt: 0,
            path_traversal: 0,
            suspicious_pattern: 0,
            rate_limit_violation: 0,
            unknown: 0,
        }
    }
}

pub struct ShieldCore {
    protection_enabled: AtomicBool,
    threats_blocked: AtomicU64,
    threats_analyzed: AtomicU64,
    start_time: SystemTime,
    recent_threats: Arc<DashMap<String, Threat>>,
    last_threat_time: Arc<RwLock<Option<DateTime<Utc>>>>,
    threat_breakdown: Arc<RwLock<ThreatBreakdown>>,
}

impl ShieldCore {
    pub fn new() -> Self {
        Self {
            protection_enabled: AtomicBool::new(true),
            threats_blocked: AtomicU64::new(0),
            threats_analyzed: AtomicU64::new(0),
            start_time: SystemTime::now(),
            recent_threats: Arc::new(DashMap::new()),
            last_threat_time: Arc::new(RwLock::new(None)),
            threat_breakdown: Arc::new(RwLock::new(ThreatBreakdown::default())),
        }
    }
    
    pub fn is_protection_enabled(&self) -> bool {
        self.protection_enabled.load(Ordering::Relaxed)
    }
    
    pub fn toggle_protection(&self) -> bool {
        let new_state = !self.is_protection_enabled();
        self.protection_enabled.store(new_state, Ordering::Relaxed);
        info!("Protection {}", if new_state { "enabled" } else { "disabled" });
        new_state
    }
    
    pub fn record_threat(&self, threat: Threat) -> Result<(), CoreError> {
        if !self.is_protection_enabled() {
            return Err(CoreError::ProtectionDisabled);
        }
        
        self.threats_analyzed.fetch_add(1, Ordering::Relaxed);
        
        if threat.blocked {
            self.threats_blocked.fetch_add(1, Ordering::Relaxed);
        }
        
        // Update threat breakdown
        {
            let mut breakdown = self.threat_breakdown.write();
            match &threat.threat_type {
                ThreatType::UnicodeInvisible => breakdown.unicode_invisible += 1,
                ThreatType::UnicodeBiDi => breakdown.unicode_bidi += 1,
                ThreatType::UnicodeHomoglyph => breakdown.unicode_homoglyph += 1,
                ThreatType::InjectionAttempt => breakdown.injection_attempt += 1,
                ThreatType::PathTraversal => breakdown.path_traversal += 1,
                ThreatType::SuspiciousPattern => breakdown.suspicious_pattern += 1,
                ThreatType::RateLimitViolation => breakdown.rate_limit_violation += 1,
                ThreatType::Unknown => breakdown.unknown += 1,
            }
        }
        
        // Update last threat time
        {
            let mut last_time = self.last_threat_time.write();
            *last_time = Some(threat.timestamp);
        }
        
        // Store in recent threats (keep last 100)
        self.recent_threats.insert(threat.id.clone(), threat.clone());
        
        // Clean up old threats if we have too many
        if self.recent_threats.len() > 100 {
            let mut threats: Vec<_> = self.recent_threats
                .iter()
                .map(|e| (e.key().clone(), e.value().timestamp))
                .collect();
            
            threats.sort_by_key(|&(_, timestamp)| timestamp);
            
            // Remove oldest threats
            for (id, _) in threats.iter().take(threats.len() - 100) {
                self.recent_threats.remove(id);
            }
        }
        
        debug!("Recorded threat: {:?}", threat);
        Ok(())
    }
    
    pub fn get_statistics(&self) -> Statistics {
        let uptime = self.start_time
            .elapsed()
            .unwrap_or(Duration::ZERO)
            .as_secs();
        
        Statistics {
            threats_blocked: self.threats_blocked.load(Ordering::Relaxed),
            threats_analyzed: self.threats_analyzed.load(Ordering::Relaxed),
            protection_enabled: self.is_protection_enabled(),
            uptime_seconds: uptime,
            last_threat_time: *self.last_threat_time.read(),
            threat_breakdown: self.threat_breakdown.read().clone(),
        }
    }
    
    pub fn get_recent_threats(&self) -> Vec<Threat> {
        let mut threats: Vec<_> = self.recent_threats
            .iter()
            .map(|e| e.value().clone())
            .collect();
        
        threats.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        threats
    }
    
    pub fn clear_threats(&self) {
        self.recent_threats.clear();
        info!("Cleared all recent threats");
    }
    
    pub fn create_threat(
        threat_type: ThreatType,
        severity: Severity,
        source: String,
        details: String,
        blocked: bool,
    ) -> Threat {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        
        Threat {
            id: format!("threat_{}", timestamp),
            threat_type,
            severity,
            source,
            details,
            timestamp: Utc::now(),
            blocked,
        }
    }
}

// Enhanced implementation module
#[cfg(feature = "enhanced")]
pub mod enhanced;

// Standard implementation module
pub mod standard;

use anyhow::Result;

/// Event processor trait for handling security events
pub trait EventProcessorTrait: Send + Sync {
    /// Process a security event
    fn process_event(&self, event: SecurityEvent) -> Result<()>;
    
    /// Get performance metrics
    fn get_metrics(&self) -> EventMetrics;
    
    /// Check if processor is healthy
    fn is_healthy(&self) -> bool;
    
    /// Flush any pending events
    fn flush(&self) -> Result<()>;
}

/// Security event for processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: String,
    pub client_id: String,
    pub threat_level: f32,
    pub timestamp: u64,
    pub data: serde_json::Value,
}

/// Event processing metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetrics {
    pub events_processed: u64,
    pub events_dropped: u64,
    pub events_per_second: f64,
    pub buffer_utilization: f64,
    pub avg_latency_ms: f64,
}

/// Factory for creating event processors
pub struct EventProcessorFactory;

impl EventProcessorFactory {
    /// Create appropriate event processor based on configuration
    pub fn create(config: &crate::config::Config) -> Result<Arc<dyn EventProcessorTrait>> {
        #[cfg(feature = "enhanced")]
        {
            if config.enhanced_mode {
                return Ok(Arc::new(enhanced::EnhancedEventProcessor::new(
                    config.event_buffer_size_mb
                )?));
            }
        }
        
        // Default to standard implementation
        Ok(Arc::new(standard::StandardEventProcessor::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_threat_recording() {
        let core = ShieldCore::new();
        
        let threat = ShieldCore::create_threat(
            ThreatType::UnicodeInvisible,
            Severity::High,
            "test".to_string(),
            "Test threat".to_string(),
            true,
        );
        
        assert!(core.record_threat(threat).is_ok());
        
        let stats = core.get_statistics();
        assert_eq!(stats.threats_analyzed, 1);
        assert_eq!(stats.threats_blocked, 1);
        assert_eq!(stats.threat_breakdown.unicode_invisible, 1);
    }
    
    #[test]
    fn test_protection_toggle() {
        let core = ShieldCore::new();
        
        assert!(core.is_protection_enabled());
        assert!(!core.toggle_protection());
        assert!(!core.is_protection_enabled());
        
        // Recording should fail when protection is disabled
        let threat = ShieldCore::create_threat(
            ThreatType::InjectionAttempt,
            Severity::Critical,
            "test".to_string(),
            "Test".to_string(),
            true,
        );
        
        assert!(matches!(
            core.record_threat(threat),
            Err(CoreError::ProtectionDisabled)
        ));
    }
    
    #[test]
    fn test_threat_cleanup() {
        let core = ShieldCore::new();
        
        // Add 120 threats
        for i in 0..120 {
            let threat = ShieldCore::create_threat(
                ThreatType::Unknown,
                Severity::Low,
                format!("source_{}", i),
                "Test".to_string(),
                false,
            );
            std::thread::sleep(Duration::from_millis(1));
            let _ = core.record_threat(threat);
        }
        
        // Should only keep 100 most recent
        assert_eq!(core.get_recent_threats().len(), 100);
    }
}