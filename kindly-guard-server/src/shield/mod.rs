//! Shield display module for security status visualization

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use anyhow::Result;
use tracing::error;

use crate::scanner::Threat;
use crate::config::ShieldConfig;
use crate::traits::SecurityEventProcessor;

pub mod display;
pub mod cli;
pub mod universal_display;

pub use display::ShieldDisplay;
pub use cli::{CliShield, DisplayFormat, ShieldStatus};
pub use universal_display::{UniversalDisplay, UniversalDisplayConfig, UniversalShieldStatus};

/// Security shield that tracks protection status
pub struct Shield {
    active: AtomicBool,
    start_time: Instant,
    threats_blocked: AtomicU64,
    recent_threats: Arc<Mutex<VecDeque<TimestampedThreat>>>,
    config: ShieldConfig,
    /// Whether advanced protection (event processor) is enabled
    event_processor_enabled: AtomicBool,
    /// Weak reference to event processor for correlation data
    event_processor: Mutex<Option<Weak<dyn SecurityEventProcessor>>>,
}

/// Threat with timestamp
#[derive(Clone)]
struct TimestampedThreat {
    threat: Threat,
    timestamp: Instant,
}

/// Shield information snapshot
pub struct ShieldInfo {
    pub active: bool,
    pub uptime: Duration,
    pub threats_blocked: u64,
    pub recent_threat_rate: f64,
}

/// Shield statistics
pub struct ShieldStats {
    pub threats_blocked: u64,
    pub active: bool,
}

impl Shield {
    /// Create a new shield
    pub fn new() -> Self {
        Self::with_config(ShieldConfig::default())
    }
    
    /// Create a new shield with specific config
    pub fn with_config(config: ShieldConfig) -> Self {
        Self {
            active: AtomicBool::new(false),
            start_time: Instant::now(),
            threats_blocked: AtomicU64::new(0),
            recent_threats: Arc::new(Mutex::new(VecDeque::with_capacity(1000))),
            config,
            event_processor_enabled: AtomicBool::new(false),
            event_processor: Mutex::new(None),
        }
    }
    
    /// Set shield active status
    pub fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::Relaxed);
    }
    
    /// Check if shield is active
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
    
    /// Set whether event processor (advanced protection) is enabled
    pub fn set_event_processor_enabled(&self, enabled: bool) {
        self.event_processor_enabled.store(enabled, Ordering::Relaxed);
    }
    
    /// Check if event processor (advanced protection) is enabled
    pub fn is_event_processor_enabled(&self) -> bool {
        self.event_processor_enabled.load(Ordering::Relaxed)
    }
    
    /// Set event processor reference for correlation data
    pub fn set_event_processor(&self, processor: &Arc<dyn SecurityEventProcessor>) {
        let mut ep = self.event_processor.lock().unwrap();
        *ep = Some(Arc::downgrade(processor));
    }
    
    /// Record detected threats
    pub fn record_threats(&self, threats: &[Threat]) {
        if threats.is_empty() {
            return;
        }
        
        let count = threats.len() as u64;
        self.threats_blocked.fetch_add(count, Ordering::Relaxed);
        
        let now = Instant::now();
        let mut recent = self.recent_threats.lock().unwrap();
        
        for threat in threats {
            // Add to recent threats
            recent.push_back(TimestampedThreat {
                threat: threat.clone(),
                timestamp: now,
            });
            
            // Keep only last N threats
            while recent.len() > 1000 {
                recent.pop_front();
            }
        }
    }
    
    /// Get shield information
    pub fn get_info(&self) -> ShieldInfo {
        let now = Instant::now();
        let uptime = now.duration_since(self.start_time);
        
        // Calculate recent threat rate (threats per minute in last 5 minutes)
        let recent_rate = {
            let recent = self.recent_threats.lock().unwrap();
            let five_mins_ago = now - Duration::from_secs(300);
            let recent_count = recent.iter()
                .filter(|t| t.timestamp > five_mins_ago)
                .count() as f64;
            recent_count / 5.0 // per minute
        };
        
        // Check for attack patterns if processor is available
        if self.is_event_processor_enabled() {
            if let Some(weak_proc) = self.event_processor.lock().unwrap().as_ref() {
                if let Some(processor) = weak_proc.upgrade() {
                    // Check if any client is under monitoring (attack detected)
                    if processor.is_monitored("any") {
                        tracing::trace!("Attack pattern correlation active");
                    }
                }
            }
        }
        
        ShieldInfo {
            active: self.is_active(),
            uptime,
            threats_blocked: self.threats_blocked.load(Ordering::Relaxed),
            recent_threat_rate: recent_rate,
        }
    }
    
    /// Get recent threats
    pub fn get_recent_threats(&self, limit: usize) -> Vec<Threat> {
        match self.recent_threats.lock() {
            Ok(recent) => recent.iter()
                .rev()
                .take(limit)
                .map(|t| t.threat.clone())
                .collect(),
            Err(e) => {
                error!("Failed to acquire recent threats lock: {}", e);
                vec![]
            }
        }
    }
    
    /// Get threat statistics by type
    pub fn get_threat_stats(&self) -> std::collections::HashMap<crate::scanner::ThreatType, u64> {
        use std::collections::HashMap;
        
        match self.recent_threats.lock() {
            Ok(recent) => {
                let mut stats = HashMap::new();
                for item in recent.iter() {
                    *stats.entry(item.threat.threat_type.clone()).or_insert(0) += 1;
                }
                stats
            }
            Err(e) => {
                error!("Failed to acquire recent threats lock: {}", e);
                HashMap::new()
            }
        }
    }
    
    /// Start the shield display if configured
    pub async fn start_display(self: Arc<Self>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        let display = ShieldDisplay::new(self.clone(), self.config.clone());
        display.run().await
    }
    
    /// Get the start time of the shield
    pub fn start_time(&self) -> Instant {
        self.start_time
    }
    
    /// Get shield statistics
    pub fn stats(&self) -> ShieldStats {
        ShieldStats {
            threats_blocked: self.threats_blocked.load(Ordering::Relaxed),
            active: self.is_active(),
        }
    }
    
    /// Get the last threat type if any
    pub fn last_threat_type(&self) -> Option<String> {
        let recent = self.recent_threats.lock().unwrap();
        recent.back().map(|t| format!("{}", t.threat.threat_type))
    }
    
    /// Get scanner statistics (placeholder for now)
    pub fn scanner_stats(&self) -> crate::scanner::ScannerStats {
        // This will be connected to the actual scanner later
        crate::scanner::ScannerStats {
            unicode_threats_detected: 0,
            injection_threats_detected: 0,
            total_scans: 0,
        }
    }
    
    /// Set enabled state
    pub fn set_enabled(&self, enabled: bool) {
        // ShieldConfig is not mutable at runtime
        // This would need to be handled differently
        if enabled {
            tracing::info!("Shield display enabled");
            self.set_active(true);
        } else {
            tracing::info!("Shield display disabled"); 
            self.set_active(false);
        }
    }
}