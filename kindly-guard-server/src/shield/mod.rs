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
//! Shield display module for security status visualization

use anyhow::Result;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tracing::error;

use crate::config::ShieldConfig;
use crate::scanner::Threat;
use crate::traits::SecurityEventProcessor;

pub mod cli;
pub mod display;
pub mod universal_display;

pub use cli::{CliShield, DisplayFormat, ShieldStatus};
pub use display::ShieldDisplay;
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
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ShieldInfo {
    pub active: bool,
    #[serde(with = "serde_duration")]
    pub uptime: Duration,
    pub threats_blocked: u64,
    pub recent_threat_rate: f64,
}

// Custom serialization for Duration
mod serde_duration {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_secs())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

/// Shield statistics
pub struct ShieldStats {
    pub threats_blocked: u64,
    pub active: bool,
}

impl Default for Shield {
    fn default() -> Self {
        Self::new()
    }
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
        self.event_processor_enabled
            .store(enabled, Ordering::Relaxed);
    }

    /// Check if event processor (advanced protection) is enabled
    pub fn is_event_processor_enabled(&self) -> bool {
        self.event_processor_enabled.load(Ordering::Relaxed)
    }

    /// Set event processor reference for correlation data
    pub fn set_event_processor(&self, processor: &Arc<dyn SecurityEventProcessor>) {
        match self.event_processor.lock() {
            Ok(mut ep) => *ep = Some(Arc::downgrade(processor)),
            Err(e) => error!("Failed to acquire event processor lock: {}", e),
        }
    }

    /// Record detected threats
    pub fn record_threats(&self, threats: &[Threat]) {
        if threats.is_empty() {
            return;
        }

        let count = threats.len() as u64;
        self.threats_blocked.fetch_add(count, Ordering::Relaxed);

        let now = Instant::now();
        let Ok(mut recent) = self.recent_threats.lock() else {
            error!("Failed to acquire recent threats lock");
            return;
        };

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
        let recent_rate = match self.recent_threats.lock() {
            Ok(recent) => {
                let five_mins_ago = now.checked_sub(Duration::from_secs(300))
                    .unwrap_or(now); // If subtraction fails (shouldn't happen), use current time
                let recent_count = recent
                    .iter()
                    .filter(|t| t.timestamp > five_mins_ago)
                    .count() as f64;
                recent_count / 5.0 // per minute
            }
            Err(e) => {
                error!("Failed to acquire recent threats lock: {}", e);
                0.0 // Default to 0 on error
            }
        };

        // Check for attack patterns if processor is available
        if self.is_event_processor_enabled() {
            if let Ok(ep_lock) = self.event_processor.lock() {
                if let Some(weak_proc) = ep_lock.as_ref() {
                    if let Some(processor) = weak_proc.upgrade() {
                        // Check if any client is under monitoring (attack detected)
                        if processor.is_monitored("any") {
                            tracing::trace!("Attack pattern correlation active");
                        }
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
            Ok(recent) => recent
                .iter()
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
    pub const fn start_time(&self) -> Instant {
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
        match self.recent_threats.lock() {
            Ok(recent) => recent.back().map(|t| format!("{}", t.threat.threat_type)),
            Err(e) => {
                error!("Failed to acquire recent threats lock: {}", e);
                None
            }
        }
    }

    /// Get scanner statistics
    pub fn scanner_stats(&self) -> crate::scanner::ScannerStats {
        // Return the threat counts tracked by the shield
        match self.recent_threats.lock() {
            Ok(threats) => {
                let (unicode_count, injection_count) =
                    threats
                        .iter()
                        .fold((0u64, 0u64), |(unicode, injection), item| {
                            match &item.threat.threat_type {
                                crate::scanner::ThreatType::UnicodeInvisible
                                | crate::scanner::ThreatType::UnicodeBiDi
                                | crate::scanner::ThreatType::UnicodeHomograph => {
                                    (unicode + 1, injection)
                                }

                                crate::scanner::ThreatType::SqlInjection
                                | crate::scanner::ThreatType::CommandInjection
                                | crate::scanner::ThreatType::PromptInjection
                                | crate::scanner::ThreatType::PathTraversal => {
                                    (unicode, injection + 1)
                                }

                                _ => (unicode, injection),
                            }
                        });

                crate::scanner::ScannerStats {
                    unicode_threats_detected: unicode_count,
                    injection_threats_detected: injection_count,
                    total_scans: self.threats_blocked.load(Ordering::Relaxed),
                }
            }
            Err(_) => crate::scanner::ScannerStats {
                unicode_threats_detected: 0,
                injection_threats_detected: 0,
                total_scans: 0,
            },
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
