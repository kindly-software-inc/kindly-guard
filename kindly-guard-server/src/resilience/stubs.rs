// Copyright 2025 Kindly-Software
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
//! Standard implementations for resilience components
//! These provide fallback types for compilation without enhanced features

// Available in all configurations for consistent trait usage

use std::sync::Arc;
use std::time::{Duration, Instant};

/// Standard event buffer implementation
pub struct EventBuffer;

impl EventBuffer {
    pub const fn new(_size: usize) -> Self {
        Self
    }

    pub const fn record_success(&self, _name: &str, _latency: Duration) {}
    pub const fn record_failure(&self, _name: &str, _error: &anyhow::Error, _latency: Duration) {}
    pub const fn record_manual_trip(&self, _name: &str, _reason: &str) {}
    pub const fn record_manual_reset(&self, _name: &str) {}
    pub const fn record_retry_success(&self, _operation: &str, _attempts: u32) {}
    pub const fn record_health_check(&self, _name: &str, _status: u8) {}
    pub const fn record_health_failure(&self, _name: &str) {}
    pub const fn record_recovery_success(&self, _service: &str, _latency: Duration) {}

    pub fn get_statistics(&self) -> EventStatistics {
        EventStatistics {
            total_events: 0,
            last_failure_timestamp: Instant::now(),
        }
    }
}

pub struct EventStatistics {
    pub total_events: u64,
    pub last_failure_timestamp: Instant,
}

/// Standard state manager implementation
pub struct StateManager;

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StateManager {
    pub const fn new() -> Self {
        Self
    }

    pub const fn get_state(&self) -> u8 {
        0
    }
    pub const fn set_state(&self, _state: u8) {}
    pub const fn try_half_open_request(&self) -> bool {
        true
    }
    pub const fn transition_to_closed(&self) {}
    pub const fn transition_to_open(&self) {}
    pub const fn get_token_count(&self) -> u32 {
        10
    }
}

/// Standard counter implementation
pub struct Counter;

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

impl Counter {
    pub const fn new() -> Self {
        Self
    }

    pub const fn increment(&self) {}
    pub const fn get(&self) -> u64 {
        0
    }
}

/// Standard threshold manager implementation
pub struct ThresholdManager;

impl ThresholdManager {
    pub fn new(_threshold: u32, _buffer: Arc<EventBuffer>) -> Self {
        Self
    }

    pub const fn update_success_metrics(&self, _latency: Duration) {}
    pub const fn update_failure_metrics(&self, _error: &anyhow::Error) {}
    pub const fn should_trip(&self) -> bool {
        false
    }
    pub const fn reset(&self) {}
    pub const fn calculate_backoff(&self, _attempts: u32) -> Duration {
        Duration::from_millis(100)
    }
    pub const fn calculate_optimal_delay(
        &self,
        _attempts: u32,
        _error_category: &crate::traits::ErrorCategory,
    ) -> Duration {
        Duration::from_millis(100)
    }
}

/// Standard analyzer implementation
pub struct Analyzer;

impl Analyzer {
    pub fn new(_buffer: Arc<EventBuffer>) -> Self {
        Self
    }

    pub const fn should_preemptively_break(&self, _name: &str) -> bool {
        false
    }
    pub const fn should_retry(&self, _operation: &str, _attempts: u32) -> bool {
        true
    }
    pub const fn analyze_retry_likelihood(
        &self,
        _error_cat: &crate::traits::ErrorCategory,
        _attempts: u32,
        _elapsed: Duration,
    ) -> RetryPrediction {
        RetryPrediction {
            success_probability: 0.5,
        }
    }
    pub const fn predict_health_in_next_window(&self) -> f64 {
        1.0
    }
    pub const fn get_health_predictions(&self) -> HealthPredictions {
        HealthPredictions {
            next_hour_health: 1.0,
        }
    }
    pub const fn get_anomaly_score(&self) -> f64 {
        0.0
    }
    pub const fn get_health_trend(&self, _name: &str) -> f64 {
        0.0
    }
    pub const fn suggest_recovery_strategy(
        &self,
        _context: &crate::traits::RecoveryContext,
    ) -> RecoveryPlan {
        RecoveryPlan { use_cache: true }
    }
    pub const fn get_predicted_result(&self, _key: &str) -> Option<serde_json::Value> {
        None
    }
    pub const fn record_recovery_outcome(
        &self,
        _context: &crate::traits::RecoveryContext,
        _success: bool,
    ) {
    }
    pub const fn predict_recovery_success(&self, _error: &anyhow::Error) -> f64 {
        0.7
    }
    pub const fn is_monitored(&self, _client: &str) -> bool {
        false
    }
}

pub struct RetryPrediction {
    pub success_probability: f64,
}

pub struct HealthPredictions {
    pub next_hour_health: f64,
}

pub struct RecoveryPlan {
    pub use_cache: bool,
}

/// Standard cache implementation
pub struct Cache;

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache {
    pub const fn new() -> Self {
        Self
    }
}
