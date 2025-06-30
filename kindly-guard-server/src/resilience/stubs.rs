//! Standard implementations for resilience components
//! These provide fallback types for compilation without enhanced features

// Available in all configurations for consistent trait usage

use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;

/// Standard event buffer implementation
pub struct EventBuffer;

impl EventBuffer {
    pub fn new(_size: usize) -> Self {
        Self
    }
    
    pub fn record_success(&self, _name: &str, _latency: Duration) {}
    pub fn record_failure(&self, _name: &str, _error: &anyhow::Error, _latency: Duration) {}
    pub fn record_manual_trip(&self, _name: &str, _reason: &str) {}
    pub fn record_manual_reset(&self, _name: &str) {}
    pub fn record_retry_success(&self, _operation: &str, _attempts: u32) {}
    pub fn record_health_check(&self, _name: &str, _status: u8) {}
    pub fn record_health_failure(&self, _name: &str) {}
    pub fn record_recovery_success(&self, _service: &str, _latency: Duration) {}
    
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

impl StateManager {
    pub fn new() -> Self {
        Self
    }
    
    pub fn get_state(&self) -> u8 { 0 }
    pub fn set_state(&self, _state: u8) {}
    pub fn try_half_open_request(&self) -> bool { true }
    pub fn transition_to_closed(&self) {}
    pub fn transition_to_open(&self) {}
    pub fn get_token_count(&self) -> u32 { 10 }
}

/// Standard counter implementation
pub struct Counter;

impl Counter {
    pub fn new() -> Self {
        Self
    }
    
    pub fn increment(&self) {}
    pub fn get(&self) -> u64 { 0 }
}

/// Standard threshold manager implementation
pub struct ThresholdManager;

impl ThresholdManager {
    pub fn new(_threshold: u32, _buffer: Arc<EventBuffer>) -> Self {
        Self
    }
    
    pub fn update_success_metrics(&self, _latency: Duration) {}
    pub fn update_failure_metrics(&self, _error: &anyhow::Error) {}
    pub fn should_trip(&self) -> bool { false }
    pub fn reset(&self) {}
    pub fn calculate_backoff(&self, _attempts: u32) -> Duration {
        Duration::from_millis(100)
    }
    pub fn calculate_optimal_delay(&self, _attempts: u32, _error_category: &crate::traits::ErrorCategory) -> Duration {
        Duration::from_millis(100)
    }
}

/// Standard analyzer implementation
pub struct Analyzer;

impl Analyzer {
    pub fn new(_buffer: Arc<EventBuffer>) -> Self {
        Self
    }
    
    pub fn should_preemptively_break(&self, _name: &str) -> bool { false }
    pub fn should_retry(&self, _operation: &str, _attempts: u32) -> bool { true }
    pub fn analyze_retry_likelihood(&self, _error_cat: &crate::traits::ErrorCategory, _attempts: u32, _elapsed: Duration) -> RetryPrediction {
        RetryPrediction {
            success_probability: 0.5,
        }
    }
    pub fn predict_health_in_next_window(&self) -> f64 { 1.0 }
    pub fn get_health_predictions(&self) -> HealthPredictions {
        HealthPredictions {
            next_hour_health: 1.0,
        }
    }
    pub fn get_anomaly_score(&self) -> f64 { 0.0 }
    pub fn get_health_trend(&self, _name: &str) -> f64 { 0.0 }
    pub fn suggest_recovery_strategy(&self, _context: &crate::traits::RecoveryContext) -> RecoveryPlan {
        RecoveryPlan {
            use_cache: true,
        }
    }
    pub fn get_predicted_result(&self, _key: &str) -> Option<serde_json::Value> { None }
    pub fn record_recovery_outcome(&self, _context: &crate::traits::RecoveryContext, _success: bool) {}
    pub fn predict_recovery_success(&self, _error: &anyhow::Error) -> f64 { 0.7 }
    pub fn is_monitored(&self, _client: &str) -> bool { false }
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

impl Cache {
    pub fn new() -> Self {
        Self
    }
}