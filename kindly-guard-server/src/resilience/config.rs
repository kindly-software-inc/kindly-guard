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
//! Resilience configuration structures

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Resilience configuration for circuit breakers and retry
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResilienceConfig {
    /// Enable enhanced resilience mode (optimized algorithms)
    #[serde(default = "default_false")]
    pub enhanced_mode: bool,

    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerConfig,

    /// Retry configuration
    pub retry: RetryConfig,

    /// Health check configuration
    pub health_check: HealthCheckConfig,

    /// Recovery configuration
    pub recovery: RecoveryConfig,
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    /// Time window for counting failures
    #[serde(default = "default_failure_window")]
    pub failure_window: Duration,

    /// Number of successes in half-open state before closing
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,

    /// Time to wait before attempting recovery
    #[serde(default = "default_recovery_timeout")]
    pub recovery_timeout: Duration,

    /// Timeout for individual requests
    #[serde(default = "default_request_timeout")]
    pub request_timeout: Duration,

    /// Maximum requests allowed in half-open state
    #[serde(default = "default_half_open_max")]
    pub half_open_max_requests: u32,
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,

    /// Initial delay before first retry
    #[serde(default = "default_initial_delay")]
    pub initial_delay: Duration,

    /// Maximum delay between retries
    #[serde(default = "default_max_delay")]
    pub max_delay: Duration,

    /// Exponential backoff multiplier
    #[serde(default = "default_multiplier")]
    pub multiplier: f64,

    /// Jitter factor (0.0 to 1.0)
    #[serde(default = "default_jitter")]
    pub jitter_factor: f64,

    /// Overall timeout for all retry attempts
    #[serde(default = "default_retry_timeout")]
    pub timeout: Duration,
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Health check interval
    #[serde(default = "default_health_check_interval")]
    pub interval: Duration,

    /// Health check timeout
    #[serde(default = "default_health_check_timeout")]
    pub timeout: Duration,

    /// Number of consecutive failures before marking unhealthy
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Number of consecutive successes before marking healthy
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,

    /// Enable predictive health monitoring (enhanced mode only)
    #[serde(default = "default_false")]
    pub predictive_monitoring: bool,
}

/// Recovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Enable cache-based recovery
    #[serde(default = "default_true")]
    pub cache_enabled: bool,

    /// Cache TTL for recovery data
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: Duration,

    /// Maximum recovery attempts
    #[serde(default = "default_max_recovery_attempts")]
    pub max_attempts: u32,

    /// Recovery timeout
    #[serde(default = "default_recovery_timeout")]
    pub timeout: Duration,

    /// Enable predictive recovery (enhanced mode only)
    #[serde(default = "default_false")]
    pub predictive_recovery: bool,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            failure_window: default_failure_window(),
            success_threshold: default_success_threshold(),
            recovery_timeout: default_recovery_timeout(),
            request_timeout: default_request_timeout(),
            half_open_max_requests: default_half_open_max(),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            initial_delay: default_initial_delay(),
            max_delay: default_max_delay(),
            multiplier: default_multiplier(),
            jitter_factor: default_jitter(),
            timeout: default_retry_timeout(),
        }
    }
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval: default_health_check_interval(),
            timeout: default_health_check_timeout(),
            unhealthy_threshold: default_unhealthy_threshold(),
            healthy_threshold: default_healthy_threshold(),
            predictive_monitoring: false,
        }
    }
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            cache_enabled: true,
            cache_ttl: default_cache_ttl(),
            max_attempts: default_max_recovery_attempts(),
            timeout: default_recovery_timeout(),
            predictive_recovery: false,
        }
    }
}

// Default value functions
const fn default_false() -> bool {
    false
}
const fn default_true() -> bool {
    true
}
const fn default_failure_threshold() -> u32 {
    5
}
const fn default_failure_window() -> Duration {
    Duration::from_secs(60)
}
const fn default_success_threshold() -> u32 {
    3
}
const fn default_recovery_timeout() -> Duration {
    Duration::from_secs(30)
}
const fn default_request_timeout() -> Duration {
    Duration::from_secs(10)
}
const fn default_half_open_max() -> u32 {
    3
}
const fn default_max_attempts() -> u32 {
    3
}
const fn default_initial_delay() -> Duration {
    Duration::from_millis(100)
}
const fn default_max_delay() -> Duration {
    Duration::from_secs(10)
}
const fn default_multiplier() -> f64 {
    2.0
}
const fn default_jitter() -> f64 {
    0.1
}
const fn default_retry_timeout() -> Duration {
    Duration::from_secs(60)
}
const fn default_health_check_interval() -> Duration {
    Duration::from_secs(30)
}
const fn default_health_check_timeout() -> Duration {
    Duration::from_secs(5)
}
const fn default_unhealthy_threshold() -> u32 {
    3
}
const fn default_healthy_threshold() -> u32 {
    2
}
const fn default_cache_ttl() -> Duration {
    Duration::from_secs(300)
}
const fn default_max_recovery_attempts() -> u32 {
    3
}
