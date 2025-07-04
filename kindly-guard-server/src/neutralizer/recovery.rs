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
//! Error recovery and resilience for neutralization operations
//!
//! This module provides error handling, retry logic, and fallback mechanisms
//! for neutralization failures to ensure robust threat mitigation.

use crate::{
    neutralizer::{NeutralizeAction, NeutralizeResult, ThreatNeutralizer},
    scanner::Threat,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// Recovery strategy for neutralization failures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    /// Retry with exponential backoff
    RetryWithBackoff {
        max_attempts: u32,
        initial_delay_ms: u64,
        max_delay_ms: u64,
    },

    /// Fall back to a safer action
    FallbackAction { action: NeutralizeAction },

    /// Quarantine the content
    Quarantine,

    /// Mark as unsafe and skip
    SkipAndMark,
}

/// Configuration for neutralization recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Enable recovery mechanisms
    pub enabled: bool,

    /// Default recovery strategy
    pub default_strategy: RecoveryStrategy,

    /// Per-threat-type strategies
    pub threat_strategies: std::collections::HashMap<String, RecoveryStrategy>,

    /// Maximum total recovery time
    pub max_recovery_time_ms: u64,

    /// Enable circuit breaker
    pub circuit_breaker_enabled: bool,

    /// Circuit breaker failure threshold
    pub failure_threshold: u32,

    /// Circuit breaker recovery timeout
    pub recovery_timeout_ms: u64,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_strategy: RecoveryStrategy::RetryWithBackoff {
                max_attempts: 3,
                initial_delay_ms: 100,
                max_delay_ms: 5000,
            },
            threat_strategies: Default::default(),
            max_recovery_time_ms: 30000,
            circuit_breaker_enabled: true,
            failure_threshold: 5,
            recovery_timeout_ms: 60000,
        }
    }
}

/// Recovery context for tracking state
pub struct RecoveryContext {
    pub attempt: u32,
    pub total_elapsed_ms: u64,
    pub last_error: Option<String>,
    pub fallback_used: bool,
}

/// Resilient neutralizer with error recovery
pub struct ResilientNeutralizer {
    inner: Arc<dyn ThreatNeutralizer>,
    config: RecoveryConfig,
    circuit_breaker: Arc<tokio::sync::Mutex<CircuitBreaker>>,
}

impl ResilientNeutralizer {
    pub fn new(neutralizer: Arc<dyn ThreatNeutralizer>, config: RecoveryConfig) -> Self {
        let circuit_breaker = Arc::new(tokio::sync::Mutex::new(CircuitBreaker::new(
            config.failure_threshold,
            Duration::from_millis(config.recovery_timeout_ms),
        )));

        Self {
            inner: neutralizer,
            config,
            circuit_breaker,
        }
    }

    /// Get recovery strategy for a threat type
    fn get_strategy(&self, threat_type: &str) -> &RecoveryStrategy {
        self.config
            .threat_strategies
            .get(threat_type)
            .unwrap_or(&self.config.default_strategy)
    }

    /// Execute recovery based on strategy
    async fn execute_recovery(
        &self,
        threat: &Threat,
        content: &str,
        strategy: &RecoveryStrategy,
        context: &mut RecoveryContext,
    ) -> Result<NeutralizeResult> {
        match strategy {
            RecoveryStrategy::RetryWithBackoff {
                max_attempts,
                initial_delay_ms,
                max_delay_ms,
            } => {
                self.retry_with_backoff(
                    threat,
                    content,
                    *max_attempts,
                    *initial_delay_ms,
                    *max_delay_ms,
                    context,
                )
                .await
            }

            RecoveryStrategy::FallbackAction { action } => {
                context.fallback_used = true;
                Ok(NeutralizeResult {
                    action_taken: *action,
                    sanitized_content: Some(self.apply_fallback_action(content, action)),
                    confidence_score: 0.5, // Lower confidence for fallback
                    processing_time_us: 1000,
                    correlation_data: None,
                    extracted_params: None,
                })
            }

            RecoveryStrategy::Quarantine => {
                context.fallback_used = true;
                Ok(NeutralizeResult {
                    action_taken: NeutralizeAction::Quarantined,
                    sanitized_content: Some("[CONTENT QUARANTINED]".to_string()),
                    confidence_score: 1.0,
                    processing_time_us: 100,
                    correlation_data: None,
                    extracted_params: None,
                })
            }

            RecoveryStrategy::SkipAndMark => Ok(NeutralizeResult {
                action_taken: NeutralizeAction::NoAction,
                sanitized_content: None,
                confidence_score: 0.0,
                processing_time_us: 0,
                correlation_data: None,
                extracted_params: None,
            }),
        }
    }

    /// Retry with exponential backoff
    async fn retry_with_backoff(
        &self,
        threat: &Threat,
        content: &str,
        max_attempts: u32,
        initial_delay_ms: u64,
        max_delay_ms: u64,
        context: &mut RecoveryContext,
    ) -> Result<NeutralizeResult> {
        let mut delay = initial_delay_ms;

        while context.attempt < max_attempts {
            context.attempt += 1;

            // Check if we've exceeded max recovery time
            if context.total_elapsed_ms > self.config.max_recovery_time_ms {
                return Err(anyhow::anyhow!("Max recovery time exceeded"));
            }

            // Wait before retry (except first attempt)
            if context.attempt > 1 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                context.total_elapsed_ms += delay;

                // Exponential backoff with jitter
                delay = (delay * 2).min(max_delay_ms);
                delay = delay + (delay / 4) * (rand::random::<u64>() % 3);
            }

            // Try neutralization
            match self.inner.neutralize(threat, content).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    context.last_error = Some(e.to_string());
                    tracing::warn!(
                        "Neutralization attempt {} failed for threat {:?}: {}",
                        context.attempt,
                        threat.threat_type,
                        e
                    );
                }
            }
        }

        Err(anyhow::anyhow!(
            "All {} retry attempts failed. Last error: {}",
            max_attempts,
            context.last_error.as_deref().unwrap_or("unknown")
        ))
    }

    /// Apply fallback action
    fn apply_fallback_action(&self, content: &str, action: &NeutralizeAction) -> String {
        match action {
            NeutralizeAction::Removed => String::new(),
            NeutralizeAction::Escaped => content
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&#x27;"),
            NeutralizeAction::Sanitized => content
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || c.is_whitespace())
                .collect(),
            _ => content.to_string(),
        }
    }
}

#[async_trait]
impl ThreatNeutralizer for ResilientNeutralizer {
    async fn neutralize(&self, threat: &Threat, content: &str) -> Result<NeutralizeResult> {
        // Check circuit breaker
        if self.config.circuit_breaker_enabled {
            let mut breaker = self.circuit_breaker.lock().await;
            if !breaker.allow_request() {
                return Err(anyhow::anyhow!("Circuit breaker open - too many failures"));
            }
        }

        let start = std::time::Instant::now();
        let mut context = RecoveryContext {
            attempt: 0,
            total_elapsed_ms: 0,
            last_error: None,
            fallback_used: false,
        };

        // First attempt
        match self.inner.neutralize(threat, content).await {
            Ok(result) => {
                // Record success
                if self.config.circuit_breaker_enabled {
                    let mut breaker = self.circuit_breaker.lock().await;
                    breaker.record_success();
                }
                Ok(result)
            }
            Err(e) if self.config.enabled => {
                // Record failure and try recovery
                if self.config.circuit_breaker_enabled {
                    let mut breaker = self.circuit_breaker.lock().await;
                    breaker.record_failure();
                }

                context.last_error = Some(e.to_string());
                context.total_elapsed_ms = start.elapsed().as_millis() as u64;

                let strategy = self.get_strategy(&format!("{:?}", threat.threat_type));
                self.execute_recovery(threat, content, strategy, &mut context)
                    .await
                    .context("Recovery failed after initial neutralization failure")
            }
            Err(e) => Err(e),
        }
    }

    fn can_neutralize(&self, threat_type: &crate::scanner::ThreatType) -> bool {
        self.inner.can_neutralize(threat_type)
    }

    fn get_capabilities(&self) -> crate::neutralizer::NeutralizerCapabilities {
        self.inner.get_capabilities()
    }

    async fn batch_neutralize(
        &self,
        threats: &[crate::scanner::Threat],
        content: &str,
    ) -> Result<crate::neutralizer::BatchNeutralizeResult> {
        // Delegate to inner neutralizer which has the sophisticated implementation
        self.inner.batch_neutralize(threats, content).await
    }
}

/// Simple circuit breaker implementation
struct CircuitBreaker {
    failure_count: u32,
    failure_threshold: u32,
    last_failure_time: Option<std::time::Instant>,
    recovery_timeout: Duration,
    state: CircuitState,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreaker {
    const fn new(failure_threshold: u32, recovery_timeout: Duration) -> Self {
        Self {
            failure_count: 0,
            failure_threshold,
            last_failure_time: None,
            recovery_timeout,
            state: CircuitState::Closed,
        }
    }

    fn allow_request(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if recovery timeout has passed
                if let Some(last_failure) = self.last_failure_time {
                    if last_failure.elapsed() > self.recovery_timeout {
                        self.state = CircuitState::HalfOpen;
                        true
                    } else {
                        false
                    }
                } else {
                    true
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    fn record_success(&mut self) {
        match self.state {
            CircuitState::HalfOpen => {
                // Recovery successful, close the circuit
                self.state = CircuitState::Closed;
                self.failure_count = 0;
                self.last_failure_time = None;
            }
            _ => {
                // Reset failure count on success
                if self.failure_count > 0 {
                    self.failure_count = self.failure_count.saturating_sub(1);
                }
            }
        }
    }

    fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(std::time::Instant::now());

        match self.state {
            CircuitState::Closed => {
                if self.failure_count >= self.failure_threshold {
                    self.state = CircuitState::Open;
                    tracing::warn!(
                        "Circuit breaker opened after {} failures",
                        self.failure_count
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Failed during recovery, reopen
                self.state = CircuitState::Open;
                tracing::warn!("Circuit breaker reopened after failure during recovery");
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neutralizer::standard::StandardNeutralizer;
    use crate::neutralizer::NeutralizationConfig;

    #[tokio::test]
    async fn test_resilient_neutralizer_retry() {
        // This would need a mock neutralizer that fails initially
        // For now, just test creation
        let config = NeutralizationConfig::default();
        let neutralizer = StandardNeutralizer::new(config);
        let recovery_config = RecoveryConfig::default();

        let resilient = ResilientNeutralizer::new(Arc::new(neutralizer), recovery_config);

        assert!(resilient.can_neutralize(&crate::scanner::ThreatType::SqlInjection));
    }
}
