//! Rate-limited neutralization wrapper
//!
//! Provides rate limiting for neutralization operations to prevent
//! denial of service through expensive neutralization requests.

use crate::{
    neutralizer::{NeutralizeResult, ThreatNeutralizer},
    scanner::Threat,
    traits::{RateLimitKey, RateLimiter},
};
use anyhow::{bail, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Rate limiting configuration for neutralization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeutralizationRateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,

    /// Maximum neutralizations per minute per client
    pub per_minute: u32,

    /// Maximum neutralizations per hour per client
    pub per_hour: u32,

    /// Maximum concurrent neutralizations per client
    pub max_concurrent: u32,

    /// Apply stricter limits for expensive operations
    pub strict_for_expensive: bool,

    /// Expensive operation threshold in content size (bytes)
    pub expensive_threshold: usize,

    /// Rate limit multiplier for expensive operations
    pub expensive_multiplier: f32,
}

impl Default for NeutralizationRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_minute: 60,
            per_hour: 1000,
            max_concurrent: 5,
            strict_for_expensive: true,
            expensive_threshold: 1024 * 100, // 100KB
            expensive_multiplier: 0.5,       // Half the rate for expensive ops
        }
    }
}

/// Rate-limited neutralizer wrapper
pub struct RateLimitedNeutralizer {
    inner: Arc<dyn ThreatNeutralizer>,
    rate_limiter: Arc<dyn RateLimiter>,
    config: NeutralizationRateLimitConfig,
    concurrent_operations: Arc<tokio::sync::Mutex<std::collections::HashMap<String, u32>>>,
}

impl RateLimitedNeutralizer {
    pub fn new(
        neutralizer: Arc<dyn ThreatNeutralizer>,
        rate_limiter: Arc<dyn RateLimiter>,
        config: NeutralizationRateLimitConfig,
    ) -> Self {
        Self {
            inner: neutralizer,
            rate_limiter,
            config,
            concurrent_operations: Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    /// Get client ID from the current context
    /// In production, this would come from the request context
    fn get_client_id(&self) -> String {
        // TODO: Get from actual context
        "anonymous".to_string()
    }

    /// Check if operation is expensive
    const fn is_expensive_operation(&self, content: &str) -> bool {
        content.len() > self.config.expensive_threshold
    }

    /// Apply rate limiting penalty for expensive operations
    async fn apply_expensive_penalty(&self, client_id: &str) -> Result<()> {
        if self.config.strict_for_expensive {
            self.rate_limiter
                .apply_penalty(client_id, self.config.expensive_multiplier)
                .await?;
        }
        Ok(())
    }

    /// Increment concurrent operations counter
    async fn increment_concurrent(&self, client_id: &str) -> Result<()> {
        let mut ops = self.concurrent_operations.lock().await;
        let count = ops.entry(client_id.to_string()).or_insert(0);

        if *count >= self.config.max_concurrent {
            bail!("Maximum concurrent neutralization operations exceeded");
        }

        *count += 1;
        Ok(())
    }

    /// Decrement concurrent operations counter
    async fn decrement_concurrent(&self, client_id: &str) {
        let mut ops = self.concurrent_operations.lock().await;
        if let Some(count) = ops.get_mut(client_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                ops.remove(client_id);
            }
        }
    }
}

#[async_trait]
impl ThreatNeutralizer for RateLimitedNeutralizer {
    async fn neutralize(&self, threat: &Threat, content: &str) -> Result<NeutralizeResult> {
        if !self.config.enabled {
            // Rate limiting disabled, pass through
            return self.inner.neutralize(threat, content).await;
        }

        let client_id = self.get_client_id();

        // Create rate limit key
        let key = RateLimitKey {
            client_id: client_id.clone(),
            method: Some("neutralize".to_string()),
        };

        // Check rate limit
        let decision = self.rate_limiter.check_rate_limit(&key).await?;

        if !decision.allowed {
            bail!(
                "Rate limit exceeded for neutralization. Reset in {:?}",
                decision.reset_after
            );
        }

        // Check and increment concurrent operations
        self.increment_concurrent(&client_id).await?;

        // Ensure we decrement on any exit path
        let _guard = ConcurrentGuard {
            concurrent_ops: self.concurrent_operations.clone(),
            client_id: client_id.clone(),
        };

        // Apply penalty for expensive operations
        if self.is_expensive_operation(content) {
            self.apply_expensive_penalty(&client_id).await?;

            tracing::debug!(
                "Applied rate limit penalty for expensive neutralization: {} bytes",
                content.len()
            );
        }

        // Record the request
        self.rate_limiter.record_request(&key).await?;

        // Perform neutralization
        let result = self.inner.neutralize(threat, content).await?;

        // If neutralization was particularly expensive, apply additional penalty
        if result.processing_time_us > 10_000_000 {
            // 10 seconds
            self.rate_limiter.apply_penalty(&client_id, 0.75).await?;

            tracing::warn!(
                "Applied additional penalty for slow neutralization: {}μs",
                result.processing_time_us
            );
        }

        Ok(result)
    }

    fn can_neutralize(&self, threat_type: &crate::scanner::ThreatType) -> bool {
        self.inner.can_neutralize(threat_type)
    }

    fn get_capabilities(&self) -> crate::neutralizer::NeutralizerCapabilities {
        let mut capabilities = self.inner.get_capabilities();

        // Indicate rate limiting is active
        if self.config.enabled {
            capabilities.real_time = false; // Rate limiting may introduce delays
        }

        capabilities
    }
}

/// RAII guard for decrementing concurrent operations
struct ConcurrentGuard {
    concurrent_ops: Arc<tokio::sync::Mutex<std::collections::HashMap<String, u32>>>,
    client_id: String,
}

impl Drop for ConcurrentGuard {
    fn drop(&mut self) {
        // Clone the values we need for the async task
        let concurrent_ops = self.concurrent_ops.clone();
        let client_id = self.client_id.clone();

        // Use tokio::spawn to run async cleanup
        tokio::spawn(async move {
            let mut ops = concurrent_ops.lock().await;
            if let Some(count) = ops.get_mut(&client_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ops.remove(&client_id);
                }
            }
        });
    }
}

/// Rate limit statistics for neutralization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeutralizationRateLimitStats {
    pub total_requests: u64,
    pub rate_limited_requests: u64,
    pub concurrent_limit_hits: u64,
    pub expensive_operations: u64,
    pub average_tokens_remaining: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neutralizer::standard::StandardNeutralizer;
    use crate::neutralizer::NeutralizationConfig;

    // Mock rate limiter for testing
    struct MockRateLimiter {
        allow: bool,
    }

    #[async_trait]
    impl RateLimiter for MockRateLimiter {
        async fn check_rate_limit(
            &self,
            _key: &crate::traits::RateLimitKey,
        ) -> Result<crate::traits::RateLimitDecision> {
            Ok(crate::traits::RateLimitDecision {
                allowed: self.allow,
                tokens_remaining: 10.0,
                reset_after: std::time::Duration::from_secs(60),
            })
        }

        async fn record_request(&self, _key: &crate::traits::RateLimitKey) -> Result<()> {
            Ok(())
        }

        async fn apply_penalty(&self, _client_id: &str, _factor: f32) -> Result<()> {
            Ok(())
        }

        fn get_stats(&self) -> crate::traits::RateLimiterStats {
            crate::traits::RateLimiterStats {
                requests_allowed: 100,
                requests_denied: 10,
                active_buckets: 5,
            }
        }
    }

    #[tokio::test]
    async fn test_rate_limited_neutralizer() {
        let config = NeutralizationConfig::default();
        let neutralizer = Arc::new(StandardNeutralizer::new(config));
        let rate_limiter = Arc::new(MockRateLimiter { allow: true });
        let rate_config = NeutralizationRateLimitConfig::default();

        let limited = RateLimitedNeutralizer::new(neutralizer, rate_limiter, rate_config);

        assert!(limited.can_neutralize(&crate::scanner::ThreatType::SqlInjection));
    }
}
