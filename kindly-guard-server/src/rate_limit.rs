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
//! Rate limiting for MCP server requests
//! Implements token bucket algorithm with per-client and per-operation limits

use anyhow::Result;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Rate limiting configuration
///
/// # Security Implications
///
/// Rate limiting is essential for preventing abuse and DoS attacks:
/// - **Prevents brute force attacks** - Limits authentication attempts
/// - **Protects against resource exhaustion** - Controls request rates
/// - **Mitigates data harvesting** - Slows down automated scraping
/// - **Adaptive penalties** - Automatically restricts suspicious clients
///
/// # Example: Secure Production Configuration
///
/// ```toml
/// [rate_limit]
/// enabled = true
/// default_rpm = 60           # 1 request per second average
/// burst_capacity = 10        # Allow short bursts
/// cleanup_interval_secs = 300
/// adaptive = true            # Auto-adjust based on threats
/// threat_penalty_multiplier = 0.5  # Halve limits for threats
///
/// [rate_limit.method_limits]
/// "tools/list" = { rpm = 120, burst = 20 }     # Read operations
/// "tools/call" = { rpm = 30, burst = 5 }       # Execution operations
/// "security/neutralize" = { rpm = 10, burst = 2 }  # Sensitive operations
///
/// [rate_limit.client_limits]
/// "trusted-app" = { rpm = 300, burst = 50, priority = "high" }
/// "public-api" = { rpm = 30, burst = 5, priority = "low" }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    ///
    /// **Default**: false (for easier testing)
    /// **Security**: MUST be true in production to prevent abuse.
    /// Without rate limiting, attackers can overwhelm the service.
    /// **Warning**: Disabling exposes you to DoS and brute force attacks
    pub enabled: bool,

    /// Default requests per minute
    ///
    /// **Default**: 60 (1 per second average)
    /// **Security**: Lower values are more secure but may impact usability.
    /// Consider your threat model and legitimate usage patterns.
    /// **Range**: 10-600 (recommend 30-120 for most APIs)
    pub default_rpm: u32,

    /// Burst capacity (tokens available immediately)
    ///
    /// **Default**: 10
    /// **Security**: Allows legitimate burst traffic while preventing abuse.
    /// Too high enables rapid attacks; too low impacts user experience.
    /// **Range**: 1-50 (recommend 5-20, should be < default_rpm/6)
    pub burst_capacity: u32,

    /// Per-method rate limits (overrides default)
    ///
    /// **Default**: Sensible limits for common operations
    /// **Security**: Set stricter limits on sensitive operations.
    /// Read operations can have higher limits than write operations.
    /// **Best Practice**: Order from least to most sensitive
    pub method_limits: HashMap<String, MethodLimit>,

    /// Per-client rate limits (by client ID)
    ///
    /// **Default**: Empty (all clients use default limits)
    /// **Security**: Assign higher limits only to trusted clients.
    /// Use priority levels to ensure critical clients aren't blocked.
    /// **Warning**: Overly generous limits can be exploited
    pub client_limits: HashMap<String, ClientLimit>,

    /// Clean up interval for expired buckets (seconds)
    ///
    /// **Default**: 300 (5 minutes)
    /// **Security**: Regular cleanup prevents memory exhaustion.
    /// Shorter intervals use more CPU but free memory faster.
    /// **Range**: 60-3600 (recommend 300-900)
    pub cleanup_interval_secs: u64,

    /// Enable adaptive rate limiting based on load
    ///
    /// **Default**: false
    /// **Security**: Automatically tightens limits under attack.
    /// Reduces false positives during traffic spikes.
    /// **Trade-off**: Adds complexity but improves resilience
    pub adaptive: bool,

    /// Penalty for security threats (multiplier)
    ///
    /// **Default**: 0.5 (halve the rate limit)
    /// **Security**: Clients triggering security alerts get reduced limits.
    /// Helps contain attacks while allowing recovery for false positives.
    /// **Range**: 0.1-1.0 (0.1 = 90% reduction, 1.0 = no penalty)
    pub threat_penalty_multiplier: f32,
}

/// Method-specific rate limit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodLimit {
    pub rpm: u32,
    pub burst: u32,
}

/// Client-specific rate limit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientLimit {
    pub rpm: u32,
    pub burst: u32,
    pub priority: ClientPriority,
}

/// Client priority levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ClientPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Premium = 3,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        let mut method_limits = HashMap::new();

        // Higher limits for read operations
        method_limits.insert("tools/list".to_string(), MethodLimit { rpm: 60, burst: 10 });
        method_limits.insert(
            "resources/list".to_string(),
            MethodLimit { rpm: 60, burst: 10 },
        );

        // Lower limits for execution operations
        method_limits.insert("tools/call".to_string(), MethodLimit { rpm: 30, burst: 5 });

        // Very low limits for security-sensitive operations
        method_limits.insert(
            "security/threats".to_string(),
            MethodLimit { rpm: 10, burst: 2 },
        );

        Self {
            enabled: false,
            default_rpm: 60,
            burst_capacity: 10,
            method_limits,
            client_limits: HashMap::new(),
            cleanup_interval_secs: 300, // 5 minutes
            adaptive: false,
            threat_penalty_multiplier: 0.5, // Halve rate limit on threat detection
        }
    }
}

/// Token bucket for rate limiting
#[derive(Debug)]
struct TokenBucket {
    /// Maximum tokens (burst capacity)
    capacity: f64,

    /// Current tokens available
    tokens: f64,

    /// Refill rate (tokens per second)
    refill_rate: f64,

    /// Last refill time
    last_refill: Instant,

    /// Penalty factor (0.0 to 1.0, where 1.0 is normal)
    penalty_factor: f64,
}

impl TokenBucket {
    /// Create a new token bucket
    fn new(rpm: u32, burst: u32) -> Self {
        let capacity = f64::from(burst);
        let refill_rate = f64::from(rpm) / 60.0; // Convert RPM to tokens per second

        Self {
            capacity,
            tokens: capacity, // Start with full bucket
            refill_rate,
            last_refill: Instant::now(),
            penalty_factor: 1.0,
        }
    }

    /// Try to consume tokens
    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();

        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        // Add tokens based on refill rate and penalty factor
        let new_tokens = elapsed * self.refill_rate * self.penalty_factor;
        self.tokens = (self.tokens + new_tokens).min(self.capacity);
        self.last_refill = now;
    }

    /// Apply penalty (reduce refill rate temporarily)
    fn apply_penalty(&mut self, factor: f64) {
        self.penalty_factor = (self.penalty_factor * factor).max(0.1); // Min 10% rate
    }

    /// Get time until next token is available
    fn time_until_available(&self, tokens: f64) -> Duration {
        if self.tokens >= tokens {
            Duration::ZERO
        } else {
            let needed = tokens - self.tokens;
            let seconds = needed / (self.refill_rate * self.penalty_factor);
            Duration::from_secs_f64(seconds)
        }
    }
}

/// Rate limiter key
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct RateLimitKey {
    client_id: String,
    method: Option<String>,
}

/// Rate limiter
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<RwLock<HashMap<RateLimitKey, Arc<Mutex<TokenBucket>>>>>,
    last_cleanup: Arc<Mutex<Instant>>,
}

/// Rate limit result
#[derive(Debug)]
pub struct RateLimitResult {
    /// Whether the request is allowed
    pub allowed: bool,

    /// Remaining requests in current window
    pub remaining: u32,

    /// Time until rate limit resets
    pub reset_after: Duration,

    /// Current limit (requests per minute)
    pub limit: u32,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        let limiter = Self {
            config,
            buckets: Arc::new(RwLock::new(HashMap::new())),
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
        };

        // Start cleanup task if enabled
        if limiter.config.enabled && limiter.config.cleanup_interval_secs > 0 {
            let buckets = limiter.buckets.clone();
            let interval = limiter.config.cleanup_interval_secs;

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(interval));
                loop {
                    interval.tick().await;
                    Self::cleanup_buckets(buckets.clone()).await;
                }
            });
        }

        limiter
    }

    /// Check rate limit for a request
    pub async fn check_limit(
        &self,
        client_id: &str,
        method: Option<&str>,
        tokens: f64,
    ) -> Result<RateLimitResult> {
        if !self.config.enabled {
            return Ok(RateLimitResult {
                allowed: true,
                remaining: u32::MAX,
                reset_after: Duration::ZERO,
                limit: u32::MAX,
            });
        }

        // Get applicable limits
        let (rpm, burst) = self.get_limits(client_id, method);

        // Create key for this check
        let key = RateLimitKey {
            client_id: client_id.to_string(),
            method: method.map(String::from),
        };

        // Get or create bucket
        let bucket = self.get_or_create_bucket(&key, rpm, burst).await;

        // Try to consume tokens
        let mut bucket = bucket.lock();
        let allowed = bucket.try_consume(tokens);
        let remaining = bucket.tokens as u32;
        let reset_after = bucket.time_until_available(1.0);

        Ok(RateLimitResult {
            allowed,
            remaining,
            reset_after,
            limit: rpm,
        })
    }

    /// Apply penalty to a client (e.g., for security threats)
    pub async fn apply_penalty(&self, client_id: &str, factor: f64) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let buckets = self.buckets.read().await;

        // Apply penalty to all buckets for this client
        for (key, bucket) in buckets.iter() {
            if key.client_id == client_id {
                bucket.lock().apply_penalty(factor);
            }
        }

        Ok(())
    }

    /// Get rate limit status for a client
    pub async fn get_status(&self, client_id: &str) -> Result<HashMap<String, RateLimitResult>> {
        let mut status = HashMap::new();

        if !self.config.enabled {
            return Ok(status);
        }

        let buckets = self.buckets.read().await;

        for (key, bucket) in buckets.iter() {
            if key.client_id == client_id {
                let bucket = bucket.lock();
                let method = key.method.as_deref().unwrap_or("default");

                status.insert(
                    method.to_string(),
                    RateLimitResult {
                        allowed: bucket.tokens >= 1.0,
                        remaining: bucket.tokens as u32,
                        reset_after: bucket.time_until_available(1.0),
                        limit: (bucket.refill_rate * 60.0) as u32,
                    },
                );
            }
        }

        Ok(status)
    }

    /// Get or create a token bucket
    async fn get_or_create_bucket(
        &self,
        key: &RateLimitKey,
        rpm: u32,
        burst: u32,
    ) -> Arc<Mutex<TokenBucket>> {
        let mut buckets = self.buckets.write().await;

        buckets
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(TokenBucket::new(rpm, burst))))
            .clone()
    }

    /// Get applicable rate limits for a client/method
    fn get_limits(&self, client_id: &str, method: Option<&str>) -> (u32, u32) {
        // Check client-specific limits first
        if let Some(client_limit) = self.config.client_limits.get(client_id) {
            return (client_limit.rpm, client_limit.burst);
        }

        // Check method-specific limits
        if let Some(method) = method {
            if let Some(method_limit) = self.config.method_limits.get(method) {
                return (method_limit.rpm, method_limit.burst);
            }
        }

        // Use defaults
        (self.config.default_rpm, self.config.burst_capacity)
    }

    /// Clean up expired buckets
    async fn cleanup_buckets(buckets: Arc<RwLock<HashMap<RateLimitKey, Arc<Mutex<TokenBucket>>>>>) {
        let mut buckets = buckets.write().await;
        let now = Instant::now();

        // Remove buckets that haven't been used in 10 minutes
        buckets.retain(|_, bucket| {
            let bucket = bucket.lock();
            now.duration_since(bucket.last_refill) < Duration::from_secs(600)
        });
    }

    /// Create rate limit headers for HTTP responses
    pub fn create_headers(result: &RateLimitResult) -> HashMap<String, String> {
        let mut headers = HashMap::new();

        headers.insert("X-RateLimit-Limit".to_string(), result.limit.to_string());
        headers.insert(
            "X-RateLimit-Remaining".to_string(),
            result.remaining.to_string(),
        );
        headers.insert(
            "X-RateLimit-Reset".to_string(),
            (Instant::now() + result.reset_after)
                .duration_since(Instant::now())
                .as_secs()
                .to_string(),
        );

        if !result.allowed {
            headers.insert(
                "Retry-After".to_string(),
                result.reset_after.as_secs().to_string(),
            );
        }

        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(60, 10);

        // Should start with full capacity
        assert!(bucket.try_consume(10.0));
        assert!(!bucket.try_consume(1.0)); // Should be empty

        // Wait a bit and refill should work
        std::thread::sleep(Duration::from_millis(1100)); // 1.1 seconds
        bucket.refill();
        assert!(bucket.tokens > 0.0); // Should have ~1 token
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let config = RateLimitConfig {
            enabled: true,
            default_rpm: 60,
            burst_capacity: 10,
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);

        // Should allow burst
        for _ in 0..10 {
            let result = limiter.check_limit("test-client", None, 1.0).await.unwrap();
            assert!(result.allowed);
        }

        // Should be rate limited
        let result = limiter.check_limit("test-client", None, 1.0).await.unwrap();
        assert!(!result.allowed);
        assert!(result.reset_after > Duration::ZERO);
    }

    #[test]
    fn test_penalty_application() {
        let mut bucket = TokenBucket::new(60, 10);
        bucket.apply_penalty(0.5);

        // Refill rate should be halved
        assert_eq!(bucket.penalty_factor, 0.5);
    }
}
