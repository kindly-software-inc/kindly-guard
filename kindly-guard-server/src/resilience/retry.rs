//! Retry logic with exponential backoff and jitter
//! 
//! Provides configurable retry policies for handling transient failures.

use std::time::Duration;
use anyhow::Result;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{debug, warn};

/// Retry policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,
    /// Initial delay before first retry
    pub initial_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Exponential backoff multiplier
    pub multiplier: f64,
    /// Jitter factor (0.0 - 1.0)
    pub jitter_factor: f64,
    /// Total timeout for all attempts
    pub timeout: Option<Duration>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
            jitter_factor: 0.1,
            timeout: Some(Duration::from_secs(30)),
        }
    }
}

/// Retry policy trait
pub trait RetryPolicy: Send + Sync {
    /// Determine if an error is retryable
    fn is_retryable(&self, error: &anyhow::Error) -> bool;
    
    /// Get delay for next retry attempt
    fn next_delay(&self, attempt: u32, config: &RetryConfig) -> Option<Duration>;
}

/// Default retry policy - retries all errors
pub struct DefaultRetryPolicy;

impl RetryPolicy for DefaultRetryPolicy {
    fn is_retryable(&self, _error: &anyhow::Error) -> bool {
        true
    }
    
    fn next_delay(&self, attempt: u32, config: &RetryConfig) -> Option<Duration> {
        if attempt > config.max_attempts {
            return None;
        }
        
        // Calculate exponential backoff (use attempt - 1 for 0-based power)
        let base_delay = config.initial_delay.as_millis() as f64
            * config.multiplier.powi((attempt - 1) as i32);
        
        // Cap at max delay
        let capped_delay = base_delay.min(config.max_delay.as_millis() as f64);
        
        // Add jitter
        let jitter_range = capped_delay * config.jitter_factor;
        let jitter = thread_rng().gen_range(-jitter_range..=jitter_range);
        let final_delay = (capped_delay + jitter).max(0.0) as u64;
        
        Some(Duration::from_millis(final_delay))
    }
}

// Implement RetryPolicy for Box<dyn RetryPolicy>
impl RetryPolicy for Box<dyn RetryPolicy> {
    fn is_retryable(&self, error: &anyhow::Error) -> bool {
        self.as_ref().is_retryable(error)
    }
    
    fn next_delay(&self, attempt: u32, config: &RetryConfig) -> Option<Duration> {
        self.as_ref().next_delay(attempt, config)
    }
}

/// HTTP retry policy - only retries specific status codes
pub struct HttpRetryPolicy {
    retryable_status_codes: Vec<u16>,
}

impl Default for HttpRetryPolicy {
    fn default() -> Self {
        Self {
            retryable_status_codes: vec![408, 429, 500, 502, 503, 504],
        }
    }
}

impl RetryPolicy for HttpRetryPolicy {
    fn is_retryable(&self, error: &anyhow::Error) -> bool {
        // Check if error contains HTTP status code information
        if let Some(status_code) = extract_status_code(error) {
            self.retryable_status_codes.contains(&status_code)
        } else {
            // Retry on network errors
            is_network_error(error)
        }
    }
    
    fn next_delay(&self, attempt: u32, config: &RetryConfig) -> Option<Duration> {
        DefaultRetryPolicy.next_delay(attempt, config)
    }
}

/// Execute a function with retry logic
pub async fn retry_with_backoff<F, T, Fut>(
    config: RetryConfig,
    policy: impl RetryPolicy,
    operation_name: &str,
    f: F,
) -> Result<T>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let start_time = std::time::Instant::now();
    let mut attempt = 0;
    
    loop {
        attempt += 1;
        debug!("Attempting {} (attempt {})", operation_name, attempt);
        
        // Check total timeout
        if let Some(timeout) = config.timeout {
            if start_time.elapsed() > timeout {
                warn!("Retry timeout exceeded for {}", operation_name);
                return Err(anyhow::anyhow!("Retry timeout exceeded"));
            }
        }
        
        match f().await {
            Ok(result) => {
                if attempt > 1 {
                    debug!("{} succeeded after {} attempts", operation_name, attempt);
                }
                return Ok(result);
            }
            Err(error) => {
                // Check if error is retryable
                if !policy.is_retryable(&error) {
                    warn!("{} failed with non-retryable error: {}", operation_name, error);
                    return Err(error);
                }
                
                // Check if we've exhausted attempts
                if attempt >= config.max_attempts {
                    warn!(
                        "{} failed after {} attempts: {}",
                        operation_name, attempt, error
                    );
                    return Err(error);
                }
                
                // Get delay for next retry
                if let Some(delay) = policy.next_delay(attempt, &config) {
                    warn!(
                        "{} failed (attempt {}), retrying in {:?}: {}",
                        operation_name, attempt, delay, error
                    );
                    sleep(delay).await;
                } else {
                    // This shouldn't happen since we check max_attempts above
                    warn!(
                        "{} failed after {} attempts: {}",
                        operation_name, attempt, error
                    );
                    return Err(error);
                }
            }
        }
    }
}

/// Retry builder for fluent API
pub struct RetryBuilder {
    config: RetryConfig,
    policy: Box<dyn RetryPolicy>,
}

impl RetryBuilder {
    /// Create a new retry builder
    pub fn new() -> Self {
        Self {
            config: RetryConfig::default(),
            policy: Box::new(DefaultRetryPolicy),
        }
    }
    
    /// Set maximum attempts
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.config.max_attempts = attempts;
        self
    }
    
    /// Set initial delay
    pub fn initial_delay(mut self, delay: Duration) -> Self {
        self.config.initial_delay = delay;
        self
    }
    
    /// Set maximum delay
    pub fn max_delay(mut self, delay: Duration) -> Self {
        self.config.max_delay = delay;
        self
    }
    
    /// Set backoff multiplier
    pub fn multiplier(mut self, multiplier: f64) -> Self {
        self.config.multiplier = multiplier;
        self
    }
    
    /// Set jitter factor
    pub fn jitter(mut self, factor: f64) -> Self {
        self.config.jitter_factor = factor.clamp(0.0, 1.0);
        self
    }
    
    /// Set total timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = Some(timeout);
        self
    }
    
    /// Set retry policy
    pub fn policy(mut self, policy: impl RetryPolicy + 'static) -> Self {
        self.policy = Box::new(policy);
        self
    }
    
    /// Execute with retry
    pub async fn run<F, T, Fut>(
        self,
        operation_name: &str,
        f: F,
    ) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        retry_with_backoff(self.config, self.policy, operation_name, f).await
    }
}

// Helper functions

fn extract_status_code(error: &anyhow::Error) -> Option<u16> {
    // This would need to be implemented based on your HTTP client
    // For now, return None
    None
}

fn is_network_error(error: &anyhow::Error) -> bool {
    // Check if error is related to network issues
    let error_str = error.to_string().to_lowercase();
    error_str.contains("connection") ||
    error_str.contains("timeout") ||
    error_str.contains("network") ||
    error_str.contains("dns")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    
    #[tokio::test]
    async fn test_retry_success_on_second_attempt() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();
        
        let result = RetryBuilder::new()
            .max_attempts(3)
            .initial_delay(Duration::from_millis(10))
            .run("test_operation", || {
                let attempts = attempts_clone.clone();
                async move {
                    let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                    if attempt == 0 {
                        Err(anyhow::anyhow!("First attempt fails"))
                    } else {
                        Ok("Success")
                    }
                }
            })
            .await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Success");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }
    
    #[tokio::test]
    async fn test_retry_exhausts_attempts() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();
        
        let result = RetryBuilder::new()
            .max_attempts(3)
            .initial_delay(Duration::from_millis(10))
            .run("test_operation", || {
                let attempts = attempts_clone.clone();
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    Err::<(), _>(anyhow::anyhow!("Always fails"))
                }
            })
            .await;
        
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }
    
    #[tokio::test]
    async fn test_exponential_backoff() {
        let config = RetryConfig {
            initial_delay: Duration::from_millis(100),
            multiplier: 2.0,
            jitter_factor: 0.0, // No jitter for predictable test
            ..Default::default()
        };
        
        let policy = DefaultRetryPolicy;
        
        // First retry: 100ms * 2^0 = 100ms
        let delay1 = policy.next_delay(1, &config).unwrap();
        assert_eq!(delay1, Duration::from_millis(100));
        
        // Second retry: 100ms * 2^1 = 200ms
        let delay2 = policy.next_delay(2, &config).unwrap();
        assert_eq!(delay2, Duration::from_millis(200));
    }
    
    #[tokio::test]
    async fn test_jitter() {
        let config = RetryConfig {
            initial_delay: Duration::from_millis(1000),
            multiplier: 1.0, // No exponential growth
            jitter_factor: 0.1, // 10% jitter
            ..Default::default()
        };
        
        let policy = DefaultRetryPolicy;
        
        // Get multiple delays and verify they're within jitter range
        for _ in 0..10 {
            let delay = policy.next_delay(1, &config).unwrap();
            let millis = delay.as_millis();
            // Should be 1000ms ± 10% (900-1100ms)
            assert!(millis >= 900 && millis <= 1100);
        }
    }
}