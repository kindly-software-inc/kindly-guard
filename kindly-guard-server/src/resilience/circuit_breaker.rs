//! Circuit breaker pattern implementation
//! 
//! Prevents cascading failures by monitoring error rates and temporarily
//! blocking requests to failing services.

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use anyhow::Result;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CircuitBreakerError {
    #[error("Circuit breaker is open")]
    CircuitOpen,
    
    #[error("Service call failed: {0}")]
    ServiceError(String),
    
    #[error("Timeout after {0:?}")]
    Timeout(Duration),
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitState {
    /// Circuit is closed - normal operation
    Closed,
    /// Circuit is open - all requests blocked
    Open,
    /// Circuit is half-open - testing if service recovered
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: u32,
    /// Time window for counting failures
    pub failure_window: Duration,
    /// Success rate required to close circuit (0.0 - 1.0)
    pub success_threshold: f64,
    /// How long to keep circuit open before testing
    pub recovery_timeout: Duration,
    /// Timeout for individual requests
    pub request_timeout: Duration,
    /// Maximum concurrent requests in half-open state
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            failure_window: Duration::from_secs(60),
            success_threshold: 0.8,
            recovery_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(10),
            half_open_max_requests: 3,
        }
    }
}

/// Circuit breaker implementation
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitState>>,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    total_requests: AtomicU64,
    last_failure_time: Arc<RwLock<Option<Instant>>>,
    last_state_change: Arc<RwLock<Instant>>,
    half_open_requests: AtomicU32,
    name: String,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            last_failure_time: Arc::new(RwLock::new(None)),
            last_state_change: Arc::new(RwLock::new(Instant::now())),
            half_open_requests: AtomicU32::new(0),
            name: name.into(),
        }
    }
    
    /// Get current circuit state
    pub fn state(&self) -> CircuitState {
        *self.state.read()
    }
    
    /// Get circuit breaker statistics
    pub fn stats(&self) -> CircuitBreakerStats {
        CircuitBreakerStats {
            state: self.state(),
            failure_count: self.failure_count.load(Ordering::Relaxed),
            success_count: self.success_count.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
        }
    }
    
    /// Execute a function with circuit breaker protection
    pub async fn call<F, T, Fut>(&self, f: F) -> Result<T, CircuitBreakerError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        
        // Check if we should allow the request
        if !self.should_allow_request() {
            return Err(CircuitBreakerError::CircuitOpen);
        }
        
        // Execute with timeout
        let result = tokio::time::timeout(self.config.request_timeout, f()).await;
        
        match result {
            Ok(Ok(value)) => {
                self.on_success();
                Ok(value)
            }
            Ok(Err(e)) => {
                self.on_failure();
                Err(CircuitBreakerError::ServiceError(e.to_string()))
            }
            Err(_) => {
                self.on_failure();
                Err(CircuitBreakerError::Timeout(self.config.request_timeout))
            }
        }
    }
    
    /// Check if request should be allowed
    fn should_allow_request(&self) -> bool {
        let state = *self.state.read();
        
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if we should transition to half-open
                let last_change = *self.last_state_change.read();
                if last_change.elapsed() >= self.config.recovery_timeout {
                    self.transition_to(CircuitState::HalfOpen);
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests in half-open state
                let current = self.half_open_requests.fetch_add(1, Ordering::SeqCst);
                current < self.config.half_open_max_requests
            }
        }
    }
    
    /// Handle successful request
    fn on_success(&self) {
        self.success_count.fetch_add(1, Ordering::Relaxed);
        
        let state = *self.state.read();
        match state {
            CircuitState::HalfOpen => {
                // Check if we should close the circuit
                let success = self.success_count.load(Ordering::Relaxed);
                let failure = self.failure_count.load(Ordering::Relaxed);
                let total = success + failure;
                
                if total > 0 {
                    let success_rate = success as f64 / total as f64;
                    if success_rate >= self.config.success_threshold {
                        self.transition_to(CircuitState::Closed);
                    }
                }
            }
            _ => {}
        }
    }
    
    /// Handle failed request
    fn on_failure(&self) {
        self.failure_count.fetch_add(1, Ordering::Relaxed);
        *self.last_failure_time.write() = Some(Instant::now());
        
        let state = *self.state.read();
        match state {
            CircuitState::Closed => {
                // Check if we should open the circuit
                let failures = self.failure_count.load(Ordering::Relaxed);
                if failures >= self.config.failure_threshold {
                    // Check if failures are within the time window
                    if let Some(first_failure) = *self.last_failure_time.read() {
                        if first_failure.elapsed() <= self.config.failure_window {
                            self.transition_to(CircuitState::Open);
                        } else {
                            // Reset counters if outside window
                            self.reset_counters();
                        }
                    }
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open state opens the circuit
                self.transition_to(CircuitState::Open);
            }
            _ => {}
        }
    }
    
    /// Transition to a new state
    fn transition_to(&self, new_state: CircuitState) {
        let mut state = self.state.write();
        if *state != new_state {
            tracing::info!(
                "Circuit breaker '{}' transitioning from {:?} to {:?}",
                self.name, *state, new_state
            );
            *state = new_state;
            *self.last_state_change.write() = Instant::now();
            
            // Reset counters on state change
            if new_state == CircuitState::Closed {
                self.reset_counters();
            } else if new_state == CircuitState::HalfOpen {
                self.half_open_requests.store(0, Ordering::SeqCst);
                self.success_count.store(0, Ordering::SeqCst);
                self.failure_count.store(0, Ordering::SeqCst);
            }
        }
    }
    
    /// Reset internal counters
    fn reset_counters(&self) {
        self.failure_count.store(0, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
        self.half_open_requests.store(0, Ordering::SeqCst);
        *self.last_failure_time.write() = None;
    }
}

/// Circuit breaker statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerStats {
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
    pub total_requests: u64,
}

/// Circuit breaker registry for managing multiple breakers
pub struct CircuitBreakerRegistry {
    breakers: RwLock<std::collections::HashMap<String, Arc<CircuitBreaker>>>,
    default_config: CircuitBreakerConfig,
}

impl CircuitBreakerRegistry {
    /// Create a new registry
    pub fn new(default_config: CircuitBreakerConfig) -> Self {
        Self {
            breakers: RwLock::new(std::collections::HashMap::new()),
            default_config,
        }
    }
    
    /// Get or create a circuit breaker
    pub fn get_or_create(&self, name: &str) -> Arc<CircuitBreaker> {
        let breakers = self.breakers.read();
        if let Some(breaker) = breakers.get(name) {
            return breaker.clone();
        }
        drop(breakers);
        
        // Create new breaker
        let mut breakers = self.breakers.write();
        breakers.entry(name.to_string())
            .or_insert_with(|| {
                Arc::new(CircuitBreaker::new(name, self.default_config.clone()))
            })
            .clone()
    }
    
    /// Get all circuit breaker stats
    pub fn all_stats(&self) -> Vec<(String, CircuitBreakerStats)> {
        self.breakers.read()
            .iter()
            .map(|(name, breaker)| (name.clone(), breaker.stats()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_circuit_breaker_normal_operation() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let breaker = CircuitBreaker::new("test", config);
        
        // Should allow requests when closed
        assert_eq!(breaker.state(), CircuitState::Closed);
        
        // Successful call
        let result = breaker.call(|| async { Ok::<_, anyhow::Error>("success") }).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
    }
    
    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            ..Default::default()
        };
        let breaker = CircuitBreaker::new("test", config);
        
        // First failure
        let _ = breaker.call(|| async { 
            Err::<String, _>(anyhow::anyhow!("failure"))
        }).await;
        assert_eq!(breaker.state(), CircuitState::Closed);
        
        // Second failure - should open
        let _ = breaker.call(|| async {
            Err::<String, _>(anyhow::anyhow!("failure"))
        }).await;
        assert_eq!(breaker.state(), CircuitState::Open);
        
        // Further requests should be blocked
        let result = breaker.call(|| async {
            Ok::<_, anyhow::Error>("should not execute")
        }).await;
        assert!(matches!(result, Err(CircuitBreakerError::CircuitOpen)));
    }
    
    #[tokio::test] 
    async fn test_circuit_breaker_half_open_recovery() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_millis(100),
            half_open_max_requests: 1,
            ..Default::default()
        };
        let breaker = CircuitBreaker::new("test", config);
        
        // Open the circuit
        let _ = breaker.call(|| async {
            Err::<String, _>(anyhow::anyhow!("failure"))
        }).await;
        assert_eq!(breaker.state(), CircuitState::Open);
        
        // Wait for recovery timeout
        sleep(Duration::from_millis(150)).await;
        
        // Should transition to half-open and allow one request
        let result = breaker.call(|| async {
            Ok::<_, anyhow::Error>("recovered")
        }).await;
        assert!(result.is_ok());
        
        // Should transition to closed after success
        assert_eq!(breaker.state(), CircuitState::Closed);
    }
}