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
//! Standard implementations of resilience traits
//! These provide solid reliability features for production use

use crate::resilience::circuit_breaker::{
    CircuitBreaker as BaseCircuitBreaker, CircuitBreakerConfig,
};
use crate::resilience::retry::{DefaultRetryPolicy, RetryBuilder, RetryConfig};
use crate::traits::{
    CircuitBreakerError, CircuitBreakerTrait, CircuitBreakerWrapper, CircuitState, CircuitStats,
    DynCircuitBreaker, DynRetryStrategy, HealthCheckMetadata,
    HealthCheckResult, HealthCheckTrait, HealthCheckType, HealthReport, HealthStatus,
    RecoveryContext, RecoveryState, RecoveryStats, RecoveryStrategyTrait, ResilienceFactory,
    RetryContext, RetryDecision, RetryStats, RetryStrategyTrait, RetryStrategyWrapper,
};
use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock as AsyncRwLock;

/// Standard circuit breaker implementation
pub struct StandardCircuitBreaker {
    breakers: RwLock<HashMap<String, Arc<BaseCircuitBreaker>>>,
    config: CircuitBreakerConfig,
}

impl StandardCircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            breakers: RwLock::new(HashMap::new()),
            config,
        }
    }

    fn get_or_create(&self, name: &str) -> Arc<BaseCircuitBreaker> {
        let breakers = self.breakers.read();
        if let Some(breaker) = breakers.get(name) {
            return breaker.clone();
        }
        drop(breakers);

        let mut breakers = self.breakers.write();
        breakers
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(BaseCircuitBreaker::new(name, self.config.clone())))
            .clone()
    }
}

#[async_trait]
impl CircuitBreakerTrait for StandardCircuitBreaker {
    async fn call<F, T, Fut>(&self, name: &str, f: F) -> Result<T, CircuitBreakerError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send,
    {
        let breaker = self.get_or_create(name);
        breaker.call(f).await.map_err(|e| match e {
            crate::resilience::circuit_breaker::CircuitBreakerError::CircuitOpen => {
                CircuitBreakerError::CircuitOpen
            }
            crate::resilience::circuit_breaker::CircuitBreakerError::ServiceError(msg) => {
                CircuitBreakerError::ServiceError(msg)
            }
            crate::resilience::circuit_breaker::CircuitBreakerError::Timeout(d) => {
                CircuitBreakerError::Timeout(d)
            }
        })
    }

    fn state(&self, name: &str) -> CircuitState {
        let breaker = self.get_or_create(name);
        match breaker.state() {
            crate::resilience::circuit_breaker::CircuitState::Closed => CircuitState::Closed,
            crate::resilience::circuit_breaker::CircuitState::Open => CircuitState::Open,
            crate::resilience::circuit_breaker::CircuitState::HalfOpen => CircuitState::HalfOpen,
        }
    }

    fn stats(&self, name: &str) -> CircuitStats {
        let breaker = self.get_or_create(name);
        let stats = breaker.stats();

        CircuitStats {
            state: self.state(name),
            failure_count: stats.failure_count,
            success_count: stats.success_count,
            total_requests: stats.total_requests,
            last_failure_time: None, // Not exposed in base implementation
            tokens_available: 0.0,   // Not applicable for standard
        }
    }

    async fn trip(&self, name: &str, reason: &str) {
        tracing::warn!("Manually tripping circuit '{}': {}", name, reason);
        // Standard implementation doesn't support manual tripping
        // Would need to trigger failures to open circuit
    }

    async fn reset(&self, name: &str) {
        tracing::info!("Manually resetting circuit '{}'", name);
        // Standard implementation doesn't support manual reset
        // Will reset based on timeout
    }
}

/// Standard retry strategy implementation
pub struct StandardRetryStrategy {
    config: RetryConfig,
    retry_budgets: RwLock<HashMap<String, u32>>,
    stats: RwLock<RetryStats>,
}

impl StandardRetryStrategy {
    pub fn new(config: RetryConfig) -> Self {
        Self {
            config,
            retry_budgets: RwLock::new(HashMap::new()),
            stats: RwLock::new(RetryStats {
                total_attempts: 0,
                successful_retries: 0,
                failed_retries: 0,
                retry_budget_remaining: 1000, // Default budget
            }),
        }
    }

    fn consume_budget(&self, operation: &str) -> bool {
        let mut budgets = self.retry_budgets.write();
        let budget = budgets.entry(operation.to_string()).or_insert(100);

        if *budget > 0 {
            *budget -= 1;
            true
        } else {
            false
        }
    }
}

#[async_trait]
impl RetryStrategyTrait for StandardRetryStrategy {
    async fn execute<F, T, Fut>(&self, operation: &str, f: F) -> Result<T>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: std::future::Future<Output = Result<T>> + Send,
        T: Send,
    {
        // Update stats
        self.stats.write().total_attempts += 1;

        // Check budget
        if !self.consume_budget(operation) {
            return Err(anyhow::anyhow!(
                "Retry budget exhausted for operation: {}",
                operation
            ));
        }

        let result = RetryBuilder::new()
            .max_attempts(self.config.max_attempts)
            .initial_delay(self.config.initial_delay)
            .max_delay(self.config.max_delay)
            .multiplier(self.config.multiplier)
            .jitter(self.config.jitter_factor)
            .policy(DefaultRetryPolicy)
            .run(operation, f)
            .await;

        // Update stats based on result
        let mut stats = self.stats.write();
        match &result {
            Ok(_) => {
                if stats.total_attempts > 1 {
                    stats.successful_retries += 1;
                }
            }
            Err(_) => {
                stats.failed_retries += 1;
            }
        }

        result
    }

    fn should_retry(&self, _error: &anyhow::Error, context: &RetryContext) -> RetryDecision {
        // Check if we've exceeded max attempts
        if context.attempts >= self.config.max_attempts {
            return RetryDecision {
                should_retry: false,
                delay: None,
                reason: "Max attempts exceeded".to_string(),
            };
        }

        // Check error category
        if !context.error_category.is_retryable {
            return RetryDecision {
                should_retry: false,
                delay: None,
                reason: format!(
                    "Error type {:?} is not retryable",
                    context.error_category.error_type
                ),
            };
        }

        // Calculate delay
        let base_delay = self.config.initial_delay;
        let multiplier = self.config.multiplier.powi(context.attempts as i32);
        let delay = base_delay.mul_f64(multiplier).min(self.config.max_delay);

        RetryDecision {
            should_retry: true,
            delay: Some(delay),
            reason: format!("Retrying after {delay:?} delay"),
        }
    }

    fn stats(&self) -> RetryStats {
        self.stats.read().clone()
    }
}

/// Standard resilience factory
pub struct StandardResilienceFactory;

impl ResilienceFactory for StandardResilienceFactory {
    fn create_circuit_breaker(
        &self,
        config: &crate::config::Config,
    ) -> Result<Arc<dyn DynCircuitBreaker>> {
        let cb_config = CircuitBreakerConfig {
            failure_threshold: config.resilience.circuit_breaker.failure_threshold,
            failure_window: config.resilience.circuit_breaker.failure_window,
            success_threshold: f64::from(config.resilience.circuit_breaker.success_threshold),
            recovery_timeout: config.resilience.circuit_breaker.recovery_timeout,
            request_timeout: config.resilience.circuit_breaker.request_timeout,
            half_open_max_requests: config.resilience.circuit_breaker.half_open_max_requests,
        };

        let breaker = StandardCircuitBreaker::new(cb_config);
        Ok(Arc::new(CircuitBreakerWrapper::new(breaker)))
    }

    fn create_retry_strategy(
        &self,
        config: &crate::config::Config,
    ) -> Result<Arc<dyn DynRetryStrategy>> {
        let retry_config = RetryConfig {
            max_attempts: config.resilience.retry.max_attempts,
            initial_delay: config.resilience.retry.initial_delay,
            max_delay: config.resilience.retry.max_delay,
            multiplier: config.resilience.retry.multiplier,
            jitter_factor: config.resilience.retry.jitter_factor,
            timeout: Some(config.resilience.retry.timeout),
        };

        let strategy = StandardRetryStrategy::new(retry_config);
        Ok(Arc::new(RetryStrategyWrapper::new(strategy)))
    }

    fn create_health_checker(
        &self,
        _config: &crate::config::Config,
    ) -> Result<Arc<dyn HealthCheckTrait>> {
        Ok(Arc::new(StandardHealthChecker::new()))
    }

    fn create_recovery_strategy(
        &self,
        _config: &crate::config::Config,
    ) -> Result<Arc<dyn RecoveryStrategyTrait>> {
        Ok(Arc::new(StandardRecoveryStrategy::new()))
    }
    
    fn create_bulkhead(
        &self,
        config: &crate::config::Config,
    ) -> Result<Arc<dyn crate::resilience::DynBulkhead>> {
        use crate::resilience::bulkhead::{BulkheadWrapper, StandardBulkhead};
        
        let bulkhead = StandardBulkhead::from_config(config);
        Ok(Arc::new(BulkheadWrapper::new(bulkhead)))
    }
}

/// Standard health checker implementation
pub struct StandardHealthChecker {
    dependencies: AsyncRwLock<HashMap<String, Arc<dyn HealthCheckTrait>>>,
    last_check: RwLock<Option<Instant>>,
    metadata: HealthCheckMetadata,
}

impl Default for StandardHealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardHealthChecker {
    pub fn new() -> Self {
        Self {
            dependencies: AsyncRwLock::new(HashMap::new()),
            last_check: RwLock::new(None),
            metadata: HealthCheckMetadata {
                name: "standard_health_check".to_string(),
                check_type: HealthCheckType::Liveness,
                timeout: Duration::from_secs(5),
                critical: true,
            },
        }
    }
}

#[async_trait]
impl HealthCheckTrait for StandardHealthChecker {
    async fn check(&self) -> Result<HealthStatus> {
        let start = Instant::now();
        *self.last_check.write() = Some(start);

        // Check all dependencies
        let deps = self.dependencies.read().await;
        let mut all_healthy = true;
        let mut has_degraded = false;

        for (name, checker) in deps.iter() {
            match tokio::time::timeout(Duration::from_secs(3), checker.check()).await {
                Ok(Ok(status)) => match status {
                    HealthStatus::Unhealthy => {
                        tracing::warn!("Dependency '{}' is unhealthy", name);
                        all_healthy = false;
                    }
                    HealthStatus::Degraded => {
                        tracing::info!("Dependency '{}' is degraded", name);
                        has_degraded = true;
                    }
                    HealthStatus::Healthy => {}
                },
                Ok(Err(e)) => {
                    tracing::error!("Health check failed for '{}': {}", name, e);
                    all_healthy = false;
                }
                Err(_) => {
                    tracing::error!("Health check timeout for '{}'", name);
                    all_healthy = false;
                }
            }
        }

        if !all_healthy {
            Ok(HealthStatus::Unhealthy)
        } else if has_degraded {
            Ok(HealthStatus::Degraded)
        } else {
            Ok(HealthStatus::Healthy)
        }
    }

    async fn detailed_check(&self) -> Result<HealthReport> {
        let start = Instant::now();
        let overall_status = self.check().await?;

        let mut checks = Vec::new();
        let deps = self.dependencies.read().await;

        for (name, checker) in deps.iter() {
            let check_start = Instant::now();
            let result = match tokio::time::timeout(Duration::from_secs(3), checker.check()).await {
                Ok(Ok(status)) => HealthCheckResult {
                    name: name.clone(),
                    status,
                    message: None,
                    metadata: serde_json::json!({
                        "latency_ms": check_start.elapsed().as_millis()
                    }),
                },
                Ok(Err(e)) => HealthCheckResult {
                    name: name.clone(),
                    status: HealthStatus::Unhealthy,
                    message: Some(e.to_string()),
                    metadata: serde_json::json!({}),
                },
                Err(_) => HealthCheckResult {
                    name: name.clone(),
                    status: HealthStatus::Unhealthy,
                    message: Some("Health check timeout".to_string()),
                    metadata: serde_json::json!({}),
                },
            };
            checks.push(result);
        }

        Ok(HealthReport {
            status: overall_status,
            checks,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            latency_ms: start.elapsed().as_millis() as u64,
        })
    }

    fn register_dependency(&self, name: String, checker: Arc<dyn HealthCheckTrait>) {
        // Since this is a sync method but we need async RwLock, we need to handle runtime context
        // Use std::mem::replace to swap with a temporary value to avoid lifetime issues
        use once_cell::sync::Lazy;
        use std::sync::Mutex;

        // Temporary storage for the dependency to add
        static PENDING_DEPS: Lazy<Mutex<Option<(String, Arc<dyn HealthCheckTrait>)>>> =
            Lazy::new(|| Mutex::new(None));

        // Store the dependency temporarily
        *PENDING_DEPS.lock().unwrap() = Some((name, checker));

        // Create or use existing runtime
        if let Ok(_handle) = tokio::runtime::Handle::try_current() {
            // We can't block_on from within a runtime, so we'll just panic with a helpful message
            panic!("register_dependency cannot be called from within an async runtime. Call it during initialization.");
        } else {
            // Not in a runtime, create a new one
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create runtime for register_dependency");

            // Take the pending dependency and insert it
            if let Some((dep_name, dep_checker)) = PENDING_DEPS.lock().unwrap().take() {
                rt.block_on(async {
                    self.dependencies
                        .write()
                        .await
                        .insert(dep_name, dep_checker);
                });
            }
        }
    }

    fn metadata(&self) -> HealthCheckMetadata {
        self.metadata.clone()
    }
}

/// Standard recovery strategy implementation
pub struct StandardRecoveryStrategy {
    state: RwLock<RecoveryState>,
    stats: RwLock<RecoveryStats>,
    cache: RwLock<HashMap<String, (Instant, Vec<u8>)>>,
    cache_ttl: Duration,
}

impl Default for StandardRecoveryStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl StandardRecoveryStrategy {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(RecoveryState::Normal),
            stats: RwLock::new(RecoveryStats {
                recoveries_attempted: 0,
                recoveries_succeeded: 0,
                fallbacks_used: 0,
                current_state: RecoveryState::Normal,
            }),
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    fn cleanup_cache(&self) {
        let now = Instant::now();
        self.cache
            .write()
            .retain(|_, (timestamp, _)| now.duration_since(*timestamp) < self.cache_ttl);
    }
}

#[async_trait]
impl RecoveryStrategyTrait for StandardRecoveryStrategy {
    async fn recover(
        &self,
        context: &RecoveryContext,
        operation_name: &str,
    ) -> Result<serde_json::Value> {
        // Update stats
        self.stats.write().recoveries_attempted += 1;
        *self.state.write() = RecoveryState::Recovering;

        // Check cache first
        let cache_key = format!("{}:{}", context.service_name, operation_name);
        if let Some((timestamp, data)) = self.cache.read().get(&cache_key) {
            if timestamp.elapsed() < self.cache_ttl {
                tracing::info!(
                    "Using cached recovery data for '{}' operation '{}'",
                    context.service_name,
                    operation_name
                );
                let mut stats = self.stats.write();
                stats.fallbacks_used += 1;
                stats.current_state = RecoveryState::Fallback;
                *self.state.write() = RecoveryState::Fallback;

                // Deserialize cached data
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
                    return Ok(value);
                }
            }
        }

        // No cache available - return error
        let mut stats = self.stats.write();
        stats.current_state = RecoveryState::Failed;
        *self.state.write() = RecoveryState::Failed;

        tracing::error!(
            "Recovery failed for service '{}' operation '{}': no fallback available",
            context.service_name,
            operation_name
        );

        Err(anyhow::anyhow!("Recovery failed: no fallback available"))
    }

    fn can_recover(&self, error: &anyhow::Error) -> bool {
        // Simple heuristic: check if error is recoverable
        let error_str = error.to_string().to_lowercase();

        // These errors are typically recoverable
        error_str.contains("timeout")
            || error_str.contains("connection")
            || error_str.contains("temporarily unavailable")
            || error_str.contains("503")
            || error_str.contains("502")
    }

    fn stats(&self) -> RecoveryStats {
        self.stats.read().clone()
    }

    async fn update_state(&self, state: RecoveryState) {
        let mut current_state = self.state.write();
        *current_state = state;
        self.stats.write().current_state = state;

        // Clean up cache periodically
        if matches!(state, RecoveryState::Normal) {
            self.cleanup_cache();
        }
    }
}
