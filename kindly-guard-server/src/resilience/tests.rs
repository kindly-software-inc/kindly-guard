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
//! Tests for resilience features

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::traits::*;
    
    #[tokio::test]
    async fn test_resilience_components_creation() {
        let config = Config::default();
        
        // Test circuit breaker creation
        let circuit_breaker = crate::resilience::create_circuit_breaker(&config);
        assert!(circuit_breaker.is_ok(), "Failed to create circuit breaker");
        
        // Test retry strategy creation
        let retry_strategy = crate::resilience::create_retry_strategy(&config);
        assert!(retry_strategy.is_ok(), "Failed to create retry strategy");
        
        // Test bulkhead creation
        let bulkhead = crate::resilience::create_bulkhead(&config);
        assert!(bulkhead.is_ok(), "Failed to create bulkhead");
    }
    
    #[tokio::test]
    async fn test_circuit_breaker_protection() {
        let config = Config::default();
        let circuit_breaker = crate::resilience::create_circuit_breaker(&config).unwrap();
        
        // Test successful call
        let result = circuit_breaker
            .call_json(
                "test_operation",
                serde_json::json!({"test": "data"}),
            )
            .await;
        
        assert!(result.is_ok(), "Circuit breaker should allow calls when closed");
    }
    
    #[tokio::test]
    async fn test_bulkhead_isolation() {
        let config = Config::default();
        let bulkhead = crate::resilience::create_bulkhead(&config).unwrap();
        
        // Test capacity check
        assert!(
            bulkhead.has_capacity("test_bulkhead"),
            "Bulkhead should have capacity initially"
        );
        
        // Test execution
        let result = bulkhead
            .execute_json(
                "test_bulkhead",
                serde_json::json!({"test": "data"}),
            )
            .await;
        
        assert!(result.is_ok(), "Bulkhead should allow execution with capacity");
    }
    
    #[tokio::test]
    async fn test_retry_strategy() {
        let config = Config::default();
        let retry_strategy = crate::resilience::create_retry_strategy(&config).unwrap();
        
        // Test execution
        let result = retry_strategy
            .execute_json(
                "test_operation",
                serde_json::json!({"test": "data"}),
            )
            .await;
        
        assert!(result.is_ok(), "Retry strategy should execute successfully");
    }
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_standard_circuit_breaker() {
        let config = Config::default();
        let circuit_breaker = create_circuit_breaker(&config).unwrap();
        
        // Circuit should be closed initially
        assert_eq!(circuit_breaker.state("test"), CircuitState::Closed);
        
        // Successful call should work
        let result = circuit_breaker.call("test", || async {
            Ok::<_, anyhow::Error>("success")
        }).await;
        assert!(result.is_ok());
        
        // Multiple failures should open the circuit
        for _ in 0..5 {
            let _ = circuit_breaker.call("test", || async {
                Err::<String, _>(anyhow::anyhow!("failure"))
            }).await;
        }
        
        // Circuit should be open after failures
        let state = circuit_breaker.state("test");
        assert!(matches!(state, CircuitState::Open | CircuitState::HalfOpen));
    }
    
    #[tokio::test]
    async fn test_standard_health_check() {
        let config = Config::default();
        let health_checker = create_health_checker(&config).unwrap();
        
        // Should be healthy initially
        let status = health_checker.check().await.unwrap();
        assert_eq!(status, HealthStatus::Healthy);
        
        // Detailed check should work
        let report = health_checker.detailed_check().await.unwrap();
        assert_eq!(report.status, HealthStatus::Healthy);
        assert!(report.checks.is_empty()); // No dependencies registered
    }
    
    #[tokio::test]
    async fn test_standard_recovery() {
        let config = Config::default();
        let recovery = create_recovery_strategy(&config).unwrap();
        
        let context = RecoveryContext {
            failure_count: 1,
            last_error: "test error".to_string(),
            recovery_attempts: 0,
            service_name: "test_service".to_string(),
        };
        
        // Recovery with no cache should fail
        let result = recovery.recover(&context, "test_operation").await;
        assert!(result.is_err());
        
        // Should be able to check if recovery is possible
        let error = anyhow::anyhow!("connection timeout");
        assert!(recovery.can_recover(&error));
        
        let error = anyhow::anyhow!("401 unauthorized");
        assert!(!recovery.can_recover(&error));
    }
    
    #[tokio::test]
    async fn test_health_check_with_dependencies() {
        let config = Config::default();
        let main_checker = create_health_checker(&config).unwrap();
        let dep_checker = create_health_checker(&config).unwrap();
        
        // Register healthy dependency
        main_checker.register_dependency("database".to_string(), dep_checker.clone());
        
        // Should still be healthy
        let status = main_checker.check().await.unwrap();
        assert_eq!(status, HealthStatus::Healthy);
        
        // Detailed report should include dependency
        let report = main_checker.detailed_check().await.unwrap();
        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.checks[0].name, "database");
        assert_eq!(report.checks[0].status, HealthStatus::Healthy);
    }
    
    #[tokio::test] 
    async fn test_recovery_stats() {
        let config = Config::default();
        let recovery = create_recovery_strategy(&config).unwrap();
        
        // Initial stats should be zero
        let stats = recovery.stats();
        assert_eq!(stats.recoveries_attempted, 0);
        assert_eq!(stats.recoveries_succeeded, 0);
        assert_eq!(stats.fallbacks_used, 0);
        assert_eq!(stats.current_state, RecoveryState::Normal);
        
        // After failed recovery, stats should update
        let context = RecoveryContext {
            failure_count: 1,
            last_error: "test".to_string(),
            recovery_attempts: 1,
            service_name: "test".to_string(),
        };
        
        let _ = recovery.recover(&context, "op").await;
        
        let stats = recovery.stats();
        assert_eq!(stats.recoveries_attempted, 1);
        assert_eq!(stats.current_state, RecoveryState::Failed);
    }
}