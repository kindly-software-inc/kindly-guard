//! Tests for resilience features

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::traits::*;
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