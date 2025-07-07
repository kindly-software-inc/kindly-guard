//! Example of using the Predictive Circuit Breaker
//!
//! Run with: cargo run --example predictive_circuit_breaker --features enhanced

use kindly_guard_server::config::Config;
use kindly_guard_server::enhanced_impl::resilience::predictive_circuit_breaker::PredictiveCircuitBreaker;
use kindly_guard_server::traits::CircuitBreakerTrait;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Create configuration with predictive circuit breaker enabled
    let mut config = Config::default();
    config.resilience.circuit_breaker.failure_threshold = 3;
    config.resilience.circuit_breaker.recovery_timeout = Duration::from_secs(5);
    config.resilience.circuit_breaker.predictive = Some(true);

    // Create the predictive circuit breaker
    let cb = PredictiveCircuitBreaker::new(&config);
    info!("Created predictive circuit breaker");

    // Simulate a service that starts healthy, then degrades
    let mut failure_rate = 0.0;
    
    for i in 0..50 {
        // Gradually increase failure rate
        if i > 10 {
            failure_rate = ((i - 10) as f64 / 30.0).min(0.9);
        }
        
        let result = cb.call("example-service", || async move {
            // Simulate service call with increasing failure rate
            if rand::random::<f64>() < failure_rate {
                sleep(Duration::from_millis(500)).await; // Slow failure
                Err::<String, _>("Service error".into())
            } else {
                sleep(Duration::from_millis(50)).await; // Normal response
                Ok("Success".to_string())
            }
        }).await;
        
        match result {
            Ok(_) => info!("Request {} succeeded", i),
            Err(e) => warn!("Request {} failed: {}", i, e),
        }
        
        // Check prediction metrics
        #[cfg(feature = "enhanced")]
        {
            if i % 10 == 0 {
                info!(
                    "Prediction confidence: {:.2}, Failure probability: {:.2}",
                    cb.prediction_confidence(),
                    cb.failure_probability()
                );
                
                let stats = cb.feature_stats();
                info!(
                    "Predictions: {} total, {} accurate",
                    stats.total_predictions,
                    stats.accurate_predictions
                );
            }
        }
        
        // Small delay between requests
        sleep(Duration::from_millis(100)).await;
    }
    
    info!("Example completed");
    Ok(())
}

#[cfg(not(feature = "enhanced"))]
fn main() {
    eprintln!("This example requires the 'enhanced' feature");
    eprintln!("Run with: cargo run --example predictive_circuit_breaker --features enhanced");
}