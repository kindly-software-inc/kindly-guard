//! Simple performance test comparing standard and enhanced modes

use std::time::Instant;
use kindly_guard_server::{
    config::Config,
    component_selector::ComponentManager,
    traits::{SecurityEvent, RateLimitKey},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 KindlyGuard Performance Test");
    println!("================================\n");

    // Test configuration
    let test_iterations = 1000;
    let test_clients = 10;

    // Test Standard Mode
    println!("Testing STANDARD mode...");
    let standard_config = create_config(false);
    let standard_results = run_test(&standard_config, test_iterations, test_clients).await?;
    
    // Test Enhanced Mode  
    println!("\nTesting ENHANCED mode...");
    let enhanced_config = create_config(true);
    let enhanced_results = run_test(&enhanced_config, test_iterations, test_clients).await?;

    // Print results
    println!("\n📊 Performance Comparison Results");
    println!("==================================");
    println!("Test iterations: {}", test_iterations);
    println!("Test clients: {}", test_clients);
    println!();
    
    println!("STANDARD mode:");
    println!("  Event Processing: {:.2} ms/op", standard_results.event_time_ms);
    println!("  Rate Limiting: {:.2} ms/op", standard_results.rate_limit_time_ms);
    println!("  Scanner: {:.2} ms/op", standard_results.scanner_time_ms);
    println!();
    
    println!("ENHANCED mode:");
    println!("  Event Processing: {:.2} ms/op", enhanced_results.event_time_ms);
    println!("  Rate Limiting: {:.2} ms/op", enhanced_results.rate_limit_time_ms);
    println!("  Scanner: {:.2} ms/op", enhanced_results.scanner_time_ms);
    println!();
    
    println!("Performance Improvement:");
    let event_improvement = (standard_results.event_time_ms - enhanced_results.event_time_ms) / standard_results.event_time_ms * 100.0;
    let rate_improvement = (standard_results.rate_limit_time_ms - enhanced_results.rate_limit_time_ms) / standard_results.rate_limit_time_ms * 100.0;
    let scanner_improvement = (standard_results.scanner_time_ms - enhanced_results.scanner_time_ms) / standard_results.scanner_time_ms * 100.0;
    
    println!("  Event Processing: {:.1}% faster", event_improvement);
    println!("  Rate Limiting: {:.1}% faster", rate_improvement);
    println!("  Scanner: {:.1}% faster", scanner_improvement);

    Ok(())
}

struct TestResults {
    event_time_ms: f64,
    rate_limit_time_ms: f64,
    scanner_time_ms: f64,
}

fn create_config(enhanced: bool) -> Config {
    let mut config = Config::default();
    config.event_processor.enabled = enhanced;
    config.event_processor.buffer_size_mb = 10;
    config.event_processor.max_endpoints = 1000;
    config.event_processor.rate_limit = 10000.0;
    config
}

async fn run_test(config: &Config, iterations: usize, clients: usize) -> Result<TestResults, Box<dyn std::error::Error>> {
    let manager = ComponentManager::new(config)?;
    
    // Test event processing
    let start = Instant::now();
    let processor = manager.event_processor();
    for i in 0..iterations {
        let event = SecurityEvent {
            event_type: "request".to_string(),
            client_id: format!("client_{}", i % clients),
            timestamp: i as u64,
            metadata: serde_json::json!({
                "method": "test",
                "index": i
            }),
        };
        processor.process_event(event).await?;
    }
    let event_time_ms = start.elapsed().as_secs_f64() * 1000.0 / iterations as f64;
    
    // Test rate limiting
    let start = Instant::now();
    let rate_limiter = manager.rate_limiter();
    for i in 0..iterations {
        let key = RateLimitKey {
            client_id: format!("client_{}", i % clients),
            method: Some("test".to_string()),
        };
        rate_limiter.check_rate_limit(&key).await?;
    }
    let rate_limit_time_ms = start.elapsed().as_secs_f64() * 1000.0 / iterations as f64;
    
    // Test scanner
    let start = Instant::now();
    let scanner = manager.scanner();
    let test_data = b"SELECT * FROM users WHERE id = 1";
    for _ in 0..iterations {
        scanner.enhanced_scan(test_data)?;
    }
    let scanner_time_ms = start.elapsed().as_secs_f64() * 1000.0 / iterations as f64;
    
    Ok(TestResults {
        event_time_ms,
        rate_limit_time_ms,
        scanner_time_ms,
    })
}