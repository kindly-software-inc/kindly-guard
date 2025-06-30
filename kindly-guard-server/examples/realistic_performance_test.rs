//! Realistic performance test with warm-up phase

use std::time::Instant;
use kindly_guard_server::{
    config::Config,
    component_selector::ComponentManager,
    traits::{SecurityEvent, RateLimitKey},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 KindlyGuard Realistic Performance Test");
    println!("=========================================\n");

    // Test configuration
    let warmup_iterations = 100;
    let test_iterations = 10000;
    let test_clients = 100;

    // Test Standard Mode
    println!("Testing STANDARD mode...");
    let standard_config = create_config(false);
    let standard_manager = ComponentManager::new(&standard_config)?;
    
    // Warm up
    println!("  Warming up...");
    warmup(&standard_manager, warmup_iterations, test_clients).await?;
    
    // Run test
    println!("  Running test...");
    let standard_results = run_test(&standard_manager, test_iterations, test_clients).await?;
    
    // Test Enhanced Mode  
    println!("\nTesting ENHANCED mode...");
    let enhanced_config = create_config(true);
    let enhanced_manager = ComponentManager::new(&enhanced_config)?;
    
    // Warm up
    println!("  Warming up...");
    warmup(&enhanced_manager, warmup_iterations, test_clients).await?;
    
    // Run test
    println!("  Running test...");
    let enhanced_results = run_test(&enhanced_manager, test_iterations, test_clients).await?;

    // Print results
    println!("\n📊 Performance Comparison Results");
    println!("==================================");
    println!("Test iterations: {}", test_iterations);
    println!("Test clients: {}", test_clients);
    println!();
    
    println!("STANDARD mode:");
    println!("  Event Processing: {:.3} ms/op ({:.0} ops/sec)", 
        standard_results.event_time_ms, 
        1000.0 / standard_results.event_time_ms);
    println!("  Rate Limiting: {:.3} ms/op ({:.0} ops/sec)", 
        standard_results.rate_limit_time_ms,
        1000.0 / standard_results.rate_limit_time_ms);
    println!("  Scanner: {:.3} ms/op ({:.0} ops/sec)", 
        standard_results.scanner_time_ms,
        1000.0 / standard_results.scanner_time_ms);
    println!("  Total time: {:.2}s", standard_results.total_time_s);
    println!();
    
    println!("ENHANCED mode:");
    println!("  Event Processing: {:.3} ms/op ({:.0} ops/sec)", 
        enhanced_results.event_time_ms,
        1000.0 / enhanced_results.event_time_ms);
    println!("  Rate Limiting: {:.3} ms/op ({:.0} ops/sec)", 
        enhanced_results.rate_limit_time_ms,
        1000.0 / enhanced_results.rate_limit_time_ms);
    println!("  Scanner: {:.3} ms/op ({:.0} ops/sec)", 
        enhanced_results.scanner_time_ms,
        1000.0 / enhanced_results.scanner_time_ms);
    println!("  Total time: {:.2}s", enhanced_results.total_time_s);
    println!();
    
    println!("Performance Improvement (Enhanced vs Standard):");
    let event_improvement = calculate_improvement(standard_results.event_time_ms, enhanced_results.event_time_ms);
    let rate_improvement = calculate_improvement(standard_results.rate_limit_time_ms, enhanced_results.rate_limit_time_ms);
    let scanner_improvement = calculate_improvement(standard_results.scanner_time_ms, enhanced_results.scanner_time_ms);
    let total_improvement = calculate_improvement(standard_results.total_time_s, enhanced_results.total_time_s);
    
    println!("  Event Processing: {}", format_improvement(event_improvement));
    println!("  Rate Limiting: {}", format_improvement(rate_improvement));
    println!("  Scanner: {}", format_improvement(scanner_improvement));
    println!("  Overall: {}", format_improvement(total_improvement));
    
    // Validate enhanced mode is working
    if enhanced_manager.is_enhanced_mode() {
        println!("\n✅ Enhanced mode (with EventBuffer) confirmed active");
    }

    Ok(())
}

fn calculate_improvement(standard: f64, enhanced: f64) -> f64 {
    if standard > 0.0 {
        (standard - enhanced) / standard * 100.0
    } else {
        0.0
    }
}

fn format_improvement(improvement: f64) -> String {
    if improvement > 0.0 {
        format!("{:.1}% faster ⚡", improvement)
    } else if improvement < 0.0 {
        format!("{:.1}% slower", -improvement)
    } else {
        "No change".to_string()
    }
}

struct TestResults {
    event_time_ms: f64,
    rate_limit_time_ms: f64,
    scanner_time_ms: f64,
    total_time_s: f64,
}

fn create_config(enhanced: bool) -> Config {
    let mut config = Config::default();
    config.event_processor.enabled = enhanced;
    config.event_processor.buffer_size_mb = 10;
    config.event_processor.max_endpoints = 1000;
    config.event_processor.rate_limit = 10000.0;
    config
}

async fn warmup(manager: &ComponentManager, iterations: usize, clients: usize) -> Result<(), Box<dyn std::error::Error>> {
    let processor = manager.event_processor();
    let rate_limiter = manager.rate_limiter();
    let scanner = manager.scanner();
    
    // Warm up all components
    for i in 0..iterations {
        // Event processing
        let event = SecurityEvent {
            event_type: "warmup".to_string(),
            client_id: format!("warmup_client_{}", i % clients),
            timestamp: i as u64,
            metadata: serde_json::json!({}),
        };
        processor.process_event(event).await?;
        
        // Rate limiting
        let key = RateLimitKey {
            client_id: format!("warmup_client_{}", i % clients),
            method: Some("warmup".to_string()),
        };
        rate_limiter.check_rate_limit(&key).await?;
        
        // Scanner
        scanner.enhanced_scan(b"warmup data")?;
    }
    
    Ok(())
}

async fn run_test(manager: &ComponentManager, iterations: usize, clients: usize) -> Result<TestResults, Box<dyn std::error::Error>> {
    let total_start = Instant::now();
    
    // Test event processing
    let start = Instant::now();
    let processor = manager.event_processor();
    for i in 0..iterations {
        let event = SecurityEvent {
            event_type: if i % 10 == 0 { "auth_failure" } else { "request" }.to_string(),
            client_id: format!("client_{}", i % clients),
            timestamp: i as u64,
            metadata: serde_json::json!({
                "method": "test",
                "index": i,
                "suspicious": i % 50 == 0
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
            method: Some(if i % 5 == 0 { "expensive" } else { "test" }.to_string()),
        };
        rate_limiter.check_rate_limit(&key).await?;
    }
    let rate_limit_time_ms = start.elapsed().as_secs_f64() * 1000.0 / iterations as f64;
    
    // Test scanner with various payloads
    let start = Instant::now();
    let scanner = manager.scanner();
    let test_payloads = [
        b"SELECT * FROM users WHERE id = 1" as &[u8],
        b"normal request data",
        b"<script>alert('xss')</script>",
        b"'; DROP TABLE users; --",
        b"../../etc/passwd",
    ];
    
    for i in 0..iterations {
        let payload = test_payloads[i % test_payloads.len()];
        scanner.enhanced_scan(payload)?;
    }
    let scanner_time_ms = start.elapsed().as_secs_f64() * 1000.0 / iterations as f64;
    
    let total_time_s = total_start.elapsed().as_secs_f64();
    
    Ok(TestResults {
        event_time_ms,
        rate_limit_time_ms,
        scanner_time_ms,
        total_time_s,
    })
}