use std::time::Duration;

use kindly_guard_shield_lib::{
    core::{Severity, Threat, ThreatType},
    ipc::{
        benchmark::IpcBenchmark,
        client::ShmClient,
        shm::{SharedMemoryIpc, ShmConfig},
    },
};
use tokio::time::sleep;
use tracing::{info, Level};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    info!("KindlyGuard Shared Memory IPC Demo");

    // Check if shared memory is available
    if !SharedMemoryIpc::is_available() {
        info!("Shared memory not available on this platform");
        return Ok(());
    }

    // Create a writer (server side)
    info!("Creating shared memory writer...");
    let mut writer = SharedMemoryIpc::new(ShmConfig::default())?;

    // Create a reader (client side)
    info!("Creating shared memory reader...");
    let reader = ShmClient::new()?;

    // Show initial stats
    let stats = reader.get_stats();
    info!("Initial stats: {:?}", stats);

    // Write some test threats
    info!("Writing test threats...");
    for i in 0..10 {
        let threat = Threat {
            id: format!("demo-{}", i),
            threat_type: match i % 4 {
                0 => ThreatType::UnicodeInvisible,
                1 => ThreatType::InjectionAttempt,
                2 => ThreatType::PathTraversal,
                _ => ThreatType::SuspiciousPattern,
            },
            severity: match i % 3 {
                0 => Severity::Low,
                1 => Severity::Medium,
                _ => Severity::High,
            },
            source: format!("demo-source-{}", i),
            details: format!("This is test threat number {}", i),
            blocked: i % 2 == 0,
            timestamp: chrono::Utc::now(),
            context: None,
        };

        writer.write_threat(&threat)?;
        info!("Wrote threat: {}", threat.id);
        
        // Small delay to simulate real-world timing
        sleep(Duration::from_millis(10)).await;
    }

    // Read threats
    info!("\nReading threats...");
    let mut count = 0;
    while let Some(threat) = reader.shm.read_threat()? {
        info!("Read threat: {} - {} ({:?})", 
            threat.id, 
            threat.details,
            threat.severity
        );
        count += 1;
    }
    info!("Total threats read: {}", count);

    // Show final stats
    let stats = reader.get_stats();
    info!("\nFinal stats: {:?}", stats);

    // Run latency benchmark
    info!("\nRunning latency benchmark...");
    let shm_transport = std::sync::Arc::new(parking_lot::Mutex::new(writer));
    let results = IpcBenchmark::benchmark_latency(shm_transport, 1000)?;
    
    info!("Benchmark Results:");
    info!("  Average latency: {:.2}μs", results.avg_latency_us);
    info!("  Min latency: {:.2}μs", results.min_latency_us);
    info!("  Max latency: {:.2}μs", results.max_latency_us);
    info!("  P99 latency: {:.2}μs", results.p99_latency_us);
    info!("  Throughput: {:.0} events/sec", results.throughput);
    
    if results.avg_latency_us < 100.0 {
        info!("✓ Achieved sub-100μs average latency!");
    }

    Ok(())
}

// To run this example:
// cargo run --example shm_demo