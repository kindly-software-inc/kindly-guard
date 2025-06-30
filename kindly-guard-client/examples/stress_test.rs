//! Stress testing example for performance validation

use anyhow::Result;
use kindly_guard_client::{
    ClientConfiguration, TestClient, MetricsCollectorImpl,
    MetricsCollector,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("🚀 Starting KindlyGuard stress test");

    // Stress test configuration
    let concurrent_clients = 10;
    let requests_per_client = 100;
    let test_duration = Duration::from_secs(30);

    // Test both modes
    for enhanced in [false, true] {
        let mode = if enhanced { "ENHANCED" } else { "STANDARD" };
        info!("\n{}", "=".repeat(50));
        info!("Stress testing {} mode", mode);
        info!("{}\n", "=".repeat(50));

        // Create config
        let config_content = format!(
            r#"[event_processor]
enabled = {}
buffer_size_mb = 50
max_endpoints = 10000
rate_limit = 10000.0

[rate_limit]
default_rpm = 1000
burst_size = 100

[shield]
enabled = false

[server]
stdio = true
"#,
            enhanced
        );

        let config_dir = tempfile::tempdir()?;
        let config_path = config_dir.path().join("config.toml");
        std::fs::write(&config_path, config_content)?;
        std::env::set_var("KINDLY_GUARD_CONFIG", config_path.to_str().unwrap());

        // Create shared metrics collector
        let metrics = Arc::new(MetricsCollectorImpl::new());

        // Start server
        let server_path = std::env::var("KINDLY_GUARD_SERVER")
            .unwrap_or_else(|_| "../target/release/kindly-guard".to_string());

        info!("Starting {} concurrent clients...", concurrent_clients);
        let start_time = Instant::now();

        // Create client tasks
        let mut tasks = JoinSet::new();

        for client_id in 0..concurrent_clients {
            let metrics_clone = metrics.clone();
            let server_path_clone = server_path.clone();
            
            tasks.spawn(async move {
                run_client_workload(
                    client_id,
                    server_path_clone,
                    requests_per_client,
                    metrics_clone,
                ).await
            });
        }

        // Wait for all clients to complete
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result {
                eprintln!("Client task failed: {}", e);
            }
        }

        let test_duration = start_time.elapsed();

        // Get metrics summary
        let summary = metrics.get_summary();
        
        info!("\n📊 Stress Test Results - {} mode", mode);
        info!("==================================");
        info!("Test duration: {:.2}s", test_duration.as_secs_f64());
        info!("Total requests: {}", summary.total_requests);
        info!("Requests/sec: {:.0}", summary.total_requests as f64 / test_duration.as_secs_f64());
        info!("Total errors: {}", summary.total_errors);
        info!("Error rate: {:.2}%", (summary.total_errors as f64 / summary.total_requests as f64) * 100.0);
        info!("Average latency: {:.2}ms", summary.avg_latency_ms);
        info!("P99 latency: {:.2}ms", summary.p99_latency_ms);
        
        if !summary.errors_by_type.is_empty() {
            info!("\nError breakdown:");
            for (error_type, count) in &summary.errors_by_type {
                info!("  {}: {}", error_type, count);
            }
        }

        // Performance expectations
        if enhanced {
            info!("\n⚡ Enhanced mode expectations:");
            info!("  - Should handle more requests/sec");
            info!("  - Lower average latency for event processing");
            info!("  - Better performance under load");
        }
    }

    info!("\n✅ Stress testing completed");
    Ok(())
}

async fn run_client_workload(
    client_id: usize,
    server_path: String,
    request_count: usize,
    metrics: Arc<MetricsCollectorImpl>,
) -> Result<()> {
    // Create client configuration
    let config = ClientConfiguration {
        endpoint: "stdio".to_string(),
        auth_token: Some(format!("stress-test-token-{}", client_id)),
        enable_signing: false,
        client_id: format!("stress-client-{}", client_id),
        signing_key: None,
    };

    // Connect client
    let mut client = TestClient::stdio(&server_path, config).await?;
    client.connect().await?;

    // Generate varied workload
    for i in 0..request_count {
        let start = Instant::now();
        
        // Mix of operations
        let operation = i % 4;
        let result = match operation {
            0 => {
                // Normal scan
                client.call_tool(
                    "scan_text",
                    serde_json::json!({
                        "text": format!("Normal text from client {} request {}", client_id, i)
                    })
                ).await
            }
            1 => {
                // Threat scan
                client.call_tool(
                    "scan_text",
                    serde_json::json!({
                        "text": "SELECT * FROM users WHERE 1=1"
                    })
                ).await
            }
            2 => {
                // Security info
                client.call_tool(
                    "get_security_info",
                    serde_json::json!({})
                ).await
            }
            _ => {
                // List tools
                client.list_tools().await.map(|_| serde_json::Value::Null)
            }
        };

        let duration = start.elapsed();

        // Record metrics
        match result {
            Ok(_) => {
                metrics.record_latency("call_tool", duration);
            }
            Err(e) => {
                metrics.record_latency("call_tool", duration);
                metrics.record_error("call_tool", &e.to_string());
            }
        }

        // Small delay to prevent overwhelming
        if i % 10 == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // Disconnect
    client.disconnect().await?;
    
    Ok(())
}