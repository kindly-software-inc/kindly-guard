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
//! Example demonstrating distributed tracing with the neutralizer
//!
//! Run with: cargo run --example `neutralizer_tracing`

use anyhow::Result;
use std::sync::Arc;
// Direct imports since not all are re-exported in lib.rs
use kindly_guard_server::{
    neutralizer::{NeutralizationConfig, NeutralizationMode},
    scanner::{Location, Severity, Threat, ThreatType},
    telemetry::TelemetryConfig,
};

// Import from modules directly
use kindly_guard_server::neutralizer::create_neutralizer_with_telemetry;
use kindly_guard_server::telemetry::{
    distributed::{DistributedTracingProvider, ProbabilitySampler, W3CTraceContextPropagator},
    standard::StandardTelemetryProvider,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("=== KindlyGuard Neutralizer with Distributed Tracing Example ===\n");

    // Configure telemetry
    let telemetry_config = TelemetryConfig {
        enabled: true,
        service_name: "kindly-guard-example".to_string(),
        service_version: "1.0.0".to_string(),
        tracing_enabled: true,
        sampling_rate: 1.0, // Sample everything for demo
        ..Default::default()
    };

    // Create telemetry providers
    let base_provider = Arc::new(StandardTelemetryProvider::new(telemetry_config.clone()));
    let sampler = Arc::new(ProbabilitySampler::new(telemetry_config.sampling_rate));
    let propagator = Arc::new(W3CTraceContextPropagator);

    let tracing_provider = Arc::new(DistributedTracingProvider::new(
        base_provider,
        sampler,
        propagator,
    ));

    // Configure neutralization
    let neutralizer_config = NeutralizationConfig {
        mode: NeutralizationMode::Automatic,
        audit_all_actions: true,
        ..Default::default()
    };

    // Create neutralizer with tracing
    let neutralizer = create_neutralizer_with_telemetry(
        &neutralizer_config,
        None, // No rate limiter for example
        Some(tracing_provider.clone()),
    );

    println!("Neutralizer created with distributed tracing enabled\n");

    // Example 1: Single threat neutralization
    println!("Example 1: Neutralizing SQL injection");
    let sql_threat = Threat {
        threat_type: ThreatType::SqlInjection,
        severity: Severity::High,
        location: Location::Text {
            offset: 28,
            length: 15,
        },
        description: "SQL injection detected in query parameter".to_string(),
        remediation: Some("Use parameterized queries".to_string()),
    };

    let sql_content = "SELECT * FROM users WHERE id='1' OR '1'='1'";
    let result = neutralizer.neutralize(&sql_threat, sql_content).await?;

    println!("  Action taken: {}", result.action_taken);
    println!("  Confidence: {:.2}", result.confidence_score);
    if let Some(sanitized) = result.sanitized_content {
        println!("  Sanitized: {sanitized}");
    }
    println!("  Processing time: {}μs\n", result.processing_time_us);

    // Example 2: Batch neutralization
    println!("Example 2: Batch neutralization of multiple threats");
    let threats = vec![
        Threat {
            threat_type: ThreatType::UnicodeBiDi,
            severity: Severity::Medium,
            location: Location::Text {
                offset: 6,
                length: 3,
            },
            description: "BiDi override character detected".to_string(),
            remediation: None,
        },
        Threat {
            threat_type: ThreatType::CommandInjection,
            severity: Severity::High,
            location: Location::Text {
                offset: 20,
                length: 10,
            },
            description: "Command injection attempt".to_string(),
            remediation: None,
        },
        Threat {
            threat_type: ThreatType::PathTraversal,
            severity: Severity::High,
            location: Location::Text {
                offset: 35,
                length: 15,
            },
            description: "Path traversal attempt".to_string(),
            remediation: None,
        },
    ];

    let mixed_content = "Hello \u{202E}World; echo 'hack'; ../../etc/passwd";
    let batch_result = neutralizer
        .batch_neutralize(&threats, mixed_content)
        .await?;

    println!("  Total threats: {}", threats.len());
    println!(
        "  Successfully neutralized: {}",
        batch_result.individual_results.len()
    );
    println!("  Final content: {}", batch_result.final_content);
    println!();

    // Export and display trace information
    println!("Exporting trace data...");
    let exported_spans = tracing_provider.export_spans().await;

    println!("Exported {} spans:", exported_spans.len());
    for span in &exported_spans {
        let duration = span
            .end_time
            .map_or(0, |end| end.duration_since(span.start_time).as_millis());

        println!("  - {} ({}ms)", span.operation_name, duration);
        println!("    Trace ID: {}", &span.trace_id[..16]);
        println!("    Span ID: {}", &span.span_id[..16]);
        if let Some(parent) = &span.parent_span_id {
            println!("    Parent: {}", &parent[..16]);
        }
        println!("    Kind: {:?}", span.kind);
        println!("    Status: {:?}", span.status.code);

        if !span.events.is_empty() {
            println!("    Events:");
            for event in &span.events {
                println!("      - {}", event.name);
            }
        }

        if !span.links.is_empty() {
            println!("    Links: {} related spans", span.links.len());
        }

        println!();
    }

    // Example 3: Error case
    println!("Example 3: Neutralization with correlation data");
    let correlated_threat = Threat {
        threat_type: ThreatType::SqlInjection,
        severity: Severity::Critical,
        location: Location::Text {
            offset: 0,
            length: 50,
        },
        description: "Complex SQL injection with multiple vectors".to_string(),
        remediation: Some("Implement input validation and parameterized queries".to_string()),
    };

    let complex_sql = "'; DROP TABLE users; SELECT * FROM admin WHERE '1'='1";
    let correlated_result = neutralizer
        .neutralize(&correlated_threat, complex_sql)
        .await?;

    println!("  Action taken: {}", correlated_result.action_taken);
    if let Some(correlation) = &correlated_result.correlation_data {
        println!("  Attack pattern: {:?}", correlation.attack_pattern);
        println!("  Prediction score: {:.2}", correlation.prediction_score);
        println!("  Related threats: {}", correlation.related_threats.len());
    }

    // Final trace export
    println!("\nFinal trace summary:");
    let final_spans = tracing_provider.export_spans().await;
    let total_duration: u128 = final_spans
        .iter()
        .filter_map(|span| {
            span.end_time
                .map(|end| end.duration_since(span.start_time).as_millis())
        })
        .sum();

    println!("  Total spans: {}", final_spans.len());
    println!("  Total processing time: {total_duration}ms");
    println!(
        "  Average span duration: {:.2}ms",
        if final_spans.is_empty() {
            0.0
        } else {
            total_duration as f64 / final_spans.len() as f64
        }
    );

    println!("\n=== Example completed successfully ===");

    Ok(())
}
