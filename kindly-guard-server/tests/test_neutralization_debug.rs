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
use anyhow::Result;
use kindly_guard_server::{
    config::Config,
    neutralizer::ThreatNeutralizer,
    scanner::{SecurityScanner, Severity},
    ScannerConfig,
};
use std::sync::Arc;

#[tokio::test]
async fn test_problematic_neutralization() -> Result<()> {
    // Enable debug logging
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    // Create scanner
    let scanner_config = ScannerConfig {
        unicode_detection: true,
        injection_detection: true,
        path_traversal_detection: true,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
        xss_detection: Some(true),
        enhanced_mode: Some(false),
        max_content_size: 5 * 1024 * 1024,
    };
    let scanner = Arc::new(SecurityScanner::new(scanner_config)?);

    // Create neutralizer
    let config = Config::default();
    let neutralizer =
        kindly_guard_server::neutralizer::create_neutralizer(&config.neutralization, None);

    // Test the problematic input
    let input = "'\u{200b} OR\u{200b} '1'='1'\u{200b} --a";
    println!("Testing input: {:?}", input);

    // Show the input with visible Unicode markers
    let visible_input: String = input
        .chars()
        .map(|c| match c {
            '\u{200b}' => "[ZWS]".to_string(),
            _ => c.to_string(),
        })
        .collect();
    println!("Visible representation: {}", visible_input);

    // Scan for threats
    let threats = scanner.scan_text(input)?;
    println!("\nDetected {} threats:", threats.len());
    for (i, threat) in threats.iter().enumerate() {
        println!(
            "  Threat {}: {:?} (severity: {:?})",
            i + 1,
            threat.threat_type,
            threat.severity
        );
        println!("    Description: {}", threat.description);
    }

    // Neutralize threats
    if !threats.is_empty() {
        println!("\nNeutralizing threats...");
        let batch_result = neutralizer.batch_neutralize(&threats, input).await?;

        println!("\nNeutralization results:");
        println!(
            "  Individual results: {}",
            batch_result.individual_results.len()
        );
        for (i, result) in batch_result.individual_results.iter().enumerate() {
            println!(
                "    Result {}: action={:?}, confidence={}",
                i + 1,
                result.action_taken,
                result.confidence_score
            );
        }

        println!("\nFinal content: {:?}", batch_result.final_content);

        // Show final content with visible Unicode markers
        let visible_final: String = batch_result
            .final_content
            .chars()
            .map(|c| match c {
                '\u{200b}' => "[ZWS]".to_string(),
                _ => c.to_string(),
            })
            .collect();
        println!("Visible final content: {}", visible_final);

        // Re-scan the neutralized content
        let final_threats = scanner.scan_text(&batch_result.final_content)?;
        println!("\nThreats in neutralized content: {}", final_threats.len());
        for (i, threat) in final_threats.iter().enumerate() {
            println!(
                "  Remaining threat {}: {:?} (severity: {:?})",
                i + 1,
                threat.threat_type,
                threat.severity
            );
            println!("    Description: {}", threat.description);
        }

        // Check if only low severity threats remain
        let high_severity_count = final_threats
            .iter()
            .filter(|t| !matches!(t.severity, Severity::Low))
            .count();

        if high_severity_count > 0 {
            println!(
                "\nERROR: {} high/medium/critical severity threats remain!",
                high_severity_count
            );
            panic!("High severity threats remain after neutralization");
        } else {
            println!("\nSUCCESS: All high severity threats neutralized!");
        }
    }

    Ok(())
}
