// Copyright 2025 Kindly-Software
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
//! Output formatting for scan results

use colored::Colorize;
use comfy_table::{presets, ContentArrangement, Table};
use kindly_guard_server::{Severity, Threat};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
    Brief,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            "brief" => Ok(Self::Brief),
            _ => anyhow::bail!(
                "Invalid output format: {}. Valid options: table, json, brief",
                s
            ),
        }
    }
}

pub fn print_scan_results(
    results: &[(PathBuf, Vec<Threat>)],
    total_files: usize,
    total_threats: usize,
    duration: Duration,
    format: OutputFormat,
) {
    match format {
        OutputFormat::Table => print_table_results(results, total_files, total_threats, duration),
        OutputFormat::Json => print_json_results(results, total_files, total_threats, duration),
        OutputFormat::Brief => print_brief_results(results, total_files, total_threats, duration),
    }
}

fn print_table_results(
    results: &[(PathBuf, Vec<Threat>)],
    total_files: usize,
    total_threats: usize,
    duration: Duration,
) {
    println!("\n{}", "=== Scan Results ===".bold().cyan());

    if results.is_empty() {
        println!("\n{}", "✓ No threats detected!".green().bold());
    } else {
        println!(
            "\n{} threats found in {} files",
            total_threats.to_string().red().bold(),
            results.len()
        );

        for (path, threats) in results {
            println!(
                "\n{}: {} threats",
                path.display().to_string().yellow(),
                threats.len().to_string().red()
            );

            let mut table = Table::new();
            table
                .load_preset(presets::UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["Type", "Severity", "Location", "Description"]);

            for threat in threats {
                let severity_color = match threat.severity {
                    Severity::Critical => "red",
                    Severity::High => "yellow",
                    Severity::Medium => "blue",
                    Severity::Low => "white",
                };

                let location = match &threat.location {
                    kindly_guard_server::scanner::Location::Text { offset, length } => {
                        format!("offset: {offset}, len: {length}")
                    }
                    kindly_guard_server::scanner::Location::Json { path } => {
                        format!("JSON path: {path}")
                    }
                    kindly_guard_server::scanner::Location::Binary { offset } => {
                        format!("binary offset: {offset}")
                    }
                };

                table.add_row(vec![
                    threat.threat_type.to_string(),
                    format!("{:?}", threat.severity)
                        .color(severity_color)
                        .to_string(),
                    location,
                    threat.description.clone(),
                ]);
            }

            println!("{table}");

            // Print remediations
            let remediations: Vec<_> = threats
                .iter()
                .filter_map(|t| t.remediation.as_ref())
                .collect();

            if !remediations.is_empty() {
                println!("\n{}", "Suggested Remediations:".bold());
                for (i, remediation) in remediations.iter().enumerate() {
                    println!("  {}. {}", i + 1, remediation);
                }
            }
        }
    }

    // Print summary
    println!("\n{}", "=== Summary ===".bold().cyan());
    println!("Files scanned: {}", total_files.to_string().bright_blue());
    println!(
        "Threats found: {}",
        if total_threats > 0 {
            total_threats.to_string().red()
        } else {
            total_threats.to_string().green()
        }
    );
    println!("Scan duration: {:.2}s", duration.as_secs_f64());

    // Threat breakdown
    if !results.is_empty() {
        let mut threat_counts = std::collections::HashMap::new();
        for (_, threats) in results {
            for threat in threats {
                *threat_counts.entry(threat.threat_type.clone()).or_insert(0) += 1;
            }
        }

        println!("\n{}", "Threat Breakdown:".bold());
        for (threat_type, count) in threat_counts {
            println!("  {threat_type}: {count}");
        }
    }
}

fn print_json_results(
    results: &[(PathBuf, Vec<Threat>)],
    total_files: usize,
    total_threats: usize,
    duration: Duration,
) {
    let json_output = serde_json::json!({
        "summary": {
            "files_scanned": total_files,
            "threats_found": total_threats,
            "duration_ms": duration.as_millis(),
        },
        "results": results.iter().map(|(path, threats)| {
            serde_json::json!({
                "file": path.to_string_lossy(),
                "threat_count": threats.len(),
                "threats": threats,
            })
        }).collect::<Vec<_>>(),
    });

    println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
}

fn print_brief_results(
    results: &[(PathBuf, Vec<Threat>)],
    total_files: usize,
    total_threats: usize,
    duration: Duration,
) {
    if results.is_empty() {
        println!("{}", "✓ Clean".green().bold());
    } else {
        println!("{}", "✗ Threats detected".red().bold());
        for (path, threats) in results {
            println!("{}: {} threats", path.display(), threats.len());
        }
    }

    println!(
        "\nScanned {} files in {:.2}s | {} threats found",
        total_files,
        duration.as_secs_f64(),
        total_threats
    );
}
