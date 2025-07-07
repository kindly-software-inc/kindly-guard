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

//! Enhanced security scanning with automatic neutralization and quarantine

use anyhow::Result;
use colored::Colorize;
use kindly_guard_server::{
    config::ScannerConfig,
    neutralizer::{ThreatNeutralizer, create_neutralizer, NeutralizationConfig},
    SecurityScanner, Threat, ThreatType,
};
use std::path::{Path, PathBuf};
use std::fs;
use chrono::Local;
use serde::{Serialize, Deserialize};

use crate::messages::Messages;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub neutralize: bool,
    pub quarantine: bool,
    pub interactive: bool,
    pub backup_original: bool,
    pub output_path: Option<String>,
    pub format: String,
    pub mode: ProtectionMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProtectionMode {
    AutoProtect,
    Interactive,
    ReportOnly,
}

#[derive(Debug, Serialize)]
pub enum ScanResult {
    Clean,
    Protected {
        original_threats: Vec<Threat>,
        neutralized_content: String,
        quarantine_id: Option<String>,
        actions_taken: Vec<(ThreatType, String)>,
    },
    ReportOnly {
        threats: Vec<Threat>,
    },
}

#[derive(Serialize, Deserialize)]
struct QuarantineManifest {
    id: String,
    timestamp: String,
    source_file: Option<String>,
    threat_count: usize,
    threats: Vec<Threat>,
    neutralized: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            neutralize: true,
            quarantine: true,
            interactive: false,
            backup_original: true,
            output_path: None,
            format: "text".to_string(),
            mode: ProtectionMode::AutoProtect,
        }
    }
}

/// Legacy function for backward compatibility
pub async fn run_scan(path: &str, format: &str, _recursive: bool) -> Result<()> {
    let options = ScanOptions {
        format: format.to_string(),
        mode: ProtectionMode::ReportOnly, // Legacy behavior
        ..Default::default()
    };
    
    run_scan_enhanced(path, options).await
}

/// Run enhanced security scan with protection
pub async fn run_scan_enhanced(path: &str, options: ScanOptions) -> Result<()> {
    // Display protection mode
    match options.mode {
        ProtectionMode::AutoProtect => println!("{}", Messages::protection_mode_info("auto")),
        ProtectionMode::Interactive => println!("{}", Messages::protection_mode_info("interactive")),
        ProtectionMode::ReportOnly => println!("{}", Messages::protection_mode_info("report")),
    }
    println!();
    
    // Show scanning progress
    println!("{}", Messages::scanning_progress(path));
    
    // Create scanner and neutralizer
    let scanner_config = ScannerConfig::default();
    let scanner = SecurityScanner::new(scanner_config)?;
    let neutralizer_config = NeutralizationConfig::default();
    let neutralizer = create_neutralizer(&neutralizer_config, None);
    
    // Determine if input is stdin, file, or text
    let (content, source_file) = if path == "-" {
        // Read from stdin
        let mut buffer = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buffer)?;
        (buffer, None)
    } else if Path::new(path).exists() {
        // Read from file
        let content = fs::read_to_string(path)?;
        (content, Some(path.to_string()))
    } else {
        // Treat as direct text input
        (path.to_string(), None)
    };
    
    // Scan and protect
    let result = scan_with_protection(
        &scanner,
        neutralizer.as_ref(),
        &content,
        &options,
        source_file.as_deref(),
    ).await?;
    
    // Display results
    display_enhanced_results(&result, &options, source_file.as_deref())?;
    
    // Save output if requested
    if let Some(output_path) = &options.output_path {
        save_output(&result, output_path)?;
    }
    
    Ok(())
}

async fn scan_with_protection(
    scanner: &SecurityScanner,
    neutralizer: &dyn ThreatNeutralizer,
    content: &str,
    options: &ScanOptions,
    source_file: Option<&str>,
) -> Result<ScanResult> {
    // 1. Scan for threats
    let threats = scanner.scan_text(content)?;
    
    if threats.is_empty() {
        return Ok(ScanResult::Clean);
    }
    
    // 2. Handle based on protection mode
    match options.mode {
        ProtectionMode::ReportOnly => {
            Ok(ScanResult::ReportOnly { threats })
        }
        ProtectionMode::AutoProtect => {
            protect_content(&scanner, neutralizer, content, threats, options, source_file).await
        }
        ProtectionMode::Interactive => {
            protect_interactive(neutralizer, content, threats, options, source_file).await
        }
    }
}

async fn protect_content(
    scanner: &SecurityScanner,
    neutralizer: &dyn ThreatNeutralizer,
    content: &str,
    threats: Vec<Threat>,
    options: &ScanOptions,
    source_file: Option<&str>,
) -> Result<ScanResult> {
    println!("{}", Messages::neutralizing_threats(threats.len()));
    
    // Quarantine original if enabled
    let quarantine_id = if options.quarantine {
        println!("{}", Messages::creating_quarantine());
        Some(quarantine_content(content, &threats, source_file)?)
    } else {
        None
    };
    
    // Neutralize threats
    let mut neutralized = content.to_string();
    let mut actions_taken = Vec::new();
    
    for threat in &threats {
        match neutralizer.neutralize(threat, &neutralized).await? {
            result => {
                if let Some(ref sanitized) = result.sanitized_content {
                    let action = format!("{:?}", result.action_taken);
                    actions_taken.push((threat.threat_type.clone(), action));
                    neutralized = sanitized.clone();
                } else {
                    // Threat couldn't be neutralized, log it
                    eprintln!("Warning: Could not neutralize {:?}", threat.threat_type);
                }
            }
        }
    }
    
    // Re-scan to verify
    let remaining_threats = scanner.scan_text(&neutralized)?;
    if !remaining_threats.is_empty() {
        eprintln!("Warning: {} threats remain after neutralization", remaining_threats.len());
    }
    
    Ok(ScanResult::Protected {
        original_threats: threats,
        neutralized_content: neutralized,
        quarantine_id,
        actions_taken,
    })
}

async fn protect_interactive(
    neutralizer: &dyn ThreatNeutralizer,
    content: &str,
    threats: Vec<Threat>,
    options: &ScanOptions,
    source_file: Option<&str>,
) -> Result<ScanResult> {
    use std::io::{self, Write};
    
    let mut neutralized = content.to_string();
    let mut actions_taken = Vec::new();
    let mut neutralize_count = 0;
    
    for threat in &threats {
        print!("{}", Messages::interactive_threat_prompt(
            &threat.threat_type,
            &format!("{:?}", threat.location)
        ));
        io::stdout().flush()?;
        
        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        
        if response.trim().to_lowercase() != "n" {
            match neutralizer.neutralize(threat, &neutralized).await? {
                result => {
                    if let Some(ref sanitized) = result.sanitized_content {
                        let action = format!("{:?}", result.action_taken);
                        actions_taken.push((threat.threat_type.clone(), action));
                        neutralized = sanitized.clone();
                        neutralize_count += 1;
                    } else {
                        eprintln!("Warning: Could not neutralize {:?}", threat.threat_type);
                    }
                }
            }
        }
    }
    
    if neutralize_count == 0 {
        return Ok(ScanResult::ReportOnly { threats });
    }
    
    // Quarantine if any threats were neutralized
    let quarantine_id = if options.quarantine && neutralize_count > 0 {
        Some(quarantine_content(content, &threats, source_file)?)
    } else {
        None
    };
    
    Ok(ScanResult::Protected {
        original_threats: threats,
        neutralized_content: neutralized,
        quarantine_id,
        actions_taken,
    })
}

fn quarantine_content(content: &str, threats: &[Threat], source_file: Option<&str>) -> Result<String> {
    let quarantine_id = Uuid::new_v4().to_string();
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    
    // Create quarantine directory if it doesn't exist
    let quarantine_dir = PathBuf::from(".kindly-guard-quarantine");
    fs::create_dir_all(&quarantine_dir)?;
    
    // Save content
    let content_path = quarantine_dir.join(format!("{}_content.txt", quarantine_id));
    fs::write(&content_path, content)?;
    
    // Save manifest
    let manifest = QuarantineManifest {
        id: quarantine_id.clone(),
        timestamp,
        source_file: source_file.map(String::from),
        threat_count: threats.len(),
        threats: threats.to_vec(),
        neutralized: false,
    };
    
    let manifest_path = quarantine_dir.join(format!("{}_manifest.json", quarantine_id));
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    fs::write(&manifest_path, manifest_json)?;
    
    Ok(quarantine_id)
}

fn display_results(threats: &[Threat], format: &str, filename: Option<&str>) -> Result<()> {
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(threats)?;
            println!("{}", json);
        }
        "yaml" => {
            // TODO: Implement YAML output
            println!("YAML output not yet implemented");
        }
        _ => {
            // Text format
            if let Some(file) = filename {
                println!("File: {}", file.bright_white());
            }
            
            if threats.is_empty() {
                println!("{} No threats detected", "✅".bright_green());
            } else {
                println!("{} Found {} threat(s):", "⚠️".bright_red(), threats.len());
                for threat in threats {
                    println!();
                    println!("  {} {}", "•".red(), format!("{:?}", threat.threat_type).bright_red());
                    println!("    Severity: {}", format!("{:?}", threat.severity).bright_yellow());
                    println!("    Location: {}", format!("{:?}", threat.location).bright_cyan());
                    println!("    Description: {}", threat.description);
                    if let Some(remediation) = &threat.remediation {
                        println!("    Remediation: {}", remediation.bright_green());
                    }
                }
            }
        }
    }
    
    Ok(())
}

fn display_enhanced_results(result: &ScanResult, options: &ScanOptions, source_file: Option<&str>) -> Result<()> {
    match result {
        ScanResult::Clean => {
            println!("{}", Messages::clean_result());
        }
        ScanResult::Protected { 
            original_threats, 
            neutralized_content: _, 
            quarantine_id, 
            actions_taken 
        } => {
            println!("{}", Messages::protection_summary(
                original_threats.len(),
                actions_taken.len(),
                quarantine_id.is_some()
            ));
            
            if options.format == "json" {
                let json = serde_json::to_string_pretty(result)?;
                println!("{}", json);
            } else {
                for (threat_type, action) in actions_taken {
                    println!("  {} {}: {}", 
                        "•".bright_green(), 
                        format!("{:?}", threat_type).bright_yellow(),
                        action.bright_cyan()
                    );
                }
                
                if let Some(id) = quarantine_id {
                    println!("\n{}", Messages::quarantine_info(id));
                }
            }
        }
        ScanResult::ReportOnly { threats } => {
            display_results(threats, &options.format, source_file)?;
        }
    }
    
    Ok(())
}

fn save_output(result: &ScanResult, path: &str) -> Result<()> {
    match result {
        ScanResult::Protected { neutralized_content, .. } => {
            fs::write(path, neutralized_content)?;
            println!("{}", Messages::saved_output(path));
        }
        _ => {
            // For other results, save as JSON
            let json = serde_json::to_string_pretty(result)?;
            fs::write(path, json)?;
            println!("{}", Messages::saved_report(path));
        }
    }
    
    Ok(())
}