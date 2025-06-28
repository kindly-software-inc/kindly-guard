//! KindlyGuard CLI tool for security scanning

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

use kindly_guard_server::{
    Config as ServerConfig, SecurityScanner, ScannerConfig, 
    Threat, ThreatType, Severity
};

mod output;
use output::{OutputFormat, print_scan_results};

/// KindlyGuard CLI - Security scanner and monitoring tool
#[derive(Parser, Debug)]
#[command(name = "kindly-guard-cli")]
#[command(about = "Security scanner for detecting unicode attacks and injection threats", long_about = None)]
struct Cli {
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan files or directories for security threats
    Scan {
        /// Path to scan (file or directory)
        path: String,
        
        /// Output format (json, table, brief)
        #[arg(short, long, default_value = "table")]
        format: String,
        
        /// Recursively scan directories
        #[arg(short, long)]
        recursive: bool,
        
        /// File extensions to include (e.g., json,txt,md)
        #[arg(short, long)]
        extensions: Option<String>,
        
        /// Maximum file size in MB
        #[arg(long, default_value = "10")]
        max_size_mb: u64,
    },
    
    /// Monitor KindlyGuard server status
    Monitor {
        /// Server URL
        #[arg(short, long, default_value = "http://localhost:8080")]
        url: String,
        
        /// Update interval in seconds
        #[arg(short, long, default_value = "5")]
        interval: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("kindly_guard={}", log_level))
        .init();
    
    match cli.command {
        Commands::Scan { path, format, recursive, extensions, max_size_mb } => {
            scan_command(path, format, recursive, extensions, max_size_mb).await
        }
        Commands::Monitor { url, interval } => {
            monitor_command(url, interval).await
        }
    }
}

async fn scan_command(
    path: String,
    format: String,
    recursive: bool,
    extensions: Option<String>,
    max_size_mb: u64,
) -> Result<()> {
    let start_time = Instant::now();
    let path = Path::new(&path);
    
    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }
    
    // Parse output format
    let output_format = OutputFormat::from_str(&format)?;
    
    // Parse extensions if provided
    let allowed_extensions: Option<Vec<String>> = extensions.map(|ext| {
        ext.split(',')
            .map(|s| s.trim().to_lowercase())
            .collect()
    });
    
    // Create scanner
    let config = ScannerConfig {
        unicode_detection: true,
        injection_detection: true,
        path_traversal_detection: true,
        custom_patterns: None,
        max_scan_depth: 10,
    };
    
    let scanner = SecurityScanner::new(config)
        .context("Failed to create security scanner")?;
    
    // Collect files to scan
    let files_to_scan = collect_files(path, recursive, &allowed_extensions, max_size_mb)?;
    
    if files_to_scan.is_empty() {
        println!("{}", "No files found to scan".yellow());
        return Ok(());
    }
    
    // Create progress bar
    let progress = if output_format != OutputFormat::Json {
        let pb = ProgressBar::new(files_to_scan.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"));
        Some(pb)
    } else {
        None
    };
    
    // Scan files
    let mut all_results = Vec::new();
    let mut total_threats = 0;
    
    for file_path in &files_to_scan {
        if let Some(pb) = &progress {
            pb.set_message(format!("Scanning {}", file_path.file_name().unwrap_or_default().to_string_lossy()));
        }
        
        match scan_file(&scanner, file_path).await {
            Ok(threats) => {
                if !threats.is_empty() {
                    total_threats += threats.len();
                    all_results.push((file_path.clone(), threats));
                }
            }
            Err(e) => {
                tracing::warn!("Failed to scan {}: {}", file_path.display(), e);
            }
        }
        
        if let Some(pb) = &progress {
            pb.inc(1);
        }
    }
    
    if let Some(pb) = progress {
        pb.finish_with_message("Scan complete");
    }
    
    // Print results
    let duration = start_time.elapsed();
    print_scan_results(
        &all_results,
        files_to_scan.len(),
        total_threats,
        duration,
        output_format,
    );
    
    Ok(())
}

async fn scan_file(scanner: &SecurityScanner, path: &Path) -> Result<Vec<Threat>> {
    let content = tokio::fs::read_to_string(path)
        .await
        .context("Failed to read file")?;
        
    scanner.scan_text(&content)
        .context("Failed to scan file content")
}

fn collect_files(
    path: &Path,
    recursive: bool,
    allowed_extensions: &Option<Vec<String>>,
    max_size_mb: u64,
) -> Result<Vec<PathBuf>> {
    let max_size = max_size_mb * 1024 * 1024;
    let mut files = Vec::new();
    
    if path.is_file() {
        // Check file size
        let metadata = path.metadata()?;
        if metadata.len() <= max_size {
            files.push(path.to_path_buf());
        } else {
            tracing::warn!("Skipping large file: {} ({} MB)", 
                path.display(), 
                metadata.len() / 1024 / 1024
            );
        }
    } else if path.is_dir() {
        let walker = if recursive {
            WalkDir::new(path)
        } else {
            WalkDir::new(path).max_depth(1)
        };
        
        for entry in walker {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() {
                // Check extension
                if let Some(ref extensions) = allowed_extensions {
                    if let Some(ext) = path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if !extensions.contains(&ext_str) {
                            continue;
                        }
                    } else {
                        continue; // Skip files without extension
                    }
                }
                
                // Check file size
                let metadata = entry.metadata()?;
                if metadata.len() <= max_size {
                    files.push(path.to_path_buf());
                } else {
                    tracing::debug!("Skipping large file: {} ({} MB)", 
                        path.display(), 
                        metadata.len() / 1024 / 1024
                    );
                }
            }
        }
    }
    
    Ok(files)
}

async fn monitor_command(url: String, interval: u64) -> Result<()> {
    println!("{}", format!("Monitoring KindlyGuard server at {}", url).green());
    println!("Press Ctrl+C to stop\n");
    
    loop {
        match fetch_server_status(&url).await {
            Ok(status) => {
                print_server_status(&status);
            }
            Err(e) => {
                println!("{}: {}", "Error".red(), e);
            }
        }
        
        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
    }
}

async fn fetch_server_status(url: &str) -> Result<serde_json::Value> {
    // For now, return a placeholder
    // TODO: Implement actual HTTP request to server
    Ok(serde_json::json!({
        "active": true,
        "uptime_seconds": 3600,
        "threats_blocked": 42,
        "scanner_stats": {
            "unicode_threats": 23,
            "injection_threats": 15,
            "total_scans": 1000,
        }
    }))
}

fn print_server_status(status: &serde_json::Value) {
    use chrono::Duration;
    
    let active = status["active"].as_bool().unwrap_or(false);
    let uptime_secs = status["uptime_seconds"].as_u64().unwrap_or(0);
    let threats_blocked = status["threats_blocked"].as_u64().unwrap_or(0);
    
    // Clear screen
    print!("\x1B[2J\x1B[1;1H");
    
    println!("{}", "╭──────────────────────────────────────╮".cyan());
    println!("{}", "│ 🛡️  KindlyGuard Server Status        │".cyan());
    println!("{}", "├──────────────────────────────────────┤".cyan());
    
    let status_text = if active {
        "● Active".green()
    } else {
        "○ Inactive".red()
    };
    println!("│ Status: {:28} │", status_text);
    
    let duration = Duration::seconds(uptime_secs as i64);
    let hours = duration.num_hours();
    let minutes = (duration.num_minutes() % 60) as u64;
    let seconds = (duration.num_seconds() % 60) as u64;
    let uptime_str = format!("{}h {}m {}s", hours, minutes, seconds);
    println!("│ Uptime: {:28} │", uptime_str);
    println!("│ Threats Blocked: {:19} │", threats_blocked);
    
    if let Some(stats) = status["scanner_stats"].as_object() {
        println!("{}", "├──────────────────────────────────────┤".cyan());
        println!("│ Scanner Statistics:                  │");
        println!("│   Unicode threats: {:17} │", 
            stats["unicode_threats"].as_u64().unwrap_or(0));
        println!("│   Injection threats: {:15} │", 
            stats["injection_threats"].as_u64().unwrap_or(0));
        println!("│   Total scans: {:21} │", 
            stats["total_scans"].as_u64().unwrap_or(0));
    }
    
    println!("{}", "╰──────────────────────────────────────╯".cyan());
}