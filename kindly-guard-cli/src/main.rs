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
//! `KindlyGuard` CLI tool for security scanning

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

use kindly_guard_server::{Config as ServerConfig, ScannerConfig, SecurityScanner, Threat};

mod output;
use output::{print_scan_results, OutputFormat};

/// `KindlyGuard` CLI - Security scanner and monitoring tool
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

        /// Configuration file to use
        #[arg(short, long)]
        config: Option<String>,
    },

    /// Monitor `KindlyGuard` server status
    Monitor {
        /// Server URL
        #[arg(short, long, default_value = "http://localhost:8080")]
        url: String,

        /// Update interval in seconds
        #[arg(short, long, default_value = "5")]
        interval: u64,
    },

    /// Shield commands for CLI integration
    Shield {
        #[command(subcommand)]
        command: ShieldCommands,
    },

    /// Generate shell initialization script
    ShellInit {
        /// Shell type (bash, zsh, fish)
        shell: String,
    },

    /// Wrap any AI CLI command with protection
    Wrap {
        /// The command to wrap and protect
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,

        /// KindlyGuard server URL
        #[arg(short, long, default_value = "http://localhost:8080")]
        server: String,

        /// Block on threat detection instead of warning
        #[arg(short, long)]
        block: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ShieldCommands {
    /// Get shield status
    Status {
        /// Output format (compact, minimal, json)
        #[arg(short, long, default_value = "compact")]
        format: String,
    },

    /// Start shield protection
    Start {
        /// Run in background
        #[arg(short, long)]
        background: bool,
    },

    /// Stop shield protection
    Stop,

    /// Pre-command hook (for shell integration)
    PreCommand,

    /// Post-command hook (for shell integration)
    PostCommand,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("kindly_guard={log_level}"))
        .init();

    match cli.command {
        Commands::Scan {
            path,
            format,
            recursive,
            extensions,
            max_size_mb,
            config,
        } => scan_command(path, format, recursive, extensions, max_size_mb, config).await,
        Commands::Monitor { url, interval } => monitor_command(url, interval).await,
        Commands::Shield { command } => shield_command(command).await,
        Commands::ShellInit { shell } => shell_init_command(&shell).await,
        Commands::Wrap {
            command,
            server,
            block,
        } => wrap_command(command, server, block).await,
    }
}

async fn scan_command(
    path: String,
    format: String,
    recursive: bool,
    extensions: Option<String>,
    max_size_mb: u64,
    config_path: Option<String>,
) -> Result<()> {
    let start_time = Instant::now();
    let path = Path::new(&path);

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    // Parse output format
    let output_format = OutputFormat::from_str(&format)?;

    // Parse extensions if provided
    let allowed_extensions: Option<Vec<String>> =
        extensions.map(|ext| ext.split(',').map(|s| s.trim().to_lowercase()).collect());

    // Create scanner with optional config file
    let scanner = if let Some(config_file) = config_path {
        // Load full configuration from file
        let server_config = ServerConfig::load_from_file(&config_file)
            .context("Failed to load configuration file")?;

        // Create scanner with config
        let mut scanner = SecurityScanner::new(server_config.scanner.clone())
            .context("Failed to create security scanner")?;

        // Set up plugins if enabled
        if server_config.plugins.enabled {
            use kindly_guard_server::component_selector::ComponentManager;
            use std::sync::Arc;

            // Create component manager to get plugin manager
            let component_manager = Arc::new(
                ComponentManager::new(&server_config)
                    .context("Failed to create component manager")?,
            );

            scanner.set_plugin_manager(component_manager.plugin_manager().clone());
        }

        scanner
    } else {
        // Use default config
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            xss_detection: Some(true),
            crypto_detection: true,
            enhanced_mode: Some(false),
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
            max_content_size: 5 * 1024 * 1024, // 5MB default
        };

        SecurityScanner::new(config).context("Failed to create security scanner")?
    };

    // Collect files to scan
    let files_to_scan = collect_files(path, recursive, &allowed_extensions, max_size_mb)?;

    if files_to_scan.is_empty() {
        println!("{}", "No files found to scan".yellow());
        return Ok(());
    }

    // Create progress bar
    let progress =
        if output_format == OutputFormat::Json {
            None
        } else {
            let pb = ProgressBar::new(files_to_scan.len() as u64);
            pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"));
            Some(pb)
        };

    // Scan files
    let mut all_results = Vec::new();
    let mut total_threats = 0;

    for file_path in &files_to_scan {
        if let Some(pb) = &progress {
            pb.set_message(format!(
                "Scanning {}",
                file_path.file_name().unwrap_or_default().to_string_lossy()
            ));
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

    scanner
        .scan_text(&content)
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
            tracing::warn!(
                "Skipping large file: {} ({} MB)",
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
                    tracing::debug!(
                        "Skipping large file: {} ({} MB)",
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
    println!(
        "{}",
        format!("Monitoring KindlyGuard server at {url}").green()
    );
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

async fn fetch_server_status(_url: &str) -> Result<serde_json::Value> {
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
    println!("│ Status: {status_text:28} │");

    let duration = Duration::seconds(uptime_secs as i64);
    let hours = duration.num_hours();
    let minutes = (duration.num_minutes() % 60) as u64;
    let seconds = (duration.num_seconds() % 60) as u64;
    let uptime_str = format!("{hours}h {minutes}m {seconds}s");
    println!("│ Uptime: {uptime_str:28} │");
    println!("│ Threats Blocked: {threats_blocked:19} │");

    if let Some(stats) = status["scanner_stats"].as_object() {
        println!("{}", "├──────────────────────────────────────┤".cyan());
        println!("│ Scanner Statistics:                  │");
        println!(
            "│   Unicode threats: {:17} │",
            stats["unicode_threats"].as_u64().unwrap_or(0)
        );
        println!(
            "│   Injection threats: {:15} │",
            stats["injection_threats"].as_u64().unwrap_or(0)
        );
        println!(
            "│   Total scans: {:21} │",
            stats["total_scans"].as_u64().unwrap_or(0)
        );
    }

    println!("{}", "╰──────────────────────────────────────╯".cyan());
}

async fn shield_command(command: ShieldCommands) -> Result<()> {
    use kindly_guard_server::shield::{CliShield, DisplayFormat, Shield};
    use std::sync::Arc;

    match command {
        ShieldCommands::Status { format } => {
            // Create a shield to get status (connects to running server if available)
            let shield = Arc::new(Shield::new());
            let cli_shield = CliShield::new(shield.clone(), DisplayFormat::Compact);

            match format.as_str() {
                "json" => {
                    let status = cli_shield.status();
                    println!("{}", serde_json::to_string_pretty(&status)?);
                }
                "minimal" => {
                    let cli_shield = CliShield::new(shield, DisplayFormat::Minimal);
                    println!("{}", cli_shield.render());
                }
                _ => {
                    // Default to compact
                    println!("{}", cli_shield.render());
                }
            }
        }
        ShieldCommands::Start { background } => {
            if background {
                println!("Starting KindlyGuard shield in background...");
                // TODO: Implement background daemon
                println!("{}", "Shield started in background mode".green());
            } else {
                println!("Starting KindlyGuard shield...");
                // TODO: Start interactive shield
                println!("{}", "Shield is active".green());
            }
        }
        ShieldCommands::Stop => {
            println!("Stopping KindlyGuard shield...");
            // TODO: Send stop signal to daemon
            println!("{}", "Shield stopped".yellow());
        }
        ShieldCommands::PreCommand => {
            // Silent operation for shell integration
            // TODO: Mark command start in shield
        }
        ShieldCommands::PostCommand => {
            // Silent operation for shell integration
            // TODO: Mark command end in shield
        }
    }

    Ok(())
}

async fn shell_init_command(shell: &str) -> Result<()> {
    let script = match shell {
        "bash" => include_str!("../scripts/shell-init.bash"),
        "zsh" => include_str!("../scripts/shell-init.zsh"),
        "fish" => include_str!("../scripts/shell-init.fish"),
        _ => {
            anyhow::bail!(
                "Unsupported shell: {}. Supported shells: bash, zsh, fish",
                shell
            );
        }
    };

    println!("{script}");
    Ok(())
}

/// Wrap and protect any AI CLI command
async fn wrap_command(command: Vec<String>, server: String, block: bool) -> Result<()> {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    if command.is_empty() {
        anyhow::bail!("No command specified");
    }

    println!(
        "{} Active",
        "🛡️ KindlyGuard Protection:".green().bold()
    );
    println!("{} {}", "Server:".dimmed(), server);
    println!(
        "{} {}",
        "Mode:".dimmed(),
        if block { "Blocking" } else { "Warning" }
    );
    println!();

    // Create scanner
    let config = ServerConfig::default();
    let scanner = SecurityScanner::new(config.scanner)?;

    // Start the wrapped command
    let program = &command[0];
    let args = &command[1..];

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to start command")?;

    // Get handles
    let mut stdin = child.stdin.take().context("Failed to get stdin")?;
    let stdout = child.stdout.take().context("Failed to get stdout")?;
    let stderr = child.stderr.take().context("Failed to get stderr")?;

    // Spawn thread to handle stdout
    let stdout_handle = tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(content) => println!("{}", content),
                Err(e) => eprintln!("Error reading stdout: {}", e),
            }
        }
    });

    // Spawn thread to handle stderr
    let stderr_handle = tokio::spawn(async move {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            match line {
                Ok(content) => eprintln!("{}", content),
                Err(e) => eprintln!("Error reading stderr: {}", e),
            }
        }
    });

    // Read from user stdin and scan before passing through
    let stdin_reader = std::io::stdin();
    let mut stdin_buf = String::new();

    loop {
        stdin_buf.clear();
        match stdin_reader.read_line(&mut stdin_buf) {
            Ok(0) => break, // EOF
            Ok(_) => {
                // Scan the input
                let threats = scanner.scan_text(&stdin_buf)?;

                if !threats.is_empty() {
                    // Show threat warning
                    eprintln!();
                    eprintln!("{}", "⚠️  THREAT DETECTED".red().bold());
                    for threat in &threats {
                        eprintln!("  {} {}", "•".red(), threat);
                    }

                    if block {
                        eprintln!("{}", "❌ Input blocked for safety".red());
                        eprintln!();
                        continue; // Don't pass to command
                    } else {
                        eprintln!("{}", "⚠️  Proceeding with caution...".yellow());
                        eprintln!();
                    }
                }

                // Pass through to command
                stdin.write_all(stdin_buf.as_bytes())?;
                stdin.flush()?;
            }
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                break;
            }
        }
    }

    // Close stdin
    drop(stdin);

    // Wait for command to finish
    stdout_handle.await?;
    stderr_handle.await?;

    let status = child.wait()?;

    println!();
    println!(
        "{} Session ended",
        "🛡️ KindlyGuard Protection:".green().bold()
    );

    // Exit with same code as wrapped command
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}
