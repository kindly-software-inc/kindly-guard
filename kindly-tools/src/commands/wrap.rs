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

//! Wrap command - Protect any AI CLI with KindlyGuard

use anyhow::{Context, Result};
use colored::Colorize;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use kindly_guard_server::{Config as ServerConfig, SecurityScanner, Severity};
use crate::config::{WrapConfig, WrapMode};

/// Wrap and protect any AI CLI command
pub async fn wrap_command(command: Vec<String>, server: String, block: bool) -> Result<()> {
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

    // Create scanner with text control chars allowed for CLI wrapping
    let mut config = ServerConfig::default();
    config.scanner.allow_text_control_chars = true;
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

                // Determine the highest severity level
                let max_severity = threats.iter()
                    .map(|t| t.severity)
                    .max()
                    .unwrap_or(Severity::Low);

                // Display the colored input based on threat level
                let colored_input = match (threats.is_empty(), max_severity) {
                    (true, _) => {
                        // No threats - display in green to indicate safe
                        format!("▶ {}", stdin_buf.trim()).green().to_string()
                    }
                    (false, Severity::Low | Severity::Medium) => {
                        // Low/Medium threats - display in yellow
                        format!("▶ {}", stdin_buf.trim()).yellow().to_string()
                    }
                    (false, Severity::High | Severity::Critical) => {
                        // High/Critical threats - display in red
                        format!("▶ {}", stdin_buf.trim()).red().to_string()
                    }
                };
                eprintln!("{}", colored_input);

                if !threats.is_empty() {
                    // Show threat warning
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

/// Wrap command using configuration
pub async fn wrap_command_with_config(command: Vec<String>, config: Option<WrapConfig>) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("No command specified");
    }

    // Load config or use provided one
    let config = match config {
        Some(c) => c,
        None => WrapConfig::load()?,
    };

    // Check if command should be wrapped
    let cmd_name = &command[0];
    if !config.should_wrap(cmd_name) {
        // Just execute the command without wrapping
        let status = Command::new(cmd_name)
            .args(&command[1..])
            .status()
            .context("Failed to execute command")?;
        
        if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
        return Ok(());
    }

    // Use configuration settings
    let block = matches!(config.mode, WrapMode::Blocking);
    let server = config.server.clone();
    
    wrap_command(command, server, block).await
}

/// Initialize wrap configuration
pub async fn init_wrap_config() -> Result<()> {
    WrapConfig::create_default_config()
}

/// Show current wrap configuration
pub async fn show_wrap_config() -> Result<()> {
    let config = WrapConfig::load()?;
    
    println!("{}", "KindlyGuard Wrap Configuration".green().bold());
    println!();
    println!("{}: {}", "Enabled".dimmed(), if config.enabled { "Yes".green() } else { "No".red() });
    println!("{}: {}", "Mode".dimmed(), config.mode_string());
    println!("{}: {}", "Server".dimmed(), config.server);
    println!("{}: {}", "Verbose".dimmed(), if config.verbose { "Yes" } else { "No" });
    println!("{}: {}", "Log Sessions".dimmed(), if config.log_sessions { "Yes" } else { "No" });
    
    if let Some(log_dir) = &config.log_directory {
        println!("{}: {}", "Log Directory".dimmed(), log_dir.display());
    }
    
    println!();
    println!("{}", "Wrapped Commands:".dimmed());
    let mut commands: Vec<_> = config.commands.iter().cloned().collect();
    commands.sort();
    for cmd in commands {
        let is_custom = config.custom_commands.contains(&cmd);
        if is_custom {
            println!("  • {} {}", cmd, "(custom)".dimmed());
        } else {
            println!("  • {}", cmd);
        }
    }
    
    Ok(())
}

/// Add a command to the wrap list
pub async fn add_wrap_command(command: String) -> Result<()> {
    let mut config = WrapConfig::load()?;
    
    if config.commands.contains(&command) {
        println!("{} {} is already in the wrap list", "ℹ".blue(), command);
        return Ok(());
    }
    
    config.add_command(command.clone());
    config.save()?;
    
    println!("{} Added {} to wrap list", "✓".green(), command.green().bold());
    Ok(())
}

/// Remove a command from the wrap list
pub async fn remove_wrap_command(command: String) -> Result<()> {
    let mut config = WrapConfig::load()?;
    
    if config.remove_command(&command) {
        config.save()?;
        println!("{} Removed {} from wrap list", "✓".green(), command.green().bold());
    } else {
        println!("{} {} is not in the wrap list", "ℹ".blue(), command);
    }
    
    Ok(())
}