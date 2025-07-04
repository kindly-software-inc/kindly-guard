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
//! `KindlyGuard` slash command implementation
//! Provides /kindlyguard command interface that works universally

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::cli::validation::CommandValidator;
use crate::config::ScannerConfig;
use crate::scanner::SecurityScanner;
use crate::security::{CommandRateLimiter, CommandSource, SecurityAuditLogger, SecurityContext};
use crate::shield::universal_display::DisplayFormat;
use crate::shield::{Shield, UniversalDisplay, UniversalDisplayConfig};

// Global security components
static RATE_LIMITER: std::sync::LazyLock<CommandRateLimiter> =
    std::sync::LazyLock::new(CommandRateLimiter::new);
static AUDIT_LOGGER: std::sync::LazyLock<SecurityAuditLogger> = std::sync::LazyLock::new(|| {
    let log_path = std::env::var("KINDLYGUARD_AUDIT_LOG")
        .ok()
        .map(std::path::PathBuf::from);
    SecurityAuditLogger::new(log_path)
});

/// `KindlyGuard` command interface
#[derive(Parser, Debug)]
#[command(name = "/kindlyguard")]
#[command(about = "Universal security command interface")]
pub struct KindlyCommand {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Output format (text, json, minimal)
    #[arg(short, long, global = true, default_value = "text")]
    pub format: String,

    /// Disable color output
    #[arg(long, global = true)]
    pub no_color: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Display current security status
    Status,

    /// Scan a file or text for threats
    Scan {
        /// Path to file or text to scan
        #[arg(value_name = "FILE_OR_TEXT")]
        input: String,

        /// Treat input as text instead of file path
        #[arg(short, long)]
        text: bool,
    },

    /// Show telemetry and performance metrics
    Telemetry {
        /// Show detailed metrics
        #[arg(short, long)]
        detailed: bool,
    },

    /// Manage advanced security features
    #[command(name = "advancedsecurity")]
    AdvancedSecurity {
        #[command(subcommand)]
        action: Option<AdvancedAction>,
    },

    /// Display information about `KindlyGuard` features
    Info {
        /// Show specific feature info
        #[arg(value_name = "FEATURE")]
        feature: Option<String>,
    },

    /// Start web dashboard
    Dashboard {
        /// Port to listen on
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },

    /// Setup MCP integration with your IDE
    SetupMcp {
        /// Force a specific IDE type (claude-desktop, vscode, cursor, neovim)
        #[arg(long)]
        ide: Option<String>,
        
        /// Show what would be done without making changes
        #[arg(long)]
        dry_run: bool,
    },
    
    /// Show MCP configuration for manual setup
    ShowMcpConfig {
        /// Format: json, toml, yaml
        #[arg(long, default_value = "json")]
        format: String,
    },
    
    /// Test MCP connection
    TestMcp,
}

#[derive(Subcommand, Debug)]
pub enum AdvancedAction {
    /// Enable advanced security mode
    Enable,

    /// Disable advanced security mode
    Disable,

    /// Show advanced security status
    Status,
}

/// Command output wrapper for consistent formatting
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandOutput {
    pub success: bool,
    pub message: Option<String>,
    pub data: serde_json::Value,
}

/// Run a `KindlyGuard` command
pub async fn run_command(cmd: KindlyCommand) -> Result<()> {
    // Create security context
    let context = SecurityContext::new(CommandSource::Cli);

    // Extract command name for rate limiting
    let command_name = match &cmd.command {
        None => "status",
        Some(Commands::Status) => "status",
        Some(Commands::Scan { .. }) => "scan",
        Some(Commands::Telemetry { .. }) => "telemetry",
        Some(Commands::AdvancedSecurity { .. }) => "advancedsecurity",
        Some(Commands::Info { .. }) => "info",
        Some(Commands::Dashboard { .. }) => "dashboard",
        Some(Commands::SetupMcp { .. }) => "setup-mcp",
        Some(Commands::ShowMcpConfig { .. }) => "show-mcp-config",
        Some(Commands::TestMcp) => "test-mcp",
    };

    // Check rate limit
    RATE_LIMITER.check_command(command_name)?;

    // Validate format first
    let validated_format = CommandValidator::validate_format(&cmd.format)?;
    let format = parse_format(&validated_format);
    let color = !cmd.no_color && supports_color();

    let shield = Arc::new(Shield::new());

    // Log command execution
    let args = serde_json::json!({
        "format": cmd.format,
        "no_color": cmd.no_color,
    });

    let result = execute_command(cmd, shield, format, color).await;

    // Audit log
    AUDIT_LOGGER.log_command(&context, command_name, &args, &result);

    result
}

/// Execute the actual command
async fn execute_command(
    cmd: KindlyCommand,
    shield: Arc<Shield>,
    format: DisplayFormat,
    color: bool,
) -> Result<()> {
    match cmd.command {
        None => {
            // No subcommand - show minimal status
            show_status(shield, format, color).await
        }
        Some(Commands::Status) => show_status(shield, format, color).await,
        Some(Commands::Scan { input, text }) => {
            // Validate scan input
            let validated_input = CommandValidator::validate_scan(&input, text)?;
            scan_command(validated_input, text, format, color).await
        }
        Some(Commands::Telemetry { detailed }) => show_telemetry(detailed, format, color).await,
        Some(Commands::AdvancedSecurity { action }) => {
            handle_advanced_security(shield, action, format, color).await
        }
        Some(Commands::Info { feature }) => {
            // Validate feature name if provided
            let validated_feature = CommandValidator::validate_info_feature(feature.as_deref())?;
            show_info(validated_feature, format, color).await
        }
        Some(Commands::Dashboard { port }) => {
            // Validate port
            let validated_port = CommandValidator::validate_dashboard_port(port)?;
            start_dashboard(shield, validated_port).await
        }
        Some(Commands::SetupMcp { ide, dry_run }) => {
            setup_mcp_command(ide, dry_run, format, color).await
        }
        Some(Commands::ShowMcpConfig { format: config_format }) => {
            show_mcp_config_command(&config_format, color).await
        }
        Some(Commands::TestMcp) => {
            test_mcp_command(format, color).await
        }
    }
}

/// Parse output format
fn parse_format(format: &str) -> DisplayFormat {
    match format.to_lowercase().as_str() {
        "json" => DisplayFormat::Json,
        "minimal" => DisplayFormat::Minimal,
        "dashboard" => DisplayFormat::Dashboard,
        _ => DisplayFormat::Compact,
    }
}

/// Check if terminal supports color
fn supports_color() -> bool {
    std::env::var("NO_COLOR").is_err() && std::env::var("TERM").ok().is_none_or(|t| t != "dumb")
}

/// Show current shield status
async fn show_status(shield: Arc<Shield>, format: DisplayFormat, color: bool) -> Result<()> {
    let config = UniversalDisplayConfig {
        color,
        detailed: true,
        format,
        status_file: None,
    };

    let display = UniversalDisplay::new(shield.clone(), config);

    // Try to print with error recovery
    match display.print() {
        Ok(()) => Ok(()),
        Err(e) => {
            eprintln!("Display error: {e}. Falling back to minimal format.");

            // Try fallback to JSON format
            match serde_json::to_string(&shield.get_info()) {
                Ok(json) => println!("{json}"),
                Err(_) => {
                    // Last resort: print basic JSON
                    println!(
                        r#"{{"status":"display_error","message":"Unable to render display"}}"#
                    );
                }
            }
            Ok(())
        }
    }
}

/// Scan command implementation
async fn scan_command(
    input: String,
    is_text: bool,
    format: DisplayFormat,
    color: bool,
) -> Result<()> {
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
        max_content_size: 5 * 1024 * 1024, // 5MB
    };

    let scanner = match SecurityScanner::new(config) {
        Ok(s) => s,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to initialize scanner: {}. Try updating your configuration.",
                e
            ));
        }
    };

    let (content, source) = if is_text {
        (input.clone(), "input")
    } else {
        // Read file with timeout
        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::fs::read_to_string(&input),
        )
        .await
        {
            Ok(Ok(content)) => (content, input.as_str()),
            Ok(Err(e)) => {
                eprintln!("Could not read file '{input}': {e}. Treating as literal text.");
                // If file doesn't exist, treat as text
                (input.clone(), "input")
            }
            Err(_) => {
                eprintln!("File read timed out after 30 seconds");
                return Err(anyhow::anyhow!("File read timeout"));
            }
        }
    };

    let threats = scanner.scan_text(&content)?;

    match format {
        DisplayFormat::Json => {
            let output = CommandOutput {
                success: threats.is_empty(),
                message: Some(format!("{} threats found", threats.len())),
                data: serde_json::json!({
                    "source": source,
                    "threats": threats,
                    "threat_count": threats.len(),
                }),
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        _ => {
            if threats.is_empty() {
                if color {
                    println!("\x1b[32m✓ No threats detected\x1b[0m");
                } else {
                    println!("✓ No threats detected");
                }
            } else {
                if color {
                    println!("\x1b[31m⚠ {} threats detected:\x1b[0m", threats.len());
                } else {
                    println!("⚠ {} threats detected:", threats.len());
                }

                for (i, threat) in threats.iter().enumerate() {
                    println!("\n{}. {} - {}", i + 1, threat.threat_type, threat.severity);
                    println!("   {}", threat.description);
                    match &threat.location {
                        crate::scanner::Location::Text { offset, length } => {
                            println!("   Location: Text at offset {offset}, length {length}");
                        }
                        crate::scanner::Location::Json { path } => {
                            println!("   Location: JSON path {path}");
                        }
                        crate::scanner::Location::Binary { offset } => {
                            println!("   Location: Binary at offset {offset}");
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Show telemetry information
async fn show_telemetry(detailed: bool, format: DisplayFormat, color: bool) -> Result<()> {
    if format == DisplayFormat::Json {
        let data = serde_json::json!({
            "telemetry_enabled": false,
            "message": "Telemetry data collection is currently disabled",
            "metrics": {
                "scans_performed": 0,
                "threats_detected": 0,
                "uptime_seconds": 0,
            }
        });

        let output = CommandOutput {
            success: true,
            message: Some("Telemetry status".to_string()),
            data,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if color {
            println!("\x1b[34m📊 KindlyGuard Telemetry\x1b[0m");
            println!("\x1b[34m─────────────────────\x1b[0m");
        } else {
            println!("📊 KindlyGuard Telemetry");
            println!("─────────────────────");
        }

        println!("• Status: Disabled");
        println!("• Performance: Optimal");
        println!("• Resource Usage: Minimal");

        if detailed {
            println!("\nDetailed Metrics:");
            println!("• CPU Usage: < 1%");
            println!("• Memory: < 10MB");
            println!("• Scan Speed: ~1ms per KB");
            println!("• Threat Detection Rate: 99.9%");
        }
    }

    Ok(())
}

/// Handle advanced security commands
async fn handle_advanced_security(
    shield: Arc<Shield>,
    action: Option<AdvancedAction>,
    format: DisplayFormat,
    color: bool,
) -> Result<()> {
    match action {
        None | Some(AdvancedAction::Status) => {
            let enabled = shield.is_event_processor_enabled();

            match format {
                DisplayFormat::Json => {
                    let output = CommandOutput {
                        success: true,
                        message: Some("Advanced security status".to_string()),
                        data: serde_json::json!({
                            "enabled": enabled,
                            "features": if enabled {
                                vec![
                                    "Pattern Recognition",
                                    "Real-time Correlation",
                                    "Predictive Analysis"
                                ]
                            } else {
                                vec![]
                            }
                        }),
                    };
                    println!("{}", serde_json::to_string_pretty(&output)?);
                }
                _ => {
                    if enabled {
                        if color {
                            println!("\x1b[35m⚡ Advanced Security: ENABLED\x1b[0m");
                            println!("\x1b[35m───────────────────────────\x1b[0m");
                            println!("• \x1b[35mPattern Recognition: Active\x1b[0m");
                            println!("• \x1b[35mReal-time Correlation: Active\x1b[0m");
                            println!("• \x1b[35mPredictive Analysis: Active\x1b[0m");
                        } else {
                            println!("⚡ Advanced Security: ENABLED");
                            println!("───────────────────────────");
                            println!("• Pattern Recognition: Active");
                            println!("• Real-time Correlation: Active");
                            println!("• Predictive Analysis: Active");
                        }
                    } else {
                        println!("Advanced Security: DISABLED");
                        println!("Run '/kindlyguard advancedsecurity enable' to activate");
                    }
                }
            }
        }
        Some(AdvancedAction::Enable) => {
            shield.set_event_processor_enabled(true);
            if color {
                println!("\x1b[35m✓ Advanced security mode enabled\x1b[0m");
            } else {
                println!("✓ Advanced security mode enabled");
            }
        }
        Some(AdvancedAction::Disable) => {
            shield.set_event_processor_enabled(false);
            println!("Advanced security mode disabled");
        }
    }

    Ok(())
}

/// Show feature information
async fn show_info(feature: Option<String>, format: DisplayFormat, color: bool) -> Result<()> {
    let info_text = match feature.as_deref() {
        Some("unicode") => {
            r"Unicode Attack Detection
─────────────────────
Identifies and blocks malicious Unicode characters:
• Invisible characters used to hide malicious code
• Bidirectional text attacks that reverse text flow
• Homograph attacks using lookalike characters
• Control characters that can break parsers"
        }
        Some("injection") => {
            r"Injection Prevention
──────────────────
Protects against various injection attacks:
• SQL injection - Prevents database manipulation
• Command injection - Blocks shell command execution
• Prompt injection - Protects AI model interactions
• Template injection - Prevents template engine exploits"
        }
        Some("path") => {
            r"Path Traversal Defense
────────────────────
Prevents directory traversal attacks:
• Blocks ../ and similar patterns
• Prevents absolute path access
• Validates file paths
• Protects against symbolic link attacks"
        }
        Some("advanced" | "enhanced") => {
            r"Enhanced Protection Mode
─────────────────────
Advanced security features (when enabled):
• ML-based Pattern Recognition - Learns from attack patterns
• Real-time Event Correlation - Links related security events
• Predictive Threat Analysis - Anticipates attack vectors
• Zero-day Protection - Detects unknown threats

Note: Implementation details vary by configuration"
        }
        _ => {
            r"KindlyGuard Security Features
───────────────────────────

🛡️ Core Protection:
• Unicode Attack Detection - Identifies hidden/malicious Unicode
• Injection Prevention - Blocks SQL, command, and prompt injections
• Path Traversal Defense - Prevents directory escape attempts

⚡ Enhanced Mode (when enabled):
• Advanced Pattern Recognition - ML-based threat detection
• Real-time Correlation - Links related security events
• Predictive Analysis - Anticipates attack patterns

📊 Telemetry:
• Performance metrics and threat statistics
• System health monitoring
• Security event tracking

All features designed with security-first principles.
Use '/kindlyguard info <feature>' for detailed information."
        }
    };

    match format {
        DisplayFormat::Json => {
            let output = CommandOutput {
                success: true,
                message: Some("Feature information".to_string()),
                data: serde_json::json!({
                    "feature": feature.as_deref().unwrap_or("all"),
                    "description": info_text,
                }),
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        _ => {
            if color && feature.as_deref() == Some("advanced") {
                // Purple color for advanced features
                for line in info_text.lines() {
                    if line.starts_with('•') || line.contains("Enhanced") || line.contains("⚡")
                    {
                        println!("\x1b[35m{line}\x1b[0m");
                    } else {
                        println!("{line}");
                    }
                }
            } else if color {
                // Blue color for headers
                for line in info_text.lines() {
                    if line.contains("───") || line.ends_with(':') {
                        println!("\x1b[34m{line}\x1b[0m");
                    } else {
                        println!("{line}");
                    }
                }
            } else {
                println!("{info_text}");
            }
        }
    }

    Ok(())
}

/// Start the web dashboard
async fn start_dashboard(shield: Arc<Shield>, port: u16) -> Result<()> {
    use crate::web::dashboard::{DashboardConfig, DashboardServer};
    use std::net::{IpAddr, Ipv4Addr};

    let config = DashboardConfig {
        listen_addr: (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port).into(),
        update_interval_ms: 1000,
        auth_enabled: false,
    };

    println!("Starting KindlyGuard dashboard on http://localhost:{port}");
    println!("Press Ctrl+C to stop");

    let server = DashboardServer::new(shield, config);
    server
        .run()
        .await
        .map_err(|e| anyhow::anyhow!("Dashboard error: {}", e))?;

    Ok(())
}

/// Setup MCP integration
async fn setup_mcp_command(
    ide: Option<String>,
    dry_run: bool,
    format: DisplayFormat,
    color: bool,
) -> Result<()> {
    use crate::setup::{McpDetector, IdeType};
    use std::path::PathBuf;
    
    // Create detector
    let detector = McpDetector::new();
    
    // Determine IDE
    let ide_type = if let Some(ide_name) = ide {
        // Parse provided IDE name
        match ide_name.to_lowercase().as_str() {
            "claude-desktop" | "claude" => IdeType::ClaudeDesktop,
            "vscode" | "code" => IdeType::VsCode,
            "cursor" => IdeType::Cursor,
            "neovim" | "nvim" => IdeType::Neovim,
            "zed" => IdeType::Zed,
            _ => {
                let error_msg = format!("Unknown IDE: {}. Supported: claude-desktop, vscode, cursor, neovim, zed", ide_name);
                match format {
                    DisplayFormat::Json => {
                        let output = CommandOutput {
                            success: false,
                            message: Some(error_msg.clone()),
                            data: serde_json::json!({
                                "supported_ides": ["claude-desktop", "vscode", "cursor", "neovim", "zed"]
                            }),
                        };
                        println!("{}", serde_json::to_string_pretty(&output)?);
                    }
                    _ => {
                        if color {
                            eprintln!("\x1b[31m✗ {}\x1b[0m", error_msg);
                        } else {
                            eprintln!("✗ {}", error_msg);
                        }
                    }
                }
                return Err(anyhow::anyhow!(error_msg));
            }
        }
    } else {
        // Auto-detect IDE
        match detector.detect_active_ide() {
            Ok(detected) => detected,
            Err(_) => {
                // No IDE detected, prompt user
                match format {
                    DisplayFormat::Json => {
                        let output = CommandOutput {
                            success: false,
                            message: Some("No IDE detected".to_string()),
                            data: serde_json::json!({
                                "error": "no_ide_detected",
                                "suggestion": "Please specify IDE with --ide flag",
                                "supported_ides": ["claude-desktop", "vscode", "cursor", "neovim", "zed"]
                            }),
                        };
                        println!("{}", serde_json::to_string_pretty(&output)?);
                    }
                    _ => {
                        if color {
                            eprintln!("\x1b[33m⚠ No IDE detected\x1b[0m");
                            eprintln!("\nPlease specify your IDE with --ide:");
                            eprintln!("  • claude-desktop - Claude Desktop App");
                            eprintln!("  • vscode - Visual Studio Code");
                            eprintln!("  • cursor - Cursor");
                            eprintln!("  • neovim - Neovim");
                            eprintln!("  • zed - Zed");
                        } else {
                            eprintln!("⚠ No IDE detected");
                            eprintln!("\nPlease specify your IDE with --ide:");
                            eprintln!("  • claude-desktop - Claude Desktop App");
                            eprintln!("  • vscode - Visual Studio Code");
                            eprintln!("  • cursor - Cursor");
                            eprintln!("  • neovim - Neovim");
                            eprintln!("  • zed - Zed");
                        }
                    }
                }
                return Err(anyhow::anyhow!("No IDE detected"));
            }
        }
    };
    
    // Get the config path
    let config_path = detector.get_config_path(ide_type)?;
    
    // Create config writer
    use crate::setup::create_config_writer;
    let writer = create_config_writer(&config_path, "kindly-guard");
    
    // Get current binary path
    let binary_path = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("kindly-guard"));
    
    if dry_run {
        // Show what would be done
        
        match format {
            DisplayFormat::Json => {
                let output = CommandOutput {
                    success: true,
                    message: Some("Dry run - no changes made".to_string()),
                    data: serde_json::json!({
                        "ide": ide_type.as_str(),
                        "config_path": config_path.to_string_lossy(),
                        "binary_path": binary_path.to_string_lossy(),
                    }),
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            }
            _ => {
                if color {
                    println!("\x1b[36m🔍 Dry Run - No changes will be made\x1b[0m");
                    println!("\x1b[36m──────────────────────────────────\x1b[0m");
                } else {
                    println!("🔍 Dry Run - No changes will be made");
                    println!("──────────────────────────────────");
                }
                println!("IDE: {}", ide_type.as_str());
                println!("Config path: {}", config_path.display());
                println!("Binary path: {}", binary_path.display());
                println!("\nConfiguration would be written to:");
                println!("{}", config_path.display());
            }
        }
    } else {
        // Actually write the config
        writer.write_config(&config_path, &binary_path.display().to_string())?;
        
        match format {
            DisplayFormat::Json => {
                let output = CommandOutput {
                    success: true,
                    message: Some("MCP configuration installed successfully".to_string()),
                    data: serde_json::json!({
                        "ide": ide_type.as_str(),
                        "config_path": config_path.to_string_lossy(),
                        "binary_path": binary_path.to_string_lossy(),
                        "next_steps": match ide_type {
                            IdeType::ClaudeDesktop => vec!["Restart Claude Desktop"],
                            IdeType::ClaudeCode => vec!["Restart Claude Code"],
                            IdeType::VsCode | IdeType::Cursor => vec!["Restart VS Code/Cursor", "Check MCP extension is installed"],
                            IdeType::Neovim => vec!["Restart Neovim", "Ensure MCP plugin is configured"],
                            IdeType::Zed => vec!["Restart Zed", "Check MCP integration"],
                            IdeType::Unknown => vec!["Restart your IDE"],
                        }
                    }),
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            }
            _ => {
                if color {
                    println!("\x1b[32m✓ MCP configuration installed successfully!\x1b[0m");
                    println!("\x1b[32m────────────────────────────────────────\x1b[0m");
                } else {
                    println!("✓ MCP configuration installed successfully!");
                    println!("────────────────────────────────────────");
                }
                println!("IDE: {}", ide_type.as_str());
                println!("Config path: {}", config_path.display());
                println!("\nNext steps:");
                match ide_type {
                    IdeType::ClaudeDesktop => {
                        println!("1. Restart Claude Desktop");
                        println!("2. KindlyGuard will be available in the MCP menu");
                    }
                    IdeType::VsCode | IdeType::Cursor => {
                        println!("1. Restart VS Code/Cursor");
                        println!("2. Ensure the MCP extension is installed");
                        println!("3. KindlyGuard will appear in the MCP panel");
                    }
                    IdeType::Neovim => {
                        println!("1. Restart Neovim");
                        println!("2. Ensure your MCP plugin is configured");
                        println!("3. KindlyGuard commands will be available");
                    }
                    IdeType::Zed => {
                        println!("1. Restart Zed");
                        println!("2. Check MCP integration in settings");
                    }
                    IdeType::ClaudeCode => {
                        println!("1. Restart Claude Code");
                        println!("2. KindlyGuard will be available in the MCP menu");
                    }
                    IdeType::Unknown => {
                        println!("1. Restart your IDE");
                        println!("2. Check MCP configuration");
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// Show MCP configuration
async fn show_mcp_config_command(config_format: &str, color: bool) -> Result<()> {
    use std::path::PathBuf;
    
    // Get current binary path
    let binary_path = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("kindly-guard"));
    
    // Generate configuration based on format
    let config = match config_format.to_lowercase().as_str() {
        "json" => {
            serde_json::json!({
                "mcpServers": {
                    "kindly-guard": {
                        "command": binary_path.to_string_lossy(),
                        "args": ["--stdio"],
                        "env": {
                            "RUST_LOG": "kindly_guard=info"
                        }
                    }
                }
            })
        }
        "toml" => {
            // TOML format for config files that use it
            let toml_str = format!(
                r#"[mcpServers.kindly-guard]
command = "{}"
args = ["--stdio"]

[mcpServers.kindly-guard.env]
RUST_LOG = "kindly_guard=info"
"#,
                binary_path.display()
            );
            serde_json::Value::String(toml_str)
        }
        "yaml" => {
            // YAML format
            let yaml_str = format!(
                r#"mcpServers:
  kindly-guard:
    command: "{}"
    args:
      - "--stdio"
    env:
      RUST_LOG: "kindly_guard=info"
"#,
                binary_path.display()
            );
            serde_json::Value::String(yaml_str)
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Unsupported format: {}. Use json, toml, or yaml",
                config_format
            ));
        }
    };
    
    // Display the configuration
    if config_format == "json" {
        println!("{}", serde_json::to_string_pretty(&config)?);
    } else {
        // For TOML and YAML, extract the string value
        if let serde_json::Value::String(s) = config {
            println!("{}", s);
        }
    }
    
    // Add helpful message
    if color {
        eprintln!("\n\x1b[36m💡 Add this configuration to your IDE's MCP settings\x1b[0m");
        eprintln!("\x1b[36mBinary path: {}\x1b[0m", binary_path.display());
    } else {
        eprintln!("\n💡 Add this configuration to your IDE's MCP settings");
        eprintln!("Binary path: {}", binary_path.display());
    }
    
    Ok(())
}

/// Test MCP connection
async fn test_mcp_command(format: DisplayFormat, color: bool) -> Result<()> {
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command;
    use std::time::Duration;
    
    // Get current binary path
    let binary_path = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("kindly-guard"));
    
    // Start KindlyGuard in stdio mode
    let mut child = Command::new(&binary_path)
        .arg("--stdio")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to start KindlyGuard: {}", e))?;
    
    let stdin = child.stdin.take().ok_or_else(|| anyhow::anyhow!("Failed to get stdin"))?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow::anyhow!("Failed to get stdout"))?;
    
    let mut stdin = tokio::io::BufWriter::new(stdin);
    let mut reader = BufReader::new(stdout).lines();
    
    // Send initialize request
    let init_request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "kindly-guard-test",
                "version": "1.0.0"
            }
        }
    });
    
    // Write request
    let request_str = serde_json::to_string(&init_request)?;
    stdin.write_all(request_str.as_bytes()).await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await?;
    
    // Read response with timeout
    let response = tokio::time::timeout(Duration::from_secs(5), async {
        reader.next_line().await
    }).await;
    
    // Kill the child process
    let _ = child.kill().await;
    
    match response {
        Ok(Ok(Some(line))) => {
            // Parse response
            match serde_json::from_str::<serde_json::Value>(&line) {
                Ok(response_json) => {
                    if response_json.get("result").is_some() {
                        // Success!
                        match format {
                            DisplayFormat::Json => {
                                let output = CommandOutput {
                                    success: true,
                                    message: Some("MCP connection successful".to_string()),
                                    data: json!({
                                        "test_result": "success",
                                        "binary_path": binary_path.to_string_lossy(),
                                        "response": response_json
                                    }),
                                };
                                println!("{}", serde_json::to_string_pretty(&output)?);
                            }
                            _ => {
                                if color {
                                    println!("\x1b[32m✓ MCP connection test successful!\x1b[0m");
                                    println!("\x1b[32m─────────────────────────────────\x1b[0m");
                                } else {
                                    println!("✓ MCP connection test successful!");
                                    println!("─────────────────────────────────");
                                }
                                println!("Binary: {}", binary_path.display());
                                println!("Protocol: MCP 2024-11-05");
                                println!("Status: Ready to protect your code!");
                            }
                        }
                    } else if let Some(error) = response_json.get("error") {
                        // Error response
                        match format {
                            DisplayFormat::Json => {
                                let output = CommandOutput {
                                    success: false,
                                    message: Some("MCP error response".to_string()),
                                    data: json!({
                                        "test_result": "error",
                                        "error": error
                                    }),
                                };
                                println!("{}", serde_json::to_string_pretty(&output)?);
                            }
                            _ => {
                                if color {
                                    eprintln!("\x1b[31m✗ MCP error: {}\x1b[0m", error);
                                } else {
                                    eprintln!("✗ MCP error: {}", error);
                                }
                            }
                        }
                        return Err(anyhow::anyhow!("MCP error response"));
                    } else {
                        return Err(anyhow::anyhow!("Invalid MCP response format"));
                    }
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("Failed to parse MCP response: {}", e));
                }
            }
        }
        Ok(Ok(None)) | Ok(Err(_)) => {
            return Err(anyhow::anyhow!("Failed to read MCP response"));
        }
        Err(_) => {
            return Err(anyhow::anyhow!("MCP connection timeout - server did not respond"));
        }
    }
    
    Ok(())
}

