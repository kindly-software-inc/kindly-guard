//! MCP (Model Context Protocol) server management

use crate::MpcOperation;
use anyhow::{Context, Result};
use colored::Colorize;
use serde_json::{json, Value};
use std::fs;
use std::process::Command;

/// Run MCP management commands
pub async fn run_mcp(operation: MpcOperation, server: Option<String>) -> Result<()> {
    match operation {
        MpcOperation::Setup => setup_mcp().await,
        MpcOperation::Verify => verify_mcp().await,
        MpcOperation::Status => show_status(server.as_deref()).await,
        MpcOperation::Start => start_server(server.as_deref()).await,
        MpcOperation::Stop => stop_server(server.as_deref()).await,
        MpcOperation::Config => edit_config().await,
        MpcOperation::List => list_servers().await,
    }
}

/// Set up MCP server configuration
async fn setup_mcp() -> Result<()> {
    use kindly_guard_server::setup::run_setup_wizard;
    
    println!("{}", "🔧 Setting up MCP server configuration...".bright_blue().bold());
    println!();
    
    // Use the interactive setup wizard
    run_setup_wizard(false).await?;
    
    Ok(())
}

/// Verify MCP configuration
async fn verify_mcp() -> Result<()> {
    use kindly_guard_server::setup::McpDetector;
    
    println!("{}", "🔍 Verifying MCP configuration...".bright_blue().bold());
    println!();
    
    // Check if kindlyguard binary is in PATH
    println!("🔎 Checking KindlyGuard installation...");
    let which_result = Command::new("which")
        .arg("kindlyguard")
        .output();
        
    match which_result {
        Ok(output) if output.status.success() => {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("   ✅ Found at: {}", path.bright_green());
        }
        _ => {
            println!("   ❌ {} not found in PATH", "kindlyguard".bright_red());
            println!("   💡 Run: {}", "npm install -g kindlyguard".bright_yellow());
            return Err(anyhow::anyhow!("KindlyGuard not installed"));
        }
    }
    
    // Use the detector to find all configurations
    let detector = McpDetector::new();
    let configs = detector.detect_all()?;
    let existing_configs: Vec<_> = configs.iter().filter(|c| c.exists).collect();
    
    println!();
    println!("🔎 Checking MCP configurations...");
    
    if existing_configs.is_empty() {
        println!("   ❌ No MCP configurations found");
        println!("   💡 Run: {}", "kindlyguard mcp setup".bright_yellow());
        return Err(anyhow::anyhow!("No MCP configurations found"));
    }
    
    let mut configured_count = 0;
    
    for config in &existing_configs {
        println!();
        println!("   📍 {} ({})", config.ide.as_str().bright_cyan(), config.path.display());
        
        // Check if KindlyGuard is configured
        if detector.is_server_configured("kindlyguard")? {
            println!("      ✅ KindlyGuard configured");
            configured_count += 1;
        } else {
            println!("      ⚠️  KindlyGuard not configured");
        }
    }
    
    // Test server startup
    println!();
    println!("🔎 Testing server startup...");
    
    let test_result = Command::new("kindlyguard")
        .args(&["serve", "--stdio"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
        
    match test_result {
        Ok(mut child) => {
            println!("   ✅ Server starts successfully");
            // Kill the test process
            let _ = child.kill();
        }
        Err(e) => {
            println!("   ❌ Server failed to start: {}", e);
            return Err(e.into());
        }
    }
    
    println!();
    if configured_count > 0 {
        println!("{}", format!("✅ KindlyGuard configured in {} AI tool(s)!", configured_count).bright_green().bold());
    } else {
        println!("{}", "⚠️  KindlyGuard not configured in any AI tools".bright_yellow().bold());
        println!("   💡 Run: {}", "kindlyguard mcp setup".bright_yellow());
    }
    
    Ok(())
}

/// Show MCP server status
async fn show_status(server: Option<&str>) -> Result<()> {
    use kindly_guard_server::setup::McpDetector;
    
    println!("{}", "📊 MCP Server Status".bright_blue().bold());
    println!();
    
    let detector = McpDetector::new();
    
    // Get overall status
    let status_summary = detector.get_status_summary()?;
    println!("{}", status_summary);
    
    // Show detailed AI tool status
    println!();
    println!("{}", "🤖 AI Tool Status:".bright_blue().bold());
    println!();
    
    let configs = detector.detect_all()?;
    let mut ai_tool_status = std::collections::HashMap::new();
    
    for config in &configs {
        let entry = ai_tool_status.entry(config.ide).or_insert_with(|| {
            (config.ide.supports_mcp(), vec![])
        });
        entry.1.push(config);
    }
    
    // Sort by IDE name
    let mut sorted_tools: Vec<_> = ai_tool_status.iter().collect();
    sorted_tools.sort_by_key(|(ide, _)| ide.as_str());
    
    for (ide, (supports_mcp, configs)) in sorted_tools {
        let icon = match ide {
            kindly_guard_server::setup::IdeType::ClaudeDesktop => "🤖",
            kindly_guard_server::setup::IdeType::ClaudeCode => "💻",
            kindly_guard_server::setup::IdeType::VsCode => "📝",
            kindly_guard_server::setup::IdeType::Cursor => "🎯",
            kindly_guard_server::setup::IdeType::Zed => "⚡",
            kindly_guard_server::setup::IdeType::Windsurf => "🌊",
            kindly_guard_server::setup::IdeType::ContinueDev => "🔄",
            kindly_guard_server::setup::IdeType::Neovim => "📟",
            _ => "📦",
        };
        
        let status = if !supports_mcp {
            "Not MCP compatible".bright_red()
        } else if configs.iter().any(|c| c.exists) {
            if configs.iter().any(|c| c.exists && detector.is_server_configured("kindlyguard").unwrap_or(false)) {
                "✅ Configured".bright_green()
            } else {
                "⚠️  Detected".bright_yellow()
            }
        } else {
            "Not installed".dimmed()
        };
        
        println!("  {} {} - {}", icon, ide.as_str().bright_cyan(), status);
        
        // Show config paths for existing configs
        for config in configs.iter().filter(|c| c.exists) {
            println!("     📍 {}", config.path.display().to_string().dimmed());
        }
    }
    
    // If specific server requested, show its config
    if let Some(server_name) = server {
        println!();
        println!("{}", format!("🔍 Server '{}' configuration:", server_name).bright_blue().bold());
        
        let mut found = false;
        for config in configs.iter().filter(|c| c.exists) {
            let content = fs::read_to_string(&config.path)?;
            let json_config: Value = serde_json::from_str(&content).unwrap_or_else(|_| json!({}));
            
            if let Some(servers) = json_config["mcpServers"].as_object() {
                if let Some(server_config) = servers.get(server_name) {
                    found = true;
                    println!();
                    println!("  In {} ({}):", config.ide.as_str(), config.path.display());
                    println!("{}", serde_json::to_string_pretty(server_config)?);
                }
            }
        }
        
        if !found {
            println!("  ❌ Server '{}' not found in any configuration", server_name);
        }
    }
    
    Ok(())
}

/// Start MCP server
async fn start_server(server: Option<&str>) -> Result<()> {
    let server_name = server.unwrap_or("kindlyguard");
    
    println!("{}", format!("🚀 Starting {} MCP server...", server_name).bright_blue().bold());
    
    if server_name == "kindlyguard" {
        // Start our server
        Command::new("kindlyguard")
            .args(&["serve", "--stdio"])
            .spawn()
            .context("Failed to start KindlyGuard server")?;
            
        println!("{}", "✅ KindlyGuard MCP server started".bright_green());
    } else {
        println!("❌ Can only start KindlyGuard server directly");
        println!("💡 Other servers are managed by Claude Desktop");
    }
    
    Ok(())
}

/// Stop MCP server
async fn stop_server(server: Option<&str>) -> Result<()> {
    let server_name = server.unwrap_or("kindlyguard");
    
    println!("{}", format!("🛑 Stopping {} MCP server...", server_name).bright_yellow().bold());
    
    // MCP servers are typically managed by the client (Claude Desktop)
    println!("💡 MCP servers are managed by Claude Desktop");
    println!("   To stop a server, disable it in Claude Desktop settings");
    
    Ok(())
}

/// Edit MCP configuration
async fn edit_config() -> Result<()> {
    use kindly_guard_server::setup::McpDetector;
    
    let detector = McpDetector::new();
    let configs = detector.detect_all()?;
    let existing_configs: Vec<_> = configs.iter().filter(|c| c.exists).collect();
    
    if existing_configs.is_empty() {
        println!("❌ No MCP configurations found");
        return Err(anyhow::anyhow!("No configurations to edit"));
    }
    
    // If only one config, use it. Otherwise ask which one
    let config_path = if existing_configs.len() == 1 {
        existing_configs[0].path.clone()
    } else {
        println!("Multiple configurations found:");
        for (i, config) in existing_configs.iter().enumerate() {
            println!("  {}. {} - {}", i + 1, config.ide.as_str(), config.path.display());
        }
        // For now, just use the first one
        // TODO: Add interactive selection
        existing_configs[0].path.clone()
    };
    
    println!("{}", "📝 Opening MCP configuration...".bright_blue().bold());
    println!("📍 Location: {}", config_path.display().to_string().bright_cyan());
    
    // Try to open with default editor
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(target_os = "linux")]
    let cmd = "xdg-open";
    #[cfg(target_os = "windows")]
    let cmd = "start";
    
    let result = Command::new(cmd)
        .arg(config_path.to_str().unwrap())
        .status();
        
    match result {
        Ok(status) if status.success() => {
            println!("✅ Opened in default editor");
        }
        _ => {
            // Fallback: show the path
            println!("💡 Open this file in your editor:");
            println!("   {}", config_path.display());
        }
    }
    
    Ok(())
}

/// List all MCP servers
async fn list_servers() -> Result<()> {
    show_status(None).await
}

