//! Development mode - start all KindlyGuard services

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tokio::task::JoinHandle;

/// Run development mode with all services
pub async fn run_dev(
    project_dir: Option<PathBuf>,
    services: Option<Vec<String>>,
    background: bool,
    config: Option<PathBuf>,
    no_npm_install: bool,
) -> Result<()> {
    println!("{}", "🚀 Starting KindlyGuard Development Mode".bright_blue().bold());
    println!();

    // Determine project directory
    let project_dir = project_dir.unwrap_or_else(|| std::env::current_dir().unwrap());
    println!("📁 Project: {}", project_dir.display().to_string().bright_cyan());

    // Determine which services to start
    let services = services.unwrap_or_else(|| vec![
        "server".to_string(),
        "shield".to_string(),
        "monitor".to_string(),
    ]);
    
    println!("🔧 Services: {}", services.join(", ").bright_green());
    
    if let Some(config) = &config {
        println!("⚙️  Config: {}", config.display().to_string().bright_yellow());
    }
    
    // Check for npm dependencies if needed
    if !no_npm_install && project_dir.join("package.json").exists() {
        println!();
        println!("📦 Installing npm dependencies...");
        
        let status = Command::new("npm")
            .arg("install")
            .current_dir(&project_dir)
            .status()
            .context("Failed to run npm install")?;
            
        if !status.success() {
            eprintln!("{}", "⚠️  npm install failed, continuing anyway...".yellow());
        }
    }
    
    // Start services
    println!();
    println!("{}", "🚦 Starting services...".bright_green());
    
    let mut handles: Vec<JoinHandle<Result<()>>> = Vec::new();
    
    for service in services {
        match service.as_str() {
            "server" => {
                println!("  • Starting MCP server...");
                let config = config.clone();
                let handle = tokio::spawn(async move {
                    start_server(config, background).await
                });
                handles.push(handle);
            }
            "shield" => {
                println!("  • Starting security shield...");
                let handle = tokio::spawn(async move {
                    start_shield(background).await
                });
                handles.push(handle);
            }
            "monitor" => {
                println!("  • Starting monitor...");
                let handle = tokio::spawn(async move {
                    start_monitor(background).await
                });
                handles.push(handle);
            }
            _ => {
                eprintln!("  ⚠️  Unknown service: {}", service);
            }
        }
    }
    
    if handles.is_empty() {
        return Err(anyhow::anyhow!("No services started"));
    }
    
    println!();
    println!("{}", "✅ All services started!".bright_green().bold());
    println!();
    println!("Press Ctrl+C to stop all services");
    
    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    
    println!();
    println!("{}", "🛑 Shutting down services...".bright_yellow());
    
    // Cancel all tasks
    for handle in handles {
        handle.abort();
    }
    
    println!("{}", "👋 Development mode stopped".bright_blue());
    
    Ok(())
}

async fn start_server(config: Option<PathBuf>, background: bool) -> Result<()> {
    let mut cmd = Command::new("kindlyguard");
    cmd.arg("serve").arg("--stdio");
    
    if let Some(config) = config {
        cmd.arg("--config").arg(config);
    }
    
    if !background {
        cmd.stdout(Stdio::inherit())
           .stderr(Stdio::inherit())
           .stdin(Stdio::inherit());
    }
    
    let mut child = cmd.spawn().context("Failed to start server")?;
    
    // Wait for the process
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow::anyhow!("Server exited with error"));
    }
    
    Ok(())
}

async fn start_shield(background: bool) -> Result<()> {
    let mut cmd = Command::new("kindlyguard");
    cmd.arg("shield");
    
    if !background {
        cmd.stdout(Stdio::inherit())
           .stderr(Stdio::inherit())
           .stdin(Stdio::inherit());
    }
    
    let mut child = cmd.spawn().context("Failed to start shield")?;
    
    // Wait for the process
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow::anyhow!("Shield exited with error"));
    }
    
    Ok(())
}

async fn start_monitor(background: bool) -> Result<()> {
    let mut cmd = Command::new("kindlyguard");
    cmd.arg("monitor");
    
    if !background {
        cmd.stdout(Stdio::inherit())
           .stderr(Stdio::inherit())
           .stdin(Stdio::inherit());
    }
    
    let mut child = cmd.spawn().context("Failed to start monitor")?;
    
    // Wait for the process
    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow::anyhow!("Monitor exited with error"));
    }
    
    Ok(())
}