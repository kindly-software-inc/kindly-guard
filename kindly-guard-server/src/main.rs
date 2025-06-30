//! KindlyGuard MCP Security Server
//! 
//! A focused security server for the Model Context Protocol that protects
//! against unicode attacks, injection attempts, and other threats.

use std::sync::Arc;
use anyhow::Result;
use clap::Parser;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Use the library crate instead of re-declaring modules
use kindly_guard_server::*;

use config::Config;
use server::McpServer;
use cli::commands::Commands;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "kindly-guard")]
#[command(about = "Security-focused MCP server", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<String>,
    
    /// Run in stdio mode (default)
    #[arg(long, default_value = "true")]
    stdio: bool,
    
    /// Run as daemon
    #[arg(long, conflicts_with = "stdio")]
    daemon: bool,
    
    /// PID file path (for daemon mode)
    #[arg(long, requires = "daemon")]
    pid_file: Option<String>,
    
    /// Enable shield display
    #[arg(long)]
    shield: bool,
    
    /// Run as command interface (e.g., /kindlyguard status)
    #[command(subcommand)]
    command: Option<Commands>,
    
    /// Output format for commands
    #[arg(short = 'f', long, global = true)]
    format: Option<String>,
    
    /// Disable color output
    #[arg(long, global = true)]
    no_color: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();
    
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kindly_guard=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Check if running in command mode
    if args.command.is_some() {
        // Command mode - don't show server startup message
        let cmd = cli::commands::KindlyCommand {
            command: args.command,
            format: args.format.unwrap_or_else(|| "text".to_string()),
            no_color: args.no_color,
        };
        return cli::commands::run_command(cmd).await;
    }

    info!("🛡️ KindlyGuard MCP Security Server starting...");

    // Load configuration
    let config = if let Some(path) = args.config {
        Config::load_from_file(&path)?
    } else {
        Config::load()?
    };
    
    // Store telemetry configuration before moving config
    let telemetry_enabled = config.telemetry.export_endpoint.is_some();
    let telemetry_interval = config.telemetry.export_interval_seconds;
    
    // Create the MCP server
    let server = Arc::new(McpServer::new(config)?);
    
    // Optionally start shield display
    let shield_handle = if args.shield {
        let shield = server.shield.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = shield.start_display().await {
                error!("Shield display error: {}", e);
            }
        }))
    } else {
        None
    };
    
    // Run the server
    if args.daemon {
        // Daemon mode
        info!("Running in daemon mode");
        
        let daemon_config = daemon::DaemonConfig {
            pid_file: args.pid_file,
            ..Default::default()
        };
        
        daemon::run_with_daemon(daemon_config, |mut shutdown_rx| async move {
            // Start HTTP server in daemon mode
            let server_clone = server.clone();
            let server_handle = tokio::spawn(async move {
                if let Err(e) = server_clone.run_http("127.0.0.1:8080").await {
                    error!("HTTP server error: {}", e);
                }
            });
            
            // Wait for shutdown signal
            let _ = shutdown_rx.recv().await;
            info!("Received shutdown signal");
            
            // Gracefully shutdown server
            server_handle.abort();
            Ok(())
        }).await?;
        
    } else if args.stdio {
        info!("Running in stdio mode");
        
        // Start periodic telemetry flush if configured
        let telemetry_flush_handle = if telemetry_enabled {
            let server_clone = server.clone();
            Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(telemetry_interval));
                loop {
                    interval.tick().await;
                    let telemetry = server_clone.component_manager.telemetry_provider();
                    if let Err(e) = telemetry.flush().await {
                        error!("Failed to flush telemetry: {}", e);
                    }
                }
            }))
        } else {
            None
        };
        
        match server.run_stdio().await {
            Ok(_) => {
                info!("KindlyGuard server shutting down gracefully");
            }
            Err(e) => {
                error!("Server error: {}", e);
                return Err(e.into());
            }
        }
        
        // Stop telemetry flush task
        if let Some(handle) = telemetry_flush_handle {
            handle.abort();
        }
    } else {
        error!("Only stdio mode is currently supported");
        return Err(anyhow::anyhow!("Only stdio mode is currently supported"));
    }

    // Stop the shield display if running
    if let Some(handle) = shield_handle {
        handle.abort();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main_compiles() {
        // Simple compilation test
        assert!(true);
    }
}