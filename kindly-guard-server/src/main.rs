//! KindlyGuard MCP Security Server
//! 
//! A focused security server for the Model Context Protocol that protects
//! against unicode attacks, injection attempts, and other threats.

use std::sync::Arc;
use anyhow::Result;
use clap::Parser;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod config;
mod error;
#[cfg(feature = "enhanced")]
mod event_processor;
mod protocol;
mod rate_limit;
mod scanner;
mod server;
mod shield;
mod signing;
mod traits;
mod standard_impl;
#[cfg(feature = "enhanced")]
mod enhanced_impl;
mod component_selector;
mod logging;
mod permissions;
mod versioning;
mod telemetry;

use config::Config;
use server::McpServer;

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
    
    /// Enable shield display
    #[arg(long)]
    shield: bool,
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
    if args.stdio {
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