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
//! `KindlyGuard` MCP Security Server
//!
//! A focused security server for the Model Context Protocol that protects
//! against unicode attacks, injection attempts, and other threats.

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Use the library crate instead of re-declaring modules
use kindly_guard_server::{cli, config, daemon, server};

use cli::commands::Commands;
use config::Config;
use server::McpServer;

/// Start telemetry flush task if enabled
fn start_telemetry_flush(
    enabled: bool,
    interval_seconds: u64,
    server: Arc<McpServer>,
) -> Option<tokio::task::JoinHandle<()>> {
    if enabled {
        Some(tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_seconds));
            loop {
                interval.tick().await;
                let telemetry = server.component_manager.telemetry_provider();
                if let Err(e) = telemetry.flush().await {
                    error!("Failed to flush telemetry: {}", e);
                }
            }
        }))
    } else {
        None
    }
}

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "kindly-guard")]
#[command(about = "Security-focused MCP server", long_about = None)]
struct Args {
    /// Path to configuration file
    #[arg(short, long)]
    config: Option<String>,

    /// Run in stdio mode (default)
    #[arg(long, conflicts_with_all = ["http", "proxy", "daemon"])]
    stdio: bool,

    /// Run HTTP API server
    #[arg(long, conflicts_with_all = ["stdio", "proxy", "daemon"])]
    http: bool,

    /// Run as HTTPS proxy
    #[arg(long, conflicts_with_all = ["stdio", "http", "daemon"])]
    proxy: bool,

    /// Bind address for HTTP/proxy mode
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: String,

    /// Run as daemon
    #[arg(long, conflicts_with_all = ["stdio", "http", "proxy"])]
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
        })
        .await?;
    } else if args.http {
        info!("Running HTTP API server on {}", args.bind);

        // Start periodic telemetry flush if configured
        let telemetry_flush_handle =
            start_telemetry_flush(telemetry_enabled, telemetry_interval, server.clone());

        match server.run_http(&args.bind).await {
            Ok(()) => {
                info!("HTTP server shutting down gracefully");
            }
            Err(e) => {
                error!("HTTP server error: {}", e);
                return Err(e);
            }
        }

        // Stop telemetry flush task
        if let Some(handle) = telemetry_flush_handle {
            handle.abort();
        }
    } else if args.proxy {
        info!("Running as HTTPS proxy on {}", args.bind);

        // Start periodic telemetry flush if configured
        let telemetry_flush_handle =
            start_telemetry_flush(telemetry_enabled, telemetry_interval, server.clone());

        match server.run_proxy(&args.bind).await {
            Ok(()) => {
                info!("Proxy server shutting down gracefully");
            }
            Err(e) => {
                error!("Proxy server error: {}", e);
                return Err(e);
            }
        }

        // Stop telemetry flush task
        if let Some(handle) = telemetry_flush_handle {
            handle.abort();
        }
    } else {
        // Default to stdio mode if no mode specified
        info!("Running in stdio mode (default)");

        // Start periodic telemetry flush if configured
        let telemetry_flush_handle =
            start_telemetry_flush(telemetry_enabled, telemetry_interval, server.clone());

        match server.run_stdio().await {
            Ok(()) => {
                info!("KindlyGuard server shutting down gracefully");
            }
            Err(e) => {
                error!("Server error: {}", e);
                return Err(e);
            }
        }

        // Stop telemetry flush task
        if let Some(handle) = telemetry_flush_handle {
            handle.abort();
        }
    }

    // Stop the shield display if running
    if let Some(handle) = shield_handle {
        handle.abort();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    

    #[test]
    fn test_main_compiles() {
        // Simple compilation test
        // This test ensures the main module compiles properly
    }
}
