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

//! Server module - delegates to kindly-guard-server

use anyhow::Result;
use std::sync::Arc;
use tracing::info;

use kindly_guard_server::{config::Config, daemon, server::McpServer};

/// Run the MCP security server with specified options
pub async fn run_server(
    _stdio: bool,
    http: bool,
    bind: String,
    daemon_mode: bool,
    shield: bool,
    config_path: Option<String>,
) -> Result<()> {
    info!("🛡️ KindlyGuard Security Server starting...");

    // Load configuration
    let config = if let Some(path) = config_path {
        Config::load_from_file(&path)?
    } else {
        Config::load()?
    };

    // Store telemetry configuration
    let telemetry_enabled = config.telemetry.export_endpoint.is_some();
    let telemetry_interval = config.telemetry.export_interval_seconds;

    // Create the MCP server
    let server = Arc::new(McpServer::new(config)?);

    // Optionally start shield display
    let shield_handle = if shield {
        let shield = server.shield.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = shield.start_display().await {
                tracing::error!("Shield display error: {}", e);
            }
        }))
    } else {
        None
    };

    // Start telemetry flush if enabled
    let telemetry_handle = if telemetry_enabled {
        let server_clone = server.clone();
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_secs(telemetry_interval)
            );
            loop {
                interval.tick().await;
                let telemetry = server_clone.component_manager.telemetry_provider();
                if let Err(e) = telemetry.flush().await {
                    tracing::error!("Failed to flush telemetry: {}", e);
                }
            }
        }))
    } else {
        None
    };

    // Run the server based on mode
    if daemon_mode {
        info!("Running in daemon mode");
        let daemon_config = daemon::DaemonConfig {
            pid_file: None,
            ..Default::default()
        };

        daemon::run_with_daemon(daemon_config, |mut shutdown_rx| async move {
            let server_clone = server.clone();
            let server_handle = tokio::spawn(async move {
                if let Err(e) = server_clone.run_http(&bind).await {
                    tracing::error!("HTTP server error: {}", e);
                }
            });

            let _ = shutdown_rx.recv().await;
            info!("Received shutdown signal");
            server_handle.abort();
            Ok(())
        })
        .await?;
    } else if http {
        info!("Running HTTP API server on {}", bind);
        server.run_http(&bind).await?;
    } else {
        // Default to stdio mode
        info!("Running in stdio mode (default)");
        server.run_stdio().await?;
    }

    // Cleanup
    if let Some(handle) = shield_handle {
        handle.abort();
    }
    if let Some(handle) = telemetry_handle {
        handle.abort();
    }

    Ok(())
}