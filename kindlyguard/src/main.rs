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

//! KindlyGuard - Unified Security Tool for AI Protection
//!
//! A single binary that combines MCP server functionality with CLI tools
//! for comprehensive AI security protection.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cli;
mod installer;
mod messages;
mod server;
mod shared;
mod tools;

#[derive(Parser)]
#[command(name = "kindlyguard")]
#[command(version, about, long_about = None)]
#[command(author = "samduchaine")]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum MpcOperation {
    /// Set up MCP server configuration
    Setup,
    /// Verify MCP configuration
    Verify,
    /// Show MCP server status
    Status,
    /// Start MCP server
    Start,
    /// Stop MCP server
    Stop,
    /// View/edit MCP configuration
    Config,
    /// List all configured MCP servers
    List,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the MCP security server
    Serve {
        /// Run in stdio mode (default)
        #[arg(long, conflicts_with_all = ["http", "daemon"])]
        stdio: bool,

        /// Run HTTP API server
        #[arg(long, conflicts_with_all = ["stdio", "daemon"])]
        http: bool,

        /// Bind address for HTTP mode
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,

        /// Run as daemon
        #[arg(long, conflicts_with_all = ["stdio", "http"])]
        daemon: bool,

        /// Enable shield display
        #[arg(long)]
        shield: bool,

        /// Path to configuration file
        #[arg(short, long)]
        config: Option<String>,
    },

    /// Scan files or text for security threats
    Scan {
        /// Path to file or directory to scan
        path: String,

        /// Output format (text, json, yaml)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Recursive scan for directories
        #[arg(short, long)]
        recursive: bool,
    },

    /// Wrap and protect command execution
    Wrap {
        /// Command to wrap and execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,

        /// Block execution on threat detection
        #[arg(long)]
        block: bool,

        /// Log threats to file
        #[arg(long)]
        log: Option<String>,
    },

    /// Monitor real-time server activity
    Monitor {
        /// Server address to monitor
        #[arg(long, default_value = "http://localhost:8080")]
        server: String,

        /// Refresh interval in seconds
        #[arg(short, long, default_value = "1")]
        interval: u64,
    },

    /// Display security shield
    Shield {
        /// Shield mode (tui, web)
        #[arg(long, default_value = "tui")]
        mode: String,

        /// Auto-wrap terminal commands
        #[arg(long)]
        auto_wrap: bool,
    },

    /// Install or manage KindlyGuard components
    Install {
        /// Component to install
        component: Option<String>,

        /// Install all components
        #[arg(long, short = 'a')]
        all: bool,

        /// Auto-detect best installation method
        #[arg(long)]
        detect: bool,

        /// Force reinstall
        #[arg(long, short = 'f')]
        force: bool,
    },

    /// Development mode - start all services
    Dev {
        /// Project root directory (defaults to current directory)
        #[arg(short, long)]
        project_dir: Option<std::path::PathBuf>,
        
        /// Services to start (defaults to all: server,shield,monitor)
        #[arg(short, long, value_delimiter = ',')]
        services: Option<Vec<String>>,
        
        /// Run in background instead of opening terminals
        #[arg(short, long)]
        background: bool,
        
        /// Configuration file to use
        #[arg(short, long)]
        config: Option<std::path::PathBuf>,
        
        /// Don't install npm dependencies
        #[arg(long)]
        no_npm_install: bool,
    },

    /// Manage MCP (Model Context Protocol) servers
    Mcp {
        /// MCP operation
        #[arg(value_enum)]
        operation: MpcOperation,
        
        /// Server name (for specific operations)
        #[arg(short, long)]
        server: Option<String>,
    },

    /// Update KindlyGuard to the latest version
    Update {
        /// Check for updates without installing
        #[arg(long)]
        check: bool,

        /// Update to a specific version
        #[arg(long)]
        version: Option<String>,
    },

    /// Diagnose system and installation issues
    Doctor {
        /// Detailed diagnostics
        #[arg(long)]
        detailed: bool,

        /// Fix common issues automatically
        #[arg(long)]
        fix: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    if !cli.no_color {
        colored::control::set_override(true);
    }

    let filter = if cli.verbose {
        "kindlyguard=debug,kindly_guard=debug"
    } else {
        "kindlyguard=info,kindly_guard=info"
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| filter.into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Handle commands
    match cli.command {
        Some(Commands::Serve { stdio, http, bind, daemon, shield, config }) => {
            server::run_server(stdio, http, bind, daemon, shield, config).await?;
        }
        Some(Commands::Scan { path, format, recursive }) => {
            tools::scan::run_scan(&path, &format, recursive).await?;
        }
        Some(Commands::Wrap { command, block, log }) => {
            tools::wrap::run_wrap(command, block, log).await?;
        }
        Some(Commands::Monitor { server, interval }) => {
            tools::monitor::run_monitor(&server, interval).await?;
        }
        Some(Commands::Shield { mode, auto_wrap }) => {
            tools::shield::run_shield(&mode, auto_wrap).await?;
        }
        Some(Commands::Install { component, all, detect, force }) => {
            installer::run_install(component, all, detect, force).await?;
        }
        Some(Commands::Dev { project_dir, services, background, config, no_npm_install }) => {
            tools::dev::run_dev(project_dir, services, background, config, no_npm_install).await?;
        }
        Some(Commands::Mcp { operation, server }) => {
            tools::mcp::run_mcp(operation, server).await?;
        }
        Some(Commands::Update { check, version }) => {
            installer::update::run_update(check, version).await?;
        }
        Some(Commands::Doctor { detailed, fix }) => {
            installer::doctor::run_doctor(detailed, fix).await?;
        }
        None => {
            // Default behavior - show help
            println!("{}", "KindlyGuard - Unified Security Tool for AI Protection".bright_blue().bold());
            println!();
            println!("Usage: {} <COMMAND>", "kindlyguard".bright_cyan());
            println!();
            println!("Commands:");
            println!("  {} Run the MCP security server", "serve    ".bright_green());
            println!("  {} Scan files or text for threats", "scan     ".bright_green());
            println!("  {} Wrap and protect command execution", "wrap     ".bright_green());
            println!("  {} Monitor real-time server activity", "monitor  ".bright_green());
            println!("  {} Display security shield", "shield   ".bright_green());
            println!("  {} Install or manage components", "install  ".bright_green());
            println!("  {} Development mode (all services)", "dev      ".bright_green());
            println!("  {} Manage MCP servers", "mcp      ".bright_green());
            println!("  {} Update to the latest version", "update   ".bright_green());
            println!("  {} Diagnose system issues", "doctor   ".bright_green());
            println!();
            println!("Run {} for more information on a command.", "kindlyguard help <COMMAND>".bright_cyan());
        }
    }

    Ok(())
}