use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

// Platform-specific code will be added here if needed

use kindly_tools::{
    dev::DevCommand, install::InstallCommand, mcp::McpCommand, monitor::MonitorCommand,
    shield::ShieldCommand, wrap::WrapCommand, Execute,
};

#[derive(Parser)]
#[command(
    name = "kindly-tools",
    about = "Development tools and utilities for KindlyGuard ecosystem",
    version,
    author
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
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

    /// Install tools and dependencies
    Install(InstallCommand),

    /// Manage MCP (Model Context Protocol) servers
    Mcp(McpCommand),

    /// Development utilities
    Dev(DevCommand),

    /// Wrap any AI CLI command with KindlyGuard protection
    Wrap(WrapCommand),

    /// Monitor KindlyGuard server status in real-time
    Monitor(MonitorCommand),

    /// Security shield commands for protecting AI interactions
    Shield(ShieldCommand),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("kindly_tools=debug,info")
    } else {
        EnvFilter::new("kindly_tools=info,warn")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    match cli.command {
        Commands::Scan {
            path,
            format,
            recursive,
            extensions,
            max_size_mb,
            config,
        } => {
            use kindly_tools::commands::scan;
            scan::execute(path, format, recursive, extensions, max_size_mb, config).await
        },
        Commands::Install(cmd) => cmd.execute().await,
        Commands::Mcp(cmd) => cmd.execute().await,
        Commands::Dev(cmd) => cmd.execute().await,
        Commands::Wrap(cmd) => cmd.execute().await,
        Commands::Monitor(cmd) => cmd.execute().await,
        Commands::Shield(cmd) => cmd.execute().await,
    }
}
