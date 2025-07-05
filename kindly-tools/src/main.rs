use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

// Platform-specific code will be added here if needed

use kindly_tools::{
    dev::DevCommand,
    install::InstallCommand,
    mcp::McpCommand,
    Execute,
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
    /// Install tools and dependencies
    Install(InstallCommand),

    /// Manage MCP (Model Context Protocol) servers
    Mcp(McpCommand),

    /// Development utilities
    Dev(DevCommand),
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
        Commands::Install(cmd) => cmd.execute().await,
        Commands::Mcp(cmd) => cmd.execute().await,
        Commands::Dev(cmd) => cmd.execute().await,
    }
}