//! KindlyGuard CLI tool for security scanning

use anyhow::Result;
use clap::{Parser, Subcommand};

/// KindlyGuard CLI - Security scanner and monitoring tool
#[derive(Parser, Debug)]
#[command(name = "kindly-guard-cli")]
#[command(about = "Security scanner for detecting unicode attacks and injection threats", long_about = None)]
struct Cli {
    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
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
    },
    
    /// Monitor KindlyGuard server status
    Monitor {
        /// Server URL
        #[arg(short, long, default_value = "http://localhost:8080")]
        url: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("kindly_guard={}", log_level))
        .init();
    
    match cli.command {
        Commands::Scan { path, format, recursive } => {
            println!("Scanning {} (format: {}, recursive: {})", path, format, recursive);
            // TODO: Implement scanning
            Ok(())
        }
        Commands::Monitor { url } => {
            println!("Monitoring server at {}", url);
            // TODO: Implement monitoring
            Ok(())
        }
    }
}