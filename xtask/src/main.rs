use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;
mod config;
mod interactive;
mod test;
mod utils;

use commands::{build, cache, ci, coverage, doctor, package, publish, release, security, test as test_cmd, validate_dist, version};

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Build automation for KindlyGuard project")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Run in interactive mode
    #[arg(short, long)]
    interactive: bool,

    /// Run in dry-run mode (no actual changes)
    #[arg(long, global = true)]
    dry_run: bool,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Release a new version
    Release(release::ReleaseCmd),
    
    /// Build the project for multiple platforms
    Build(build::BuildCmd),
    
    /// Run CI pipeline locally
    Ci(ci::CiCmd),
    
    /// Generate code coverage reports
    Coverage(coverage::CoverageCmd),
    
    /// Manage build cache
    Cache(cache::CacheCmd),
    
    /// Run tests and benchmarks
    Test(test_cmd::TestCmd),
    
    /// Run security audits
    Security(security::SecurityCmd),
    
    /// Manage project versions
    Version(version::VersionCmd),
    
    /// Publish to registries
    Publish(publish::PublishCmd),
    
    /// Package binaries for distribution
    Package(package::PackageCmd),
    
    /// Check development environment health
    Doctor(doctor::DoctorCmd),
    
    /// Validate dist configuration
    ValidateDist(validate_dist::ValidateDistCmd),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Configure colored output
    if cli.no_color {
        colored::control::set_override(false);
    }

    // Set up logging
    if cli.verbose {
        std::env::set_var("RUST_LOG", "debug");
    }

    // Create shared context
    let ctx = utils::Context {
        dry_run: cli.dry_run,
        verbose: cli.verbose,
    };

    // Check if running in interactive mode
    if cli.interactive || cli.command.is_none() {
        let mut interactive = interactive::InteractiveMode::new(ctx);
        return interactive.run().await;
    }

    // Normal command mode
    match cli.command.unwrap() {
        Commands::Release(cmd) => release::run(cmd, ctx).await,
        Commands::Build(cmd) => build::run(cmd, ctx).await,
        Commands::Ci(cmd) => ci::run(cmd, ctx).await,
        Commands::Coverage(cmd) => coverage::run(cmd, ctx).await,
        Commands::Cache(cmd) => cache::run(cmd, ctx).await,
        Commands::Test(cmd) => test_cmd::run(cmd, ctx).await,
        Commands::Security(cmd) => security::run(cmd, ctx).await,
        Commands::Version(cmd) => version::run(cmd, ctx).await,
        Commands::Publish(cmd) => publish::run(cmd, ctx).await,
        Commands::Package(cmd) => package::run(cmd, ctx).await,
        Commands::Doctor(cmd) => doctor::run(cmd, ctx).await,
        Commands::ValidateDist(cmd) => validate_dist::run(cmd, ctx).await,
    }
}