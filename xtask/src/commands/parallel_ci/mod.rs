//! Parallel CI/CD system for maximizing hardware utilization
//!
//! This module implements a massively parallel CI/CD pipeline that runs
//! all tests, builds, and security scans simultaneously across multiple
//! OS targets.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

pub mod cache;
pub mod coordinator;
pub mod monitor;
pub mod pipelines;
pub mod targets;
pub mod workers;

use crate::utils::Context;
use coordinator::Coordinator;

#[derive(Debug, Parser)]
pub struct ParallelCiCmd {
    /// Target platforms to build for (comma-separated)
    /// e.g., "linux-x64,linux-arm64,macos,windows"
    #[arg(long, value_delimiter = ',')]
    targets: Option<Vec<String>>,

    /// Run quick smoke tests
    #[arg(long)]
    smoke_tests: bool,

    /// Run complete test suite
    #[arg(long)]
    full_suite: bool,

    /// Run security scans
    #[arg(long)]
    security_scan: bool,

    /// Run performance benchmarks
    #[arg(long)]
    benchmark: bool,

    /// Maximum parallel tasks (defaults to CPU count)
    #[arg(long)]
    max_parallel: Option<usize>,

    /// Show real-time TUI dashboard
    #[arg(long)]
    dashboard: bool,

    /// Fail fast on first error
    #[arg(long)]
    fail_fast: bool,

    /// Clean CI artifacts before running
    #[arg(long)]
    clean: bool,

    /// Configuration file path
    #[arg(long)]
    config: Option<PathBuf>,

    /// Show detailed output
    #[arg(short, long)]
    verbose: bool,
}

impl ParallelCiCmd {
    pub async fn run(&self, ctx: &Context) -> Result<()> {
        let ctx = Arc::new(ctx.clone());

        // Print header
        ctx.info("");
        ctx.info("╔══════════════════════════════════════════════╗");
        ctx.info("║     KindlyGuard Parallel CI/CD System        ║");
        ctx.info("║          Maximizing Hardware Power           ║");
        ctx.info("╚══════════════════════════════════════════════╝");
        ctx.info("");

        // Create coordinator
        let mut coordinator = Coordinator::new(
            ctx.clone(),
            self.max_parallel,
            self.fail_fast,
            self.dashboard,
        )
        .await?;

        // Configure pipelines based on flags
        if !self.smoke_tests && !self.full_suite && !self.security_scan && !self.benchmark {
            // Default: run everything
            coordinator.enable_all_pipelines();
        } else {
            // Selective execution
            if self.smoke_tests {
                coordinator.enable_smoke_tests();
            }
            if self.full_suite {
                coordinator.enable_full_tests();
            }
            if self.security_scan {
                coordinator.enable_security_scan();
            }
            if self.benchmark {
                coordinator.enable_benchmarks();
            }
        }

        // Configure targets
        if let Some(targets) = &self.targets {
            coordinator.set_targets(targets.clone());
        } else {
            // Default: current platform + common targets
            coordinator.use_default_targets();
        }

        // Load configuration if provided
        if let Some(config_path) = &self.config {
            coordinator.load_config(config_path).await?;
        }

        // Clean artifacts if requested
        if self.clean {
            ctx.info("Cleaning CI artifacts...");
            coordinator.clean_artifacts().await?;
        }

        // Run the parallel CI pipeline
        ctx.info("Starting parallel CI pipeline...");
        ctx.info(&format!(
            "Max parallelism: {} tasks",
            coordinator.max_parallel()
        ));
        ctx.info(&format!(
            "Target platforms: {}",
            coordinator.targets().join(", ")
        ));
        ctx.info("");

        // Execute all pipelines in parallel
        let results = coordinator.execute().await?;

        // Display results
        results.print_summary(&ctx);

        // Exit with appropriate code
        if results.has_failures() {
            if self.fail_fast {
                ctx.error("CI pipeline failed (fail-fast mode)");
            } else {
                ctx.error(&format!(
                    "CI pipeline completed with {} failures",
                    results.failure_count()
                ));
            }
            std::process::exit(1);
        } else {
            ctx.success("All CI pipelines completed successfully!");
            Ok(())
        }
    }
}
