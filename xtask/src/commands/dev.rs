//! Development utilities command implementation

use anyhow::Result;
use std::process::Command;

use crate::utils::{cargo, Context};

/// Execute the dev command
pub async fn execute(
    ctx: Context,
    fmt: bool,
    clippy: bool,
    update: bool,
    outdated: bool,
    clean: bool,
    doc: bool,
) -> Result<()> {
    if !fmt && !clippy && !update && !outdated && !clean && !doc {
        ctx.warn("No dev action specified. Use --fmt, --clippy, --update, --outdated, --clean, or --doc");
        return Ok(());
    }

    // Format code
    if fmt {
        ctx.status("Format", "Formatting code");
        cargo::run_cargo(&ctx, &["fmt"])?;
        ctx.status("Done", "Code formatted");
    }

    // Run clippy
    if clippy {
        ctx.status("Clippy", "Running lints");
        cargo::run_cargo(&ctx, &[
            "clippy",
            "--all-targets",
            "--all-features",
            "--",
            "-W", "clippy::all",
            "-W", "clippy::pedantic",
            "-A", "clippy::module_name_repetitions",
            "-A", "clippy::must_use_candidate",
        ])?;
        ctx.status("Done", "Clippy checks passed");
    }

    // Update dependencies
    if update {
        ctx.status("Update", "Updating dependencies");
        cargo::run_cargo(&ctx, &["update"])?;
        ctx.status("Done", "Dependencies updated");
    }

    // Check for outdated dependencies
    if outdated {
        ctx.status("Outdated", "Checking for outdated dependencies");
        
        // Ensure cargo-outdated is installed
        cargo::ensure_cargo_extension("cargo-outdated")?;
        
        let mut cmd = Command::new("cargo");
        cmd.args(&["outdated", "--root-deps-only"]);
        ctx.run_command(&mut cmd)?;
    }

    // Clean build artifacts
    if clean {
        ctx.status("Clean", "Removing build artifacts");
        cargo::run_cargo(&ctx, &["clean"])?;
        
        // Also clean other directories
        let dirs_to_clean = ["target", "dist", "node_modules"];
        for dir in dirs_to_clean {
            if std::path::Path::new(dir).exists() {
                ctx.status("Removing", dir);
                std::fs::remove_dir_all(dir)?;
            }
        }
        
        ctx.status("Done", "Build artifacts cleaned");
    }

    // Generate documentation
    if doc {
        ctx.status("Docs", "Generating documentation");
        cargo::run_cargo(&ctx, &["doc", "--no-deps", "--all-features"])?;
        
        // Open in browser
        if !ctx.dry_run {
            cargo::run_cargo(&ctx, &["doc", "--no-deps", "--all-features", "--open"])?;
        }
        
        ctx.status("Done", "Documentation generated");
    }

    Ok(())
}