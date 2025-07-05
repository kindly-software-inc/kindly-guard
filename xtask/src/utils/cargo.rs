//! Cargo-related utilities

use anyhow::{Context as AnyhowContext, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::debug;

use crate::utils::Context;

/// Find the workspace root directory by looking for Cargo.toml with [workspace]
pub fn workspace_root() -> Result<PathBuf> {
    let current_dir = std::env::current_dir()
        .with_context(|| "Failed to get current directory")?;
    
    let mut dir = current_dir.as_path();
    
    loop {
        let cargo_toml = dir.join("Cargo.toml");
        
        if cargo_toml.exists() {
            // Read the file and check if it contains [workspace]
            let contents = std::fs::read_to_string(&cargo_toml)
                .with_context(|| format!("Failed to read {:?}", cargo_toml))?;
            
            if contents.contains("[workspace]") {
                debug!("Found workspace root at: {:?}", dir);
                return Ok(dir.to_path_buf());
            }
        }
        
        // Move up one directory
        match dir.parent() {
            Some(parent) => dir = parent,
            None => {
                return Err(anyhow::anyhow!(
                    "Could not find workspace root (no Cargo.toml with [workspace] found)"
                ));
            }
        }
    }
}

/// Run cargo with the given arguments
pub fn run_cargo(ctx: &Context, args: &[&str]) -> Result<()> {
    ctx.run_command("cargo", args)?;
    Ok(())
}

/// Check if a package exists in the workspace
pub fn package_exists(name: &str) -> Result<bool> {
    let metadata = cargo_metadata::MetadataCommand::new().exec()?;
    
    Ok(metadata.packages.iter().any(|pkg| pkg.name == name))
}

/// Get all packages in the workspace
pub fn get_packages() -> Result<Vec<String>> {
    let metadata = cargo_metadata::MetadataCommand::new().exec()?;
    
    Ok(metadata
        .packages
        .iter()
        .map(|pkg| pkg.name.clone())
        .collect())
}

/// Build a specific package with options
pub fn build_package(
    ctx: &Context,
    package: Option<&str>,
    profile: &str,
    target: Option<&str>,
    features: Option<&str>,
    all_features: bool,
) -> Result<()> {
    let mut args = vec!["build"];
    
    if let Some(pkg) = package {
        args.push("--package");
        args.push(pkg);
    }
    
    if profile != "debug" {
        args.push("--profile");
        args.push(profile);
    }
    
    if let Some(t) = target {
        args.push("--target");
        args.push(t);
    }
    
    if all_features {
        args.push("--all-features");
    } else if let Some(f) = features {
        args.push("--features");
        args.push(f);
    }
    
    run_cargo(ctx, &args)
}

/// Run tests with options
pub fn run_tests(
    ctx: &Context,
    package: Option<&str>,
    test_name: Option<&str>,
    all_features: bool,
) -> Result<()> {
    let mut args = vec!["test"];
    
    if let Some(pkg) = package {
        args.push("--package");
        args.push(pkg);
    }
    
    if let Some(name) = test_name {
        args.push(name);
    }
    
    if all_features {
        args.push("--all-features");
    }
    
    run_cargo(ctx, &args)
}

/// Check if cargo-dist is installed
pub fn has_cargo_dist() -> bool {
    Command::new("cargo")
        .args(&["dist", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if cargo-audit is installed
pub fn has_cargo_audit() -> bool {
    Command::new("cargo")
        .args(&["audit", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Install a cargo extension if not present
pub fn ensure_cargo_extension(name: &str) -> Result<()> {
    let check_cmd = format!("{} --version", name.replace("cargo-", ""));
    
    if Command::new("cargo")
        .args(&check_cmd.split_whitespace().collect::<Vec<_>>())
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        debug!("{} is already installed", name);
        return Ok(());
    }
    
    println!("Installing {}...", name);
    let output = Command::new("cargo")
        .args(&["install", name])
        .output()?;
    
    if !output.status.success() {
        anyhow::bail!("Failed to install {}", name);
    }
    
    Ok(())
}