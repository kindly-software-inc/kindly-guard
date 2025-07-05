use anyhow::{Context as _, Result};
use clap::Args;
use colored::*;
use indicatif::{MultiProgress, ProgressBar};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::utils::{Context, ensure_command_exists};

#[derive(Args)]
pub struct BuildCmd {
    /// Target platforms to build for
    #[arg(long, value_delimiter = ',')]
    pub targets: Option<Vec<String>>,

    /// Build in release mode
    #[arg(long)]
    pub release: bool,

    /// Strip debug symbols from binaries
    #[arg(long)]
    pub strip: bool,

    /// Create archives for each platform
    #[arg(long)]
    pub archive: bool,

    /// Output directory for build artifacts
    #[arg(long, default_value = "dist")]
    pub output_dir: Option<String>,
}

pub async fn run(cmd: BuildCmd, ctx: Context) -> Result<()> {
    // Ensure required tools
    ensure_command_exists("cargo")?;
    ensure_command_exists("cross")?;

    let targets = cmd.targets.unwrap_or_else(default_targets);
    let output_dir = PathBuf::from(cmd.output_dir.unwrap_or_else(|| "dist".to_string()));

    ctx.info(&format!("Building for {} targets", targets.len()));

    // Create output directory
    std::fs::create_dir_all(&output_dir)
        .context("Failed to create output directory")?;

    // Setup progress tracking
    let multi_progress = Arc::new(MultiProgress::new());
    let semaphore = Arc::new(Semaphore::new(num_cpus::get()));

    let mut handles = vec![];

    for target in &targets {
        let target = target.clone();
        let ctx = ctx.clone();
        let output_dir = output_dir.clone();
        let multi_progress = Arc::clone(&multi_progress);
        let semaphore = Arc::clone(&semaphore);
        let cmd = BuildCmdClone {
            release: cmd.release,
            strip: cmd.strip,
            archive: cmd.archive,
        };

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            build_target(&target, &cmd, &ctx, &output_dir, &multi_progress).await
        });

        handles.push(handle);
    }

    // Wait for all builds to complete
    let results: Vec<Result<()>> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    // Check for failures
    let mut failed = false;
    for (target, result) in targets.iter().zip(results.iter()) {
        match result {
            Ok(_) => ctx.success(&format!("✓ {}", target)),
            Err(e) => {
                ctx.error(&format!("✗ {}: {}", target, e));
                failed = true;
            }
        }
    }

    if failed {
        anyhow::bail!("Some builds failed");
    }

    ctx.success("All builds completed successfully!");

    // List artifacts
    if cmd.archive {
        println!("\n{}", "Build artifacts:".bold());
        for entry in std::fs::read_dir(&output_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let size = entry.metadata()?.len();
                let size_mb = size as f64 / 1_048_576.0;
                println!("  {} ({:.2} MB)", path.display(), size_mb);
            }
        }
    }

    Ok(())
}

#[derive(Clone)]
struct BuildCmdClone {
    release: bool,
    strip: bool,
    archive: bool,
}

async fn build_target(
    target: &str,
    cmd: &BuildCmdClone,
    ctx: &Context,
    output_dir: &Path,
    multi_progress: &MultiProgress,
) -> Result<()> {
    let pb = multi_progress.add(ProgressBar::new_spinner());
    pb.set_message(format!("Building {}", target));
    pb.enable_steady_tick(std::time::Duration::from_millis(100));

    // Determine build tool
    let use_cross = should_use_cross(target);
    let build_cmd = if use_cross { "cross" } else { "cargo" };

    // Build arguments
    let mut args = vec!["build", "--target", target];
    
    if cmd.release {
        args.push("--release");
    }

    // Add features
    args.extend(&["--features", "full"]);

    // Run build
    ctx.run_command(build_cmd, &args)?;

    pb.set_message(format!("Processing {}", target));

    // Find built binaries
    let target_dir = if cmd.release { "release" } else { "debug" };
    let binary_paths = find_binaries(target, target_dir)?;

    // Process each binary
    for binary_path in binary_paths {
        let binary_name = binary_path.file_name()
            .context("Invalid binary name")?
            .to_string_lossy();

        // Strip if requested
        if cmd.strip && cmd.release {
            strip_binary(&binary_path, target)?;
        }

        // Create platform-specific directory
        let platform_dir = output_dir.join(target);
        std::fs::create_dir_all(&platform_dir)?;

        // Copy binary
        let dest_path = platform_dir.join(binary_name.as_ref());
        std::fs::copy(&binary_path, &dest_path)
            .context("Failed to copy binary")?;

        // Create archive if requested
        if cmd.archive {
            create_archive(target, &platform_dir, output_dir, binary_name.as_ref())?;
        }
    }

    pb.finish_with_message(format!("✓ {}", target));
    Ok(())
}

fn should_use_cross(target: &str) -> bool {
    // Use cross for cross-compilation targets
    let host = std::env::var("HOST").unwrap_or_else(|_| {
        std::env::consts::ARCH.to_string() + "-" + std::env::consts::OS
    });

    // Special cases where we always use cross
    let always_cross = [
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-gnu",
        "aarch64-unknown-linux-musl",
        "arm-unknown-linux-gnueabi",
        "arm-unknown-linux-gnueabihf",
        "armv7-unknown-linux-gnueabihf",
    ];

    target != host || always_cross.contains(&target)
}

fn find_binaries(target: &str, build_type: &str) -> Result<Vec<PathBuf>> {
    let target_dir = PathBuf::from("target").join(target).join(build_type);
    
    let mut binaries = vec![];
    
    // Look for known binary names
    let binary_names = ["kindly-guard", "kindly-guard-server", "kindly-guard-cli"];
    
    for name in &binary_names {
        let mut path = target_dir.join(name);
        
        // Add .exe extension for Windows
        if target.contains("windows") {
            path.set_extension("exe");
        }
        
        if path.exists() {
            binaries.push(path);
        }
    }

    if binaries.is_empty() {
        anyhow::bail!("No binaries found for target {}", target);
    }

    Ok(binaries)
}

fn strip_binary(binary_path: &Path, target: &str) -> Result<()> {
    let strip_cmd = if target.contains("apple") {
        "strip".to_string()
    } else if target.contains("windows") {
        // Windows binaries are typically stripped during build
        return Ok(());
    } else {
        // Try to use target-specific strip
        let target_strip = format!("{}-strip", target.split('-').next().unwrap());
        if which::which(&target_strip).is_ok() {
            target_strip
        } else {
            "strip".to_string()
        }
    };

    std::process::Command::new(&strip_cmd)
        .arg(binary_path)
        .status()
        .context("Failed to strip binary")?;

    Ok(())
}

fn create_archive(
    target: &str,
    platform_dir: &Path,
    output_dir: &Path,
    binary_name: &str,
) -> Result<()> {
    let archive_name = format!("{}-{}", binary_name.trim_end_matches(".exe"), target);
    
    if target.contains("windows") {
        // Create ZIP for Windows
        let archive_path = output_dir.join(format!("{}.zip", archive_name));
        create_zip_archive(platform_dir, &archive_path)?;
    } else {
        // Create tar.gz for Unix-like systems
        let archive_path = output_dir.join(format!("{}.tar.gz", archive_name));
        create_tar_archive(platform_dir, &archive_path)?;
    }

    Ok(())
}

fn create_zip_archive(src_dir: &Path, dest_path: &Path) -> Result<()> {
    use crate::utils::archive::{create_zip, CreateOptions};
    
    let mut options = CreateOptions::default();
    options.compression_level = 6;
    options.preserve_permissions = true;
    
    create_zip(dest_path, src_dir, options)
}

fn create_tar_archive(src_dir: &Path, dest_path: &Path) -> Result<()> {
    use crate::utils::archive::{create_tar_gz, CreateOptions};
    
    let mut options = CreateOptions::default();
    options.compression_level = 6;
    options.preserve_permissions = true;
    
    create_tar_gz(dest_path, src_dir, options)
}

fn default_targets() -> Vec<String> {
    vec![
        "x86_64-unknown-linux-gnu".to_string(),
        "x86_64-unknown-linux-musl".to_string(),
        "x86_64-apple-darwin".to_string(),
        "aarch64-apple-darwin".to_string(),
        "x86_64-pc-windows-msvc".to_string(),
    ]
}