use anyhow::{Context as _, Result};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use std::process::Command;
use std::time::Duration;

// Sub-modules
pub mod archive;
pub mod cargo;
pub mod docker;
pub mod fs;
pub mod git;
pub mod nextest;
pub mod npm;
pub mod process;
pub mod tools;
pub mod version;

// Re-exports for convenience
pub use tools::{ensure_tool_installed, is_tool_installed, is_ci_environment, ToolInstallConfig};

#[derive(Clone, Debug)]
pub struct Context {
    pub dry_run: bool,
    pub verbose: bool,
}

impl Context {
    pub fn info(&self, msg: &str) {
        println!("{} {}", "info:".blue().bold(), msg);
    }

    pub fn success(&self, msg: &str) {
        println!("{} {}", "✓".green().bold(), msg);
    }

    pub fn warn(&self, msg: &str) {
        println!("{} {}", "warning:".yellow().bold(), msg);
    }

    pub fn error(&self, msg: &str) {
        eprintln!("{} {}", "error:".red().bold(), msg);
    }

    pub fn debug(&self, msg: &str) {
        if self.verbose {
            println!("{} {}", "debug:".dimmed(), msg.dimmed());
        }
    }

    pub fn run_command(&self, cmd: &str, args: &[&str]) -> Result<String> {
        if self.dry_run {
            println!("{} {} {}", "[dry-run]".yellow(), cmd, args.join(" "));
            return Ok(String::new());
        }

        self.debug(&format!("Running: {} {}", cmd, args.join(" ")));

        let output = Command::new(cmd)
            .args(args)
            .output()
            .with_context(|| format!("Failed to execute {}", cmd))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("{} failed:\n{}", cmd, stderr);
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        
        if self.verbose && !stdout.is_empty() {
            println!("{}", stdout);
        }

        Ok(stdout)
    }

    pub async fn run_async(&self, cmd: &str, args: &[&str]) -> Result<String> {
        use tokio::process::Command;

        if self.dry_run {
            println!("{} {} {}", "[dry-run]".yellow(), cmd, args.join(" "));
            return Ok(String::new());
        }

        self.debug(&format!("Running async: {} {}", cmd, args.join(" ")));

        let output = Command::new(cmd)
            .args(args)
            .output()
            .await
            .with_context(|| format!("Failed to execute {}", cmd))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("{} failed:\n{}", cmd, stderr);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    pub fn run_command_obj(&self, cmd: &mut Command) -> Result<()> {
        if self.dry_run {
            println!("{} {:?}", "[dry-run]".yellow(), cmd);
            return Ok(());
        }

        self.debug(&format!("Running: {:?}", cmd));

        let output = cmd
            .output()
            .with_context(|| format!("Failed to execute {:?}", cmd))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Command {:?} failed:\n{}", cmd, stderr);
        }

        if self.verbose {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.is_empty() {
                println!("{}", stdout);
            }
        }

        Ok(())
    }
}

pub fn progress_bar(len: u64, msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

pub fn ensure_command_exists(cmd: &str) -> Result<()> {
    which::which(cmd)
        .with_context(|| format!("{} not found in PATH. Please install it first.", cmd))?;
    Ok(())
}

pub fn command_exists(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

pub fn workspace_root() -> Result<std::path::PathBuf> {
    // If we're running from inside the workspace, use cargo
    let output = Command::new("cargo")
        .args(&["locate-project", "--workspace", "--message-format", "plain"])
        .current_dir(".")
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let path = String::from_utf8(output.stdout)
                .context("Invalid UTF-8 in cargo output")?
                .trim()
                .to_string();

            return Ok(std::path::Path::new(&path)
                .parent()
                .context("Failed to get parent of Cargo.toml")?
                .to_path_buf());
        }
    }

    // Fallback: use current directory
    let current_dir = std::env::current_dir()?;
    
    // Walk up to find a directory containing Cargo.toml with workspace
    let mut dir = current_dir.as_path();
    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            // Check if this is a workspace
            if let Ok(contents) = std::fs::read_to_string(&cargo_toml) {
                if contents.contains("[workspace]") {
                    return Ok(dir.to_path_buf());
                }
            }
        }
        
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }
    
    // If all else fails, assume we're in kindly-guard
    Ok(current_dir)
}