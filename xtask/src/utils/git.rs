//! Git utilities

use anyhow::{Context as _, Result};
use std::process::Command;

use crate::utils::Context;

/// Run a command and return its stdout as a string
fn run_command_output(mut cmd: Command) -> Result<String> {
    let output = cmd
        .output()
        .context("Failed to execute command")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Command failed:\n{}", stderr);
    }
    
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

/// Check if we're in a git repository
pub fn is_git_repo() -> bool {
    Command::new("git")
        .args(&["rev-parse", "--git-dir"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Get the current git branch
pub fn current_branch() -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.args(&["rev-parse", "--abbrev-ref", "HEAD"]);
    run_command_output(cmd)
}

/// Get the current commit hash
pub fn current_commit() -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.args(&["rev-parse", "HEAD"]);
    run_command_output(cmd)
}

/// Get the current commit hash (short form)
pub fn current_commit_short() -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.args(&["rev-parse", "--short", "HEAD"]);
    run_command_output(cmd)
}

/// Check if the working directory is clean
pub fn is_clean() -> Result<bool> {
    let mut cmd = Command::new("git");
    cmd.args(&["status", "--porcelain"]);
    let output = run_command_output(cmd)?;
    Ok(output.is_empty())
}

/// Get list of changed files
pub fn changed_files() -> Result<Vec<String>> {
    let mut cmd = Command::new("git");
    cmd.args(&["status", "--porcelain"]);
    let output = run_command_output(cmd)?;
    
    Ok(output
        .lines()
        .map(|line| line[3..].to_string())
        .collect())
}

/// Create a git tag
pub fn create_tag(ctx: &Context, tag: &str, message: &str) -> Result<()> {
    ctx.run_command("git", &["tag", "-a", tag, "-m", message])?;
    Ok(())
}

/// Push a tag to remote
pub fn push_tag(ctx: &Context, tag: &str) -> Result<()> {
    ctx.run_command("git", &["push", "origin", tag])?;
    Ok(())
}

/// Check if a tag exists
pub fn tag_exists(tag: &str) -> Result<bool> {
    let output = Command::new("git")
        .args(&["tag", "-l", tag])
        .output()?;
    
    Ok(!output.stdout.is_empty())
}

/// Get the latest tag
pub fn latest_tag() -> Result<Option<String>> {
    let output = Command::new("git")
        .args(&["describe", "--tags", "--abbrev=0"])
        .output()?;
    
    if output.status.success() {
        Ok(Some(String::from_utf8(output.stdout)?.trim().to_string()))
    } else {
        Ok(None)
    }
}

/// Get commits since a tag
pub fn commits_since_tag(tag: &str) -> Result<Vec<String>> {
    let mut cmd = Command::new("git");
    cmd.args(&["log", "--oneline", &format!("{}..HEAD", tag)]);
    let output = run_command_output(cmd)?;
    
    Ok(output.lines().map(|s| s.to_string()).collect())
}

/// Stage files for commit
pub fn stage_files(ctx: &Context, files: &[&str]) -> Result<()> {
    let mut args = vec!["add"];
    args.extend(files);
    
    ctx.run_command("git", &args)?;
    Ok(())
}

/// Create a commit
pub fn commit(ctx: &Context, message: &str) -> Result<()> {
    ctx.run_command("git", &["commit", "-m", message])?;
    Ok(())
}