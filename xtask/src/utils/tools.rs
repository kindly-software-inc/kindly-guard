//! Tool installation utilities for KindlyGuard
//!
//! Provides functions to check for and install cargo tools with proper
//! handling for CI environments and user interaction.

use anyhow::{Context as AnyhowContext, Result};
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm};
use std::process::Command;
use tracing::debug;

use crate::utils::Context;

/// Configuration for tool installation behavior
#[derive(Debug, Clone)]
pub struct ToolInstallConfig {
    /// Whether to auto-install in CI environments
    pub ci_auto_install: bool,
    /// Whether to use interactive prompts when not in CI
    pub interactive: bool,
    /// Custom installation command (if different from `cargo install`)
    pub install_command: Option<Vec<String>>,
}

impl Default for ToolInstallConfig {
    fn default() -> Self {
        Self {
            ci_auto_install: true,
            interactive: true,
            install_command: None,
        }
    }
}

/// Check if we're running in a CI environment
///
/// Detects CI by checking for the CI environment variable, which is
/// set by most CI systems (GitHub Actions, GitLab CI, Travis CI, etc.)
pub fn is_ci_environment() -> bool {
    std::env::var("CI")
        .map(|val| val == "true" || val == "1")
        .unwrap_or(false)
}

/// Check if we're running specifically in GitHub Actions
///
/// GitHub Actions sets the GITHUB_ACTIONS environment variable to "true"
pub fn is_github_actions() -> bool {
    std::env::var("GITHUB_ACTIONS")
        .map(|val| val == "true")
        .unwrap_or(false)
}

/// Get the CI environment type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiEnvironment {
    /// Not in CI
    None,
    /// GitHub Actions
    GitHubActions,
    /// Other CI system (has CI=true but not GitHub Actions)
    Other,
}

impl CiEnvironment {
    /// Detect the current CI environment
    pub fn detect() -> Self {
        if is_github_actions() {
            CiEnvironment::GitHubActions
        } else if is_ci_environment() {
            CiEnvironment::Other
        } else {
            CiEnvironment::None
        }
    }
    
    /// Check if we're in any CI environment
    pub fn is_ci(&self) -> bool {
        !matches!(self, CiEnvironment::None)
    }
}

/// Check if a cargo tool is installed
///
/// # Arguments
/// * `tool_name` - Name of the cargo tool (e.g., "cargo-audit", "cargo-nextest")
///
/// # Returns
/// * `Ok(true)` if the tool is installed and working
/// * `Ok(false)` if the tool is not installed
/// * `Err(_)` if there was an error checking for the tool
pub fn is_tool_installed(tool_name: &str) -> Result<bool> {
    let subcommand = tool_name
        .strip_prefix("cargo-")
        .unwrap_or(tool_name);
    
    debug!("Checking if {} is installed", tool_name);
    
    let output = Command::new("cargo")
        .args(&[subcommand, "--version"])
        .output()
        .with_context(|| format!("Failed to check for {}", tool_name))?;
    
    Ok(output.status.success())
}

/// Ensure a cargo tool is installed, with CI and interactive handling
///
/// Behavior varies by environment:
/// - GitHub Actions: Only checks if tool exists, never attempts installation.
///   The workflow should handle tool installation explicitly.
/// - Other CI environments: Tools are automatically installed without prompting
///   if `ci_auto_install` is enabled in config.
/// - Interactive environments: The user is asked for permission before installation.
///
/// # Arguments
/// * `ctx` - Context for logging and command execution
/// * `tool_name` - Name of the cargo tool (e.g., "cargo-audit", "cargo-nextest")
/// * `config` - Optional configuration for installation behavior
///
/// # Returns
/// * `Ok(true)` if the tool is now installed (either was already installed or just installed)
/// * `Ok(false)` if the user declined installation
/// * `Err(_)` if there was an error during the process
///
/// # Example
/// ```no_run
/// let ctx = Context { dry_run: false, verbose: true };
/// match ensure_tool_installed(&ctx, "cargo-audit", None) {
///     Ok(true) => println!("Tool is available"),
///     Ok(false) => println!("User declined installation"),
///     Err(e) => eprintln!("Error: {}", e),
/// }
/// ```
pub fn ensure_tool_installed(
    ctx: &Context,
    tool_name: &str,
    config: Option<ToolInstallConfig>,
) -> Result<bool> {
    let config = config.unwrap_or_default();
    
    // Always check if tool is already installed first
    if is_tool_installed(tool_name).unwrap_or(false) {
        ctx.debug(&format!("{} is already installed", tool_name));
        return Ok(true);
    }
    
    // If we reach here, the tool is not installed or we couldn't verify
    match is_tool_installed(tool_name) {
        Ok(false) => {
            ctx.info(&format!("{} is not installed", tool_name));
        }
        Err(e) => {
            ctx.warn(&format!("Failed to check if {} is installed: {}", tool_name, e));
            // Continue anyway - attempt installation
        }
        Ok(true) => {
            // This shouldn't happen due to the check above, but handle it anyway
            return Ok(true);
        }
    }
    
    // Handle CI environment based on type
    match CiEnvironment::detect() {
        CiEnvironment::GitHubActions => {
            // GitHub Actions should handle tool installation in workflow
            ctx.error(&format!(
                "{} is required but not installed in GitHub Actions. \
                Please ensure the workflow installs required tools. \
                For example, use 'taiki-e/install-action@{}' or add to the workflow:\n  \
                - run: cargo install {}",
                tool_name, tool_name, tool_name
            ));
            return Ok(false);
        }
        CiEnvironment::Other => {
            // Other CI systems - attempt auto-installation if configured
            if config.ci_auto_install {
                ctx.info(&format!("CI environment detected - auto-installing {}", tool_name));
                return install_tool(ctx, tool_name, &config);
            } else {
                ctx.error(&format!("{} is required but not installed in CI", tool_name));
                return Ok(false);
            }
        }
        CiEnvironment::None => {
            // Not in CI - continue to interactive handling below
        }
    }
    
    // Handle interactive environment
    if config.interactive {
        let theme = ColorfulTheme::default();
        let prompt = format!(
            "{} is required but not installed. Would you like to install it now?",
            tool_name.yellow()
        );
        
        let should_install = match Confirm::with_theme(&theme)
            .with_prompt(prompt)
            .default(true)
            .interact()
        {
            Ok(answer) => answer,
            Err(e) => {
                ctx.error(&format!("Failed to read user input: {}", e));
                return Ok(false);
            }
        };
        
        if !should_install {
            ctx.info("Installation cancelled by user");
            return Ok(false);
        }
    } else {
        // Non-interactive and not CI - just report the missing tool
        ctx.error(&format!("{} is required but not installed", tool_name));
        return Ok(false);
    }
    
    // Proceed with installation
    install_tool(ctx, tool_name, &config)
}

/// Install a cargo tool
///
/// # Arguments
/// * `ctx` - Context for logging and command execution
/// * `tool_name` - Name of the cargo tool to install
/// * `config` - Configuration for installation
///
/// # Returns
/// * `Ok(true)` if installation succeeded
/// * `Err(_)` if installation failed
fn install_tool(ctx: &Context, tool_name: &str, config: &ToolInstallConfig) -> Result<bool> {
    if ctx.dry_run {
        ctx.info(&format!("[dry-run] Would install {}", tool_name));
        return Ok(true);
    }
    
    ctx.info(&format!("Installing {}...", tool_name));
    
    let (cmd, args) = if let Some(custom_cmd) = &config.install_command {
        // Use custom installation command
        let cmd = custom_cmd.first()
            .with_context(|| "Custom install command is empty")?;
        let args: Vec<&str> = custom_cmd[1..].iter().map(|s| s.as_str()).collect();
        (cmd.as_str(), args)
    } else {
        // Default cargo install
        ("cargo", vec!["install", tool_name])
    };
    
    match ctx.run_command(cmd, &args) {
        Ok(_) => {
            ctx.success(&format!("Successfully installed {}", tool_name));
            
            // Verify installation
            match is_tool_installed(tool_name) {
                Ok(true) => {
                    ctx.debug(&format!("Verified {} is now available", tool_name));
                    Ok(true)
                }
                Ok(false) => {
                    ctx.error(&format!(
                        "{} installation appeared to succeed but tool is not available",
                        tool_name
                    ));
                    Err(anyhow::anyhow!("Tool installation verification failed"))
                }
                Err(e) => {
                    ctx.warn(&format!("Could not verify installation: {}", e));
                    // Assume success since the install command succeeded
                    Ok(true)
                }
            }
        }
        Err(e) => {
            ctx.error(&format!("Failed to install {}: {}", tool_name, e));
            Err(e.context(format!("Failed to install {}", tool_name)))
        }
    }
}

/// Ensure multiple tools are installed
///
/// Attempts to install all specified tools. If any tool installation fails
/// or is declined by the user, the function continues with the remaining
/// tools and returns a summary.
///
/// # Arguments
/// * `ctx` - Context for logging and command execution
/// * `tools` - List of tool names to ensure are installed
/// * `config` - Optional configuration for installation behavior
///
/// # Returns
/// * `Ok(results)` - A vector of tuples containing (tool_name, success)
/// * `Err(_)` if there was a critical error preventing the check
pub fn ensure_tools_installed(
    ctx: &Context,
    tools: &[&str],
    config: Option<ToolInstallConfig>,
) -> Result<Vec<(String, bool)>> {
    let config = config.unwrap_or_default();
    let mut results = Vec::new();
    
    for tool in tools {
        match ensure_tool_installed(ctx, tool, Some(config.clone())) {
            Ok(installed) => {
                results.push((tool.to_string(), installed));
            }
            Err(e) => {
                ctx.error(&format!("Error handling {}: {}", tool, e));
                results.push((tool.to_string(), false));
            }
        }
    }
    
    // Report summary
    let installed_count = results.iter().filter(|(_, success)| *success).count();
    let total_count = results.len();
    
    if installed_count == total_count {
        ctx.success(&format!("All {} tools are available", total_count));
    } else if installed_count > 0 {
        ctx.warn(&format!(
            "{} of {} tools are available",
            installed_count, total_count
        ));
    } else {
        ctx.error("No tools are available");
    }
    
    Ok(results)
}

/// Common cargo tools used in the KindlyGuard project
pub mod common_tools {
    /// Security audit tool
    pub const CARGO_AUDIT: &str = "cargo-audit";
    
    /// Nextest test runner
    pub const CARGO_NEXTEST: &str = "cargo-nextest";
    
    /// Release management tool
    pub const CARGO_DIST: &str = "cargo-dist";
    
    /// Dependency tree visualization
    pub const CARGO_TREE: &str = "cargo-tree";
    
    /// Check for outdated dependencies
    pub const CARGO_OUTDATED: &str = "cargo-outdated";
    
    /// Generate shell completions
    pub const CARGO_COMPLETIONS: &str = "cargo-completions";
    
    /// MSRV (Minimum Supported Rust Version) checker
    pub const CARGO_MSRV: &str = "cargo-msrv";
    
    /// Binary size analyzer
    pub const CARGO_BLOAT: &str = "cargo-bloat";
    
    /// Unsafe code checker
    pub const CARGO_GEIGER: &str = "cargo-geiger";
    
    /// Code coverage tool
    pub const CARGO_LLVM_COV: &str = "cargo-llvm-cov";
    
    /// All security-related tools
    pub const SECURITY_TOOLS: &[&str] = &[CARGO_AUDIT, CARGO_GEIGER];
    
    /// All testing-related tools  
    pub const TEST_TOOLS: &[&str] = &[CARGO_NEXTEST];
    
    /// All release-related tools
    pub const RELEASE_TOOLS: &[&str] = &[CARGO_DIST];
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ci_detection() {
        // Save original values
        let original_ci = std::env::var("CI").ok();
        let original_gh = std::env::var("GITHUB_ACTIONS").ok();
        
        // Test CI=true
        std::env::set_var("CI", "true");
        assert!(is_ci_environment());
        
        // Test CI=1
        std::env::set_var("CI", "1");
        assert!(is_ci_environment());
        
        // Test CI=false
        std::env::set_var("CI", "false");
        assert!(!is_ci_environment());
        
        // Test CI not set
        std::env::remove_var("CI");
        assert!(!is_ci_environment());
        
        // Restore original values
        if let Some(val) = original_ci {
            std::env::set_var("CI", val);
        }
        if let Some(val) = original_gh {
            std::env::set_var("GITHUB_ACTIONS", val);
        }
    }
    
    #[test]
    fn test_github_actions_detection() {
        // Save original values
        let original_ci = std::env::var("CI").ok();
        let original_gh = std::env::var("GITHUB_ACTIONS").ok();
        
        // Test GitHub Actions
        std::env::set_var("GITHUB_ACTIONS", "true");
        assert!(is_github_actions());
        
        // Test not GitHub Actions
        std::env::set_var("GITHUB_ACTIONS", "false");
        assert!(!is_github_actions());
        
        // Test not set
        std::env::remove_var("GITHUB_ACTIONS");
        assert!(!is_github_actions());
        
        // Restore original values
        if let Some(val) = original_ci {
            std::env::set_var("CI", val);
        } else {
            std::env::remove_var("CI");
        }
        if let Some(val) = original_gh {
            std::env::set_var("GITHUB_ACTIONS", val);
        } else {
            std::env::remove_var("GITHUB_ACTIONS");
        }
    }
    
    #[test]
    fn test_ci_environment_detection() {
        // Save original values
        let original_ci = std::env::var("CI").ok();
        let original_gh = std::env::var("GITHUB_ACTIONS").ok();
        
        // Test no CI
        std::env::remove_var("CI");
        std::env::remove_var("GITHUB_ACTIONS");
        assert_eq!(CiEnvironment::detect(), CiEnvironment::None);
        
        // Test GitHub Actions
        std::env::set_var("CI", "true");
        std::env::set_var("GITHUB_ACTIONS", "true");
        assert_eq!(CiEnvironment::detect(), CiEnvironment::GitHubActions);
        
        // Test other CI
        std::env::set_var("CI", "true");
        std::env::remove_var("GITHUB_ACTIONS");
        assert_eq!(CiEnvironment::detect(), CiEnvironment::Other);
        
        // Restore original values
        if let Some(val) = original_ci {
            std::env::set_var("CI", val);
        } else {
            std::env::remove_var("CI");
        }
        if let Some(val) = original_gh {
            std::env::set_var("GITHUB_ACTIONS", val);
        } else {
            std::env::remove_var("GITHUB_ACTIONS");
        }
    }
    
    #[test]
    fn test_tool_name_parsing() {
        // This test would require mocking Command execution
        // For now, we just test that the function compiles correctly
        let _result = is_tool_installed("cargo-audit");
        let _result = is_tool_installed("cargo-nextest");
    }
}