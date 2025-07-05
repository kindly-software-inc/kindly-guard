use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, Context as AnyhowContext, Result};
use cargo_metadata::{MetadataCommand, Package};
use clap::Args;
use colored::Colorize;
use serde::Deserialize;
use serde_json::Value;

use crate::utils::{self, Context};
use crate::utils::cargo::workspace_root;

/// Command arguments for validate-dist
#[derive(Args)]
pub struct ValidateDistCmd {
    /// Check a specific package only
    #[arg(long)]
    package: Option<String>,
    
    /// Fix issues automatically if possible
    #[arg(long)]
    fix: bool,
    
    /// Show detailed validation output
    #[arg(short, long)]
    detailed: bool,
}

/// Run the validate-dist command
pub async fn run(cmd: ValidateDistCmd, ctx: Context) -> Result<()> {
    if cmd.fix && ctx.dry_run {
        ctx.warn("Cannot fix issues in dry-run mode");
    }
    
    validate_dist_with_options(cmd, ctx)
}

/// Configuration for a binary in dist
#[derive(Debug, Deserialize)]
struct DistBinary {
    name: String,
    package_name: String,
}

/// Partial structure for parsing cargo dist plan output
#[derive(Debug, Deserialize)]
struct DistPlan {
    announcement_tag: Option<String>,
    releases: Vec<DistRelease>,
}

#[derive(Debug, Deserialize)]
struct DistRelease {
    app_name: String,
    artifacts: Vec<String>,
}

/// Validation result for a workspace member
#[derive(Debug)]
struct ValidationResult {
    package_name: String,
    issues: Vec<String>,
    warnings: Vec<String>,
}

/// Validates the dist configuration with options
fn validate_dist_with_options(cmd: ValidateDistCmd, ctx: Context) -> Result<()> {
    ctx.info("🔍 Validating dist configuration...");
    
    let workspace_root = workspace_root()?;
    let metadata = MetadataCommand::new()
        .current_dir(&workspace_root)
        .exec()
        .with_context(|| "Failed to read workspace metadata")?;
    
    let mut all_results = Vec::new();
    let mut has_errors = false;
    
    // Check each workspace member
    for package in &metadata.packages {
        // Skip if a specific package was requested and this isn't it
        if let Some(ref requested) = cmd.package {
            if &package.name != requested {
                continue;
            }
        }
        
        if should_validate_package(package) {
            let result = validate_package(package, &workspace_root, &ctx)?;
            if !result.issues.is_empty() {
                has_errors = true;
            }
            all_results.push(result);
        }
    }
    
    // Only run cargo dist plan if not checking a specific package
    if cmd.package.is_none() {
        let dist_plan_result = validate_dist_plan(&workspace_root, &ctx)?;
        if !dist_plan_result.issues.is_empty() {
            has_errors = true;
        }
        all_results.push(dist_plan_result);
    }
    
    // Print results
    print_validation_results(&all_results, cmd.detailed, &ctx);
    
    if has_errors {
        Err(anyhow!("Dist configuration validation failed"))
    } else {
        ctx.success("✅ All dist configurations are valid!");
        Ok(())
    }
}

/// Determines if a package should be validated for dist configuration
fn should_validate_package(package: &Package) -> bool {
    // Skip packages that are not meant to be distributed
    let skip_packages = ["xtask", "kindly-tools"];
    !skip_packages.contains(&package.name.as_str())
}

/// Validates a single package's dist configuration
fn validate_package(package: &Package, workspace_root: &Path, ctx: &Context) -> Result<ValidationResult> {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    
    // Check if package has any binaries
    let has_binaries = package.targets.iter().any(|t| t.is_bin());
    
    if has_binaries {
        // Validate binary names
        for target in &package.targets {
            if target.is_bin() {
                let binary_name = &target.name;
                
                // Check naming convention
                if !is_valid_binary_name(binary_name, &package.name) {
                    issues.push(format!(
                        "Binary '{}' doesn't follow expected naming pattern for package '{}'",
                        binary_name, package.name
                    ));
                }
                
                // Check for hyphens vs underscores
                if binary_name.contains('_') {
                    warnings.push(format!(
                        "Binary '{}' uses underscores. Consider using hyphens for consistency",
                        binary_name
                    ));
                }
            }
        }
        
        // Check if package has dist metadata
        if let Some(metadata) = &package.metadata {
            if !metadata.get("dist").is_some() && !metadata.get("wix").is_some() {
                warnings.push(format!(
                    "Package '{}' has binaries but no dist or wix metadata",
                    package.name
                ));
            }
        }
        
        // Check Cargo.toml for required fields
        let cargo_toml_path = workspace_root
            .join(&package.manifest_path)
            .parent()
            .unwrap()
            .join("Cargo.toml");
            
        if cargo_toml_path.exists() {
            let cargo_toml = std::fs::read_to_string(&cargo_toml_path)
                .with_context(|| format!("Failed to read Cargo.toml for {}", package.name))?;
            
            // Check for explicit binary definitions
            if has_binaries && !cargo_toml.contains("[[bin]]") {
                warnings.push(format!(
                    "Package '{}' has implicit binary targets. Consider explicit [[bin]] sections",
                    package.name
                ));
            }
        }
    }
    
    Ok(ValidationResult {
        package_name: package.name.clone(),
        issues,
        warnings,
    })
}

/// Validates binary naming conventions
fn is_valid_binary_name(binary_name: &str, package_name: &str) -> bool {
    // Expected patterns:
    // 1. Binary name matches package name (e.g., kindly-guard-server)
    // 2. Binary name is a shortened version (e.g., kindly-server for kindly-guard-server)
    // 3. Binary name is the main command (e.g., kindlyguard for the CLI)
    
    let valid_patterns = [
        package_name,
        &package_name.replace("-guard", ""),
        "kindlyguard",
        "kindly",
    ];
    
    valid_patterns.contains(&binary_name)
}

/// Runs cargo dist plan and validates the output
fn validate_dist_plan(workspace_root: &Path, ctx: &Context) -> Result<ValidationResult> {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    
    // Check if cargo-dist is installed
    if !is_cargo_dist_installed()? {
        issues.push("cargo-dist is not installed. Run 'cargo install cargo-dist'".to_string());
        return Ok(ValidationResult {
            package_name: "cargo-dist".to_string(),
            issues,
            warnings,
        });
    }
    
    // Run cargo dist plan
    let output = Command::new("cargo")
        .args(&["dist", "plan", "--output-format=json"])
        .current_dir(workspace_root)
        .output()
        .with_context(|| "Failed to run cargo dist plan")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        issues.push(format!("cargo dist plan failed: {}", stderr));
        return Ok(ValidationResult {
            package_name: "cargo-dist".to_string(),
            issues,
            warnings,
        });
    }
    
    // Parse the JSON output
    let stdout = String::from_utf8_lossy(&output.stdout);
    let plan: Value = serde_json::from_str(&stdout)
        .with_context(|| "Failed to parse cargo dist plan output")?;
    
    // Validate the plan structure
    if let Some(dist_plan) = plan.as_object() {
        // Check for expected fields
        if !dist_plan.contains_key("announcement_tag") {
            warnings.push("No announcement_tag found in dist plan".to_string());
        }
        
        if let Some(releases) = dist_plan.get("releases").and_then(|v| v.as_array()) {
            if releases.is_empty() {
                issues.push("No releases found in dist plan".to_string());
            } else {
                // Validate each release
                for release in releases {
                    if let Some(app_name) = release.get("app_name").and_then(|v| v.as_str()) {
                        // Check if app name follows conventions
                        if !app_name.starts_with("kindly") {
                            warnings.push(format!(
                                "App '{}' doesn't follow 'kindly' naming convention",
                                app_name
                            ));
                        }
                        
                        // Check artifacts
                        if let Some(artifacts) = release.get("artifacts").and_then(|v| v.as_array()) {
                            if artifacts.is_empty() {
                                issues.push(format!("No artifacts defined for app '{}'", app_name));
                            }
                        }
                    }
                }
            }
        } else {
            issues.push("No releases array found in dist plan".to_string());
        }
        
        // Check for installer configurations
        if let Some(installers) = dist_plan.get("installers").and_then(|v| v.as_array()) {
            let expected_installers = ["shell", "powershell", "npm", "homebrew", "msi"];
            let found_installers: HashSet<_> = installers
                .iter()
                .filter_map(|v| v.as_str())
                .collect();
            
            for expected in &expected_installers {
                if !found_installers.contains(expected) {
                    warnings.push(format!("Expected installer '{}' not found in plan", expected));
                }
            }
        }
    }
    
    Ok(ValidationResult {
        package_name: "cargo-dist".to_string(),
        issues,
        warnings,
    })
}

/// Checks if cargo-dist is installed
fn is_cargo_dist_installed() -> Result<bool> {
    let output = Command::new("cargo")
        .args(&["dist", "--version"])
        .output()
        .with_context(|| "Failed to check cargo-dist version")?;
    
    Ok(output.status.success())
}

/// Prints the validation results in a formatted way
fn print_validation_results(results: &[ValidationResult], detailed: bool, ctx: &Context) {
    for result in results {
        println!("\n📦 {}", result.package_name.cyan().bold());
        
        if result.issues.is_empty() && result.warnings.is_empty() {
            println!("  ✅ No issues found");
        } else {
            if !result.issues.is_empty() {
                println!("  {} Issues:", "❌".red());
                for issue in &result.issues {
                    println!("    • {}", issue.red());
                }
            }
            
            if !result.warnings.is_empty() {
                println!("  {} Warnings:", "⚠️ ".yellow());
                for warning in &result.warnings {
                    println!("    • {}", warning.yellow());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_valid_binary_names() {
        assert!(is_valid_binary_name("kindly-guard-server", "kindly-guard-server"));
        assert!(is_valid_binary_name("kindly-server", "kindly-guard-server"));
        assert!(is_valid_binary_name("kindlyguard", "kindly-guard-cli"));
        assert!(!is_valid_binary_name("random-name", "kindly-guard-server"));
    }
}