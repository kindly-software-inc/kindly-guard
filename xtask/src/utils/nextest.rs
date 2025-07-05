//! cargo-nextest integration for faster test execution
//!
//! This module provides integration with cargo-nextest, a next-generation test runner
//! for Rust that provides 3x faster test execution through better parallelization,
//! machine-readable output, and advanced retry strategies.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use which::which;

/// Nextest profile configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextestProfile {
    /// Profile name
    pub name: String,
    /// Number of test threads (0 = number of logical CPUs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_threads: Option<usize>,
    /// Number of retries for flaky tests
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    /// Slow test threshold in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slow_timeout: Option<u32>,
    /// Test timeout in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    /// Fail fast on first test failure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_fast: Option<bool>,
    /// Status level (none, fail, retry, slow, pass, skip, all)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_level: Option<String>,
    /// Output format (human, json, junit)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_format: Option<String>,
}

/// Nextest configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextestConfig {
    /// Profile configurations
    pub profiles: Vec<NextestProfile>,
}

impl Default for NextestConfig {
    fn default() -> Self {
        Self {
            profiles: vec![
                NextestProfile {
                    name: "default".to_string(),
                    test_threads: None,
                    retries: Some(2),
                    slow_timeout: Some(60),
                    timeout: Some(300),
                    fail_fast: Some(false),
                    status_level: Some("fail".to_string()),
                    output_format: Some("human".to_string()),
                },
                NextestProfile {
                    name: "ci".to_string(),
                    test_threads: Some(4),
                    retries: Some(3),
                    slow_timeout: Some(120),
                    timeout: Some(600),
                    fail_fast: Some(false),
                    status_level: Some("retry".to_string()),
                    output_format: Some("junit".to_string()),
                },
                NextestProfile {
                    name: "quick".to_string(),
                    test_threads: Some(0), // Use all CPUs
                    retries: Some(0),
                    slow_timeout: Some(30),
                    timeout: Some(60),
                    fail_fast: Some(true),
                    status_level: Some("fail".to_string()),
                    output_format: Some("human".to_string()),
                },
            ],
        }
    }
}

/// Check if cargo-nextest is installed
pub fn is_installed() -> bool {
    which("cargo-nextest").is_ok()
}

/// Get the cargo-nextest version
pub fn get_version() -> Result<Option<String>> {
    if !is_installed() {
        return Ok(None);
    }

    let output = Command::new("cargo")
        .args(["nextest", "--version"])
        .output()
        .context("Failed to get cargo-nextest version")?;

    if output.status.success() {
        let version = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().last())
            .map(|v| v.to_string());
        Ok(version)
    } else {
        Ok(None)
    }
}

/// Install cargo-nextest if not already installed
pub async fn ensure_installed() -> Result<()> {
    if is_installed() {
        if let Some(version) = get_version()? {
            println!("✓ cargo-nextest {} is already installed", version);
        }
        return Ok(());
    }

    println!("Installing cargo-nextest...");
    
    // Try to install using cargo-binstall first (faster)
    if which("cargo-binstall").is_ok() {
        println!("Using cargo-binstall for faster installation...");
        let status = Command::new("cargo")
            .args(["binstall", "-y", "cargo-nextest"])
            .status()
            .context("Failed to run cargo-binstall")?;

        if status.success() {
            println!("✓ Successfully installed cargo-nextest using cargo-binstall");
            return Ok(());
        }
    }

    // Fall back to regular cargo install
    println!("Installing from source (this may take a few minutes)...");
    let status = Command::new("cargo")
        .args(["install", "cargo-nextest", "--locked"])
        .status()
        .context("Failed to run cargo install")?;

    if !status.success() {
        anyhow::bail!("Failed to install cargo-nextest");
    }

    println!("✓ Successfully installed cargo-nextest");
    Ok(())
}

/// Create nextest configuration file
pub fn create_config(project_root: &Path) -> Result<()> {
    let config_dir = project_root.join(".config");
    std::fs::create_dir_all(&config_dir)
        .context("Failed to create .config directory")?;

    let config_path = config_dir.join("nextest.toml");
    
    // Check if config already exists
    if config_path.exists() {
        println!("Nextest configuration already exists at: {}", config_path.display());
        return Ok(());
    }

    let config_content = r#"# Nextest configuration for KindlyGuard
# See: https://nexte.st/book/configuration.html

[profile.default]
# Run tests with 2 retries for flaky tests
retries = { backoff = "exponential", count = 2, delay = "1s" }

# Show output for failed tests
failure-output = "immediate"
success-output = "never"

# Consider tests slow after 60s
slow-timeout = { period = "60s", terminate-after = 3 }

[profile.default.junit]
# Store JUnit XML in CI-friendly location
path = "target/nextest/junit.xml"

[profile.ci]
# CI-specific settings
test-threads = 4

# More retries in CI
retries = { backoff = "exponential", count = 3, delay = "1s", max-delay = "10s" }

# Longer timeouts for CI
slow-timeout = { period = "120s", terminate-after = 3 }

# Output for debugging CI failures
failure-output = "immediate"
success-output = "final"
status-level = "retry"

# Machine-readable output
reporter = "json"

[profile.ci.junit]
path = "target/nextest/ci/junit.xml"

[profile.quick]
# Quick local testing
test-threads = "num-cpus"
retries = 0
fail-fast = true
slow-timeout = { period = "30s" }

# Minimal output
failure-output = "immediate"
success-output = "never"
status-level = "fail"

# Test groups for parallelization
[[profile.default.overrides]]
filter = "test(integration)"
test-threads = 2
slow-timeout = { period = "180s" }

[[profile.default.overrides]]
filter = "test(property)"
test-threads = 1
retries = { backoff = "exponential", count = 5, delay = "1s" }

[[profile.default.overrides]]
filter = "test(benchmark)"
test-threads = 1
retries = 0

# Platform-specific overrides
[profile.default-mac]
inherits = "default"

[profile.default-windows]
inherits = "default"
slow-timeout = { period = "90s" }

[profile.default-linux]
inherits = "default"
"#;

    std::fs::write(&config_path, config_content)
        .context("Failed to write nextest configuration")?;

    println!("✓ Created nextest configuration at: {}", config_path.display());
    Ok(())
}

/// Run tests using nextest
pub async fn run_tests(args: NextestArgs) -> Result<()> {
    ensure_installed().await?;

    let mut cmd = Command::new("cargo");
    cmd.arg("nextest").arg("run");

    // Add profile
    if let Some(profile) = &args.profile {
        cmd.args(["--profile", profile]);
    }

    // Add package filter
    if let Some(package) = &args.package {
        cmd.args(["--package", package]);
    }

    // Add test filter
    if let Some(filter) = &args.filter {
        cmd.arg(filter);
    }

    // Add features
    if !args.features.is_empty() {
        cmd.arg("--features").arg(args.features.join(","));
    }

    if args.all_features {
        cmd.arg("--all-features");
    }

    if args.no_default_features {
        cmd.arg("--no-default-features");
    }

    // Add workspace options
    if args.workspace {
        cmd.arg("--workspace");
    }

    // Add output options
    if let Some(format) = &args.output_format {
        cmd.args(["--reporter", format]);
    }

    if let Some(junit_path) = &args.junit_path {
        cmd.arg("--junit").arg(junit_path);
    }

    // Add retry options
    if let Some(retries) = args.retries {
        cmd.arg("--retries").arg(retries.to_string());
    }

    if args.no_retries {
        cmd.arg("--no-retries");
    }

    // Add other options
    if args.fail_fast {
        cmd.arg("--fail-fast");
    }

    if args.no_capture {
        cmd.arg("--no-capture");
    }

    if let Some(jobs) = args.jobs {
        cmd.arg("--test-threads").arg(jobs.to_string());
    }

    // Add any extra arguments
    for arg in &args.extra_args {
        cmd.arg(arg);
    }

    // Run the command
    let status = cmd.status().context("Failed to run nextest")?;

    if !status.success() {
        anyhow::bail!("Tests failed");
    }

    Ok(())
}

/// Arguments for running nextest
#[derive(Debug, Clone, Default)]
pub struct NextestArgs {
    /// Test profile to use
    pub profile: Option<String>,
    /// Package to test
    pub package: Option<String>,
    /// Test name filter
    pub filter: Option<String>,
    /// Features to enable
    pub features: Vec<String>,
    /// Enable all features
    pub all_features: bool,
    /// Disable default features
    pub no_default_features: bool,
    /// Test entire workspace
    pub workspace: bool,
    /// Output format (human, json, junit)
    pub output_format: Option<String>,
    /// Path for JUnit XML output
    pub junit_path: Option<PathBuf>,
    /// Number of retries
    pub retries: Option<u32>,
    /// Disable retries
    pub no_retries: bool,
    /// Fail on first test failure
    pub fail_fast: bool,
    /// Don't capture test output
    pub no_capture: bool,
    /// Number of parallel test threads
    pub jobs: Option<usize>,
    /// Extra arguments to pass through
    pub extra_args: Vec<String>,
}

/// Parse machine-readable test output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub name: String,
    pub package: String,
    pub status: TestStatus,
    pub duration: f64,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub retry_data: Option<RetryData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestStatus {
    Passed,
    Failed,
    Ignored,
    #[serde(rename = "LEAK")]
    Leaked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryData {
    pub attempt: u32,
    pub total_attempts: u32,
}

/// Parse nextest JSON output
pub fn parse_json_output(output: &str) -> Result<Vec<TestResult>> {
    let mut results = Vec::new();
    
    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }
        
        // Try to parse each line as a test event
        if let Ok(event) = serde_json::from_str::<serde_json::Value>(line) {
            if event["type"] == "test" && event["event"] == "finished" {
                let result = TestResult {
                    name: event["name"].as_str().unwrap_or("").to_string(),
                    package: event["package"].as_str().unwrap_or("").to_string(),
                    status: match event["exec_result"].as_str() {
                        Some("passed") => TestStatus::Passed,
                        Some("failed") => TestStatus::Failed,
                        Some("ignored") => TestStatus::Ignored,
                        Some("leak") => TestStatus::Leaked,
                        _ => TestStatus::Failed,
                    },
                    duration: event["exec_time_ms"].as_f64().unwrap_or(0.0) / 1000.0,
                    stdout: event["stdout"].as_str().map(|s| s.to_string()),
                    stderr: event["stderr"].as_str().map(|s| s.to_string()),
                    retry_data: if let (Some(attempt), Some(total)) = (
                        event["retry_data"]["attempt"].as_u64(),
                        event["retry_data"]["total_attempts"].as_u64(),
                    ) {
                        Some(RetryData {
                            attempt: attempt as u32,
                            total_attempts: total as u32,
                        })
                    } else {
                        None
                    },
                };
                results.push(result);
            }
        }
    }
    
    Ok(results)
}

/// Get test statistics from results
pub fn get_test_stats(results: &[TestResult]) -> TestStats {
    let mut stats = TestStats::default();
    
    for result in results {
        match result.status {
            TestStatus::Passed => stats.passed += 1,
            TestStatus::Failed => stats.failed += 1,
            TestStatus::Ignored => stats.ignored += 1,
            TestStatus::Leaked => stats.leaked += 1,
        }
        
        stats.total_duration += result.duration;
        
        if result.retry_data.is_some() {
            stats.retried += 1;
        }
    }
    
    stats.total = results.len();
    stats
}

#[derive(Debug, Default)]
pub struct TestStats {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub ignored: usize,
    pub leaked: usize,
    pub retried: usize,
    pub total_duration: f64,
}

impl TestStats {
    /// Print a summary of test statistics
    pub fn print_summary(&self) {
        use colored::Colorize;
        
        println!("\n{}", "Test Summary".bold());
        println!("{}", "─".repeat(40));
        
        println!("Total:    {}", self.total);
        println!("Passed:   {} {}", self.passed, "✓".green());
        
        if self.failed > 0 {
            println!("Failed:   {} {}", self.failed, "✗".red());
        }
        
        if self.ignored > 0 {
            println!("Ignored:  {}", self.ignored);
        }
        
        if self.leaked > 0 {
            println!("Leaked:   {} {}", self.leaked, "⚠".yellow());
        }
        
        if self.retried > 0 {
            println!("Retried:  {} {}", self.retried, "↻".yellow());
        }
        
        println!("Duration: {:.2}s", self.total_duration);
        println!("{}", "─".repeat(40));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NextestConfig::default();
        assert_eq!(config.profiles.len(), 3);
        assert_eq!(config.profiles[0].name, "default");
        assert_eq!(config.profiles[1].name, "ci");
        assert_eq!(config.profiles[2].name, "quick");
    }

    #[test]
    fn test_parse_test_status() {
        let json = r#"{"type":"test","event":"finished","name":"test_example","package":"my_crate","exec_result":"passed","exec_time_ms":123.45}"#;
        let results = parse_json_output(json).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "test_example");
        assert!(matches!(results[0].status, TestStatus::Passed));
    }
}