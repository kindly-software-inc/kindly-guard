// Copyright 2025 Kindly Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! System diagnostics and health checks

use anyhow::Result;
use colored::Colorize;
use std::env;
use std::path::Path;

use super::platform::{Platform, detect_environment};

/// Run system diagnostics
pub async fn run_doctor(detailed: bool, fix: bool) -> Result<()> {
    println!("{}", "KindlyGuard System Doctor".bright_blue().bold());
    println!();

    let mut issues = Vec::new();

    // Check system requirements
    println!("{} Checking system requirements...", "🔍".bright_cyan());
    check_system_requirements(&mut issues)?;

    // Check installation
    println!("{} Checking KindlyGuard installation...", "🔍".bright_cyan());
    check_installation(&mut issues)?;

    // Check environment
    println!("{} Checking environment...", "🔍".bright_cyan());
    check_environment(&mut issues)?;

    // Check network
    println!("{} Checking network connectivity...", "🔍".bright_cyan());
    check_network_connectivity(&mut issues).await?;

    // Show results
    println!();
    if issues.is_empty() {
        println!("{} All checks passed! System is healthy.", "✅".bright_green());
    } else {
        println!("{} Found {} issue(s):", "⚠️".yellow(), issues.len());
        for issue in &issues {
            println!("  {} {}", "•".red(), issue.description);
            if detailed {
                println!("    Fix: {}", issue.fix.bright_cyan());
            }
        }

        if fix {
            println!();
            println!("{} Attempting to fix issues...", "🔧".bright_cyan());
            fix_issues(&issues).await?;
        }
    }

    if detailed {
        println!();
        show_detailed_diagnostics().await?;
    }

    Ok(())
}

#[derive(Debug)]
struct Issue {
    description: String,
    fix: String,
    fixable: bool,
}

fn check_system_requirements(issues: &mut Vec<Issue>) -> Result<()> {
    // Check Rust version
    if let Ok(output) = std::process::Command::new("rustc").arg("--version").output() {
        let version = String::from_utf8_lossy(&output.stdout);
        println!("  ✓ Rust installed: {}", version.trim().bright_green());
    } else {
        issues.push(Issue {
            description: "Rust not found".to_string(),
            fix: "Install Rust from https://rustup.rs".to_string(),
            fixable: false,
        });
    }

    // Check disk space
    // TODO: Implement actual disk space check

    // Check memory
    // TODO: Implement memory check

    Ok(())
}

fn check_installation(issues: &mut Vec<Issue>) -> Result<()> {
    // Check if binary is in PATH
    let exe_name = env::current_exe()?.file_name().unwrap().to_string_lossy().to_string();
    
    if let Ok(path) = which::which(&exe_name) {
        println!("  ✓ {} found in PATH: {}", exe_name, path.display().to_string().bright_green());
    } else {
        issues.push(Issue {
            description: format!("{} not found in PATH", exe_name),
            fix: format!("Add {} to your PATH", env::current_exe()?.parent().unwrap().display()),
            fixable: true,
        });
    }

    // Check configuration
    let config_dir = dirs::config_dir()
        .map(|d| d.join("kindlyguard"))
        .unwrap_or_else(|| Path::new(".").to_path_buf());

    if config_dir.exists() {
        println!("  ✓ Configuration directory exists: {}", 
            config_dir.display().to_string().bright_green());
    } else {
        println!("  ℹ Configuration directory not found (will be created on first use)");
    }

    Ok(())
}

fn check_environment(issues: &mut Vec<Issue>) -> Result<()> {
    let env_info = detect_environment();

    // Check for problematic environments
    if env_info.docker && !env::var("KINDLY_ALLOW_DOCKER").is_ok() {
        println!("  ⚠️ Running in Docker container");
        issues.push(Issue {
            description: "Docker environment detected".to_string(),
            fix: "Set KINDLY_ALLOW_DOCKER=1 if intentional".to_string(),
            fixable: false,
        });
    }

    if env_info.ssh && !env::var("KINDLY_ALLOW_SSH").is_ok() {
        println!("  ℹ Running over SSH");
    }

    // Check proxy settings
    if let Some(proxy) = env_info.proxy {
        println!("  ℹ HTTP proxy configured: {}", proxy.bright_cyan());
    }

    Ok(())
}

async fn check_network_connectivity(issues: &mut Vec<Issue>) -> Result<()> {
    // Check GitHub connectivity
    match reqwest::get("https://api.github.com").await {
        Ok(resp) if resp.status().is_success() => {
            println!("  ✓ GitHub API accessible");
        }
        _ => {
            issues.push(Issue {
                description: "Cannot reach GitHub API".to_string(),
                fix: "Check internet connection and proxy settings".to_string(),
                fixable: false,
            });
        }
    }

    // Check crates.io connectivity
    match reqwest::get("https://crates.io/api/v1/crates").await {
        Ok(resp) if resp.status().is_success() => {
            println!("  ✓ crates.io accessible");
        }
        _ => {
            issues.push(Issue {
                description: "Cannot reach crates.io".to_string(),
                fix: "Check internet connection and proxy settings".to_string(),
                fixable: false,
            });
        }
    }

    Ok(())
}

async fn fix_issues(issues: &[Issue]) -> Result<()> {
    for issue in issues {
        if issue.fixable {
            println!("  Fixing: {}", issue.description);
            // TODO: Implement actual fixes
        } else {
            println!("  Cannot auto-fix: {} (manual action required)", issue.description);
        }
    }
    Ok(())
}

/// Show detailed diagnostics information
pub async fn show_diagnostics(_platform: &Platform) -> Result<()> {
    show_detailed_diagnostics().await
}

async fn show_detailed_diagnostics() -> Result<()> {
    println!();
    println!("{}", "Detailed System Information:".bright_cyan().bold());
    println!();

    // System info
    println!("System:");
    println!("  OS: {} {}", env::consts::OS, env::consts::ARCH);
    println!("  Family: {}", env::consts::FAMILY);
    
    if let Ok(hostname) = whoami::fallible::hostname() {
        println!("  Hostname: {}", hostname);
    }
    
    println!("  Username: {}", whoami::username());

    // Environment
    println!();
    println!("Environment:");
    println!("  Current directory: {}", env::current_dir()?.display());
    println!("  Home directory: {}", dirs::home_dir().unwrap_or_default().display());
    
    // Rust toolchain
    println!();
    println!("Rust Toolchain:");
    if let Ok(output) = std::process::Command::new("rustc").arg("--version").output() {
        println!("  rustc: {}", String::from_utf8_lossy(&output.stdout).trim());
    }
    if let Ok(output) = std::process::Command::new("cargo").arg("--version").output() {
        println!("  cargo: {}", String::from_utf8_lossy(&output.stdout).trim());
    }

    // Network
    println!();
    println!("Network:");
    for (key, value) in env::vars() {
        if key.contains("PROXY") || key.contains("proxy") {
            println!("  {}: {}", key, value);
        }
    }

    Ok(())
}