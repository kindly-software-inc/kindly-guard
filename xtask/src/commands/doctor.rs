use anyhow::Result;
use clap::Args;
use colored::*;
use std::env;
use std::path::Path;
use std::process::Command;

use crate::utils::{self, Context};

#[derive(Args)]
pub struct DoctorCmd {
    /// Check a specific component only
    #[arg(long)]
    component: Option<String>,
    
    /// Show detailed information
    #[arg(short, long)]
    detailed: bool,
}

pub async fn run(cmd: DoctorCmd, ctx: Context) -> Result<()> {
    ctx.info("Running environment diagnostics...\n");
    
    let mut checks = CheckResults::new();
    
    // Run all checks or specific component
    match cmd.component.as_deref() {
        Some("rust") => check_rust(&mut checks, &ctx, cmd.detailed)?,
        Some("tools") => check_tools(&mut checks, &ctx, cmd.detailed)?,
        Some("workspace") => check_workspace(&mut checks, &ctx, cmd.detailed)?,
        Some("env") => check_environment(&mut checks, &ctx, cmd.detailed)?,
        Some("resources") => check_resources(&mut checks, &ctx, cmd.detailed)?,
        None => {
            // Run all checks
            check_rust(&mut checks, &ctx, cmd.detailed)?;
            check_tools(&mut checks, &ctx, cmd.detailed)?;
            check_workspace(&mut checks, &ctx, cmd.detailed)?;
            check_environment(&mut checks, &ctx, cmd.detailed)?;
            check_resources(&mut checks, &ctx, cmd.detailed)?;
        }
        Some(comp) => {
            ctx.error(&format!("Unknown component: {}", comp));
            ctx.info("Available components: rust, tools, workspace, env, resources");
            return Ok(());
        }
    }
    
    // Display results
    checks.display(&ctx);
    
    // Return error if any critical checks failed
    if checks.has_critical_failures() {
        anyhow::bail!("Critical environment issues detected. Please fix them before proceeding.");
    }
    
    Ok(())
}

struct CheckResults {
    categories: Vec<(String, Vec<CheckResult>)>,
}

struct CheckResult {
    name: String,
    status: CheckStatus,
    message: String,
    fix_hint: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CheckStatus {
    Ok,
    Warning,
    Error,
}

impl CheckResults {
    fn new() -> Self {
        Self {
            categories: Vec::new(),
        }
    }
    
    fn add_category(&mut self, name: impl Into<String>) -> &mut Vec<CheckResult> {
        self.categories.push((name.into(), Vec::new()));
        &mut self.categories.last_mut().unwrap().1
    }
    
    fn has_critical_failures(&self) -> bool {
        self.categories
            .iter()
            .any(|(_, results)| results.iter().any(|r| matches!(r.status, CheckStatus::Error)))
    }
    
    fn display(&self, ctx: &Context) {
        let mut total_ok = 0;
        let mut total_warn = 0;
        let mut total_err = 0;
        
        for (category, results) in &self.categories {
            println!("\n{}", category.bold());
            println!("{}", "─".repeat(category.len()));
            
            for result in results {
                let status_icon = match result.status {
                    CheckStatus::Ok => "✓".green(),
                    CheckStatus::Warning => "⚠".yellow(),
                    CheckStatus::Error => "✗".red(),
                };
                
                println!("  {} {}: {}", status_icon, result.name, result.message);
                
                if let Some(hint) = &result.fix_hint {
                    println!("    {} {}", "→".dimmed(), hint.dimmed());
                }
                
                match result.status {
                    CheckStatus::Ok => total_ok += 1,
                    CheckStatus::Warning => total_warn += 1,
                    CheckStatus::Error => total_err += 1,
                }
            }
        }
        
        // Summary
        println!("\n{}", "Summary".bold());
        println!("{}", "─".repeat(7));
        println!(
            "  {} passed, {} warnings, {} errors",
            total_ok.to_string().green(),
            total_warn.to_string().yellow(),
            total_err.to_string().red()
        );
        
        if total_err > 0 {
            ctx.error("\nEnvironment check failed!");
        } else if total_warn > 0 {
            ctx.warn("\nEnvironment check passed with warnings.");
        } else {
            ctx.success("\nAll environment checks passed!");
        }
    }
}

fn check_rust(checks: &mut CheckResults, ctx: &Context, detailed: bool) -> Result<()> {
    let results = checks.add_category("Rust Toolchain");
    
    // Check rustc
    match Command::new("rustc").arg("--version").output() {
        Ok(output) => {
            let version = String::from_utf8_lossy(&output.stdout);
            let version = version.trim();
            
            // Parse version
            if let Some(version_num) = version.split_whitespace().nth(1) {
                let min_version = "1.75.0";
                results.push(CheckResult {
                    name: "rustc".to_string(),
                    status: if version_num >= min_version {
                        CheckStatus::Ok
                    } else {
                        CheckStatus::Warning
                    },
                    message: version.to_string(),
                    fix_hint: if version_num < min_version {
                        Some(format!("Consider updating to Rust {} or later", min_version))
                    } else {
                        None
                    },
                });
            }
            
            if detailed {
                ctx.debug(&format!("Rust version: {}", version));
            }
        }
        Err(_) => {
            results.push(CheckResult {
                name: "rustc".to_string(),
                status: CheckStatus::Error,
                message: "Not found".to_string(),
                fix_hint: Some("Install Rust from https://rustup.rs".to_string()),
            });
        }
    }
    
    // Check cargo
    match Command::new("cargo").arg("--version").output() {
        Ok(output) => {
            let version = String::from_utf8_lossy(&output.stdout);
            results.push(CheckResult {
                name: "cargo".to_string(),
                status: CheckStatus::Ok,
                message: version.trim().to_string(),
                fix_hint: None,
            });
        }
        Err(_) => {
            results.push(CheckResult {
                name: "cargo".to_string(),
                status: CheckStatus::Error,
                message: "Not found".to_string(),
                fix_hint: Some("Install Rust from https://rustup.rs".to_string()),
            });
        }
    }
    
    // Check important components
    let components = [
        ("rustfmt", "cargo install rustfmt"),
        ("clippy", "rustup component add clippy"),
        ("rust-analyzer", "rustup component add rust-analyzer"),
    ];
    
    for (component, install_cmd) in components {
        let found = Command::new("rustup")
            .args(&["component", "list", "--installed"])
            .output()
            .map(|output| {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout.contains(component)
            })
            .unwrap_or(false);
        
        results.push(CheckResult {
            name: component.to_string(),
            status: if found { CheckStatus::Ok } else { CheckStatus::Warning },
            message: if found { "Installed".to_string() } else { "Not installed".to_string() },
            fix_hint: if !found { Some(install_cmd.to_string()) } else { None },
        });
    }
    
    // Check targets for cross-compilation
    if detailed {
        let targets = [
            "x86_64-pc-windows-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
        ];
        
        for target in targets {
            let installed = Command::new("rustup")
                .args(&["target", "list", "--installed"])
                .output()
                .map(|output| {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    stdout.contains(target)
                })
                .unwrap_or(false);
            
            results.push(CheckResult {
                name: format!("target: {}", target),
                status: if installed { CheckStatus::Ok } else { CheckStatus::Warning },
                message: if installed { "Installed".to_string() } else { "Not installed".to_string() },
                fix_hint: if !installed { 
                    Some(format!("rustup target add {}", target))
                } else { 
                    None 
                },
            });
        }
    }
    
    Ok(())
}

fn check_tools(checks: &mut CheckResults, ctx: &Context, detailed: bool) -> Result<()> {
    let results = checks.add_category("System Tools");
    
    // Essential tools
    let tools = [
        ("git", "Git version control", true),
        ("docker", "Docker container runtime", false),
        ("node", "Node.js runtime", false),
        ("npm", "NPM package manager", false),
        ("python3", "Python 3 interpreter", false),
        ("make", "GNU Make", false),
        ("cmake", "CMake build system", false),
        ("pkg-config", "Package configuration tool", true),
    ];
    
    for (tool, description, required) in tools {
        match Command::new(tool).arg("--version").output() {
            Ok(output) => {
                let version = String::from_utf8_lossy(&output.stdout);
                let version = version.lines().next().unwrap_or("").trim();
                
                results.push(CheckResult {
                    name: tool.to_string(),
                    status: CheckStatus::Ok,
                    message: version.to_string(),
                    fix_hint: None,
                });
                
                if detailed {
                    ctx.debug(&format!("{}: {}", tool, version));
                }
            }
            Err(_) => {
                results.push(CheckResult {
                    name: tool.to_string(),
                    status: if required { CheckStatus::Error } else { CheckStatus::Warning },
                    message: format!("Not found - {}", description),
                    fix_hint: Some(format!("Install {} for your platform", tool)),
                });
            }
        }
    }
    
    // Check for cross-compilation tools
    if detailed {
        let cross_tools = [
            ("cross", "cargo install cross", "Cross-compilation helper"),
            ("zigbuild", "cargo install cargo-zigbuild", "Zig-based cross compiler"),
        ];
        
        for (tool, install_cmd, desc) in cross_tools {
            let found = Command::new(tool).arg("--version").output().is_ok();
            
            results.push(CheckResult {
                name: tool.to_string(),
                status: if found { CheckStatus::Ok } else { CheckStatus::Warning },
                message: if found { "Installed".to_string() } else { format!("Not found - {}", desc) },
                fix_hint: if !found { Some(install_cmd.to_string()) } else { None },
            });
        }
    }
    
    Ok(())
}

fn check_workspace(checks: &mut CheckResults, ctx: &Context, detailed: bool) -> Result<()> {
    let results = checks.add_category("Cargo Workspace");
    
    // Get workspace root
    let workspace_root = utils::workspace_root()?;
    results.push(CheckResult {
        name: "Workspace root".to_string(),
        status: CheckStatus::Ok,
        message: workspace_root.display().to_string(),
        fix_hint: None,
    });
    
    // Check Cargo.toml exists
    let cargo_toml = workspace_root.join("Cargo.toml");
    if cargo_toml.exists() {
        results.push(CheckResult {
            name: "Cargo.toml".to_string(),
            status: CheckStatus::Ok,
            message: "Found".to_string(),
            fix_hint: None,
        });
        
        // Parse and validate workspace
        let contents = std::fs::read_to_string(&cargo_toml)?;
        if contents.contains("[workspace]") {
            results.push(CheckResult {
                name: "Workspace config".to_string(),
                status: CheckStatus::Ok,
                message: "Valid workspace configuration".to_string(),
                fix_hint: None,
            });
        } else {
            results.push(CheckResult {
                name: "Workspace config".to_string(),
                status: CheckStatus::Error,
                message: "Not a workspace root".to_string(),
                fix_hint: Some("Ensure Cargo.toml contains [workspace] section".to_string()),
            });
        }
    } else {
        results.push(CheckResult {
            name: "Cargo.toml".to_string(),
            status: CheckStatus::Error,
            message: "Not found".to_string(),
            fix_hint: Some("Run from within a Cargo workspace".to_string()),
        });
    }
    
    // Check cargo metadata
    match Command::new("cargo")
        .args(&["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(&workspace_root)
        .output()
    {
        Ok(output) if output.status.success() => {
            results.push(CheckResult {
                name: "Cargo metadata".to_string(),
                status: CheckStatus::Ok,
                message: "Valid".to_string(),
                fix_hint: None,
            });
            
            if detailed {
                // Parse metadata for more info
                if let Ok(metadata) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                    if let Some(packages) = metadata["packages"].as_array() {
                        ctx.debug(&format!("Found {} workspace packages", packages.len()));
                    }
                }
            }
        }
        _ => {
            results.push(CheckResult {
                name: "Cargo metadata".to_string(),
                status: CheckStatus::Error,
                message: "Failed to parse".to_string(),
                fix_hint: Some("Run 'cargo check' to diagnose issues".to_string()),
            });
        }
    }
    
    // Check Cargo.lock
    let cargo_lock = workspace_root.join("Cargo.lock");
    if cargo_lock.exists() {
        results.push(CheckResult {
            name: "Cargo.lock".to_string(),
            status: CheckStatus::Ok,
            message: "Found".to_string(),
            fix_hint: None,
        });
    } else {
        results.push(CheckResult {
            name: "Cargo.lock".to_string(),
            status: CheckStatus::Warning,
            message: "Not found".to_string(),
            fix_hint: Some("Run 'cargo generate-lockfile' to create".to_string()),
        });
    }
    
    // Check target directory
    let target_dir = workspace_root.join("target");
    if target_dir.exists() {
        if let Ok(_metadata) = std::fs::metadata(&target_dir) {
            let size = dir_size(&target_dir).unwrap_or(0);
            let size_gb = size as f64 / 1_073_741_824.0;
            
            results.push(CheckResult {
                name: "Target directory".to_string(),
                status: if size_gb > 10.0 { CheckStatus::Warning } else { CheckStatus::Ok },
                message: format!("{:.2} GB", size_gb),
                fix_hint: if size_gb > 10.0 {
                    Some("Consider running 'cargo clean' to free space".to_string())
                } else {
                    None
                },
            });
        }
    }
    
    Ok(())
}

fn check_environment(checks: &mut CheckResults, _ctx: &Context, detailed: bool) -> Result<()> {
    let results = checks.add_category("Environment Variables");
    
    // Check important environment variables
    let env_vars = [
        ("RUST_LOG", false, "Set to 'debug' for verbose output"),
        ("CARGO_HOME", false, "Cargo installation directory"),
        ("RUSTUP_HOME", false, "Rustup installation directory"),
        ("PATH", true, "Must include cargo bin directory"),
    ];
    
    for (var, required, description) in env_vars {
        match env::var(var) {
            Ok(value) => {
                let display_value = if var == "PATH" {
                    // Check if cargo is in PATH
                    let has_cargo = value.split(':').any(|p| p.contains("cargo"));
                    if has_cargo {
                        "Contains cargo bin directory".to_string()
                    } else {
                        "Missing cargo bin directory".to_string()
                    }
                } else if detailed {
                    value.clone()
                } else {
                    "Set".to_string()
                };
                
                results.push(CheckResult {
                    name: var.to_string(),
                    status: if var == "PATH" && !value.split(':').any(|p| p.contains("cargo")) {
                        CheckStatus::Error
                    } else {
                        CheckStatus::Ok
                    },
                    message: display_value,
                    fix_hint: None,
                });
            }
            Err(_) => {
                results.push(CheckResult {
                    name: var.to_string(),
                    status: if required { CheckStatus::Error } else { CheckStatus::Warning },
                    message: format!("Not set - {}", description),
                    fix_hint: Some(format!("Set {} environment variable", var)),
                });
            }
        }
    }
    
    // Check for proxy settings
    if detailed {
        for proxy_var in ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"] {
            if let Ok(_value) = env::var(proxy_var) {
                results.push(CheckResult {
                    name: proxy_var.to_string(),
                    status: CheckStatus::Ok,
                    message: "Set (may affect downloads)".to_string(),
                    fix_hint: None,
                });
            }
        }
    }
    
    Ok(())
}

fn check_resources(checks: &mut CheckResults, _ctx: &Context, detailed: bool) -> Result<()> {
    let results = checks.add_category("System Resources");
    
    // Check disk space
    let workspace_root = utils::workspace_root()?;
    if let Some(parent) = workspace_root.parent() {
        match fs2::available_space(parent) {
            Ok(bytes) => {
                let gb = bytes as f64 / 1_073_741_824.0;
                results.push(CheckResult {
                    name: "Disk space".to_string(),
                    status: if gb < 1.0 {
                        CheckStatus::Error
                    } else if gb < 5.0 {
                        CheckStatus::Warning
                    } else {
                        CheckStatus::Ok
                    },
                    message: format!("{:.2} GB available", gb),
                    fix_hint: if gb < 5.0 {
                        Some("Consider freeing up disk space".to_string())
                    } else {
                        None
                    },
                });
            }
            Err(_) => {
                results.push(CheckResult {
                    name: "Disk space".to_string(),
                    status: CheckStatus::Warning,
                    message: "Unable to check".to_string(),
                    fix_hint: None,
                });
            }
        }
    }
    
    // Check memory (Linux/macOS)
    #[cfg(unix)]
    {
        if let Ok(output) = Command::new("free").arg("-b").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(mem_line) = stdout.lines().find(|l| l.starts_with("Mem:")) {
                let parts: Vec<&str> = mem_line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if let (Ok(total), Ok(available)) = (parts[1].parse::<u64>(), parts[6].parse::<u64>()) {
                        let total_gb = total as f64 / 1_073_741_824.0;
                        let available_gb = available as f64 / 1_073_741_824.0;
                        
                        results.push(CheckResult {
                            name: "Memory".to_string(),
                            status: if available_gb < 1.0 {
                                CheckStatus::Warning
                            } else {
                                CheckStatus::Ok
                            },
                            message: format!("{:.1} GB available of {:.1} GB", available_gb, total_gb),
                            fix_hint: if available_gb < 1.0 {
                                Some("Close unnecessary applications".to_string())
                            } else {
                                None
                            },
                        });
                    }
                }
            }
        } else if let Ok(output) = Command::new("sysctl").arg("hw.memsize").output() {
            // macOS fallback
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(value) = stdout.split(':').nth(1) {
                if let Ok(bytes) = value.trim().parse::<u64>() {
                    let gb = bytes as f64 / 1_073_741_824.0;
                    results.push(CheckResult {
                        name: "Total memory".to_string(),
                        status: CheckStatus::Ok,
                        message: format!("{:.1} GB", gb),
                        fix_hint: None,
                    });
                }
            }
        }
    }
    
    // Check CPU cores
    let num_cpus = num_cpus::get();
    results.push(CheckResult {
        name: "CPU cores".to_string(),
        status: CheckStatus::Ok,
        message: format!("{} cores available", num_cpus),
        fix_hint: None,
    });
    
    // Check for running services that might interfere
    if detailed {
        let interfering_services = [
            ("docker", "Docker daemon"),
            ("containerd", "Container daemon"),
            ("rust-analyzer", "Rust language server"),
        ];
        
        for (service, description) in interfering_services {
            let running = Command::new("pgrep").arg(service).output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            
            if running {
                results.push(CheckResult {
                    name: format!("{} process", service),
                    status: CheckStatus::Ok,
                    message: format!("Running - {}", description),
                    fix_hint: None,
                });
            }
        }
    }
    
    Ok(())
}

fn dir_size(path: &Path) -> Result<u64> {
    let mut size = 0;
    for entry in walkdir::WalkDir::new(path).min_depth(1) {
        let entry = entry?;
        if entry.file_type().is_file() {
            size += entry.metadata()?.len();
        }
    }
    Ok(size)
}