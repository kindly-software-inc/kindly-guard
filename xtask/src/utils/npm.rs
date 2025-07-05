//! NPM utilities for packaging and publishing

use anyhow::{Context as _, Result};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

use crate::utils::Context;

/// Check if Node.js is installed
pub fn is_node_installed() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Check if NPM is installed
pub fn is_npm_installed() -> bool {
    Command::new("npm")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Get Node.js version
pub fn node_version() -> Result<String> {
    let output = Command::new("node")
        .arg("--version")
        .output()
        .context("Failed to get node version")?;
    
    if !output.status.success() {
        anyhow::bail!("Failed to get node version");
    }
    
    Ok(String::from_utf8(output.stdout)?
        .trim()
        .trim_start_matches('v')
        .to_string())
}

/// Get NPM version
pub fn npm_version() -> Result<String> {
    let output = Command::new("npm")
        .arg("--version")
        .output()
        .context("Failed to get npm version")?;
    
    if !output.status.success() {
        anyhow::bail!("Failed to get npm version");
    }
    
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

/// Run npm command with arguments
pub fn run_npm(ctx: &Context, args: &[&str]) -> Result<()> {
    if ctx.dry_run {
        println!("[dry-run] npm {}", args.join(" "));
        return Ok(());
    }

    ctx.debug(&format!("Running: npm {}", args.join(" ")));

    let output = Command::new("npm")
        .args(args)
        .output()
        .context("Failed to execute npm")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("npm failed:\n{}", stderr);
    }

    if ctx.verbose {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.is_empty() {
            println!("{}", stdout);
        }
    }

    Ok(())
}

/// Run npm command and get output
pub fn run_npm_output(args: &[&str]) -> Result<String> {
    let output = Command::new("npm")
        .args(args)
        .output()
        .context("Failed to execute npm")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("npm failed:\n{}", stderr);
    }

    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

/// Install NPM dependencies
pub fn install(ctx: &Context, dir: &Path, ci: bool) -> Result<()> {
    let prev_dir = std::env::current_dir()?;
    std::env::set_current_dir(dir)?;
    
    let result = if ci {
        run_npm(ctx, &["ci"])
    } else {
        run_npm(ctx, &["install"])
    };
    
    std::env::set_current_dir(prev_dir)?;
    result
}

/// Build NPM package
pub fn build(ctx: &Context, dir: &Path) -> Result<()> {
    let prev_dir = std::env::current_dir()?;
    std::env::set_current_dir(dir)?;
    
    let result = run_npm(ctx, &["run", "build"]);
    
    std::env::set_current_dir(prev_dir)?;
    result
}

/// Run NPM tests
pub fn test(ctx: &Context, dir: &Path) -> Result<()> {
    let prev_dir = std::env::current_dir()?;
    std::env::set_current_dir(dir)?;
    
    let result = run_npm(ctx, &["test"]);
    
    std::env::set_current_dir(prev_dir)?;
    result
}

/// Pack NPM package (create tarball)
pub fn pack(ctx: &Context, dir: &Path) -> Result<String> {
    let prev_dir = std::env::current_dir()?;
    std::env::set_current_dir(dir)?;
    
    let output = if ctx.dry_run {
        ctx.info("[dry-run] Would create NPM package tarball");
        "dry-run-package.tgz".to_string()
    } else {
        run_npm_output(&["pack", "--json"])?
    };
    
    std::env::set_current_dir(prev_dir)?;
    
    // Parse the JSON output to get the filename
    if !ctx.dry_run {
        let json: Value = serde_json::from_str(&output)?;
        if let Some(filename) = json[0]["filename"].as_str() {
            Ok(filename.to_string())
        } else {
            anyhow::bail!("Failed to parse npm pack output")
        }
    } else {
        Ok(output)
    }
}

/// Publish NPM package
pub fn publish(ctx: &Context, dir: &Path, tag: Option<&str>, access: Option<&str>) -> Result<()> {
    let prev_dir = std::env::current_dir()?;
    std::env::set_current_dir(dir)?;
    
    let mut args = vec!["publish"];
    
    if let Some(t) = tag {
        args.push("--tag");
        args.push(t);
    }
    
    if let Some(a) = access {
        args.push("--access");
        args.push(a);
    }
    
    let result = run_npm(ctx, &args);
    
    std::env::set_current_dir(prev_dir)?;
    result
}

/// Read package.json
pub fn read_package_json(path: &Path) -> Result<Value> {
    let package_json = if path.is_dir() {
        path.join("package.json")
    } else {
        path.to_path_buf()
    };
    
    let contents = std::fs::read_to_string(&package_json)
        .with_context(|| format!("Failed to read {}", package_json.display()))?;
    
    serde_json::from_str(&contents)
        .context("Failed to parse package.json")
}

/// Write package.json
pub fn write_package_json(path: &Path, package: &Value) -> Result<()> {
    let package_json = if path.is_dir() {
        path.join("package.json")
    } else {
        path.to_path_buf()
    };
    
    let contents = serde_json::to_string_pretty(package)?;
    std::fs::write(&package_json, contents)
        .with_context(|| format!("Failed to write {}", package_json.display()))
}

/// Get package version from package.json
pub fn get_package_version(dir: &Path) -> Result<String> {
    let package = read_package_json(dir)?;
    
    package["version"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("No version field in package.json"))
}

/// Set package version in package.json
pub fn set_package_version(dir: &Path, version: &str) -> Result<()> {
    let mut package = read_package_json(dir)?;
    package["version"] = json!(version);
    write_package_json(dir, &package)
}

/// Create platform-specific package name
pub fn platform_package_name(base_name: &str, target: &str) -> String {
    // Map Rust target triples to NPM platform conventions
    let platform = match target {
        "x86_64-pc-windows-msvc" => "win32-x64",
        "i686-pc-windows-msvc" => "win32-ia32",
        "aarch64-pc-windows-msvc" => "win32-arm64",
        "x86_64-apple-darwin" => "darwin-x64",
        "aarch64-apple-darwin" => "darwin-arm64",
        "x86_64-unknown-linux-gnu" => "linux-x64",
        "x86_64-unknown-linux-musl" => "linux-x64-musl",
        "aarch64-unknown-linux-gnu" => "linux-arm64",
        "aarch64-unknown-linux-musl" => "linux-arm64-musl",
        "armv7-unknown-linux-gnueabihf" => "linux-arm",
        _ => target,
    };
    
    format!("{}-{}", base_name, platform)
}

/// Create platform-specific package.json
pub fn create_platform_package(
    base_package: &Value,
    target: &str,
    binary_name: &str,
    version: &str,
) -> Result<Value> {
    let mut package = base_package.clone();
    
    // Update package name
    let base_name = package["name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("No name field in package.json"))?;
    
    package["name"] = json!(platform_package_name(base_name, target));
    package["version"] = json!(version);
    
    // Add platform-specific fields
    package["os"] = json!(platform_os(target));
    package["cpu"] = json!(platform_cpu(target));
    
    // Set up binary field
    package["bin"] = json!({
        binary_name: format!("./bin/{}", binary_executable_name(binary_name, target))
    });
    
    Ok(package)
}

/// Get OS field for package.json from target triple
fn platform_os(target: &str) -> Vec<&str> {
    if target.contains("windows") {
        vec!["win32"]
    } else if target.contains("darwin") {
        vec!["darwin"]
    } else if target.contains("linux") {
        vec!["linux"]
    } else {
        vec![]
    }
}

/// Get CPU field for package.json from target triple
fn platform_cpu(target: &str) -> Vec<&str> {
    if target.contains("x86_64") {
        vec!["x64"]
    } else if target.contains("i686") {
        vec!["ia32"]
    } else if target.contains("aarch64") {
        vec!["arm64"]
    } else if target.contains("armv7") {
        vec!["arm"]
    } else {
        vec![]
    }
}

/// Get binary executable name for target platform
fn binary_executable_name(base_name: &str, target: &str) -> String {
    if target.contains("windows") {
        format!("{}.exe", base_name)
    } else {
        base_name.to_string()
    }
}

/// Check if user is logged in to NPM
pub fn is_logged_in() -> Result<bool> {
    let output = Command::new("npm")
        .args(&["whoami"])
        .output()?;
    
    Ok(output.status.success())
}

/// Get current NPM user
pub fn whoami() -> Result<String> {
    run_npm_output(&["whoami"])
}

/// Set NPM registry
pub fn set_registry(ctx: &Context, registry: &str) -> Result<()> {
    run_npm(ctx, &["config", "set", "registry", registry])
}

/// Get NPM registry
pub fn get_registry() -> Result<String> {
    run_npm_output(&["config", "get", "registry"])
}

/// Set auth token for a registry
pub fn set_auth_token(ctx: &Context, registry: &str, token: &str) -> Result<()> {
    let registry_url = registry.trim_end_matches('/');
    let auth_key = format!("{}/:_authToken", registry_url);
    
    run_npm(ctx, &["config", "set", &auth_key, token])
}

/// Run npm audit
pub fn audit(ctx: &Context, dir: &Path, fix: bool) -> Result<()> {
    let prev_dir = std::env::current_dir()?;
    std::env::set_current_dir(dir)?;
    
    let args = if fix {
        vec!["audit", "fix"]
    } else {
        vec!["audit"]
    };
    
    let result = run_npm(ctx, &args);
    
    std::env::set_current_dir(prev_dir)?;
    result
}

/// Check if package exists in registry
pub fn package_exists(name: &str) -> Result<bool> {
    let output = Command::new("npm")
        .args(&["view", name, "version"])
        .output()?;
    
    Ok(output.status.success())
}

/// Get latest version of a package from registry
pub fn get_latest_version(name: &str) -> Result<Option<String>> {
    let output = Command::new("npm")
        .args(&["view", name, "version"])
        .output()?;
    
    if output.status.success() {
        Ok(Some(String::from_utf8(output.stdout)?.trim().to_string()))
    } else {
        Ok(None)
    }
}

/// Create .npmignore file
pub fn create_npmignore(dir: &Path, patterns: &[&str]) -> Result<()> {
    let npmignore = dir.join(".npmignore");
    let contents = patterns.join("\n");
    
    std::fs::write(&npmignore, contents)
        .with_context(|| format!("Failed to write {}", npmignore.display()))
}

/// Ensure package.json has required fields for publishing
pub fn validate_package_json(package: &Value) -> Result<()> {
    let required_fields = ["name", "version", "description", "license"];
    
    for field in &required_fields {
        if !package[field].is_string() {
            anyhow::bail!("Missing required field '{}' in package.json", field);
        }
    }
    
    // Validate package name
    if let Some(name) = package["name"].as_str() {
        if !is_valid_package_name(name) {
            anyhow::bail!("Invalid package name: {}", name);
        }
    }
    
    Ok(())
}

/// Check if package name is valid according to NPM rules
fn is_valid_package_name(name: &str) -> bool {
    // NPM package names must:
    // - be lowercase
    // - contain only URL-safe characters
    // - not start with . or _
    // - not contain spaces
    // - be less than 214 characters
    
    name.len() < 214
        && name == name.to_lowercase()
        && !name.starts_with('.')
        && !name.starts_with('_')
        && !name.contains(' ')
        && name.chars().all(|c| c.is_alphanumeric() || "-._~@/".contains(c))
}