use anyhow::{Context as _, Result};
use clap::Args;
use colored::*;
use indicatif::{MultiProgress, ProgressBar};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;
use walkdir::WalkDir;

use crate::utils::{
    archive::{create_tar_gz, create_zip, CreateOptions},
    npm,
    version::get_version,
    Context, ensure_command_exists, spinner, workspace_root,
};

#[derive(Args)]
pub struct PackageCmd {
    /// Target platforms to package for
    #[arg(long, value_delimiter = ',')]
    pub targets: Option<Vec<String>>,

    /// Output directory for packages
    #[arg(long, default_value = "dist")]
    pub output_dir: String,

    /// Create NPM packages with platform binaries
    #[arg(long)]
    pub npm: bool,

    /// NPM package scope (e.g., @myorg)
    #[arg(long)]
    pub npm_scope: Option<String>,

    /// Generate checksums for all artifacts
    #[arg(long)]
    pub checksums: bool,

    /// Skip building binaries (assume they exist)
    #[arg(long)]
    pub skip_build: bool,

    /// Build in release mode
    #[arg(long)]
    pub release: bool,

    /// Strip debug symbols from binaries
    #[arg(long)]
    pub strip: bool,

    /// Compress archives with maximum compression
    #[arg(long)]
    pub max_compression: bool,

    /// Version to use for packages (defaults to Cargo.toml version)
    #[arg(long)]
    pub version: Option<String>,
}

pub async fn run(cmd: PackageCmd, ctx: Context) -> Result<()> {
    // Ensure we're in the workspace root
    std::env::set_current_dir(workspace_root()?)?;

    // Ensure required tools
    ensure_command_exists("cargo")?;
    if !cmd.skip_build {
        ensure_command_exists("cross")?;
    }

    let targets = cmd.targets.clone().unwrap_or_else(default_targets);
    let output_dir = PathBuf::from(&cmd.output_dir);
    let version = cmd.version.clone().unwrap_or_else(|| {
        get_version(None).unwrap_or_else(|_| "0.1.0".to_string())
    });

    ctx.info(&format!(
        "Packaging {} targets for version {}",
        targets.len(),
        version
    ));

    // Create output directory structure
    std::fs::create_dir_all(&output_dir)?;
    let archives_dir = output_dir.join("archives");
    let npm_dir = output_dir.join("npm");
    std::fs::create_dir_all(&archives_dir)?;
    if cmd.npm {
        std::fs::create_dir_all(&npm_dir)?;
    }

    // Build binaries if not skipping
    if !cmd.skip_build {
        ctx.info("Building binaries for all targets...");
        build_all_targets(&targets, &cmd, &ctx).await?;
    }

    // Package binaries
    ctx.info("Creating platform archives...");
    let artifacts = package_binaries(&targets, &cmd, &ctx, &archives_dir, &version).await?;

    // Create NPM packages if requested
    if cmd.npm {
        ctx.info("Creating NPM packages...");
        create_npm_packages(&artifacts, &cmd, &ctx, &npm_dir, &version).await?;
    }

    // Generate checksums if requested
    if cmd.checksums {
        ctx.info("Generating checksums...");
        generate_checksums(&output_dir, &ctx)?;
    }

    // Summary
    print_summary(&output_dir, &ctx)?;

    Ok(())
}

async fn build_all_targets(
    targets: &[String],
    cmd: &PackageCmd,
    ctx: &Context,
) -> Result<()> {
    let multi_progress = Arc::new(MultiProgress::new());
    let semaphore = Arc::new(Semaphore::new(num_cpus::get()));
    let mut handles = vec![];

    for target in targets {
        let target = target.clone();
        let ctx = ctx.clone();
        let multi_progress = Arc::clone(&multi_progress);
        let semaphore = Arc::clone(&semaphore);
        let release = cmd.release;

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            build_single_target(&target, release, &ctx, &multi_progress).await
        });

        handles.push(handle);
    }

    // Wait for all builds
    let results: Vec<Result<()>> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    // Check for failures
    for (target, result) in targets.iter().zip(results.iter()) {
        if let Err(e) = result {
            return Err(anyhow::anyhow!("Failed to build {}: {}", target, e));
        }
    }

    Ok(())
}

async fn build_single_target(
    target: &str,
    release: bool,
    ctx: &Context,
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
    if release {
        args.push("--release");
    }
    args.extend(&["--features", "full"]);

    // Run build
    ctx.run_command(build_cmd, &args)?;

    pb.finish_with_message(format!("✓ Built {}", target));
    Ok(())
}

#[derive(Clone)]
struct Artifact {
    target: String,
    binary_path: PathBuf,
    binary_name: String,
    archive_path: PathBuf,
}

async fn package_binaries(
    targets: &[String],
    cmd: &PackageCmd,
    ctx: &Context,
    archives_dir: &Path,
    version: &str,
) -> Result<Vec<Artifact>> {
    let mut artifacts = Vec::new();
    let multi_progress = Arc::new(MultiProgress::new());
    let semaphore = Arc::new(Semaphore::new(num_cpus::get()));
    let mut handles = vec![];

    for target in targets {
        let target = target.clone();
        let ctx = ctx.clone();
        let archives_dir = archives_dir.to_path_buf();
        let multi_progress = Arc::clone(&multi_progress);
        let semaphore = Arc::clone(&semaphore);
        let release = cmd.release;
        let strip = cmd.strip;
        let max_compression = cmd.max_compression;
        let version = version.to_string();

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            package_single_target(
                &target,
                release,
                strip,
                max_compression,
                &ctx,
                &archives_dir,
                &version,
                &multi_progress,
            )
            .await
        });

        handles.push(handle);
    }

    // Collect results
    let results: Vec<Result<Vec<Artifact>>> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();

    for result in results {
        artifacts.extend(result?);
    }

    Ok(artifacts)
}

async fn package_single_target(
    target: &str,
    release: bool,
    strip: bool,
    max_compression: bool,
    ctx: &Context,
    archives_dir: &Path,
    version: &str,
    multi_progress: &MultiProgress,
) -> Result<Vec<Artifact>> {
    let pb = multi_progress.add(spinner(&format!("Packaging {}", target)));

    let mut artifacts = Vec::new();

    // Find binaries
    let target_dir = if release { "release" } else { "debug" };
    let binary_paths = find_binaries(target, target_dir)?;

    for binary_path in binary_paths {
        let binary_name = binary_path
            .file_name()
            .context("Invalid binary name")?
            .to_string_lossy();

        // Strip if requested
        if strip && release {
            strip_binary(&binary_path, target)?;
        }

        // Create temporary directory for packaging
        let temp_dir = tempfile::tempdir()?;
        let package_dir = temp_dir.path().join(format!("kindly-guard-{}", version));
        std::fs::create_dir_all(&package_dir)?;

        // Copy binary
        let dest_binary = package_dir.join(binary_name.as_ref());
        std::fs::copy(&binary_path, &dest_binary)?;

        // Add README and LICENSE
        add_package_files(&package_dir, target)?;

        // Create archive
        let archive_name = format!(
            "kindly-guard-{}-{}",
            version,
            target_to_platform_string(target)
        );

        let archive_path = if target.contains("windows") {
            let zip_path = archives_dir.join(format!("{}.zip", archive_name));
            create_zip_archive(&package_dir, &zip_path, max_compression)?;
            zip_path
        } else {
            let tar_path = archives_dir.join(format!("{}.tar.gz", archive_name));
            create_tar_gz_archive(&package_dir, &tar_path, max_compression)?;
            tar_path
        };

        artifacts.push(Artifact {
            target: target.to_string(),
            binary_path: dest_binary,
            binary_name: binary_name.into_owned(),
            archive_path,
        });
    }

    pb.finish_with_message(format!("✓ Packaged {}", target));
    Ok(artifacts)
}

async fn create_npm_packages(
    artifacts: &[Artifact],
    cmd: &PackageCmd,
    ctx: &Context,
    npm_dir: &Path,
    version: &str,
) -> Result<()> {
    // Read base package.json template
    let base_package = load_npm_template()?;

    // Group artifacts by target
    let mut by_target: HashMap<String, Vec<&Artifact>> = HashMap::new();
    for artifact in artifacts {
        by_target
            .entry(artifact.target.clone())
            .or_default()
            .push(artifact);
    }

    // Create platform-specific packages
    for (target, target_artifacts) in &by_target {
        create_platform_npm_package(
            target,
            target_artifacts.clone(),
            &base_package,
            cmd,
            ctx,
            npm_dir,
            version,
        )
        .await?;
    }

    // Create main package with optionalDependencies
    create_main_npm_package(&by_target, &base_package, cmd, ctx, npm_dir, version).await?;

    Ok(())
}

async fn create_platform_npm_package(
    target: &str,
    artifacts: Vec<&Artifact>,
    base_package: &Value,
    cmd: &PackageCmd,
    ctx: &Context,
    npm_dir: &Path,
    version: &str,
) -> Result<()> {
    let platform_name = target_to_platform_string(target);
    let package_name = if let Some(scope) = &cmd.npm_scope {
        format!("{}/kindly-guard-{}", scope, platform_name)
    } else {
        format!("kindly-guard-{}", platform_name)
    };

    let package_dir = npm_dir.join(&package_name.replace('/', "_"));
    std::fs::create_dir_all(&package_dir)?;

    // Create bin directory
    let bin_dir = package_dir.join("bin");
    std::fs::create_dir_all(&bin_dir)?;

    // Copy binaries
    for artifact in &artifacts {
        let dest = bin_dir.join(&artifact.binary_name);
        std::fs::copy(&artifact.binary_path, &dest)?;

        // Make executable on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&dest)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&dest, perms)?;
        }
    }

    // Create platform-specific package.json
    let mut package = base_package.clone();
    package["name"] = json!(package_name);
    package["version"] = json!(version);
    package["description"] = json!(format!(
        "KindlyGuard security MCP server - {} platform binaries",
        platform_name
    ));

    // Platform restrictions
    package["os"] = json!(platform_os(target));
    package["cpu"] = json!(platform_cpu(target));

    // Binary mapping
    let mut bin = serde_json::Map::new();
    for artifact in &artifacts {
        let bin_name = artifact
            .binary_name
            .trim_end_matches(".exe")
            .to_string();
        bin.insert(
            bin_name,
            json!(format!("./bin/{}", artifact.binary_name)),
        );
    }
    package["bin"] = json!(bin);

    // Write package.json
    npm::write_package_json(&package_dir, &package)?;

    // Create .npmignore
    npm::create_npmignore(&package_dir, &[
        "*.tar.gz",
        "*.zip",
        "*.log",
        ".DS_Store",
        "Thumbs.db",
    ])?;

    // Add README
    let readme_content = format!(
        r#"# KindlyGuard - {} Platform Binaries

This package contains the platform-specific binaries for KindlyGuard on {}.

## Installation

This package is automatically installed as an optional dependency when you install the main `kindly-guard` package.

For manual installation:

```bash
npm install {}
```

## Usage

The binaries are available in the `node_modules/{}/bin` directory after installation.

## License

See LICENSE file in the main package.
"#,
        platform_name, platform_name, package_name, package_name
    );

    std::fs::write(package_dir.join("README.md"), readme_content)?;

    ctx.success(&format!("Created NPM package: {}", package_name));
    Ok(())
}

async fn create_main_npm_package(
    targets: &HashMap<String, Vec<&Artifact>>,
    base_package: &Value,
    cmd: &PackageCmd,
    ctx: &Context,
    npm_dir: &Path,
    version: &str,
) -> Result<()> {
    let package_name = if let Some(scope) = &cmd.npm_scope {
        format!("{}/kindly-guard", scope)
    } else {
        "kindly-guard".to_string()
    };

    let package_dir = npm_dir.join(&package_name.replace('/', "_"));
    std::fs::create_dir_all(&package_dir)?;

    // Create main package.json with optionalDependencies
    let mut package = base_package.clone();
    package["name"] = json!(package_name);
    package["version"] = json!(version);
    package["description"] = json!("KindlyGuard - Security-focused MCP server");

    // Add optional dependencies for all platforms
    let mut optional_deps = serde_json::Map::new();
    for target in targets.keys() {
        let platform_name = target_to_platform_string(target);
        let dep_name = if let Some(scope) = &cmd.npm_scope {
            format!("{}/kindly-guard-{}", scope, platform_name)
        } else {
            format!("kindly-guard-{}", platform_name)
        };
        optional_deps.insert(dep_name, json!(version));
    }
    package["optionalDependencies"] = json!(optional_deps);

    // Add postinstall script
    package["scripts"] = json!({
        "postinstall": "node scripts/postinstall.js"
    });

    // Write package.json
    npm::write_package_json(&package_dir, &package)?;

    // Create postinstall script
    let scripts_dir = package_dir.join("scripts");
    std::fs::create_dir_all(&scripts_dir)?;

    let postinstall_content = r#"#!/usr/bin/env node
const { platform, arch } = process;
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const PLATFORM_MAP = {
  'darwin-x64': 'darwin-x64',
  'darwin-arm64': 'darwin-arm64',
  'linux-x64': 'linux-x64',
  'linux-arm64': 'linux-arm64',
  'win32-x64': 'win32-x64',
  'win32-arm64': 'win32-arm64',
};

const platformKey = `${platform}-${arch}`;
const mappedPlatform = PLATFORM_MAP[platformKey];

if (!mappedPlatform) {
  console.error(`Unsupported platform: ${platformKey}`);
  process.exit(1);
}

// Check if platform package is installed
const platformPackage = `kindly-guard-${mappedPlatform}`;
try {
  require.resolve(platformPackage);
  console.log(`Platform binaries installed: ${platformPackage}`);
} catch (e) {
  console.warn(`Platform package ${platformPackage} not found. Please install manually.`);
}
"#;

    std::fs::write(scripts_dir.join("postinstall.js"), postinstall_content)?;

    // Create main README
    let readme_content = format!(
        r#"# KindlyGuard

Security-focused MCP (Model Context Protocol) server that protects against unicode attacks, injection attempts, and other threats.

## Installation

```bash
npm install {}
```

This will automatically install the appropriate platform-specific binaries for your system.

## Usage

After installation, the `kindly-guard` command will be available:

```bash
kindly-guard --help
```

### As an MCP Server

```bash
kindly-guard server --stdio
```

### Scanning Files

```bash
kindly-guard scan suspicious_file.json
```

## Platform Support

- macOS (x64, arm64)
- Linux (x64, arm64, musl variants)
- Windows (x64, arm64)

## License

See LICENSE file.
"#,
        package_name
    );

    std::fs::write(package_dir.join("README.md"), readme_content)?;

    // Copy LICENSE
    if let Ok(license) = std::fs::read_to_string("LICENSE") {
        std::fs::write(package_dir.join("LICENSE"), license)?;
    }

    ctx.success(&format!("Created main NPM package: {}", package_name));
    Ok(())
}

fn generate_checksums(output_dir: &Path, ctx: &Context) -> Result<()> {
    let mut checksums = Vec::new();

    // Generate checksums for all files in archives and npm directories
    for subdir in &["archives", "npm"] {
        let dir = output_dir.join(subdir);
        if !dir.exists() {
            continue;
        }

        for entry in WalkDir::new(&dir)
            .min_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                let path = entry.path();
                let checksum = calculate_sha256(path)?;
                let relative_path = path.strip_prefix(output_dir)?;
                checksums.push((relative_path.to_path_buf(), checksum));
            }
        }
    }

    // Write checksums file
    let checksums_path = output_dir.join("checksums.sha256");
    let mut file = File::create(&checksums_path)?;

    for (path, checksum) in &checksums {
        writeln!(file, "{}  {}", checksum, path.display())?;
    }

    ctx.success(&format!(
        "Generated checksums for {} files",
        checksums.len()
    ));
    Ok(())
}

fn calculate_sha256(path: &Path) -> Result<String> {
    let mut file = BufReader::new(File::open(path)?);
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn print_summary(output_dir: &Path, ctx: &Context) -> Result<()> {
    println!("\n{}", "Package Summary:".bold().green());
    println!("{}", "=".repeat(50));

    // List archives
    let archives_dir = output_dir.join("archives");
    if archives_dir.exists() {
        println!("\n{}:", "Archives".bold());
        for entry in std::fs::read_dir(&archives_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let size = entry.metadata()?.len() as f64 / 1_048_576.0;
                println!("  {} ({:.2} MB)", entry.file_name().to_string_lossy(), size);
            }
        }
    }

    // List NPM packages
    let npm_dir = output_dir.join("npm");
    if npm_dir.exists() {
        println!("\n{}:", "NPM Packages".bold());
        for entry in std::fs::read_dir(&npm_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                println!("  {}/", entry.file_name().to_string_lossy());
            }
        }
    }

    // Checksums file
    let checksums_path = output_dir.join("checksums.sha256");
    if checksums_path.exists() {
        println!("\n{}:", "Checksums".bold());
        println!("  checksums.sha256");
    }

    println!("\n{}", "All packages created successfully!".green().bold());
    Ok(())
}

// Helper functions

fn should_use_cross(target: &str) -> bool {
    let host_triple = target_triple::TARGET;
    target != host_triple
}

fn find_binaries(target: &str, build_type: &str) -> Result<Vec<PathBuf>> {
    let target_dir = PathBuf::from("target").join(target).join(build_type);
    let mut binaries = vec![];

    // Look for known binary names
    let binary_names = [
        "kindly-guard",
        "kindly-guard-server",
        "kindly-guard-cli",
        "kindly-guard-shield",
    ];

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
        // Try to find any executable in the directory
        if target_dir.exists() {
            for entry in std::fs::read_dir(&target_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let metadata = entry.metadata()?;
                        if metadata.permissions().mode() & 0o111 != 0 {
                            binaries.push(path);
                        }
                    }
                    #[cfg(windows)]
                    {
                        if path.extension().map_or(false, |ext| ext == "exe") {
                            binaries.push(path);
                        }
                    }
                }
            }
        }
    }

    if binaries.is_empty() {
        anyhow::bail!("No binaries found for target {}", target);
    }

    Ok(binaries)
}

fn strip_binary(binary_path: &Path, target: &str) -> Result<()> {
    let strip_cmd = if target.contains("apple") || target.contains("darwin") {
        "strip".to_string()
    } else if target.contains("windows") {
        // Windows binaries are typically stripped during build
        return Ok(());
    } else {
        // Try to use target-specific strip
        format!("{}-strip", target.split('-').next().unwrap_or("strip"))
    };

    // Check if strip command exists
    if which::which(&strip_cmd).is_err() {
        // Fallback to generic strip
        if which::which("strip").is_ok() {
            std::process::Command::new("strip")
                .arg(binary_path)
                .status()?;
        }
    } else {
        std::process::Command::new(&strip_cmd)
            .arg(binary_path)
            .status()?;
    }

    Ok(())
}

fn create_zip_archive(src_dir: &Path, dest_path: &Path, max_compression: bool) -> Result<()> {
    let mut options = CreateOptions::default();
    options.compression_level = if max_compression { 9 } else { 6 };
    options.preserve_permissions = true;

    create_zip(dest_path, src_dir, options)
}

fn create_tar_gz_archive(src_dir: &Path, dest_path: &Path, max_compression: bool) -> Result<()> {
    let mut options = CreateOptions::default();
    options.compression_level = if max_compression { 9 } else { 6 };
    options.preserve_permissions = true;

    create_tar_gz(dest_path, src_dir, options)
}

fn add_package_files(package_dir: &Path, target: &str) -> Result<()> {
    // Add README
    let readme_content = format!(
        r#"# KindlyGuard

Security-focused MCP server for {}

## Usage

Run the server:
```bash
./kindly-guard server --stdio
```

Scan a file:
```bash
./kindly-guard scan file.json
```

## Documentation

See https://github.com/yourusername/kindly-guard for full documentation.
"#,
        target_to_platform_string(target)
    );

    std::fs::write(package_dir.join("README.md"), readme_content)?;

    // Copy LICENSE if it exists
    if let Ok(license) = std::fs::read_to_string("LICENSE") {
        std::fs::write(package_dir.join("LICENSE"), license)?;
    }

    Ok(())
}

fn load_npm_template() -> Result<Value> {
    // Default template if no package.json exists
    let template = json!({
        "name": "kindly-guard",
        "version": "0.1.0",
        "description": "Security-focused MCP server",
        "keywords": ["mcp", "security", "unicode", "injection"],
        "author": "",
        "license": "MIT",
        "repository": {
            "type": "git",
            "url": "https://github.com/yourusername/kindly-guard.git"
        },
        "engines": {
            "node": ">=16.0.0"
        },
        "files": ["bin/**/*", "README.md", "LICENSE"],
        "publishConfig": {
            "access": "public"
        }
    });

    // Try to load from npm/package.json if it exists
    let npm_package_path = PathBuf::from("npm/package.json");
    if npm_package_path.exists() {
        npm::read_package_json(&npm_package_path)
    } else {
        Ok(template)
    }
}

fn target_to_platform_string(target: &str) -> String {
    match target {
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
    }
    .to_string()
}

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

fn platform_cpu(target: &str) -> Vec<&str> {
    if target.contains("x86_64") {
        vec!["x64"]
    } else if target.contains("i686") {
        vec!["ia32"]
    } else if target.contains("aarch64") {
        vec!["arm64"]
    } else if target.contains("armv7") || target.contains("arm") {
        vec!["arm"]
    } else {
        vec![]
    }
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