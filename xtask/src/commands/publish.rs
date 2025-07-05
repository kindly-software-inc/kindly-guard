use anyhow::{Context as _, Result};
use clap::Args;
use colored::*;
use std::path::Path;

use crate::utils::{Context, ensure_command_exists, spinner};

#[derive(Args)]
pub struct PublishCmd {
    /// Publish to crates.io
    #[arg(long)]
    pub crates_io: bool,

    /// Publish to npm
    #[arg(long)]
    pub npm: bool,

    /// Publish to Docker Hub
    #[arg(long)]
    pub docker: bool,

    /// Skip verification steps
    #[arg(long)]
    pub skip_verification: bool,
}

pub async fn run(cmd: PublishCmd, ctx: Context) -> Result<()> {
    // Default to publishing all if none specified
    let publish_all = !cmd.crates_io && !cmd.npm && !cmd.docker;
    
    let mut results = PublishResults::default();

    // Verify before publishing
    if !cmd.skip_verification {
        verify_before_publish(&ctx)?;
    }

    // Publish to crates.io
    if publish_all || cmd.crates_io {
        ctx.info("Publishing to crates.io...");
        results.crates_io = Some(publish_to_crates_io(&ctx).await?);
    }

    // Publish to npm
    if publish_all || cmd.npm {
        ctx.info("Publishing to npm...");
        results.npm = Some(publish_to_npm(&ctx).await?);
    }

    // Publish to Docker Hub
    if publish_all || cmd.docker {
        ctx.info("Publishing to Docker Hub...");
        results.docker = Some(publish_to_docker(&ctx).await?);
    }

    // Print summary
    print_publish_summary(&results, &ctx);

    Ok(())
}

#[derive(Default)]
struct PublishResults {
    crates_io: Option<PublishResult>,
    npm: Option<PublishResult>,
    docker: Option<PublishResult>,
}

#[derive(Clone)]
struct PublishResult {
    success: bool,
    package: String,
    version: String,
    url: Option<String>,
    error: Option<String>,
}

fn verify_before_publish(ctx: &Context) -> Result<()> {
    let spinner = spinner("Running pre-publish checks");

    // Check git status
    let output = std::process::Command::new("git")
        .args(&["status", "--porcelain"])
        .output()?;

    if !output.stdout.is_empty() {
        spinner.finish_and_clear();
        anyhow::bail!("Git working directory is not clean. Commit or stash changes first.");
    }

    // Check if on main branch
    let branch = std::process::Command::new("git")
        .args(&["branch", "--show-current"])
        .output()?;
    
    let branch = String::from_utf8_lossy(&branch.stdout).trim().to_string();
    if branch != "main" && branch != "master" {
        ctx.warn(&format!("Not on main branch (current: {})", branch));
    }

    // Verify tags
    let version = get_current_version()?;
    let tag = format!("v{}", version);
    
    let tag_exists = std::process::Command::new("git")
        .args(&["tag", "-l", &tag])
        .output()?;

    if tag_exists.stdout.is_empty() {
        spinner.finish_and_clear();
        anyhow::bail!("Git tag {} does not exist. Create it first.", tag);
    }

    spinner.finish_with_message("Pre-publish checks passed");
    Ok(())
}

async fn publish_to_crates_io(ctx: &Context) -> Result<PublishResult> {
    ensure_command_exists("cargo")?;
    
    let spinner = spinner("Publishing to crates.io");
    
    // Get package info
    let metadata = cargo_metadata::MetadataCommand::new()
        .exec()
        .context("Failed to get cargo metadata")?;
    
    let root_package = metadata.root_package()
        .context("No root package found")?;
    
    let package_name = &root_package.name;
    let version = &root_package.version.to_string();

    // Check if already published
    if !ctx.dry_run && is_crate_published(package_name, version).await? {
        spinner.finish_with_message("Already published");
        return Ok(PublishResult {
            success: true,
            package: package_name.clone(),
            version: version.clone(),
            url: Some(format!("https://crates.io/crates/{}", package_name)),
            error: Some("Already published".to_string()),
        });
    }

    // Publish workspace members first
    let members = vec![
        "kindly-guard-server",
        "kindly-guard-cli", 
        "kindly-guard-shield",
    ];

    for member in members {
        if workspace_has_member(&metadata, member) {
            publish_crate(member, ctx)?;
            
            // Wait a bit between publishes
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }

    // Publish root package
    publish_crate(".", ctx)?;

    spinner.finish_with_message("Published to crates.io");

    Ok(PublishResult {
        success: true,
        package: package_name.clone(),
        version: version.clone(),
        url: Some(format!("https://crates.io/crates/{}", package_name)),
        error: None,
    })
}

fn publish_crate(path: &str, ctx: &Context) -> Result<()> {
    let mut args = vec!["publish"];
    
    if path != "." {
        args.extend(&["-p", path]);
    }

    if ctx.dry_run {
        args.push("--dry-run");
    }

    // Add token if available
    let token = std::env::var("CARGO_REGISTRY_TOKEN").ok();
    if let Some(ref token) = token {
        args.extend(&["--token", token]);
    }

    ctx.run_command("cargo", &args)?;
    Ok(())
}

async fn is_crate_published(name: &str, version: &str) -> Result<bool> {
    // Check using cargo search instead of HTTP API
    let output = std::process::Command::new("cargo")
        .args(&["search", "--limit", "1", &format!("{}={}", name, version)])
        .output()
        .context("Failed to run cargo search")?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains(name) && stdout.contains(version))
}

fn workspace_has_member(metadata: &cargo_metadata::Metadata, member: &str) -> bool {
    metadata.workspace_members
        .iter()
        .any(|pkg_id| {
            metadata.packages
                .iter()
                .find(|pkg| &pkg.id == pkg_id)
                .map_or(false, |pkg| pkg.name == member)
        })
}

async fn publish_to_npm(ctx: &Context) -> Result<PublishResult> {
    ensure_command_exists("npm")?;
    
    let spinner = spinner("Publishing to npm");

    // Check if package.json exists
    if !Path::new("package.json").exists() {
        spinner.finish_and_clear();
        return Ok(PublishResult {
            success: false,
            package: "unknown".to_string(),
            version: "unknown".to_string(),
            url: None,
            error: Some("No package.json found".to_string()),
        });
    }

    // Get package info
    let package_json = std::fs::read_to_string("package.json")?;
    let package: serde_json::Value = serde_json::from_str(&package_json)?;
    
    let package_name = package["name"].as_str().unwrap_or("unknown");
    let version = package["version"].as_str().unwrap_or("unknown");

    // Check if already published
    if !ctx.dry_run && is_npm_published(package_name, version).await? {
        spinner.finish_with_message("Already published");
        return Ok(PublishResult {
            success: true,
            package: package_name.to_string(),
            version: version.to_string(),
            url: Some(format!("https://www.npmjs.com/package/{}", package_name)),
            error: Some("Already published".to_string()),
        });
    }

    // Build before publishing
    if Path::new("build.js").exists() || package["scripts"]["build"].is_string() {
        ctx.run_command("npm", &["run", "build"])?;
    }

    // Publish
    let mut args = vec!["publish"];
    
    if ctx.dry_run {
        args.push("--dry-run");
    }

    // Add access for scoped packages
    if package_name.starts_with('@') {
        args.extend(&["--access", "public"]);
    }

    ctx.run_command("npm", &args)?;

    spinner.finish_with_message("Published to npm");

    Ok(PublishResult {
        success: true,
        package: package_name.to_string(),
        version: version.to_string(),
        url: Some(format!("https://www.npmjs.com/package/{}", package_name)),
        error: None,
    })
}

async fn is_npm_published(name: &str, version: &str) -> Result<bool> {
    let output = std::process::Command::new("npm")
        .args(&["view", &format!("{}@{}", name, version), "version"])
        .output()?;

    Ok(output.status.success())
}

async fn publish_to_docker(ctx: &Context) -> Result<PublishResult> {
    ensure_command_exists("docker")?;
    
    let spinner = spinner("Publishing to Docker Hub");

    // Check if Dockerfile exists
    if !Path::new("Dockerfile").exists() {
        spinner.finish_and_clear();
        return Ok(PublishResult {
            success: false,
            package: "unknown".to_string(),
            version: "unknown".to_string(),
            url: None,
            error: Some("No Dockerfile found".to_string()),
        });
    }

    let version = get_current_version()?;
    let image_name = "kindly/guard";
    let versioned_tag = format!("{}:{}", image_name, version);
    let latest_tag = format!("{}:latest", image_name);

    // Build multi-platform image
    if !ctx.dry_run {
        build_docker_image(&versioned_tag, ctx)?;
    }

    // Tag as latest
    if !ctx.dry_run {
        ctx.run_command("docker", &["tag", &versioned_tag, &latest_tag])?;
    }

    // Push both tags
    if !ctx.dry_run {
        ctx.run_command("docker", &["push", &versioned_tag])?;
        ctx.run_command("docker", &["push", &latest_tag])?;
    }

    spinner.finish_with_message("Published to Docker Hub");

    Ok(PublishResult {
        success: true,
        package: image_name.to_string(),
        version: version.to_string(),
        url: Some(format!("https://hub.docker.com/r/{}", image_name)),
        error: None,
    })
}

fn build_docker_image(tag: &str, ctx: &Context) -> Result<()> {
    // Use buildx for multi-platform builds
    let platforms = "linux/amd64,linux/arm64";
    
    ctx.run_command("docker", &[
        "buildx", "build",
        "--platform", platforms,
        "--tag", tag,
        "--push",
        ".",
    ])?;

    Ok(())
}

fn get_current_version() -> Result<String> {
    let manifest = std::fs::read_to_string("Cargo.toml")?;
    let manifest: toml::Value = toml::from_str(&manifest)?;
    
    manifest["package"]["version"]
        .as_str()
        .map(|s| s.to_string())
        .context("No version found in Cargo.toml")
}

fn print_publish_summary(results: &PublishResults, ctx: &Context) {
    println!("\n{}", "Publish Summary:".bold());
    println!("{}", "=".repeat(50));

    if let Some(result) = &results.crates_io {
        print_publish_result("crates.io", result);
    }

    if let Some(result) = &results.npm {
        print_publish_result("npm", result);
    }

    if let Some(result) = &results.docker {
        print_publish_result("Docker Hub", result);
    }

    println!("{}", "=".repeat(50));

    let all_success = [&results.crates_io, &results.npm, &results.docker]
        .iter()
        .filter_map(|r| r.as_ref())
        .all(|r| r.success);

    if all_success {
        ctx.success("All packages published successfully!");
    } else {
        ctx.error("Some publishes failed!");
    }
}

fn print_publish_result(registry: &str, result: &PublishResult) {
    let status = if result.success {
        if result.error.is_some() {
            "SKIPPED".yellow()
        } else {
            "SUCCESS".green()
        }
    } else {
        "FAILED".red()
    };

    print!("{:<15} {} ", format!("{}:", registry), status);
    
    if result.success && result.error.is_none() {
        println!("{} @ {}", result.package.bold(), result.version);
        if let Some(url) = &result.url {
            println!("{:<15} {}", "", url.blue());
        }
    } else if let Some(error) = &result.error {
        println!("({})", error);
    }
}