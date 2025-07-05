//! Docker command implementation

use anyhow::Result;
use std::process::Command;

use crate::utils::{version, Context};

/// Execute the docker command
pub async fn execute(
    ctx: Context,
    build: bool,
    push: bool,
    tag: Option<String>,
    multiplatform: bool,
) -> Result<()> {
    if !build && !push {
        ctx.warn("No Docker action specified. Use --build or --push");
        return Ok(());
    }

    // Get version for tagging
    let version = version::get_current_version()?;
    let version_tag = tag.unwrap_or_else(|| version.to_string());

    let image_name = "kindlyguard";
    let registry = std::env::var("DOCKER_REGISTRY").unwrap_or_else(|_| "samduchaine".to_string());
    
    let tags = vec![
        format!("{}/{}:{}", registry, image_name, version_tag),
        format!("{}/{}:latest", registry, image_name),
    ];

    // Build Docker image
    if build {
        if multiplatform {
            build_multiplatform(&ctx, &tags).await?;
        } else {
            build_single_platform(&ctx, &tags).await?;
        }
    }

    // Push Docker image
    if push && !ctx.dry_run {
        push_images(&ctx, &tags).await?;
    }

    ctx.status("Success", "Docker operations completed");
    
    Ok(())
}

async fn build_single_platform(ctx: &Context, tags: &[String]) -> Result<()> {
    ctx.status("Building", "Docker image for current platform");

    let mut cmd = Command::new("docker");
    cmd.arg("build");
    
    for tag in tags {
        cmd.args(&["-t", tag]);
    }
    
    cmd.arg(".");
    
    ctx.run_command(&mut cmd)?;
    
    Ok(())
}

async fn build_multiplatform(ctx: &Context, tags: &[String]) -> Result<()> {
    ctx.status("Building", "multi-platform Docker image");

    // Ensure buildx is available
    ensure_buildx(ctx)?;

    let mut cmd = Command::new("docker");
    cmd.args(&["buildx", "build"]);
    cmd.args(&["--platform", "linux/amd64,linux/arm64"]);
    
    for tag in tags {
        cmd.args(&["-t", tag]);
    }
    
    // Load into local registry if not pushing
    if ctx.dry_run {
        cmd.arg("--load");
    }
    
    cmd.arg(".");
    
    ctx.run_command(&mut cmd)?;
    
    Ok(())
}

async fn push_images(ctx: &Context, tags: &[String]) -> Result<()> {
    for tag in tags {
        ctx.status("Pushing", tag);
        
        let mut cmd = Command::new("docker");
        cmd.args(&["push", tag]);
        
        ctx.run_command(&mut cmd)?;
    }
    
    Ok(())
}

fn ensure_buildx(ctx: &Context) -> Result<()> {
    // Check if buildx is available
    let check = Command::new("docker")
        .args(&["buildx", "version"])
        .output();
    
    if check.is_err() || !check.unwrap().status.success() {
        ctx.status("Setup", "Installing Docker buildx");
        
        // Create buildx builder
        let mut cmd = Command::new("docker");
        cmd.args(&["buildx", "create", "--use", "--name", "kindlyguard-builder"]);
        ctx.run_command(&mut cmd)?;
        
        // Bootstrap the builder
        let mut cmd = Command::new("docker");
        cmd.args(&["buildx", "inspect", "--bootstrap"]);
        ctx.run_command(&mut cmd)?;
    }
    
    Ok(())
}