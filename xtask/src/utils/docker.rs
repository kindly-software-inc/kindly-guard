//! Docker utilities

use anyhow::{Context as _, Result};
use std::collections::HashMap;
use std::process::Command;

use crate::utils::Context;

/// Check if Docker is installed
pub fn is_installed() -> bool {
    Command::new("docker")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Check if Docker daemon is running
pub fn is_daemon_running() -> Result<bool> {
    let output = Command::new("docker")
        .args(&["info"])
        .output()
        .context("Failed to check Docker daemon status")?;
    
    Ok(output.status.success())
}

/// Get Docker version
pub fn get_version() -> Result<String> {
    let output = Command::new("docker")
        .args(&["version", "--format", "{{.Server.Version}}"])
        .output()
        .context("Failed to get Docker version")?;
    
    if !output.status.success() {
        anyhow::bail!("Failed to get Docker version");
    }
    
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Check if Docker Buildx is available
pub fn has_buildx() -> bool {
    Command::new("docker")
        .args(&["buildx", "version"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Build a Docker image
pub fn build_image(
    ctx: &Context,
    dockerfile: &str,
    tag: &str,
    build_args: Option<&HashMap<String, String>>,
    target: Option<&str>,
    context_path: &str,
) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.args(&["build", "-f", dockerfile, "-t", tag]);
    
    if let Some(args) = build_args {
        for (key, value) in args {
            cmd.arg("--build-arg");
            cmd.arg(format!("{}={}", key, value));
        }
    }
    
    if let Some(target) = target {
        cmd.args(&["--target", target]);
    }
    
    cmd.arg(context_path);
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

/// Build multi-platform images using buildx
pub fn build_multiplatform(
    ctx: &Context,
    dockerfile: &str,
    tag: &str,
    platforms: &[&str],
    build_args: Option<&HashMap<String, String>>,
    push: bool,
    context_path: &str,
) -> Result<()> {
    if !has_buildx() {
        anyhow::bail!("Docker Buildx is not available. Please install it first.");
    }
    
    let mut cmd = Command::new("docker");
    cmd.args(&["buildx", "build", "-f", dockerfile, "-t", tag]);
    
    // Set platforms
    cmd.arg("--platform");
    cmd.arg(platforms.join(","));
    
    if let Some(args) = build_args {
        for (key, value) in args {
            cmd.arg("--build-arg");
            cmd.arg(format!("{}={}", key, value));
        }
    }
    
    if push {
        cmd.arg("--push");
    } else {
        cmd.arg("--load");
    }
    
    cmd.arg(context_path);
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

/// Tag a Docker image
pub fn tag_image(ctx: &Context, source: &str, target: &str) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.args(&["tag", source, target]);
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

/// Push a Docker image to registry
pub fn push_image(ctx: &Context, image: &str) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.args(&["push", image]);
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

/// Pull a Docker image from registry
pub fn pull_image(ctx: &Context, image: &str) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.args(&["pull", image]);
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

/// List Docker images
pub fn list_images(filter: Option<&str>) -> Result<Vec<String>> {
    let mut cmd = Command::new("docker");
    cmd.args(&["images", "--format", "{{.Repository}}:{{.Tag}}"]);
    
    if let Some(filter) = filter {
        cmd.args(&["--filter", filter]);
    }
    
    let output = cmd.output()
        .context("Failed to list Docker images")?;
    
    if !output.status.success() {
        anyhow::bail!("Failed to list Docker images");
    }
    
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect())
}

/// Remove Docker images
pub fn remove_images(ctx: &Context, images: &[&str], force: bool) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.arg("rmi");
    
    if force {
        cmd.arg("-f");
    }
    
    cmd.args(images);
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

/// Check if an image exists locally
pub fn image_exists(image: &str) -> Result<bool> {
    let output = Command::new("docker")
        .args(&["images", "-q", image])
        .output()
        .context("Failed to check if image exists")?;
    
    Ok(!output.stdout.is_empty())
}

/// Run a Docker container
pub fn run_container(
    ctx: &Context,
    image: &str,
    name: Option<&str>,
    ports: Option<&HashMap<String, String>>,
    volumes: Option<&HashMap<String, String>>,
    env_vars: Option<&HashMap<String, String>>,
    detach: bool,
    rm: bool,
    command: Option<&[&str]>,
) -> Result<String> {
    let mut cmd = Command::new("docker");
    cmd.arg("run");
    
    if detach {
        cmd.arg("-d");
    }
    
    if rm {
        cmd.arg("--rm");
    }
    
    if let Some(name) = name {
        cmd.args(&["--name", name]);
    }
    
    if let Some(ports) = ports {
        for (host, container) in ports {
            cmd.arg("-p");
            cmd.arg(format!("{}:{}", host, container));
        }
    }
    
    if let Some(volumes) = volumes {
        for (host, container) in volumes {
            cmd.arg("-v");
            cmd.arg(format!("{}:{}", host, container));
        }
    }
    
    if let Some(env_vars) = env_vars {
        for (key, value) in env_vars {
            cmd.arg("-e");
            cmd.arg(format!("{}={}", key, value));
        }
    }
    
    cmd.arg(image);
    
    if let Some(command) = command {
        cmd.args(command);
    }
    
    if ctx.dry_run {
        ctx.info(&format!("Would run: {:?}", cmd));
        return Ok(String::new());
    }
    
    let output = cmd.output()
        .context("Failed to run Docker container")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to run container: {}", stderr);
    }
    
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Stop a Docker container
pub fn stop_container(ctx: &Context, container: &str, timeout: Option<u32>) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.arg("stop");
    
    if let Some(timeout) = timeout {
        cmd.arg("-t");
        cmd.arg(timeout.to_string());
    }
    
    cmd.arg(container);
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

/// Remove a Docker container
pub fn remove_container(ctx: &Context, container: &str, force: bool) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.arg("rm");
    
    if force {
        cmd.arg("-f");
    }
    
    cmd.arg(container);
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

/// Check if a container exists
pub fn container_exists(container: &str) -> Result<bool> {
    let output = Command::new("docker")
        .args(&["ps", "-a", "--format", "{{.Names}}", "--filter", &format!("name={}", container)])
        .output()
        .context("Failed to check if container exists")?;
    
    Ok(!output.stdout.is_empty())
}

/// Get container status
pub fn container_status(container: &str) -> Result<String> {
    let output = Command::new("docker")
        .args(&["ps", "-a", "--format", "{{.Status}}", "--filter", &format!("name={}", container)])
        .output()
        .context("Failed to get container status")?;
    
    if !output.status.success() {
        anyhow::bail!("Failed to get container status");
    }
    
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Execute a command in a running container
pub fn exec_command(
    ctx: &Context,
    container: &str,
    command: &[&str],
    interactive: bool,
    tty: bool,
) -> Result<String> {
    let mut cmd = Command::new("docker");
    cmd.arg("exec");
    
    if interactive {
        cmd.arg("-i");
    }
    
    if tty {
        cmd.arg("-t");
    }
    
    cmd.arg(container);
    cmd.args(command);
    
    if ctx.dry_run {
        ctx.info(&format!("Would execute: {:?}", cmd));
        return Ok(String::new());
    }
    
    let output = cmd.output()
        .context("Failed to execute command in container")?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to execute command: {}", stderr);
    }
    
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Copy files between container and host
pub fn copy_files(
    ctx: &Context,
    source: &str,
    destination: &str,
) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.args(&["cp", source, destination]);
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

/// Create a Docker builder for buildx
pub fn create_builder(ctx: &Context, name: &str, driver: Option<&str>) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.args(&["buildx", "create", "--name", name]);
    
    if let Some(driver) = driver {
        cmd.args(&["--driver", driver]);
    }
    
    cmd.arg("--use");
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

/// Remove a Docker builder
pub fn remove_builder(ctx: &Context, name: &str) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.args(&["buildx", "rm", name]);
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

/// Login to Docker registry
pub fn login(
    ctx: &Context,
    registry: Option<&str>,
    username: &str,
    password: &str,
) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.arg("login");
    
    if let Some(registry) = registry {
        cmd.arg(registry);
    }
    
    cmd.args(&["-u", username, "-p", password]);
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

/// Logout from Docker registry
pub fn logout(ctx: &Context, registry: Option<&str>) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.arg("logout");
    
    if let Some(registry) = registry {
        cmd.arg(registry);
    }
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

/// Get container logs
pub fn get_logs(container: &str, lines: Option<u32>, follow: bool) -> Result<String> {
    let mut cmd = Command::new("docker");
    cmd.arg("logs");
    
    if let Some(lines) = lines {
        cmd.arg("--tail");
        cmd.arg(lines.to_string());
    }
    
    if follow {
        cmd.arg("-f");
    }
    
    cmd.arg(container);
    
    let output = cmd.output()
        .context("Failed to get container logs")?;
    
    // Docker logs go to stderr by default
    Ok(String::from_utf8_lossy(&output.stderr).to_string())
}

/// Prune Docker system
pub fn prune_system(ctx: &Context, all: bool, volumes: bool) -> Result<()> {
    let mut cmd = Command::new("docker");
    cmd.args(&["system", "prune", "-f"]);
    
    if all {
        cmd.arg("-a");
    }
    
    if volumes {
        cmd.arg("--volumes");
    }
    
    ctx.run_command_obj(&mut cmd)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_is_installed() {
        // This test requires Docker to be installed
        let installed = is_installed();
        println!("Docker installed: {}", installed);
    }
    
    #[test]
    fn test_image_exists() {
        // Test with a non-existent image
        let exists = image_exists("this-image-does-not-exist:latest").unwrap();
        assert!(!exists);
    }
    
    #[test]
    fn test_container_exists() {
        // Test with a non-existent container
        let exists = container_exists("this-container-does-not-exist").unwrap();
        assert!(!exists);
    }
}