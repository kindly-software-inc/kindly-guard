//! Package pipeline for creating distribution artifacts

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::process::Command;

use crate::utils::{Context, cargo::workspace_root};
use super::{Pipeline, MonitorEvent, TargetMatrix, send_progress};

/// Package creation pipeline
pub struct PackagePipeline {
    create_npm: bool,
    create_checksums: bool,
}

impl PackagePipeline {
    pub fn new() -> Self {
        Self {
            create_npm: true,
            create_checksums: true,
        }
    }
}

#[async_trait]
impl Pipeline for PackagePipeline {
    fn name(&self) -> &str {
        "Package"
    }
    
    fn task_count(&self, targets: &TargetMatrix) -> usize {
        targets.all_targets().len() + if self.create_npm { 1 } else { 0 }
    }
    
    fn priority(&self) -> u32 {
        40 // Run after everything else
    }
    
    async fn execute(
        &self,
        ctx: Arc<Context>,
        targets: TargetMatrix,
        event_tx: mpsc::Sender<MonitorEvent>,
    ) -> Result<String> {
        let pipeline_name = self.name();
        let mut results = Vec::new();
        let workspace_root = workspace_root()?;
        let artifacts_dir = workspace_root.join(".ci/artifacts");
        tokio::fs::create_dir_all(&artifacts_dir).await?;
        
        let all_targets = targets.all_targets();
        let total_tasks = self.task_count(&targets);
        let mut current_task = 0;
        
        // Package binaries for each target
        for target in &all_targets {
            current_task += 1;
            send_progress(
                &event_tx,
                pipeline_name,
                current_task,
                total_tasks,
                format!("Packaging binaries for {}...", target),
            ).await;
            
            // Use cargo-dist if available
            let dist_available = Command::new("cargo")
                .args(&["dist", "--version"])
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);
            
            if dist_available {
                let dist_result = Command::new("cargo")
                    .args(&["dist", "build", "--target", target])
                    .output()
                    .await?;
                
                if dist_result.status.success() {
                    results.push(format!("✓ {} packaged with cargo-dist", target));
                } else {
                    ctx.warn(&format!("cargo-dist failed for {}, using fallback", target));
                }
            } else {
                // Fallback: manually copy binaries
                ctx.debug("cargo-dist not available, using manual packaging");
                
                // Build release binary if not already built
                let mut build_cmd = Command::new("cargo");
                build_cmd.arg("build").arg("--release");
                
                if target != current_platform() {
                    build_cmd.arg("--target").arg(target);
                }
                
                let build_result = build_cmd.output().await?;
                if !build_result.status.success() {
                    ctx.warn(&format!("Failed to build for {}", target));
                    continue;
                }
                
                // Copy binary to artifacts
                let binary_name = if target.contains("windows") {
                    "kindly-guard.exe"
                } else {
                    "kindly-guard"
                };
                
                let target_dir = if target == current_platform() {
                    workspace_root.join("target/release")
                } else {
                    workspace_root.join(format!("target/{}/release", target))
                };
                
                let source = target_dir.join(binary_name);
                let dest = artifacts_dir.join(format!("kindly-guard-{}", target));
                
                if source.exists() {
                    tokio::fs::copy(&source, &dest).await?;
                    results.push(format!("✓ {} binary packaged", target));
                    
                    // Create checksum if requested
                    if self.create_checksums {
                        let checksum = calculate_sha256(&dest).await?;
                        let checksum_file = artifacts_dir.join(format!("kindly-guard-{}.sha256", target));
                        tokio::fs::write(&checksum_file, format!("{} *{}\n", checksum, dest.file_name().unwrap().to_string_lossy())).await?;
                    }
                }
            }
        }
        
        // Create NPM package if requested
        if self.create_npm {
            current_task += 1;
            send_progress(
                &event_tx,
                pipeline_name,
                current_task,
                total_tasks,
                "Creating NPM package...".to_string(),
            ).await;
            
            // Check if xtask package command exists
            let npm_result = Command::new("cargo")
                .args(&["xtask", "package", "--npm", "--targets", &all_targets.join(",")])
                .output()
                .await?;
            
            if npm_result.status.success() {
                results.push("✓ NPM package created".to_string());
            } else {
                ctx.warn("NPM package creation failed");
                results.push("⚠ NPM package creation failed".to_string());
            }
        }
        
        Ok(results.join("\n"))
    }
}

/// Get current platform string
fn current_platform() -> &'static str {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return "x86_64-unknown-linux-gnu";
    
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    return "aarch64-unknown-linux-gnu";
    
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    return "x86_64-apple-darwin";
    
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return "aarch64-apple-darwin";
    
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    return "x86_64-pc-windows-msvc";
    
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "windows", target_arch = "x86_64"),
    )))]
    return "unknown";
}

/// Calculate SHA256 checksum of a file
async fn calculate_sha256(path: &std::path::Path) -> Result<String> {
    use sha2::{Sha256, Digest};
    use tokio::io::AsyncReadExt;
    
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 8192];
    
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    
    Ok(format!("{:x}", hasher.finalize()))
}