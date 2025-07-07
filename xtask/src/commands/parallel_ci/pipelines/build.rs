//! Multi-target build pipeline with cross-compilation support

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::{mpsc, Mutex};

use super::{send_progress, MonitorEvent, Pipeline, TargetMatrix};
use crate::utils::Context;

/// Pipeline for building across multiple targets
pub struct BuildPipeline {
    release_mode: bool,
    features: Option<String>,
}

impl Default for BuildPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl BuildPipeline {
    pub fn new() -> Self {
        Self {
            release_mode: true,
            features: Some("all".to_string()),
        }
    }
}

#[async_trait]
impl Pipeline for BuildPipeline {
    fn name(&self) -> &str {
        "Build"
    }

    fn task_count(&self, targets: &TargetMatrix) -> usize {
        targets.all_targets().len()
    }

    fn priority(&self) -> u32 {
        90 // Run after format but before tests
    }

    async fn execute(
        &self,
        ctx: Arc<Context>,
        targets: TargetMatrix,
        event_tx: mpsc::Sender<MonitorEvent>,
    ) -> Result<String> {
        let pipeline_name = self.name();
        let all_targets = targets.all_targets();
        let total_targets = all_targets.len();
        let results = Arc::new(Mutex::new(Vec::new()));

        // Check if cross is installed for cross-compilation
        let cross_available = Command::new("cross")
            .arg("--version")
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !cross_available
            && all_targets
                .iter()
                .any(|t| t.contains("linux") || t.contains("windows"))
        {
            ctx.warn("'cross' not installed - using cargo for native builds only");
        }

        // Build all targets in parallel using Rayon
        let build_tasks: Vec<_> = all_targets
            .iter()
            .enumerate()
            .map(|(idx, target)| {
                let _ctx = ctx.clone();
                let event_tx = event_tx.clone();
                let results = results.clone();
                let target = target.clone();
                let release_mode = self.release_mode;
                let features = self.features.clone();
                let pipeline_name = pipeline_name.to_string();

                tokio::spawn(async move {
                    send_progress(
                        &event_tx,
                        &pipeline_name,
                        idx + 1,
                        total_targets,
                        format!("Building for {}...", target),
                    )
                    .await;

                    // Determine build command
                    let (cmd, _use_cross) = if target.contains("wasm") {
                        ("cargo", false)
                    } else if cross_available && !cfg!(target_os = "macos") {
                        ("cross", true)
                    } else {
                        ("cargo", false)
                    };

                    let mut command = Command::new(cmd);
                    command.arg("build");

                    // Add target if cross-compiling
                    if target != current_platform::CURRENT_PLATFORM {
                        command.arg("--target").arg(&target);
                    }

                    if release_mode {
                        command.arg("--release");
                    }

                    if let Some(features) = &features {
                        if features == "all" {
                            command.arg("--all-features");
                        } else {
                            command.arg("--features").arg(features);
                        }
                    }

                    let output = command.output().await?;

                    if output.status.success() {
                        let mut res = results.lock().await;
                        res.push(format!("✓ {} built successfully", target));
                        Ok(())
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        Err(anyhow::anyhow!("Build failed for {}:\n{}", target, stderr))
                    }
                })
            })
            .collect();

        // Wait for all builds to complete
        for task in build_tasks {
            task.await??;
        }

        let results = results.lock().await;
        Ok(results.join("\n"))
    }
}

mod current_platform {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub const CURRENT_PLATFORM: &str = "x86_64-unknown-linux-gnu";

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    pub const CURRENT_PLATFORM: &str = "aarch64-unknown-linux-gnu";

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    pub const CURRENT_PLATFORM: &str = "x86_64-apple-darwin";

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub const CURRENT_PLATFORM: &str = "aarch64-apple-darwin";

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    pub const CURRENT_PLATFORM: &str = "x86_64-pc-windows-msvc";

    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "windows", target_arch = "x86_64"),
    )))]
    pub const CURRENT_PLATFORM: &str = "unknown";
}
