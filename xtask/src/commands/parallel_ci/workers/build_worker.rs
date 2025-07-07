//! Build worker for parallel compilation tasks

use anyhow::Result;
use std::process::Command;
use std::time::Instant;

use super::{Worker, WorkerResult, WorkerTask};

/// Worker for build tasks
pub struct BuildWorker {
    use_cross: bool,
}

impl BuildWorker {
    /// Create a new build worker
    #[allow(dead_code)]
    pub fn new() -> Self {
        // Check if cross is available
        let use_cross = Command::new("cross")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        Self { use_cross }
    }
}

impl Worker for BuildWorker {
    fn execute(&self, task: WorkerTask) -> Result<WorkerResult> {
        match task {
            WorkerTask::Build {
                target,
                release,
                features,
            } => {
                let start = Instant::now();

                // Determine build command
                let cmd = if target.contains("wasm") {
                    "cargo"
                } else if self.use_cross && !cfg!(target_os = "macos") {
                    "cross"
                } else {
                    "cargo"
                };

                let mut command = Command::new(cmd);
                command.arg("build");

                // Add target
                command.arg("--target").arg(&target);

                if release {
                    command.arg("--release");
                }

                if let Some(features) = features {
                    if features == "all" {
                        command.arg("--all-features");
                    } else {
                        command.arg("--features").arg(&features);
                    }
                }

                // Execute build
                let output = command.output()?;
                let duration = start.elapsed();

                let success = output.status.success();
                let output_str = if success {
                    format!("Successfully built for {}", target)
                } else {
                    format!(
                        "Build failed for {}:\n{}",
                        target,
                        String::from_utf8_lossy(&output.stderr)
                    )
                };

                Ok(WorkerResult {
                    success,
                    output: output_str,
                    duration,
                })
            },
            _ => Err(anyhow::anyhow!("BuildWorker can only handle Build tasks")),
        }
    }
}
