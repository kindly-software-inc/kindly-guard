//! Format and lint pipeline implementation

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::mpsc;

use super::{send_progress, MonitorEvent, Pipeline, TargetMatrix};
use crate::utils::Context;

/// Pipeline for code formatting and linting
pub struct FormatPipeline {
    _check_only: bool,
}

impl FormatPipeline {
    pub fn new() -> Self {
        Self { _check_only: true }
    }
}

#[async_trait]
impl Pipeline for FormatPipeline {
    fn name(&self) -> &str {
        "Format/Lint"
    }

    fn task_count(&self, _targets: &TargetMatrix) -> usize {
        3 // rustfmt, clippy, cargo-deny
    }

    fn priority(&self) -> u32 {
        100 // Run first to fail fast on formatting issues
    }

    async fn execute(
        &self,
        ctx: Arc<Context>,
        _targets: TargetMatrix,
        event_tx: mpsc::Sender<MonitorEvent>,
    ) -> Result<String> {
        let mut results = Vec::new();
        let pipeline_name = self.name();

        // Step 1: rustfmt check
        send_progress(
            &event_tx,
            pipeline_name,
            1,
            3,
            "Checking code formatting...".to_string(),
        )
        .await;

        let rustfmt_result = Command::new("cargo")
            .args(&["fmt", "--", "--check"])
            .output()
            .await?;

        if !rustfmt_result.status.success() {
            let stderr = String::from_utf8_lossy(&rustfmt_result.stderr);
            return Err(anyhow::anyhow!("rustfmt check failed:\n{}", stderr));
        }
        results.push("✓ Code formatting check passed");

        // Step 2: clippy
        send_progress(
            &event_tx,
            pipeline_name,
            2,
            3,
            "Running clippy lints...".to_string(),
        )
        .await;

        let clippy_result = Command::new("cargo")
            .args(&[
                "clippy",
                "--all-features",
                "--all-targets",
                "--",
                "-D",
                "warnings",
                "-W",
                "clippy::all",
                "-W",
                "clippy::pedantic",
                "-A",
                "clippy::missing_errors_doc", // Allow for now
                "-A",
                "clippy::module_name_repetitions", // Allow for now
            ])
            .output()
            .await?;

        if !clippy_result.status.success() {
            let stderr = String::from_utf8_lossy(&clippy_result.stderr);
            let stdout = String::from_utf8_lossy(&clippy_result.stdout);
            return Err(anyhow::anyhow!(
                "clippy check failed:\n{}\n{}",
                stdout,
                stderr
            ));
        }
        results.push("✓ Clippy analysis passed");

        // Step 3: cargo-deny (if available)
        send_progress(
            &event_tx,
            pipeline_name,
            3,
            3,
            "Checking dependencies...".to_string(),
        )
        .await;

        let deny_check = Command::new("cargo")
            .args(&["deny", "--version"])
            .output()
            .await;

        if deny_check.is_ok() && deny_check.unwrap().status.success() {
            let deny_result = Command::new("cargo")
                .args(&["deny", "check"])
                .output()
                .await?;

            if !deny_result.status.success() {
                ctx.warn("cargo-deny found issues (non-blocking)");
                let stderr = String::from_utf8_lossy(&deny_result.stderr);
                ctx.debug(&format!("cargo-deny output:\n{}", stderr));
            }
            results.push("✓ Dependency check completed");
        } else {
            ctx.debug("cargo-deny not installed, skipping dependency checks");
            results.push("⊘ Dependency check skipped (cargo-deny not installed)");
        }

        Ok(results.join("\n"))
    }
}
