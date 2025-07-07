//! Benchmark pipeline for performance regression detection

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::mpsc;

use super::{send_progress, MonitorEvent, Pipeline, TargetMatrix};
use crate::utils::Context;

/// Performance benchmark pipeline
pub struct BenchmarkPipeline {
    baseline: Option<String>,
}

impl Default for BenchmarkPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl BenchmarkPipeline {
    pub fn new() -> Self {
        Self { baseline: None }
    }

    pub fn with_baseline(baseline: String) -> Self {
        Self {
            baseline: Some(baseline),
        }
    }
}

#[async_trait]
impl Pipeline for BenchmarkPipeline {
    fn name(&self) -> &str {
        "Benchmarks"
    }

    fn task_count(&self, _targets: &TargetMatrix) -> usize {
        1 // Single benchmark run
    }

    fn priority(&self) -> u32 {
        50 // Lower priority, can run last
    }

    async fn execute(
        &self,
        ctx: Arc<Context>,
        _targets: TargetMatrix,
        event_tx: mpsc::Sender<MonitorEvent>,
    ) -> Result<String> {
        let pipeline_name = self.name();

        send_progress(
            &event_tx,
            pipeline_name,
            1,
            1,
            "Running performance benchmarks...".to_string(),
        )
        .await;

        // Check if there are any benchmarks
        let bench_check = Command::new("cargo")
            .args(["bench", "--no-run"])
            .output()
            .await?;

        if !bench_check.status.success() {
            return Ok("⊘ No benchmarks found".to_string());
        }

        // Run benchmarks
        let mut bench_args = vec!["bench"];

        if let Some(baseline) = &self.baseline {
            bench_args.push("--");
            bench_args.push("--baseline");
            bench_args.push(baseline);
        }

        let bench_result = Command::new("cargo").args(&bench_args).output().await?;

        if !bench_result.status.success() {
            let stderr = String::from_utf8_lossy(&bench_result.stderr);
            return Err(anyhow::anyhow!("Benchmarks failed:\n{}", stderr));
        }

        let output = String::from_utf8_lossy(&bench_result.stdout);

        // Check for performance regressions
        if output.contains("Performance has regressed") {
            ctx.warn("Performance regressions detected");
            return Ok("⚠ Benchmarks completed with regressions".to_string());
        }

        Ok("✓ Benchmarks completed successfully".to_string())
    }
}
