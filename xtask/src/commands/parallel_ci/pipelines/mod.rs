//! Pipeline trait and implementations for parallel CI/CD

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use super::monitor::MonitorEvent;
use super::targets::TargetMatrix;
use crate::utils::Context;

mod benchmark;
mod build;
mod format;
mod package;
mod security;
mod test;

pub use benchmark::BenchmarkPipeline;
pub use build::BuildPipeline;
pub use format::FormatPipeline;
pub use package::PackagePipeline;
pub use security::SecurityPipeline;
pub use test::TestPipeline;

/// Status of a pipeline execution
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineStatus {
    Success,
    Failed,
    Skipped,
}

/// Result from a pipeline execution
#[derive(Debug, Clone)]
pub struct PipelineResult {
    pub name: String,
    pub status: PipelineStatus,
    pub duration: Duration,
    pub output: Option<String>,
    pub error: Option<String>,
}

/// Trait for all CI/CD pipelines
#[async_trait]
pub trait Pipeline: Send + Sync {
    /// Name of the pipeline
    fn name(&self) -> &str;

    /// Number of tasks this pipeline will execute
    fn task_count(&self, targets: &TargetMatrix) -> usize;

    /// Execute the pipeline
    async fn execute(
        &self,
        ctx: Arc<Context>,
        targets: TargetMatrix,
        event_tx: mpsc::Sender<MonitorEvent>,
    ) -> Result<String>;

    /// Check if this pipeline can run in parallel with others
    fn parallel_safe(&self) -> bool {
        true
    }

    /// Priority level (higher runs first)
    fn priority(&self) -> u32 {
        50
    }
}

/// Helper for sending progress events
pub async fn send_progress(
    event_tx: &mpsc::Sender<MonitorEvent>,
    pipeline: &str,
    current: usize,
    total: usize,
    message: String,
) {
    let _ = event_tx
        .send(MonitorEvent::Progress {
            pipeline: pipeline.to_string(),
            current,
            total,
            message,
        })
        .await;
}
