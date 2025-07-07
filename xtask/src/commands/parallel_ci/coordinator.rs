//! Tokio-based coordinator for orchestrating parallel CI/CD pipelines

use anyhow::Result;
use dashmap::DashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

use super::monitor::{Monitor, MonitorEvent};
use super::pipelines::{Pipeline, PipelineResult, PipelineStatus};
use super::targets::TargetMatrix;
use crate::utils::{cargo::workspace_root, Context};

/// Coordinates parallel execution of all CI pipelines
pub struct Coordinator {
    ctx: Arc<Context>,
    max_parallel: usize,
    fail_fast: bool,
    _enable_dashboard: bool,
    pipelines: Vec<Box<dyn Pipeline>>,
    targets: TargetMatrix,
    results: Arc<DashMap<String, PipelineResult>>,
    semaphore: Arc<Semaphore>,
    monitor: Option<Monitor>,
    _start_time: Instant,
}

impl Coordinator {
    /// Create a new coordinator with specified settings
    pub async fn new(
        ctx: Arc<Context>,
        max_parallel: Option<usize>,
        fail_fast: bool,
        _enable_dashboard: bool,
    ) -> Result<Self> {
        let max_parallel = max_parallel.unwrap_or_else(num_cpus::get);
        let semaphore = Arc::new(Semaphore::new(max_parallel));

        let monitor = if _enable_dashboard {
            Some(Monitor::new().await?)
        } else {
            None
        };

        Ok(Self {
            ctx,
            max_parallel,
            fail_fast,
            _enable_dashboard,
            pipelines: Vec::new(),
            targets: TargetMatrix::default(),
            results: Arc::new(DashMap::new()),
            semaphore,
            monitor,
            _start_time: Instant::now(),
        })
    }

    /// Enable all available pipelines
    pub fn enable_all_pipelines(&mut self) {
        use super::pipelines::*;

        self.pipelines.push(Box::new(FormatPipeline::new()));
        self.pipelines.push(Box::new(BuildPipeline::new()));
        self.pipelines.push(Box::new(TestPipeline::new()));
        self.pipelines.push(Box::new(SecurityPipeline::new()));
        self.pipelines.push(Box::new(BenchmarkPipeline::new()));
        self.pipelines.push(Box::new(PackagePipeline::new()));
    }

    /// Enable smoke tests only
    pub fn enable_smoke_tests(&mut self) {
        use super::pipelines::*;

        self.pipelines.push(Box::new(FormatPipeline::new()));
        self.pipelines.push(Box::new(BuildPipeline::new()));
        self.pipelines.push(Box::new(TestPipeline::smoke_only()));
    }

    /// Enable full test suite
    pub fn enable_full_tests(&mut self) {
        use super::pipelines::*;

        self.pipelines.push(Box::new(FormatPipeline::new()));
        self.pipelines.push(Box::new(BuildPipeline::new()));
        self.pipelines.push(Box::new(TestPipeline::full_suite()));
    }

    /// Enable security scanning
    pub fn enable_security_scan(&mut self) {
        use super::pipelines::*;

        self.pipelines.push(Box::new(SecurityPipeline::new()));
    }

    /// Enable benchmarks
    pub fn enable_benchmarks(&mut self) {
        use super::pipelines::*;

        self.pipelines.push(Box::new(BenchmarkPipeline::new()));
    }

    /// Set target platforms
    pub fn set_targets(&mut self, targets: Vec<String>) {
        self.targets = TargetMatrix::from_strings(targets);
    }

    /// Use default target platforms
    pub fn use_default_targets(&mut self) {
        self.targets = TargetMatrix::default_platforms();
    }

    /// Load configuration from file
    pub async fn load_config(&mut self, path: &Path) -> Result<()> {
        // TODO: Implement config loading
        self.ctx
            .info(&format!("Loading config from: {}", path.display()));
        Ok(())
    }

    /// Clean CI artifacts
    pub async fn clean_artifacts(&self) -> Result<()> {
        let workspace_root = workspace_root()?;
        let ci_dir = workspace_root.join(".ci");

        if ci_dir.exists() {
            for subdir in &["reports", "logs", "artifacts", "cache"] {
                let dir = ci_dir.join(subdir);
                if dir.exists() {
                    tokio::fs::remove_dir_all(&dir).await?;
                    tokio::fs::create_dir_all(&dir).await?;
                }
            }
        }

        Ok(())
    }

    /// Get maximum parallelism
    pub fn max_parallel(&self) -> usize {
        self.max_parallel
    }

    /// Get configured targets
    pub fn targets(&self) -> Vec<String> {
        self.targets.all_targets()
    }

    /// Execute all pipelines in parallel
    pub async fn execute(&mut self) -> Result<ExecutionResults> {
        let start_time = Instant::now();

        // Create channels for communication
        let (event_tx, mut event_rx) = mpsc::channel::<MonitorEvent>(1000);

        // Start monitor if enabled
        let monitor_handle = if let Some(monitor) = &mut self.monitor {
            let mon = monitor.clone();
            Some(tokio::spawn(async move { mon.run(event_rx).await }))
        } else {
            // Drain events if no monitor
            Some(tokio::spawn(async move {
                while event_rx.recv().await.is_some() {}
            }))
        };

        // Create a JoinSet for all pipeline tasks
        let mut tasks = JoinSet::new();

        // Launch all pipelines
        for pipeline in self.pipelines.drain(..) {
            let pipeline_name = pipeline.name().to_string();
            let ctx = self.ctx.clone();
            let semaphore = self.semaphore.clone();
            let results = self.results.clone();
            let event_tx = event_tx.clone();
            let targets = self.targets.clone();
            let fail_fast = self.fail_fast;

            tasks.spawn(async move {
                // Send start event
                let _ = event_tx
                    .send(MonitorEvent::PipelineStarted {
                        name: pipeline_name.clone(),
                        total_tasks: pipeline.task_count(&targets),
                    })
                    .await;

                // Acquire semaphore permit
                let _permit = semaphore.acquire().await.unwrap();

                // Execute pipeline
                let start = Instant::now();
                let result = pipeline
                    .execute(ctx.clone(), targets, event_tx.clone())
                    .await;

                let duration = start.elapsed();

                // Check success before storing result
                let success = result.is_ok();

                // Store result
                let pipeline_result = match result {
                    Ok(output) => PipelineResult {
                        name: pipeline_name.clone(),
                        status: PipelineStatus::Success,
                        duration,
                        output: Some(output),
                        error: None,
                    },
                    Err(e) => PipelineResult {
                        name: pipeline_name.clone(),
                        status: PipelineStatus::Failed,
                        duration,
                        output: None,
                        error: Some(e.to_string()),
                    },
                };

                results.insert(pipeline_name.clone(), pipeline_result.clone());

                // Send completion event
                let _ = event_tx
                    .send(MonitorEvent::PipelineCompleted {
                        name: pipeline_name.clone(),
                        success,
                        duration,
                    })
                    .await;

                // Check fail-fast
                if fail_fast && !success {
                    return Err(anyhow::anyhow!("Pipeline {} failed", pipeline_name));
                }

                Ok(pipeline_result)
            });
        }

        // Wait for all pipelines to complete
        let mut all_results = Vec::new();
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(pipeline_result)) => all_results.push(pipeline_result),
                Ok(Err(e)) => {
                    if self.fail_fast {
                        // Cancel remaining tasks
                        tasks.abort_all();
                        return Err(e);
                    }
                    self.ctx.error(&format!("Pipeline error: {}", e));
                },
                Err(e) => {
                    self.ctx.error(&format!("Task join error: {}", e));
                },
            }
        }

        // Stop monitor
        drop(event_tx);
        if let Some(handle) = monitor_handle {
            let _ = handle.await;
        }

        // Create execution results
        Ok(ExecutionResults {
            pipelines: all_results,
            total_duration: start_time.elapsed(),
            targets_tested: self.targets.all_targets(),
        })
    }
}

/// Results from parallel CI execution
pub struct ExecutionResults {
    pub pipelines: Vec<PipelineResult>,
    pub total_duration: Duration,
    pub targets_tested: Vec<String>,
}

impl ExecutionResults {
    /// Check if any pipeline failed
    pub fn has_failures(&self) -> bool {
        self.pipelines
            .iter()
            .any(|p| p.status == PipelineStatus::Failed)
    }

    /// Count number of failures
    pub fn failure_count(&self) -> usize {
        self.pipelines
            .iter()
            .filter(|p| p.status == PipelineStatus::Failed)
            .count()
    }

    /// Print summary of results
    pub fn print_summary(&self, ctx: &Context) {
        ctx.info("");
        ctx.info("╔══════════════════ CI Results ══════════════════╗");

        for pipeline in &self.pipelines {
            let status_icon = match pipeline.status {
                PipelineStatus::Success => "✓".green(),
                PipelineStatus::Failed => "✗".red(),
                PipelineStatus::Skipped => "⊘".yellow(),
            };

            let duration = format!("{:.2}s", pipeline.duration.as_secs_f64());
            ctx.info(&format!(
                "║ {} {:<20} {:>10} ║",
                status_icon, pipeline.name, duration
            ));

            if let Some(error) = &pipeline.error {
                ctx.info(&format!("║   Error: {} ║", error));
            }
        }

        ctx.info("╚═══════════════════════════════════════════════╝");
        ctx.info("");
        ctx.info(&format!(
            "Total duration: {:.2}s",
            self.total_duration.as_secs_f64()
        ));
        ctx.info(&format!(
            "Targets tested: {}",
            self.targets_tested.join(", ")
        ));
    }
}

use colored::Colorize;
