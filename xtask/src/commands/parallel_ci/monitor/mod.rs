//! Real-time monitoring and dashboard for parallel CI execution

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

mod dashboard;
mod metrics;

pub use dashboard::Dashboard;
pub use metrics::{PipelineMetrics, SystemMetrics};

/// Events sent from pipelines to monitor
#[derive(Debug, Clone)]
pub enum MonitorEvent {
    PipelineStarted {
        name: String,
        total_tasks: usize,
    },
    PipelineCompleted {
        name: String,
        success: bool,
        duration: Duration,
    },
    Progress {
        pipeline: String,
        current: usize,
        total: usize,
        message: String,
    },
    SystemMetrics {
        cpu_usage: f32,
        memory_usage: f32,
        disk_io: f32,
    },
    Error {
        pipeline: String,
        error: String,
    },
    Warning {
        pipeline: String,
        warning: String,
    },
}

/// Monitor that tracks CI execution progress
#[derive(Clone)]
pub struct Monitor {
    state: Arc<Mutex<MonitorState>>,
    dashboard: Option<Arc<Dashboard>>,
}

struct MonitorState {
    pipelines: HashMap<String, PipelineState>,
    start_time: Instant,
    system_metrics: SystemMetrics,
}

struct PipelineState {
    status: PipelineStatus,
    progress: (usize, usize),
    start_time: Instant,
    duration: Option<Duration>,
    last_message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PipelineStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl Monitor {
    /// Create a new monitor
    pub async fn new() -> Result<Self> {
        let state = Arc::new(Mutex::new(MonitorState {
            pipelines: HashMap::new(),
            start_time: Instant::now(),
            system_metrics: SystemMetrics::new(),
        }));

        // Dashboard will be created when TUI is implemented
        let dashboard = None;

        Ok(Self { state, dashboard })
    }

    /// Run the monitor, processing events
    pub async fn run(&self, mut event_rx: mpsc::Receiver<MonitorEvent>) {
        // Start system metrics collection
        let metrics_state = self.state.clone();
        let metrics_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;

                // Collect system metrics
                if let Ok(metrics) = SystemMetrics::collect().await {
                    let mut state = metrics_state.lock().await;
                    state.system_metrics = metrics;
                }
            }
        });

        // Process events
        while let Some(event) = event_rx.recv().await {
            if let Err(e) = self.handle_event(event).await {
                eprintln!("Monitor error: {}", e);
            }
        }

        // Stop metrics collection
        metrics_handle.abort();
    }

    /// Handle a monitor event
    async fn handle_event(&self, event: MonitorEvent) -> Result<()> {
        let mut state = self.state.lock().await;

        match event {
            MonitorEvent::PipelineStarted { name, total_tasks } => {
                state.pipelines.insert(
                    name.clone(),
                    PipelineState {
                        status: PipelineStatus::Running,
                        progress: (0, total_tasks),
                        start_time: Instant::now(),
                        duration: None,
                        last_message: "Starting...".to_string(),
                    },
                );
            },

            MonitorEvent::PipelineCompleted {
                name,
                success,
                duration,
            } => {
                if let Some(pipeline) = state.pipelines.get_mut(&name) {
                    pipeline.status = if success {
                        PipelineStatus::Completed
                    } else {
                        PipelineStatus::Failed
                    };
                    pipeline.duration = Some(duration);
                    pipeline.progress.0 = pipeline.progress.1; // Set to 100%
                }
            },

            MonitorEvent::Progress {
                pipeline,
                current,
                total,
                message,
            } => {
                if let Some(p) = state.pipelines.get_mut(&pipeline) {
                    p.progress = (current, total);
                    p.last_message = message;
                }
            },

            MonitorEvent::SystemMetrics {
                cpu_usage,
                memory_usage,
                disk_io,
            } => {
                state.system_metrics.cpu_usage = cpu_usage;
                state.system_metrics.memory_usage = memory_usage;
                state.system_metrics.disk_io = disk_io;
            },

            MonitorEvent::Error { pipeline, error } => {
                if let Some(p) = state.pipelines.get_mut(&pipeline) {
                    p.last_message = format!("ERROR: {}", error);
                    p.status = PipelineStatus::Failed;
                }
            },

            MonitorEvent::Warning { pipeline, warning } => {
                if let Some(p) = state.pipelines.get_mut(&pipeline) {
                    p.last_message = format!("WARNING: {}", warning);
                }
            },
        }

        // Update dashboard if available
        if let Some(_dashboard) = &self.dashboard {
            // TODO: Update dashboard display
        }

        Ok(())
    }

    /// Get current state snapshot
    pub async fn snapshot(&self) -> MonitorSnapshot {
        let state = self.state.lock().await;

        MonitorSnapshot {
            elapsed: state.start_time.elapsed(),
            pipelines: state
                .pipelines
                .iter()
                .map(|(name, p)| {
                    (
                        name.clone(),
                        PipelineSnapshot {
                            status: p.status.clone(),
                            progress_percent: if p.progress.1 > 0 {
                                (p.progress.0 as f32 / p.progress.1 as f32) * 100.0
                            } else {
                                0.0
                            },
                            duration: p.duration.or_else(|| Some(p.start_time.elapsed())),
                            message: p.last_message.clone(),
                        },
                    )
                })
                .collect(),
            system_metrics: state.system_metrics.clone(),
        }
    }
}

/// Snapshot of monitor state
pub struct MonitorSnapshot {
    pub elapsed: Duration,
    pub pipelines: HashMap<String, PipelineSnapshot>,
    pub system_metrics: SystemMetrics,
}

pub struct PipelineSnapshot {
    pub status: PipelineStatus,
    pub progress_percent: f32,
    pub duration: Option<Duration>,
    pub message: String,
}
