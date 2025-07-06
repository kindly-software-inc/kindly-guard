//! System metrics collection for monitoring

use anyhow::Result;
use sysinfo::System;

/// System resource metrics
#[derive(Debug, Clone, Default)]
pub struct SystemMetrics {
    pub cpu_usage: f32,
    pub memory_usage: f32,
    pub disk_io: f32,
}

/// Pipeline execution metrics
#[derive(Debug, Clone)]
pub struct PipelineMetrics {
    pub total_tasks: usize,
    pub completed_tasks: usize,
    pub failed_tasks: usize,
    pub average_task_time: std::time::Duration,
}

impl SystemMetrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Collect current system metrics
    pub async fn collect() -> Result<Self> {
        let mut sys = System::new_all();
        
        // Refresh system information
        sys.refresh_all();
        
        // Calculate CPU usage
        let cpu_usage = sys.global_cpu_usage();
        
        // Calculate memory usage
        let total_memory = sys.total_memory();
        let used_memory = sys.used_memory();
        let memory_usage = if total_memory > 0 {
            (used_memory as f32 / total_memory as f32) * 100.0
        } else {
            0.0
        };
        
        // Disk I/O is harder to measure accurately
        // For now, use a placeholder
        let disk_io = 0.0;
        
        Ok(Self {
            cpu_usage,
            memory_usage,
            disk_io,
        })
    }
}

impl PipelineMetrics {
    /// Create new pipeline metrics
    pub fn new(total_tasks: usize) -> Self {
        Self {
            total_tasks,
            completed_tasks: 0,
            failed_tasks: 0,
            average_task_time: std::time::Duration::ZERO,
        }
    }
    
    /// Update metrics with task completion
    pub fn task_completed(&mut self, duration: std::time::Duration, success: bool) {
        if success {
            self.completed_tasks += 1;
        } else {
            self.failed_tasks += 1;
        }
        
        // Update average time
        let total_finished = self.completed_tasks + self.failed_tasks;
        if total_finished > 0 {
            let current_total = self.average_task_time.as_secs_f64() * (total_finished - 1) as f64;
            let new_total = current_total + duration.as_secs_f64();
            self.average_task_time = std::time::Duration::from_secs_f64(new_total / total_finished as f64);
        }
    }
    
    /// Get completion percentage
    pub fn completion_percent(&self) -> f32 {
        if self.total_tasks > 0 {
            let finished = self.completed_tasks + self.failed_tasks;
            (finished as f32 / self.total_tasks as f32) * 100.0
        } else {
            0.0
        }
    }
}