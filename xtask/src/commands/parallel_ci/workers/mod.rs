//! Worker pool implementations for CPU-bound parallel tasks

use anyhow::Result;
use rayon::prelude::*;
use std::sync::Arc;
use tokio::sync::Semaphore;

mod build_worker;
mod test_worker;

// pub use build_worker::BuildWorker;
// pub use test_worker::TestWorker;

/// Trait for worker implementations
pub trait Worker: Send + Sync {
    /// Execute a task
    fn execute(&self, task: WorkerTask) -> Result<WorkerResult>;
}

/// Task to be executed by a worker
#[derive(Debug, Clone)]
pub enum WorkerTask {
    Build {
        target: String,
        release: bool,
        features: Option<String>,
    },
    Test {
        package: String,
        test_name: Option<String>,
        parallel: bool,
    },
    Benchmark {
        name: String,
        baseline: Option<String>,
    },
}

/// Result from worker execution
#[derive(Debug)]
pub struct WorkerResult {
    pub success: bool,
    pub output: String,
    pub duration: std::time::Duration,
}

/// Worker pool for parallel task execution
pub struct WorkerPool {
    workers: Vec<Arc<dyn Worker>>,
    semaphore: Arc<Semaphore>,
}

impl WorkerPool {
    /// Create a new worker pool
    pub fn new(max_workers: usize) -> Self {
        let semaphore = Arc::new(Semaphore::new(max_workers));

        Self {
            workers: Vec::new(),
            semaphore,
        }
    }

    /// Add a worker to the pool
    pub fn add_worker(&mut self, worker: Arc<dyn Worker>) {
        self.workers.push(worker);
    }

    /// Execute tasks in parallel using Rayon
    pub async fn execute_parallel(&self, tasks: Vec<WorkerTask>) -> Vec<Result<WorkerResult>> {
        let workers = self.workers.clone();
        let semaphore = self.semaphore.clone();

        // Use Rayon for CPU-bound parallel execution
        tokio::task::spawn_blocking(move || {
            tasks
                .par_iter()
                .map(|task| {
                    // Acquire semaphore permit (blocking)
                    let _permit = futures::executor::block_on(semaphore.clone().acquire_owned());

                    // Round-robin worker selection
                    let worker_idx = rayon::current_thread_index().unwrap_or(0) % workers.len();
                    let worker = &workers[worker_idx];

                    // Execute task
                    worker.execute(task.clone())
                })
                .collect()
        })
        .await
        .unwrap_or_else(|_| vec![Err(anyhow::anyhow!("Worker pool panic"))])
    }

    /// Execute tasks with a custom thread pool
    pub async fn execute_with_pool_size(
        &self,
        tasks: Vec<WorkerTask>,
        pool_size: usize,
    ) -> Vec<Result<WorkerResult>> {
        let workers = self.workers.clone();

        tokio::task::spawn_blocking(move || {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(pool_size)
                .build()
                .unwrap();

            pool.install(|| {
                tasks
                    .par_iter()
                    .map(|task| {
                        let worker_idx = rayon::current_thread_index().unwrap_or(0) % workers.len();
                        let worker = &workers[worker_idx];
                        worker.execute(task.clone())
                    })
                    .collect()
            })
        })
        .await
        .unwrap_or_else(|_| vec![Err(anyhow::anyhow!("Worker pool panic"))])
    }
}
