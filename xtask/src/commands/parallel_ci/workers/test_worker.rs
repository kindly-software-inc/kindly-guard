//! Test worker for parallel test execution

use anyhow::Result;
use std::process::Command;
use std::time::Instant;

use super::{Worker, WorkerResult, WorkerTask};

/// Worker for test execution
pub struct TestWorker {
    use_nextest: bool,
}

impl TestWorker {
    /// Create a new test worker
    #[allow(dead_code)]
    pub fn new() -> Self {
        // Check if nextest is available
        let use_nextest = Command::new("cargo")
            .args(["nextest", "--version"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        Self { use_nextest }
    }
}

impl Worker for TestWorker {
    fn execute(&self, task: WorkerTask) -> Result<WorkerResult> {
        match task {
            WorkerTask::Test {
                package,
                test_name,
                parallel,
            } => {
                let start = Instant::now();

                let mut command = Command::new("cargo");

                // Use nextest if available
                if self.use_nextest {
                    command.arg("nextest").arg("run");

                    if !parallel {
                        command.arg("--test-threads=1");
                    }
                } else {
                    command.arg("test");

                    if !parallel {
                        command.arg("--").arg("--test-threads=1");
                    }
                }

                // Add package filter
                command.arg("--package").arg(&package);

                // Add specific test if provided
                if let Some(test) = test_name {
                    command.arg(&test);
                }

                // Execute tests
                let output = command.output()?;
                let duration = start.elapsed();

                let success = output.status.success();
                let output_str = if success {
                    format!("Tests passed for package: {}", package)
                } else {
                    format!(
                        "Tests failed for package {}:\n{}",
                        package,
                        String::from_utf8_lossy(&output.stderr)
                    )
                };

                Ok(WorkerResult {
                    success,
                    output: output_str,
                    duration,
                })
            },
            WorkerTask::Benchmark { name, baseline } => {
                let start = Instant::now();

                let mut command = Command::new("cargo");
                command.arg("bench").arg(&name);

                if let Some(baseline) = baseline {
                    command.arg("--").arg("--baseline").arg(&baseline);
                }

                let output = command.output()?;
                let duration = start.elapsed();

                let success = output.status.success();
                let output_str = String::from_utf8_lossy(&output.stdout).to_string();

                Ok(WorkerResult {
                    success,
                    output: output_str,
                    duration,
                })
            },
            _ => Err(anyhow::anyhow!(
                "TestWorker can only handle Test and Benchmark tasks"
            )),
        }
    }
}
