use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::thread;

use indicatif::{ProgressBar, ProgressStyle};
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

/// Enhanced process builder with additional features
pub struct ProcessBuilder {
    command: String,
    args: Vec<String>,
    env_vars: HashMap<String, String>,
    working_dir: Option<PathBuf>,
    timeout_duration: Option<Duration>,
    capture_output: bool,
    stream_output: bool,
    inherit_env: bool,
}

impl ProcessBuilder {
    /// Create a new process builder
    pub fn new<S: AsRef<str>>(command: S) -> Self {
        Self {
            command: command.as_ref().to_string(),
            args: Vec::new(),
            env_vars: HashMap::new(),
            working_dir: None,
            timeout_duration: None,
            capture_output: true,
            stream_output: false,
            inherit_env: true,
        }
    }

    /// Add an argument
    pub fn arg<S: AsRef<str>>(mut self, arg: S) -> Self {
        self.args.push(arg.as_ref().to_string());
        self
    }

    /// Add multiple arguments
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.args.extend(args.into_iter().map(|s| s.as_ref().to_string()));
        self
    }

    /// Set an environment variable
    pub fn env<K, V>(mut self, key: K, value: V) -> Self
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        self.env_vars.insert(
            key.as_ref().to_string(),
            value.as_ref().to_string(),
        );
        self
    }

    /// Set working directory
    pub fn current_dir<P: AsRef<Path>>(mut self, dir: P) -> Self {
        self.working_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Set timeout
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout_duration = Some(duration);
        self
    }

    /// Stream output to stdout/stderr
    pub fn stream_output(mut self, stream: bool) -> Self {
        self.stream_output = stream;
        self
    }

    /// Whether to capture output
    pub fn capture_output(mut self, capture: bool) -> Self {
        self.capture_output = capture;
        self
    }

    /// Clear environment variables
    pub fn env_clear(mut self) -> Self {
        self.inherit_env = false;
        self
    }

    /// Run the command synchronously
    pub fn run(self) -> Result<ProcessOutput> {
        let start = std::time::Instant::now();
        
        let mut cmd = Command::new(&self.command);
        cmd.args(&self.args);

        if !self.inherit_env {
            cmd.env_clear();
        }

        for (k, v) in &self.env_vars {
            cmd.env(k, v);
        }

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        if self.stream_output {
            return self.run_streaming();
        }

        if self.capture_output {
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn command: {}", self.command))?;

        let output = if let Some(timeout_duration) = self.timeout_duration {
            wait_with_timeout(child, timeout_duration)?
        } else {
            child.wait_with_output()?
        };

        Ok(ProcessOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            status: output.status,
            elapsed: start.elapsed(),
        })
    }

    /// Run with streaming output
    fn run_streaming(self) -> Result<ProcessOutput> {
        let start = std::time::Instant::now();
        
        let mut cmd = Command::new(&self.command);
        cmd.args(&self.args);

        if !self.inherit_env {
            cmd.env_clear();
        }

        for (k, v) in &self.env_vars {
            cmd.env(k, v);
        }

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn command: {}", self.command))?;

        // Stream stdout
        let stdout_handle = if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            Some(thread::spawn(move || {
                let mut output = String::new();
                for line in reader.lines() {
                    if let Ok(line) = line {
                        println!("{}", line);
                        output.push_str(&line);
                        output.push('\n');
                    }
                }
                output
            }))
        } else {
            None
        };

        // Stream stderr
        let stderr_handle = if let Some(stderr) = child.stderr.take() {
            let reader = BufReader::new(stderr);
            Some(thread::spawn(move || {
                let mut output = String::new();
                for line in reader.lines() {
                    if let Ok(line) = line {
                        eprintln!("{}", line);
                        output.push_str(&line);
                        output.push('\n');
                    }
                }
                output
            }))
        } else {
            None
        };

        let status = child.wait()?;
        
        let stdout = stdout_handle
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default();
        
        let stderr = stderr_handle
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default();

        Ok(ProcessOutput {
            stdout,
            stderr,
            status,
            elapsed: start.elapsed(),
        })
    }

    /// Run the command asynchronously
    pub async fn run_async(self) -> Result<ProcessOutput> {
        let start = tokio::time::Instant::now();
        
        let mut cmd = TokioCommand::new(&self.command);
        cmd.args(&self.args);

        if !self.inherit_env {
            cmd.env_clear();
        }

        for (k, v) in &self.env_vars {
            cmd.env(k, v);
        }

        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        if self.capture_output {
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
        }

        let output = if let Some(timeout_duration) = self.timeout_duration {
            timeout(timeout_duration, cmd.output())
                .await
                .with_context(|| format!("Command '{}' timed out", self.command))??
        } else {
            cmd.output().await?
        };

        Ok(ProcessOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            status: output.status,
            elapsed: start.elapsed().into(),
        })
    }
}

/// Process output
#[derive(Debug)]
pub struct ProcessOutput {
    pub stdout: String,
    pub stderr: String,
    pub status: std::process::ExitStatus,
    pub elapsed: Duration,
}

impl ProcessOutput {
    /// Check if the process was successful
    pub fn success(&self) -> bool {
        self.status.success()
    }

    /// Get the exit code
    pub fn code(&self) -> Option<i32> {
        self.status.code()
    }
}

/// Wait for a process with timeout
fn wait_with_timeout(
    mut child: std::process::Child,
    duration: Duration,
) -> Result<std::process::Output> {
    let start = std::time::Instant::now();
    let timeout = Arc::new(AtomicBool::new(false));
    let timeout_clone = timeout.clone();

    thread::spawn(move || {
        thread::sleep(duration);
        timeout_clone.store(true, Ordering::SeqCst);
    });

    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(child.wait_with_output()?),
            Ok(None) => {
                if timeout.load(Ordering::SeqCst) {
                    // Try to kill the process
                    #[cfg(unix)]
                    {
                        use nix::sys::signal::{self, Signal};
                        use nix::unistd::Pid;
                        let pid = Pid::from_raw(child.id() as i32);
                        let _ = signal::kill(pid, Signal::SIGTERM);
                        thread::sleep(Duration::from_millis(100));
                        let _ = signal::kill(pid, Signal::SIGKILL);
                    }
                    #[cfg(not(unix))]
                    {
                        let _ = child.kill();
                    }
                    anyhow::bail!("Process timed out after {:?}", duration);
                }
            }
            Err(e) => return Err(e.into()),
        }

        if start.elapsed() > duration {
            #[cfg(unix)]
            {
                use nix::sys::signal::{self, Signal};
                use nix::unistd::Pid;
                let pid = Pid::from_raw(child.id() as i32);
                let _ = signal::kill(pid, Signal::SIGTERM);
                thread::sleep(Duration::from_millis(100));
                let _ = signal::kill(pid, Signal::SIGKILL);
            }
            #[cfg(not(unix))]
            {
                let _ = child.kill();
            }
            anyhow::bail!("Process timed out after {:?}", duration);
        }

        thread::sleep(Duration::from_millis(100));
    }
}

/// Run multiple commands in parallel
pub async fn run_parallel<F>(futures: Vec<F>) -> Result<Vec<ProcessOutput>>
where
    F: std::future::Future<Output = Result<ProcessOutput>> + Send,
{
    use futures::future::join_all;
    
    let results = join_all(futures).await;
    
    let mut outputs = Vec::new();
    for result in results {
        outputs.push(result?);
    }
    
    Ok(outputs)
}

/// Pipeline commands (pipe output from one to another)
pub struct Pipeline {
    commands: Vec<ProcessBuilder>,
}

impl Pipeline {
    /// Create a new pipeline
    pub fn new() -> Self {
        Self {
            commands: Vec::new(),
        }
    }

    /// Add a command to the pipeline
    pub fn pipe(mut self, command: ProcessBuilder) -> Self {
        self.commands.push(command);
        self
    }

    /// Run the pipeline
    pub fn run(self) -> Result<ProcessOutput> {
        if self.commands.is_empty() {
            anyhow::bail!("Pipeline has no commands");
        }

        if self.commands.len() == 1 {
            return self.commands.into_iter().next().unwrap().run();
        }

        let start = std::time::Instant::now();
        let mut children = Vec::new();
        let mut prev_stdout = None;
        let num_commands = self.commands.len();

        for (i, builder) in self.commands.into_iter().enumerate() {
            let mut cmd = Command::new(&builder.command);
            cmd.args(&builder.args);

            if !builder.inherit_env {
                cmd.env_clear();
            }

            for (k, v) in builder.env_vars {
                cmd.env(k, v);
            }

            if let Some(dir) = builder.working_dir {
                cmd.current_dir(dir);
            }

            // Set up piping
            if let Some(stdout) = prev_stdout.take() {
                cmd.stdin(stdout);
            }
            
            if i < num_commands - 1 {
                cmd.stdout(Stdio::piped());
            } else {
                // Last command captures output
                cmd.stdout(Stdio::piped());
                cmd.stderr(Stdio::piped());
            }

            let mut child = cmd.spawn()?;
            prev_stdout = child.stdout.take().map(Stdio::from);
            children.push(child);
        }

        // Wait for all commands and get the output from the last one
        let mut last_output = None;
        for (i, mut child) in children.into_iter().enumerate() {
            if i == num_commands - 1 {
                last_output = Some(child.wait_with_output()?);
            } else {
                child.wait()?;
            }
        }

        let output = last_output.unwrap();
        
        Ok(ProcessOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            status: output.status,
            elapsed: start.elapsed(),
        })
    }
}

/// Run a command with a progress indicator
pub fn run_with_progress<F, T>(message: &str, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));

    let result = f();
    pb.finish_and_clear();
    
    result
}

/// Run an async command with a progress indicator
pub async fn run_with_progress_async<F, T>(message: &str, f: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));

    let result = f.await;
    pb.finish_and_clear();
    
    result
}

/// Check if a command exists in PATH
pub fn command_exists(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

/// Create a process builder configured for CI environments
pub fn ci_command<S: AsRef<str>>(command: S) -> ProcessBuilder {
    ProcessBuilder::new(command)
        .env("CI", "true")
        .env("TERM", "dumb")
        .env("NO_COLOR", "1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_builder() {
        let output = ProcessBuilder::new("echo")
            .arg("hello")
            .arg("world")
            .run()
            .unwrap();

        assert!(output.success());
        assert_eq!(output.stdout.trim(), "hello world");
    }

    #[test]
    fn test_pipeline() {
        let output = Pipeline::new()
            .pipe(ProcessBuilder::new("echo").arg("hello world"))
            .pipe(ProcessBuilder::new("tr").args(&["a-z", "A-Z"]))
            .run()
            .unwrap();

        assert!(output.success());
        assert_eq!(output.stdout.trim(), "HELLO WORLD");
    }

    #[test]
    fn test_command_exists() {
        assert!(command_exists("echo"));
        assert!(!command_exists("this-command-does-not-exist"));
    }

    #[tokio::test]
    async fn test_async_execution() {
        let output = ProcessBuilder::new("echo")
            .arg("async test")
            .run_async()
            .await
            .unwrap();

        assert!(output.success());
        assert_eq!(output.stdout.trim(), "async test");
    }
}