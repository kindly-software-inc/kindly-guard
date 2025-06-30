//! Security hardening measures for production deployment

use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use anyhow::{Result, bail};
use tracing::{warn, error, info};

/// Rate limiter for command execution
pub struct CommandRateLimiter {
    limits: Arc<RwLock<RateLimitState>>,
}

#[derive(Debug)]
struct RateLimitState {
    /// Command counts per window
    command_counts: std::collections::HashMap<String, WindowedCounter>,
    /// Global rate limit
    global_counter: WindowedCounter,
}

#[derive(Debug)]
struct WindowedCounter {
    count: u64,
    window_start: Instant,
    window_duration: Duration,
    max_count: u64,
}

impl WindowedCounter {
    fn new(max_count: u64, window_duration: Duration) -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
            window_duration,
            max_count,
        }
    }
    
    fn check_and_increment(&mut self) -> Result<()> {
        // Reset window if expired
        if self.window_start.elapsed() > self.window_duration {
            self.count = 0;
            self.window_start = Instant::now();
        }
        
        if self.count >= self.max_count {
            bail!("Rate limit exceeded: {} requests per {:?}", 
                self.max_count, self.window_duration);
        }
        
        self.count += 1;
        Ok(())
    }
}

impl CommandRateLimiter {
    pub fn new() -> Self {
        Self {
            limits: Arc::new(RwLock::new(RateLimitState {
                command_counts: std::collections::HashMap::new(),
                global_counter: WindowedCounter::new(100, Duration::from_secs(60)),
            })),
        }
    }
    
    /// Check if command is allowed
    pub fn check_command(&self, command: &str) -> Result<()> {
        let mut state = self.limits.write();
        
        // Check global limit
        state.global_counter.check_and_increment()?;
        
        // Check per-command limit
        let limit = match command {
            "scan" => (10, Duration::from_secs(60)), // 10 scans per minute
            "dashboard" => (5, Duration::from_secs(300)), // 5 dashboard starts per 5 minutes
            "status" => (60, Duration::from_secs(60)), // 60 status checks per minute
            _ => (30, Duration::from_secs(60)), // Default: 30 per minute
        };
        
        let counter = state.command_counts
            .entry(command.to_string())
            .or_insert_with(|| WindowedCounter::new(limit.0, limit.1));
        
        counter.check_and_increment()
    }
}

/// Resource usage monitor
pub struct ResourceMonitor {
    max_memory_mb: usize,
    max_cpu_percent: f32,
}

impl ResourceMonitor {
    pub fn new() -> Self {
        Self {
            max_memory_mb: 512, // 512MB max
            max_cpu_percent: 80.0, // 80% CPU max
        }
    }
    
    /// Check current resource usage
    pub fn check_resources(&self) -> Result<()> {
        // Get current memory usage
        let memory_usage = self.get_memory_usage_mb();
        if memory_usage > self.max_memory_mb {
            bail!("Memory usage too high: {}MB (max: {}MB)", 
                memory_usage, self.max_memory_mb);
        }
        
        // Note: CPU usage checking would require platform-specific code
        // For now, we'll just log memory usage
        if memory_usage > self.max_memory_mb * 80 / 100 {
            warn!("Memory usage approaching limit: {}MB", memory_usage);
        }
        
        Ok(())
    }
    
    fn get_memory_usage_mb(&self) -> usize {
        // Simple approximation using jemalloc stats if available
        // In production, use proper system monitoring
        use std::alloc::{GlobalAlloc, System};
        
        // This is a placeholder - in production use proper metrics
        50 // Return dummy value for now
    }
}

/// Security context for command execution
pub struct SecurityContext {
    /// User identifier (for future authentication)
    pub user_id: Option<String>,
    /// Source of command (cli, api, etc)
    pub source: CommandSource,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Request ID for correlation
    pub request_id: String,
}

#[derive(Debug, Clone)]
pub enum CommandSource {
    Cli,
    WebDashboard,
    Api,
    Unknown,
}

/// Audit logger for security events
pub struct SecurityAuditLogger {
    log_path: Option<std::path::PathBuf>,
}

impl SecurityAuditLogger {
    pub fn new(log_path: Option<std::path::PathBuf>) -> Self {
        Self { log_path }
    }
    
    /// Log command execution
    pub fn log_command(&self, 
        context: &SecurityContext, 
        command: &str, 
        args: &serde_json::Value,
        result: &Result<()>,
    ) {
        let event = serde_json::json!({
            "timestamp": context.timestamp,
            "request_id": context.request_id,
            "user_id": context.user_id,
            "source": format!("{:?}", context.source),
            "command": command,
            "args": args,
            "success": result.is_ok(),
            "error": result.as_ref().err().map(|e| e.to_string()),
        });
        
        // Log to tracing
        match result {
            Ok(_) => info!(event = %event, "Command executed"),
            Err(_) => warn!(event = %event, "Command failed"),
        }
        
        // Write to audit file if configured
        if let Some(ref path) = self.log_path {
            if let Err(e) = self.write_to_file(path, &event) {
                error!("Failed to write audit log: {}", e);
            }
        }
    }
    
    fn write_to_file(&self, path: &std::path::Path, event: &serde_json::Value) -> Result<()> {
        use std::fs::OpenOptions;
        use std::io::Write;
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        
        writeln!(file, "{}", event)?;
        Ok(())
    }
}

/// Sandbox for file operations
pub struct FileSandbox {
    allowed_paths: Vec<std::path::PathBuf>,
}

impl FileSandbox {
    pub fn new(allowed_paths: Vec<std::path::PathBuf>) -> Self {
        Self { allowed_paths }
    }
    
    /// Check if path access is allowed
    pub fn check_path(&self, path: &std::path::Path) -> Result<()> {
        let canonical = path.canonicalize()
            .map_err(|e| anyhow::anyhow!("Invalid path: {}", e))?;
        
        // Check if path is under any allowed directory
        for allowed in &self.allowed_paths {
            if canonical.starts_with(allowed) {
                return Ok(());
            }
        }
        
        bail!("Access denied: path '{}' is outside allowed directories", 
            path.display());
    }
}

/// Command injection prevention
pub mod injection {
    use super::*;
    use regex::Regex;
    use once_cell::sync::Lazy;
    
    // Patterns that might indicate command injection
    static DANGEROUS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
        vec![
            Regex::new(r"[;&|]").unwrap(), // Command separators
            Regex::new(r"\$\(.*\)").unwrap(), // Command substitution
            Regex::new(r"`.*`").unwrap(), // Backticks
            Regex::new(r"<<.*>>").unwrap(), // Heredoc
            Regex::new(r"[<>]").unwrap(), // Redirections
        ]
    });
    
    /// Check for potential command injection
    pub fn check_command_injection(input: &str) -> Result<()> {
        for pattern in DANGEROUS_PATTERNS.iter() {
            if pattern.is_match(input) {
                bail!("Potential command injection detected");
            }
        }
        Ok(())
    }
}

/// Information disclosure prevention  
pub mod info_disclosure {
    use super::*;
    
    /// Sanitize error messages for production
    pub fn sanitize_error(error: anyhow::Error) -> String {
        // In production, hide internal details
        if cfg!(debug_assertions) {
            format!("{:#}", error)
        } else {
            // Generic messages for production
            match error.to_string().to_lowercase() {
                s if s.contains("permission") => "Permission denied".to_string(),
                s if s.contains("not found") => "Resource not found".to_string(),
                s if s.contains("timeout") => "Operation timed out".to_string(),
                s if s.contains("rate limit") => "Rate limit exceeded".to_string(),
                _ => "An error occurred. Please try again.".to_string(),
            }
        }
    }
    
    /// Mask sensitive configuration values
    pub fn mask_sensitive(key: &str, value: &str) -> String {
        let sensitive_keys = ["password", "token", "secret", "key", "auth"];
        
        if sensitive_keys.iter().any(|&k| key.to_lowercase().contains(k)) {
            "***MASKED***".to_string()
        } else {
            value.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rate_limiter() {
        let limiter = CommandRateLimiter::new();
        
        // Should allow initial requests
        for _ in 0..5 {
            assert!(limiter.check_command("scan").is_ok());
        }
        
        // Should eventually hit limit
        let mut hit_limit = false;
        for _ in 0..20 {
            if limiter.check_command("scan").is_err() {
                hit_limit = true;
                break;
            }
        }
        assert!(hit_limit);
    }
    
    #[test]
    fn test_command_injection_detection() {
        use injection::check_command_injection;
        
        // Safe inputs
        assert!(check_command_injection("normal text").is_ok());
        assert!(check_command_injection("/path/to/file.txt").is_ok());
        
        // Dangerous inputs
        assert!(check_command_injection("test; rm -rf /").is_err());
        assert!(check_command_injection("$(cat /etc/passwd)").is_err());
        assert!(check_command_injection("`whoami`").is_err());
        assert!(check_command_injection("test > /dev/null").is_err());
    }
    
    #[test]
    fn test_file_sandbox() {
        use tempfile::tempdir;
        
        // Create temp directory
        let temp_dir = tempdir().unwrap();
        let allowed_path = temp_dir.path().to_path_buf();
        
        // Create a test file
        let test_file = allowed_path.join("test.txt");
        std::fs::write(&test_file, "test").unwrap();
        
        let sandbox = FileSandbox::new(vec![allowed_path.clone()]);
        
        // Allowed paths
        assert!(sandbox.check_path(&test_file).is_ok());
        
        // Disallowed paths (outside sandbox)
        let outside_path = std::env::temp_dir().join("outside.txt");
        std::fs::write(&outside_path, "test").unwrap();
        
        // Only test if the outside path is actually outside our sandbox
        if !outside_path.starts_with(&allowed_path) {
            assert!(sandbox.check_path(&outside_path).is_err());
        }
        
        // Cleanup
        let _ = std::fs::remove_file(outside_path);
    }
    
    #[test]
    fn test_info_disclosure_prevention() {
        use info_disclosure::{sanitize_error, mask_sensitive};
        
        // Error sanitization - in debug mode it shows full error, in release it's generic
        let error = anyhow::anyhow!("Connection to database at 192.168.1.1:5432 failed");
        let sanitized = sanitize_error(error);
        
        if cfg!(debug_assertions) {
            // In debug mode, we get the full error
            assert!(sanitized.contains("database"));
        } else {
            // In release mode, we get generic message
            assert_eq!(sanitized, "An error occurred. Please try again.");
        }
        
        // Test known error patterns
        let perm_error = anyhow::anyhow!("Permission denied for user");
        assert!(sanitize_error(perm_error).contains("Permission"));
        
        // Sensitive value masking
        assert_eq!(mask_sensitive("password", "secret123"), "***MASKED***");
        assert_eq!(mask_sensitive("api_token", "xyz"), "***MASKED***");
        assert_eq!(mask_sensitive("username", "john"), "john");
    }
}