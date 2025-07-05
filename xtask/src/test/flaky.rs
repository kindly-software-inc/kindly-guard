//! Intelligent flaky test management system
//!
//! This module provides comprehensive flaky test detection, management, and reporting.
//! It integrates with cargo-nextest for retry policies and maintains a history of test
//! executions to identify patterns in test failures.

use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::RwLock,
};
use tracing::{debug, info, warn};

use crate::utils::Context;

/// Maximum number of historical test runs to track per test
const MAX_HISTORY_SIZE: usize = 100;

/// Default retry count for flaky tests
const DEFAULT_RETRY_COUNT: u32 = 3;

/// Default backoff base duration
const DEFAULT_BACKOFF_BASE: Duration = Duration::from_millis(100);

/// Threshold for marking a test as flaky (failure rate)
const FLAKY_THRESHOLD: f64 = 0.1; // 10% failure rate

/// Minimum number of runs before calculating flakiness
const MIN_RUNS_FOR_FLAKINESS: usize = 5;

/// Test execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestExecution {
    /// Test name (fully qualified)
    pub test_name: String,
    /// Execution timestamp
    pub timestamp: DateTime<Utc>,
    /// Whether the test passed
    pub passed: bool,
    /// Execution duration
    pub duration: Duration,
    /// Retry attempt number (0 for first attempt)
    pub retry_attempt: u32,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Test output
    pub output: Option<String>,
}

/// Test statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestStats {
    /// Total number of executions
    pub total_runs: u64,
    /// Number of passed executions
    pub passed_runs: u64,
    /// Number of failed executions
    pub failed_runs: u64,
    /// Average duration
    pub avg_duration: Duration,
    /// Maximum duration
    pub max_duration: Duration,
    /// Minimum duration
    pub min_duration: Duration,
    /// Flakiness score (0.0 to 1.0)
    pub flakiness_score: f64,
    /// Whether the test is quarantined
    pub quarantined: bool,
    /// Reason for quarantine
    pub quarantine_reason: Option<String>,
    /// Last execution time
    pub last_execution: DateTime<Utc>,
}

/// Retry policy for a test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Backoff strategy
    pub backoff: BackoffStrategy,
    /// Whether to fail fast on first failure
    pub fail_fast: bool,
}

/// Backoff strategy for retries
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BackoffStrategy {
    /// No backoff between retries
    None,
    /// Fixed delay between retries
    Fixed { delay: Duration },
    /// Linear backoff (delay * attempt)
    Linear { base: Duration },
    /// Exponential backoff (base * 2^attempt)
    Exponential { base: Duration, max: Duration },
    /// Exponential backoff with jitter
    ExponentialJitter { base: Duration, max: Duration },
}

/// Flaky test manager
pub struct FlakyTestManager {
    /// Path to the history database
    db_path: PathBuf,
    /// In-memory cache of test executions
    executions: Arc<RwLock<HashMap<String, VecDeque<TestExecution>>>>,
    /// Test statistics cache
    stats: Arc<RwLock<HashMap<String, TestStats>>>,
    /// Retry policies per test
    retry_policies: Arc<RwLock<HashMap<String, RetryPolicy>>>,
    /// Global default retry policy
    default_retry_policy: RetryPolicy,
}

impl FlakyTestManager {
    /// Create a new flaky test manager
    pub async fn new(workspace_root: &Path) -> Result<Self> {
        let db_path = workspace_root.join(".xtask").join("flaky-tests.json");
        
        // Ensure directory exists
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let mut manager = Self {
            db_path,
            executions: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(HashMap::new())),
            retry_policies: Arc::new(RwLock::new(HashMap::new())),
            default_retry_policy: RetryPolicy {
                max_retries: DEFAULT_RETRY_COUNT,
                backoff: BackoffStrategy::ExponentialJitter {
                    base: DEFAULT_BACKOFF_BASE,
                    max: Duration::from_secs(10),
                },
                fail_fast: false,
            },
        };

        // Load existing data
        manager.load_database().await?;
        
        Ok(manager)
    }

    /// Load database from disk
    async fn load_database(&mut self) -> Result<()> {
        if !self.db_path.exists() {
            return Ok(());
        }

        let mut file = File::open(&self.db_path).await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;

        #[derive(Deserialize)]
        struct Database {
            executions: HashMap<String, Vec<TestExecution>>,
            stats: HashMap<String, TestStats>,
            retry_policies: HashMap<String, RetryPolicy>,
        }

        if let Ok(db) = serde_json::from_str::<Database>(&contents) {
            let mut executions = self.executions.write().await;
            let mut stats = self.stats.write().await;
            let mut policies = self.retry_policies.write().await;

            for (test, execs) in db.executions {
                let mut deque = VecDeque::with_capacity(MAX_HISTORY_SIZE);
                for exec in execs.into_iter().take(MAX_HISTORY_SIZE) {
                    deque.push_back(exec);
                }
                executions.insert(test, deque);
            }

            *stats = db.stats;
            *policies = db.retry_policies;
        }

        Ok(())
    }

    /// Save database to disk
    async fn save_database(&self) -> Result<()> {
        let executions = self.executions.read().await;
        let stats = self.stats.read().await;
        let policies = self.retry_policies.read().await;

        #[derive(Serialize)]
        struct Database<'a> {
            executions: HashMap<String, Vec<&'a TestExecution>>,
            stats: &'a HashMap<String, TestStats>,
            retry_policies: &'a HashMap<String, RetryPolicy>,
        }

        let exec_map: HashMap<String, Vec<&TestExecution>> = executions
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().collect()))
            .collect();

        let db = Database {
            executions: exec_map,
            stats: &*stats,
            retry_policies: &*policies,
        };

        let json = serde_json::to_string_pretty(&db)?;
        
        let mut file = File::create(&self.db_path).await?;
        file.write_all(json.as_bytes()).await?;
        file.sync_all().await?;

        Ok(())
    }

    /// Record a test execution
    pub async fn record_execution(&self, execution: TestExecution) -> Result<()> {
        let test_name = execution.test_name.clone();
        
        // Update executions
        {
            let mut executions = self.executions.write().await;
            let history = executions.entry(test_name.clone()).or_insert_with(VecDeque::new);
            
            // Maintain max history size
            if history.len() >= MAX_HISTORY_SIZE {
                history.pop_front();
            }
            
            history.push_back(execution.clone());
        }

        // Update statistics
        self.update_stats(&test_name).await?;
        
        // Save to disk
        self.save_database().await?;
        
        Ok(())
    }

    /// Update statistics for a test
    async fn update_stats(&self, test_name: &str) -> Result<()> {
        let executions = self.executions.read().await;
        
        if let Some(history) = executions.get(test_name) {
            if history.is_empty() {
                return Ok(());
            }

            let total_runs = history.len() as u64;
            let passed_runs = history.iter().filter(|e| e.passed).count() as u64;
            let failed_runs = total_runs - passed_runs;
            
            let durations: Vec<Duration> = history.iter().map(|e| e.duration).collect();
            let total_duration: Duration = durations.iter().sum();
            let avg_duration = total_duration / total_runs as u32;
            let max_duration = durations.iter().max().copied().unwrap_or_default();
            let min_duration = durations.iter().min().copied().unwrap_or_default();
            
            // Calculate flakiness score
            let flakiness_score = if total_runs >= MIN_RUNS_FOR_FLAKINESS as u64 {
                // Consider a test flaky if it has inconsistent results
                let failure_rate = failed_runs as f64 / total_runs as f64;
                let has_recent_failures = history.iter().rev().take(10).any(|e| !e.passed);
                let has_recent_passes = history.iter().rev().take(10).any(|e| e.passed);
                
                if has_recent_failures && has_recent_passes {
                    failure_rate.max(0.1) // At least 10% flaky if inconsistent
                } else {
                    failure_rate
                }
            } else {
                0.0
            };

            let last_execution = history.back().map(|e| e.timestamp).unwrap_or_else(Utc::now);

            let mut stats = self.stats.write().await;
            let test_stats = stats.entry(test_name.to_string()).or_insert_with(|| TestStats {
                total_runs: 0,
                passed_runs: 0,
                failed_runs: 0,
                avg_duration,
                max_duration,
                min_duration,
                flakiness_score: 0.0,
                quarantined: false,
                quarantine_reason: None,
                last_execution,
            });

            test_stats.total_runs = total_runs;
            test_stats.passed_runs = passed_runs;
            test_stats.failed_runs = failed_runs;
            test_stats.avg_duration = avg_duration;
            test_stats.max_duration = max_duration;
            test_stats.min_duration = min_duration;
            test_stats.flakiness_score = flakiness_score;
            test_stats.last_execution = last_execution;

            // Auto-quarantine highly flaky tests
            if flakiness_score > 0.5 && !test_stats.quarantined {
                test_stats.quarantined = true;
                test_stats.quarantine_reason = Some(format!(
                    "Auto-quarantined due to high flakiness score: {:.2}",
                    flakiness_score
                ));
                warn!("Test {} auto-quarantined with flakiness score {:.2}", test_name, flakiness_score);
            }
        }

        Ok(())
    }

    /// Get retry policy for a test
    pub async fn get_retry_policy(&self, test_name: &str) -> RetryPolicy {
        let policies = self.retry_policies.read().await;
        let stats = self.stats.read().await;
        
        // Check for custom policy
        if let Some(policy) = policies.get(test_name) {
            return policy.clone();
        }

        // Generate policy based on flakiness
        if let Some(test_stats) = stats.get(test_name) {
            if test_stats.flakiness_score > FLAKY_THRESHOLD {
                // More aggressive retries for flaky tests
                return RetryPolicy {
                    max_retries: (DEFAULT_RETRY_COUNT as f64 * (1.0 + test_stats.flakiness_score)) as u32,
                    backoff: BackoffStrategy::ExponentialJitter {
                        base: Duration::from_millis(200),
                        max: Duration::from_secs(30),
                    },
                    fail_fast: false,
                };
            }
        }

        self.default_retry_policy.clone()
    }

    /// Set custom retry policy for a test
    pub async fn set_retry_policy(&self, test_name: String, policy: RetryPolicy) -> Result<()> {
        let mut policies = self.retry_policies.write().await;
        policies.insert(test_name, policy);
        self.save_database().await
    }

    /// Quarantine a test
    pub async fn quarantine_test(&self, test_name: &str, reason: String) -> Result<()> {
        let mut stats = self.stats.write().await;
        
        if let Some(test_stats) = stats.get_mut(test_name) {
            test_stats.quarantined = true;
            test_stats.quarantine_reason = Some(reason);
        } else {
            stats.insert(test_name.to_string(), TestStats {
                total_runs: 0,
                passed_runs: 0,
                failed_runs: 0,
                avg_duration: Duration::default(),
                max_duration: Duration::default(),
                min_duration: Duration::default(),
                flakiness_score: 1.0,
                quarantined: true,
                quarantine_reason: Some(reason),
                last_execution: Utc::now(),
            });
        }

        self.save_database().await
    }

    /// Un-quarantine a test
    pub async fn unquarantine_test(&self, test_name: &str) -> Result<()> {
        let mut stats = self.stats.write().await;
        
        if let Some(test_stats) = stats.get_mut(test_name) {
            test_stats.quarantined = false;
            test_stats.quarantine_reason = None;
        }

        self.save_database().await
    }

    /// Get list of quarantined tests
    pub async fn get_quarantined_tests(&self) -> Vec<(String, TestStats)> {
        let stats = self.stats.read().await;
        stats
            .iter()
            .filter(|(_, s)| s.quarantined)
            .map(|(name, stats)| (name.clone(), stats.clone()))
            .collect()
    }

    /// Get list of flaky tests (above threshold)
    pub async fn get_flaky_tests(&self) -> Vec<(String, TestStats)> {
        let stats = self.stats.read().await;
        stats
            .iter()
            .filter(|(_, s)| s.flakiness_score > FLAKY_THRESHOLD)
            .map(|(name, stats)| (name.clone(), stats.clone()))
            .collect()
    }

    /// Generate flakiness report
    pub async fn generate_report(&self, ctx: &Context) -> Result<FlakinessReport> {
        let stats = self.stats.read().await;
        let executions = self.executions.read().await;

        let total_tests = stats.len();
        let flaky_tests = stats.values().filter(|s| s.flakiness_score > FLAKY_THRESHOLD).count();
        let quarantined_tests = stats.values().filter(|s| s.quarantined).count();

        let mut test_reports = Vec::new();

        for (name, test_stats) in stats.iter() {
            if test_stats.flakiness_score > 0.0 || test_stats.quarantined {
                let recent_executions = executions
                    .get(name)
                    .map(|h| h.iter().rev().take(10).cloned().collect())
                    .unwrap_or_default();

                test_reports.push(TestReport {
                    test_name: name.clone(),
                    stats: test_stats.clone(),
                    recent_executions,
                });
            }
        }

        // Sort by flakiness score (descending)
        test_reports.sort_by(|a, b| {
            b.stats.flakiness_score
                .partial_cmp(&a.stats.flakiness_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let report = FlakinessReport {
            generated_at: Utc::now(),
            total_tests,
            flaky_tests,
            quarantined_tests,
            test_reports,
        };

        Ok(report)
    }

    /// Generate nextest retry configuration
    pub async fn generate_nextest_config(&self) -> Result<String> {
        let stats = self.stats.read().await;
        let policies = self.retry_policies.read().await;

        let mut config = String::from("[profile.default]\n");
        config.push_str("# Generated by xtask flaky test manager\n\n");

        // Add global retry settings
        config.push_str("retries = { backoff = \"exponential\", count = 2 }\n\n");

        // Add per-test overrides for flaky tests
        config.push_str("[[profile.default.overrides]]\n");
        config.push_str("# Flaky test overrides\n");
        
        let mut has_overrides = false;

        for (test_name, test_stats) in stats.iter() {
            if test_stats.flakiness_score > FLAKY_THRESHOLD && !test_stats.quarantined {
                if has_overrides {
                    config.push_str("\n[[profile.default.overrides]]\n");
                }
                
                config.push_str(&format!("filter = 'test(={})'\n", test_name));
                
                let policy = policies.get(test_name)
                    .cloned()
                    .unwrap_or_else(|| self.default_retry_policy.clone());
                
                let backoff_str = match policy.backoff {
                    BackoffStrategy::None => "fixed",
                    BackoffStrategy::Fixed { .. } => "fixed",
                    BackoffStrategy::Linear { .. } => "linear",
                    BackoffStrategy::Exponential { .. } | BackoffStrategy::ExponentialJitter { .. } => "exponential",
                };
                
                config.push_str(&format!(
                    "retries = {{ backoff = \"{}\", count = {} }}\n",
                    backoff_str, policy.max_retries
                ));
                
                has_overrides = true;
            }
        }

        // Add quarantined test filter
        let quarantined: Vec<_> = stats
            .iter()
            .filter(|(_, s)| s.quarantined)
            .map(|(name, _)| name.as_str())
            .collect();

        if !quarantined.is_empty() {
            config.push_str("\n[[profile.default.overrides]]\n");
            config.push_str("# Quarantined tests\n");
            
            let filter = quarantined
                .iter()
                .map(|name| format!("test(={})", name))
                .collect::<Vec<_>>()
                .join(" | ");
            
            config.push_str(&format!("filter = '{}'\n", filter));
            config.push_str("retries = { backoff = \"exponential\", count = 5 }\n");
        }

        Ok(config)
    }

    /// Calculate backoff duration
    pub fn calculate_backoff(strategy: &BackoffStrategy, attempt: u32) -> Duration {
        match strategy {
            BackoffStrategy::None => Duration::ZERO,
            BackoffStrategy::Fixed { delay } => *delay,
            BackoffStrategy::Linear { base } => *base * attempt,
            BackoffStrategy::Exponential { base, max } => {
                let exp = (*base * 2u32.pow(attempt.saturating_sub(1))).min(*max);
                exp
            }
            BackoffStrategy::ExponentialJitter { base, max } => {
                let exp = (*base * 2u32.pow(attempt.saturating_sub(1))).min(*max);
                // Add jitter: ±25%
                use rand::Rng;
                let mut rng = rand::thread_rng();
                let jitter = exp.as_millis() as f64 * 0.25;
                let jittered = exp.as_millis() as f64 + (rng.gen::<f64>() - 0.5) * jitter;
                Duration::from_millis(jittered.max(0.0) as u64)
            }
        }
    }
}

/// Test report for a single test
#[derive(Debug, Clone, Serialize)]
pub struct TestReport {
    /// Test name
    pub test_name: String,
    /// Test statistics
    pub stats: TestStats,
    /// Recent executions (up to 10)
    pub recent_executions: Vec<TestExecution>,
}

/// Flakiness report
#[derive(Debug, Clone, Serialize)]
pub struct FlakinessReport {
    /// When the report was generated
    pub generated_at: DateTime<Utc>,
    /// Total number of tests tracked
    pub total_tests: usize,
    /// Number of flaky tests
    pub flaky_tests: usize,
    /// Number of quarantined tests
    pub quarantined_tests: usize,
    /// Individual test reports
    pub test_reports: Vec<TestReport>,
}

impl FlakinessReport {
    /// Save report to file
    pub async fn save_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json).await?;
        Ok(())
    }

    /// Generate HTML report
    pub async fn save_as_html(&self, path: &Path) -> Result<()> {
        let html = self.generate_html();
        fs::write(path, html).await?;
        Ok(())
    }

    fn generate_html(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Flaky Test Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .test-card {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 10px 0; }}
        .flaky {{ border-left: 4px solid #ff9800; }}
        .quarantined {{ border-left: 4px solid #f44336; }}
        .metric {{ display: inline-block; margin: 0 15px 0 0; }}
        .metric-label {{ font-weight: 600; color: #666; }}
        .metric-value {{ font-size: 1.2em; }}
        .execution {{ background: #fafafa; padding: 5px 10px; margin: 5px 0; border-radius: 3px; font-family: monospace; font-size: 0.9em; }}
        .passed {{ color: #4caf50; }}
        .failed {{ color: #f44336; }}
        table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
        th {{ background: #f5f5f5; font-weight: 600; }}
    </style>
</head>
<body>
    <h1>Flaky Test Report</h1>
    <div class="summary">
        <div class="metric">
            <span class="metric-label">Generated:</span>
            <span class="metric-value">{}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Total Tests:</span>
            <span class="metric-value">{}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Flaky Tests:</span>
            <span class="metric-value">{}</span>
        </div>
        <div class="metric">
            <span class="metric-label">Quarantined:</span>
            <span class="metric-value">{}</span>
        </div>
    </div>
    
    <h2>Test Details</h2>
    {}
</body>
</html>"#,
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            self.total_tests,
            self.flaky_tests,
            self.quarantined_tests,
            self.generate_test_cards()
        )
    }

    fn generate_test_cards(&self) -> String {
        self.test_reports
            .iter()
            .map(|report| {
                let class = if report.stats.quarantined {
                    "test-card quarantined"
                } else if report.stats.flakiness_score > FLAKY_THRESHOLD {
                    "test-card flaky"
                } else {
                    "test-card"
                };

                let quarantine_info = if let Some(reason) = &report.stats.quarantine_reason {
                    format!("<p><strong>Quarantine Reason:</strong> {}</p>", reason)
                } else {
                    String::new()
                };

                let recent_executions = report
                    .recent_executions
                    .iter()
                    .map(|exec| {
                        let status = if exec.passed {
                            "<span class='passed'>PASSED</span>"
                        } else {
                            "<span class='failed'>FAILED</span>"
                        };
                        format!(
                            "<div class='execution'>{} - {} - {:.2}s{}</div>",
                            exec.timestamp.format("%Y-%m-%d %H:%M:%S"),
                            status,
                            exec.duration.as_secs_f64(),
                            exec.error_message
                                .as_ref()
                                .map(|e| format!(" - {}", e))
                                .unwrap_or_default()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("");

                format!(
                    r#"<div class="{}">
        <h3>{}</h3>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Total Runs</td>
                <td>{}</td>
            </tr>
            <tr>
                <td>Pass Rate</td>
                <td>{:.1}%</td>
            </tr>
            <tr>
                <td>Flakiness Score</td>
                <td>{:.2}</td>
            </tr>
            <tr>
                <td>Average Duration</td>
                <td>{:.2}s</td>
            </tr>
            <tr>
                <td>Last Run</td>
                <td>{}</td>
            </tr>
        </table>
        {}
        <h4>Recent Executions</h4>
        {}
    </div>"#,
                    class,
                    report.test_name,
                    report.stats.total_runs,
                    (report.stats.passed_runs as f64 / report.stats.total_runs as f64) * 100.0,
                    report.stats.flakiness_score,
                    report.stats.avg_duration.as_secs_f64(),
                    report.stats.last_execution.format("%Y-%m-%d %H:%M:%S"),
                    quarantine_info,
                    recent_executions
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_flaky_detection() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let manager = FlakyTestManager::new(tmp_dir.path()).await.unwrap();

        // Simulate a flaky test
        let test_name = "test::flaky_test";
        
        for i in 0..10 {
            let execution = TestExecution {
                test_name: test_name.to_string(),
                timestamp: Utc::now(),
                passed: i % 3 != 0, // Fails every 3rd run
                duration: Duration::from_millis(100 + i * 10),
                retry_attempt: 0,
                error_message: if i % 3 == 0 {
                    Some("Random failure".to_string())
                } else {
                    None
                },
                output: None,
            };
            
            manager.record_execution(execution).await.unwrap();
        }

        // Check stats
        let stats = manager.stats.read().await;
        let test_stats = stats.get(test_name).unwrap();
        
        assert_eq!(test_stats.total_runs, 10);
        assert_eq!(test_stats.failed_runs, 4); // Failed on 0, 3, 6, 9
        assert!(test_stats.flakiness_score > 0.3);
    }

    #[test]
    fn test_backoff_calculation() {
        // Test exponential backoff
        let strategy = BackoffStrategy::Exponential {
            base: Duration::from_millis(100),
            max: Duration::from_secs(10),
        };
        
        assert_eq!(
            FlakyTestManager::calculate_backoff(&strategy, 1),
            Duration::from_millis(100)
        );
        assert_eq!(
            FlakyTestManager::calculate_backoff(&strategy, 2),
            Duration::from_millis(200)
        );
        assert_eq!(
            FlakyTestManager::calculate_backoff(&strategy, 3),
            Duration::from_millis(400)
        );
        
        // Test max limit
        assert_eq!(
            FlakyTestManager::calculate_backoff(&strategy, 20),
            Duration::from_secs(10)
        );
    }
}