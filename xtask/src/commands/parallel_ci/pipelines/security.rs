//! Security scanning pipeline with SARIF output support

use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::process::Command;
use tokio::fs;

use crate::utils::{Context, cargo::workspace_root};
use super::{Pipeline, MonitorEvent, TargetMatrix, send_progress};

/// Security scanning pipeline
pub struct SecurityPipeline {
    generate_sarif: bool,
}

impl SecurityPipeline {
    pub fn new() -> Self {
        Self {
            generate_sarif: true,
        }
    }
}

#[async_trait]
impl Pipeline for SecurityPipeline {
    fn name(&self) -> &str {
        "Security Scan"
    }
    
    fn task_count(&self, _targets: &TargetMatrix) -> usize {
        4 // cargo-audit, cargo-deny, cargo-geiger, sarif generation
    }
    
    fn priority(&self) -> u32 {
        70 // Can run in parallel with tests
    }
    
    async fn execute(
        &self,
        ctx: Arc<Context>,
        _targets: TargetMatrix,
        event_tx: mpsc::Sender<MonitorEvent>,
    ) -> Result<String> {
        let pipeline_name = self.name();
        let mut results = Vec::new();
        let workspace_root = workspace_root()?;
        let reports_dir = workspace_root.join(".ci/reports");
        fs::create_dir_all(&reports_dir).await?;
        
        // Step 1: cargo-audit
        send_progress(&event_tx, pipeline_name, 1, 4, "Running cargo-audit...".to_string()).await;
        
        let audit_available = Command::new("cargo")
            .args(&["audit", "--version"])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        
        if audit_available {
            let audit_result = Command::new("cargo")
                .args(&["audit", "--json"])
                .output()
                .await?;
            
            // Save JSON output
            let audit_json = reports_dir.join("cargo-audit.json");
            fs::write(&audit_json, &audit_result.stdout).await?;
            
            if !audit_result.status.success() {
                let output = String::from_utf8_lossy(&audit_result.stdout);
                ctx.warn("cargo-audit found vulnerabilities");
                
                // Parse and report critical issues
                if let Ok(audit_data) = serde_json::from_str::<serde_json::Value>(&output) {
                    if let Some(vulns) = audit_data["vulnerabilities"]["list"].as_array() {
                        let critical_count = vulns.iter()
                            .filter(|v| v["advisory"]["severity"].as_str() == Some("critical"))
                            .count();
                        
                        if critical_count > 0 {
                            return Err(anyhow::anyhow!(
                                "Found {} critical vulnerabilities - see report at {}",
                                critical_count,
                                audit_json.display()
                            ));
                        }
                    }
                }
                results.push("⚠ cargo-audit found non-critical issues".to_string());
            } else {
                results.push("✓ cargo-audit found no vulnerabilities".to_string());
            }
        } else {
            ctx.warn("cargo-audit not installed - skipping vulnerability scan");
            results.push("⊘ Vulnerability scan skipped (cargo-audit not installed)".to_string());
        }
        
        // Step 2: cargo-deny
        send_progress(&event_tx, pipeline_name, 2, 4, "Running cargo-deny...".to_string()).await;
        
        let deny_available = Command::new("cargo")
            .args(&["deny", "--version"])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        
        if deny_available {
            let deny_result = Command::new("cargo")
                .args(&["deny", "check", "--format", "json"])
                .output()
                .await?;
            
            // Save JSON output
            let deny_json = reports_dir.join("cargo-deny.json");
            fs::write(&deny_json, &deny_result.stdout).await?;
            
            if !deny_result.status.success() {
                ctx.warn("cargo-deny found policy violations");
                results.push("⚠ cargo-deny found policy issues".to_string());
            } else {
                results.push("✓ cargo-deny checks passed".to_string());
            }
        } else {
            results.push("⊘ Policy check skipped (cargo-deny not installed)".to_string());
        }
        
        // Step 3: cargo-geiger (unsafe code detection)
        send_progress(&event_tx, pipeline_name, 3, 4, "Checking for unsafe code...".to_string()).await;
        
        let geiger_available = Command::new("cargo")
            .args(&["geiger", "--version"])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);
        
        if geiger_available {
            let geiger_result = Command::new("cargo")
                .args(&["geiger", "--output-format", "Json"])
                .output()
                .await?;
            
            // Save JSON output
            let geiger_json = reports_dir.join("cargo-geiger.json");
            fs::write(&geiger_json, &geiger_result.stdout).await?;
            
            results.push("✓ Unsafe code report generated".to_string());
        } else {
            results.push("⊘ Unsafe code check skipped (cargo-geiger not installed)".to_string());
        }
        
        // Step 4: Generate SARIF report
        if self.generate_sarif {
            send_progress(&event_tx, pipeline_name, 4, 4, "Generating SARIF report...".to_string()).await;
            
            // Combine all security findings into SARIF format
            let sarif_report = generate_sarif_report(&reports_dir).await?;
            let sarif_path = reports_dir.join("security-scan.sarif");
            fs::write(&sarif_path, serde_json::to_string_pretty(&sarif_report)?).await?;
            
            results.push(format!("✓ SARIF report generated at {}", sarif_path.display()));
        }
        
        Ok(results.join("\n"))
    }
}

/// Generate SARIF report from security scan results
async fn generate_sarif_report(reports_dir: &PathBuf) -> Result<serde_json::Value> {
    use serde_json::json;
    
    let mut results = Vec::new();
    
    // Parse cargo-audit results if available
    let audit_json = reports_dir.join("cargo-audit.json");
    if audit_json.exists() {
        if let Ok(audit_data) = fs::read_to_string(&audit_json).await {
            if let Ok(audit) = serde_json::from_str::<serde_json::Value>(&audit_data) {
                // Convert audit findings to SARIF format
                if let Some(vulns) = audit["vulnerabilities"]["list"].as_array() {
                    for vuln in vulns {
                        results.push(json!({
                            "ruleId": vuln["advisory"]["id"],
                            "level": match vuln["advisory"]["severity"].as_str() {
                                Some("critical") => "error",
                                Some("high") => "error",
                                Some("medium") => "warning",
                                _ => "note",
                            },
                            "message": {
                                "text": vuln["advisory"]["title"]
                            },
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "Cargo.lock"
                                    }
                                }
                            }]
                        }));
                    }
                }
            }
        }
    }
    
    // Create SARIF report
    Ok(json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "KindlyGuard Security Scanner",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/yourusername/kindly-guard",
                    "rules": []
                }
            },
            "results": results,
            "columnKind": "utf16CodeUnits"
        }]
    }))
}