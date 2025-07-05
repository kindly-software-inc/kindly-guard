use anyhow::{Context as _, Result};
use clap::Args;
use colored::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::utils::{Context, ensure_command_exists, spinner};

#[derive(Args)]
pub struct SecurityCmd {
    /// Run cargo-audit
    #[arg(long)]
    audit: bool,

    /// Run cargo-deny
    #[arg(long)]
    deny: bool,

    /// Generate SARIF report
    #[arg(long)]
    sarif: bool,

    /// Run all security checks
    #[arg(long)]
    all: bool,

    /// Fix vulnerabilities if possible
    #[arg(long)]
    fix: bool,

    /// Fail on warnings
    #[arg(long)]
    strict: bool,

    /// Output format (json, human)
    #[arg(long, default_value = "human")]
    format: OutputFormat,
}

#[derive(Clone, Debug, Deserialize)]
enum OutputFormat {
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "human")]
    Human,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Self::Json),
            "human" => Ok(Self::Human),
            _ => Err(format!("Unknown format: {}", s)),
        }
    }
}

pub async fn run(cmd: SecurityCmd, ctx: Context) -> Result<()> {
    let run_all = cmd.all || (!cmd.audit && !cmd.deny && !cmd.sarif);
    
    let mut results = SecurityResults::default();

    // Run cargo-audit
    if run_all || cmd.audit {
        ctx.info("Running cargo-audit...");
        let audit_result = run_audit(&ctx)?;
        results.audit = Some(audit_result);
    }

    // Run cargo-deny
    if run_all || cmd.deny {
        ctx.info("Running cargo-deny...");
        let deny_result = run_deny(&ctx)?;
        results.deny = Some(deny_result);
    }

    // Generate SARIF report
    if cmd.sarif {
        ctx.info("Generating SARIF report...");
        generate_sarif_report(&results, &ctx)?;
    }

    // Print summary
    print_security_summary(&results, &ctx);

    // Check if we should fail
    if cmd.strict && results.has_issues() {
        anyhow::bail!("Security issues found");
    }

    Ok(())
}

#[derive(Default)]
struct SecurityResults {
    audit: Option<AuditResult>,
    deny: Option<DenyResult>,
}

impl SecurityResults {
    fn has_issues(&self) -> bool {
        self.audit.as_ref().map_or(false, |r| r.vulnerabilities > 0)
            || self.deny.as_ref().map_or(false, |r| r.errors > 0)
    }

    fn has_warnings(&self) -> bool {
        self.audit.as_ref().map_or(false, |r| r.warnings > 0)
            || self.deny.as_ref().map_or(false, |r| r.warnings > 0)
    }
}

#[derive(Debug, Serialize)]
pub struct AuditResult {
    vulnerabilities: u32,
    warnings: u32,
    notices: u32,
    unmaintained: u32,
    yanked: u32,
    vulnerable_packages: Vec<VulnerablePackage>,
}

#[derive(Debug, Serialize)]
struct VulnerablePackage {
    name: String,
    version: String,
    advisory: String,
    severity: String,
    title: String,
}

#[derive(Debug, Serialize)]
pub struct DenyResult {
    errors: u32,
    warnings: u32,
    notes: u32,
    licenses: LicenseCheck,
    bans: BansCheck,
}

#[derive(Debug, Serialize)]
struct LicenseCheck {
    allowed: u32,
    denied: u32,
    exceptions: u32,
}

#[derive(Debug, Serialize)]
struct BansCheck {
    banned: u32,
    allowed: u32,
    skipped: u32,
}

pub fn run_audit(ctx: &Context) -> Result<AuditResult> {
    ensure_command_exists("cargo-audit")?;
    
    let spinner = spinner("Checking for vulnerabilities");

    let output = std::process::Command::new("cargo")
        .args(&["audit", "--json"])
        .output()
        .context("Failed to run cargo-audit")?;

    spinner.finish_and_clear();

    // Parse JSON output
    let audit_output: serde_json::Value = serde_json::from_slice(&output.stdout)
        .context("Failed to parse audit output")?;

    // Extract results
    let vulnerabilities = audit_output["vulnerabilities"]["count"]
        .as_u64()
        .unwrap_or(0) as u32;
    
    let warnings = audit_output["warnings"]["count"]
        .as_u64()
        .unwrap_or(0) as u32;

    let mut vulnerable_packages = Vec::new();
    
    if let Some(vulns) = audit_output["vulnerabilities"]["list"].as_array() {
        for vuln in vulns {
            vulnerable_packages.push(VulnerablePackage {
                name: vuln["package"]["name"].as_str().unwrap_or("").to_string(),
                version: vuln["package"]["version"].as_str().unwrap_or("").to_string(),
                advisory: vuln["advisory"]["id"].as_str().unwrap_or("").to_string(),
                severity: vuln["advisory"]["severity"].as_str().unwrap_or("unknown").to_string(),
                title: vuln["advisory"]["title"].as_str().unwrap_or("").to_string(),
            });
        }
    }

    let result = AuditResult {
        vulnerabilities,
        warnings,
        notices: 0,
        unmaintained: 0,
        yanked: 0,
        vulnerable_packages,
    };

    // Print results
    if vulnerabilities > 0 {
        ctx.error(&format!("Found {} vulnerabilities", vulnerabilities));
        for pkg in &result.vulnerable_packages {
            println!("  {} {} - {} ({})", 
                pkg.name.red(), 
                pkg.version,
                pkg.title,
                match pkg.severity.as_str() {
                    "critical" => pkg.severity.red().bold(),
                    "high" => pkg.severity.red(),
                    "medium" => pkg.severity.yellow(),
                    "low" => pkg.severity.blue(),
                    _ => pkg.severity.normal(),
                }
            );
        }
    } else {
        ctx.success("No vulnerabilities found");
    }

    Ok(result)
}

pub fn run_deny(ctx: &Context) -> Result<DenyResult> {
    ensure_command_exists("cargo-deny")?;
    
    let spinner = spinner("Checking dependencies");

    // Ensure deny.toml exists
    if !Path::new("deny.toml").exists() {
        create_default_deny_config()?;
        ctx.info("Created default deny.toml configuration");
    }

    let output = std::process::Command::new("cargo")
        .args(&["deny", "check", "--format", "json"])
        .output()
        .context("Failed to run cargo-deny")?;

    spinner.finish_and_clear();

    // Parse output line by line (cargo-deny outputs NDJSON)
    let mut errors = 0;
    let mut warnings = 0;
    let mut notes = 0;

    for line in output.stdout.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }

        if let Ok(entry) = serde_json::from_slice::<serde_json::Value>(line) {
            match entry["type"].as_str() {
                Some("error") => errors += 1,
                Some("warning") => warnings += 1,
                Some("note") => notes += 1,
                _ => {}
            }
        }
    }

    let result = DenyResult {
        errors,
        warnings,
        notes,
        licenses: LicenseCheck {
            allowed: 0,
            denied: 0,
            exceptions: 0,
        },
        bans: BansCheck {
            banned: 0,
            allowed: 0,
            skipped: 0,
        },
    };

    // Print summary
    if errors > 0 {
        ctx.error(&format!("cargo-deny found {} errors", errors));
    } else if warnings > 0 {
        ctx.warn(&format!("cargo-deny found {} warnings", warnings));
    } else {
        ctx.success("All dependency checks passed");
    }

    Ok(result)
}

fn create_default_deny_config() -> Result<()> {
    let deny_toml = r#"[licenses]
unlicensed = "deny"
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-3-Clause", "ISC"]
copyleft = "warn"

[bans]
multiple-versions = "warn"
wildcards = "allow"
deny = []

[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
notice = "warn"
ignore = []

[sources]
unknown-registry = "warn"
unknown-git = "warn"
"#;

    std::fs::write("deny.toml", deny_toml)
        .context("Failed to write deny.toml")?;

    Ok(())
}

fn generate_sarif_report(results: &SecurityResults, ctx: &Context) -> Result<()> {
    let spinner = spinner("Generating SARIF report");

    #[derive(Serialize)]
    struct SarifReport {
        version: String,
        runs: Vec<SarifRun>,
    }

    #[derive(Serialize)]
    struct SarifRun {
        tool: SarifTool,
        results: Vec<SarifResult>,
    }

    #[derive(Serialize)]
    struct SarifTool {
        driver: SarifDriver,
    }

    #[derive(Serialize)]
    struct SarifDriver {
        name: String,
        version: String,
        rules: Vec<SarifRule>,
    }

    #[derive(Serialize)]
    struct SarifRule {
        id: String,
        name: String,
        #[serde(rename = "shortDescription")]
        short_description: SarifText,
    }

    #[derive(Serialize)]
    struct SarifText {
        text: String,
    }

    #[derive(Serialize)]
    struct SarifResult {
        #[serde(rename = "ruleId")]
        rule_id: String,
        level: String,
        message: SarifText,
    }

    let mut sarif_results = Vec::new();

    // Add audit results
    if let Some(audit) = &results.audit {
        for pkg in &audit.vulnerable_packages {
            sarif_results.push(SarifResult {
                rule_id: pkg.advisory.clone(),
                level: match pkg.severity.as_str() {
                    "critical" | "high" => "error",
                    "medium" => "warning",
                    _ => "note",
                }.to_string(),
                message: SarifText {
                    text: format!("{} {} - {}", pkg.name, pkg.version, pkg.title),
                },
            });
        }
    }

    let report = SarifReport {
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "kindly-guard-security".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    rules: vec![],
                },
            },
            results: sarif_results,
        }],
    };

    let json = serde_json::to_string_pretty(&report)
        .context("Failed to serialize SARIF report")?;

    std::fs::write("security-report.sarif", json)
        .context("Failed to write SARIF report")?;

    spinner.finish_with_message("SARIF report generated");
    ctx.info("SARIF report saved to: security-report.sarif");

    Ok(())
}

fn print_security_summary(results: &SecurityResults, ctx: &Context) {
    println!("\n{}", "Security Summary:".bold());
    println!("{}", "=".repeat(50));

    if let Some(audit) = &results.audit {
        let status = if audit.vulnerabilities > 0 {
            "VULNERABLE".red()
        } else {
            "SECURE".green()
        };
        
        println!("{:<20} {} ({} vulnerabilities, {} warnings)",
            "Cargo Audit:",
            status,
            audit.vulnerabilities,
            audit.warnings
        );
    }

    if let Some(deny) = &results.deny {
        let status = if deny.errors > 0 {
            "FAILED".red()
        } else if deny.warnings > 0 {
            "WARNING".yellow()
        } else {
            "PASSED".green()
        };
        
        println!("{:<20} {} ({} errors, {} warnings)",
            "Cargo Deny:",
            status,
            deny.errors,
            deny.warnings
        );
    }

    println!("{}", "=".repeat(50));

    if results.has_issues() {
        ctx.error("Security issues found!");
        ctx.info("Run 'cargo update' to update dependencies");
        ctx.info("Run 'cargo audit fix' to apply available fixes");
    } else if results.has_warnings() {
        ctx.warn("Security warnings found");
    } else {
        ctx.success("All security checks passed!");
    }
}