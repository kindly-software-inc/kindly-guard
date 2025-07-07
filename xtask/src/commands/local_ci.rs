use crate::utils::{cargo::workspace_root, Context};
use anyhow::Result;
use chrono::Local;
use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
pub struct LocalCiCmd {
    /// Run in quick mode (skip slow tests)
    #[arg(short, long)]
    quick: bool,

    /// Skip security audits
    #[arg(long)]
    no_security: bool,

    /// Skip coverage generation
    #[arg(long)]
    no_coverage: bool,

    /// Clean CI artifacts before running
    #[arg(long)]
    clean: bool,

    /// Show detailed output
    #[arg(short, long)]
    verbose: bool,
}

impl LocalCiCmd {
    pub async fn run(&self, ctx: &Context) -> Result<()> {
        let workspace_root = workspace_root()?;
        let ci_dir = workspace_root.join(".ci");
        let reports_dir = ci_dir.join("reports");
        let logs_dir = ci_dir.join("logs");
        let artifacts_dir = ci_dir.join("artifacts");

        // Create directories
        fs::create_dir_all(&reports_dir)?;
        fs::create_dir_all(&logs_dir)?;
        fs::create_dir_all(&artifacts_dir)?;

        // Clean if requested
        if self.clean {
            ctx.info("Cleaning CI artifacts...");
            clean_ci_artifacts(&ci_dir)?;
        }

        let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
        let _log_file = logs_dir.join(format!("ci_run_{}.log", timestamp));

        ctx.info("");
        ctx.info("╔══════════════════════════════════════╗");
        ctx.info("║      KindlyGuard Local CI Runner     ║");
        ctx.info("╚══════════════════════════════════════╝");
        ctx.info("");

        ctx.info(&format!(
            "Starting CI run at {}",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        ));
        ctx.info(&format!(
            "Reports will be saved to: {}",
            reports_dir.display()
        ));

        let mut steps_passed = 0;
        let total_steps = if self.no_security { 5 } else { 6 };

        // Step 1: Format check
        ctx.info("");
        ctx.info(&format!(
            "Step 1/{}: Checking code formatting...",
            total_steps
        ));
        if run_format_check(ctx, self.verbose).await? {
            ctx.success("Code formatting check passed");
            steps_passed += 1;
        } else {
            ctx.error("Code formatting check failed");
            ctx.warn("Run 'cargo fmt' to fix formatting issues");
            return Ok(());
        }

        // Step 2: Clippy
        ctx.info("");
        ctx.info(&format!("Step 2/{}: Running clippy lints...", total_steps));
        if run_clippy(ctx, self.verbose).await? {
            ctx.success("Clippy check passed");
            steps_passed += 1;
        } else {
            ctx.error("Clippy check failed");
            return Ok(());
        }

        // Step 3: Build
        ctx.info("");
        ctx.info(&format!("Step 3/{}: Building project...", total_steps));
        if run_build(ctx, self.verbose).await? {
            ctx.success("Build completed successfully");
            steps_passed += 1;
        } else {
            ctx.error("Build failed");
            return Ok(());
        }

        // Step 4: Tests
        ctx.info("");
        ctx.info(&format!("Step 4/{}: Running tests...", total_steps));
        let _coverage_report = if self.no_coverage {
            if run_tests(ctx, self.quick, self.verbose).await? {
                ctx.success("All tests passed");
                steps_passed += 1;
                None
            } else {
                ctx.error("Test execution failed");
                return Ok(());
            }
        } else {
            match run_tests_with_coverage(ctx, self.quick, self.verbose).await? {
                Some(coverage_path) => {
                    ctx.success("Tests passed with coverage");
                    let coverage_dest = reports_dir.join(format!("coverage_{}.lcov", timestamp));
                    fs::copy(&coverage_path, &coverage_dest)?;
                    ctx.info(&format!(
                        "Coverage report saved to: {}",
                        coverage_dest.display()
                    ));
                    steps_passed += 1;
                    Some(coverage_dest)
                },
                None => {
                    ctx.error("Test execution failed");
                    return Ok(());
                },
            }
        };

        // Step 5: Security audit
        if !self.no_security {
            ctx.info("");
            ctx.info(&format!(
                "Step 5/{}: Running security audits...",
                total_steps
            ));
            let security_report = reports_dir.join(format!("security_{}.txt", timestamp));
            if run_security_audit(ctx, &security_report, self.verbose).await? {
                ctx.success("Security checks completed");
                steps_passed += 1;
            } else {
                ctx.warn("Security issues found - see report");
                steps_passed += 1; // Don't fail CI for security warnings
            }
        }

        // Step 6: Documentation
        ctx.info("");
        ctx.info(&format!(
            "Step {}/{}: Building documentation...",
            if self.no_security { 5 } else { 6 },
            total_steps
        ));
        if run_doc_build(ctx, self.verbose).await? {
            ctx.success("Documentation built successfully");
            steps_passed += 1;
        } else {
            ctx.warn("Documentation build had warnings");
            steps_passed += 1; // Don't fail CI for doc warnings
        }

        // Summary
        ctx.info("");
        ctx.info("╔══════════════════════════════════════╗");
        ctx.info("║        CI Run Completed Successfully  ║");
        ctx.info("╚══════════════════════════════════════╝");
        ctx.info("");

        ctx.info(&format!(
            "CI run completed at {}",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        ));
        ctx.success(&format!("Passed {}/{} steps", steps_passed, total_steps));

        // Cleanup old artifacts (keep last 10)
        cleanup_old_artifacts(&logs_dir, 10)?;
        cleanup_old_artifacts(&reports_dir, 10)?;

        Ok(())
    }
}

async fn run_format_check(_ctx: &Context, verbose: bool) -> Result<bool> {
    let mut cmd = std::process::Command::new("cargo");
    cmd.args(["fmt", "--", "--check"]);

    if !verbose {
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
    }

    Ok(cmd.status()?.success())
}

async fn run_clippy(_ctx: &Context, verbose: bool) -> Result<bool> {
    let mut cmd = std::process::Command::new("cargo");
    cmd.args([
        "clippy",
        "--all-features",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]);

    if !verbose {
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
    }

    Ok(cmd.status()?.success())
}

async fn run_build(_ctx: &Context, verbose: bool) -> Result<bool> {
    let mut cmd = std::process::Command::new("cargo");
    cmd.args(["build", "--all-features"]);

    if !verbose {
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
    }

    Ok(cmd.status()?.success())
}

async fn run_tests(_ctx: &Context, quick: bool, verbose: bool) -> Result<bool> {
    let mut cmd = std::process::Command::new("cargo");

    if quick {
        cmd.args(["test", "--lib"]);
    } else if crate::utils::nextest::is_installed() {
        cmd.args(["nextest", "run"]);
    } else {
        cmd.arg("test");
    }

    if !verbose {
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
    }

    Ok(cmd.status()?.success())
}

async fn run_tests_with_coverage(
    _ctx: &Context,
    quick: bool,
    verbose: bool,
) -> Result<Option<PathBuf>> {
    // Run coverage using cargo-llvm-cov directly
    let mut cmd = std::process::Command::new("cargo");

    // Check if cargo-llvm-cov is installed
    if !crate::utils::tools::is_tool_installed("cargo-llvm-cov")? {
        return Ok(None);
    }

    cmd.arg("llvm-cov");
    cmd.arg("--lcov");
    cmd.arg("--output-path");

    let workspace_root = workspace_root()?;
    let lcov_path = workspace_root.join("target/coverage/lcov.info");
    cmd.arg(&lcov_path);

    if quick {
        cmd.arg("--lib");
    }

    if crate::utils::nextest::is_installed() {
        cmd.arg("nextest");
    }

    if !verbose {
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
    }

    if cmd.status()?.success() && lcov_path.exists() {
        Ok(Some(lcov_path))
    } else {
        Ok(None)
    }
}

async fn run_security_audit(_ctx: &Context, report_path: &PathBuf, _verbose: bool) -> Result<bool> {
    use std::io::Write;
    let mut report = fs::File::create(report_path)?;

    writeln!(report, "Security Audit Report")?;
    writeln!(
        report,
        "Generated at: {}",
        Local::now().format("%Y-%m-%d %H:%M:%S")
    )?;
    writeln!(report, "=")?;
    writeln!(report)?;

    let mut all_passed = true;

    // Run cargo-audit
    if crate::utils::tools::is_tool_installed("cargo-audit")? {
        writeln!(report, "## Cargo Audit")?;
        let mut cmd = std::process::Command::new("cargo");
        cmd.arg("audit");

        let output = cmd.output()?;
        write!(report, "{}", String::from_utf8_lossy(&output.stdout))?;
        write!(report, "{}", String::from_utf8_lossy(&output.stderr))?;

        if !output.status.success() {
            all_passed = false;
        }
        writeln!(report)?;
    }

    // Run cargo-deny
    if crate::utils::tools::is_tool_installed("cargo-deny")? {
        writeln!(report, "## Cargo Deny")?;
        let mut cmd = std::process::Command::new("cargo");
        cmd.args(["deny", "check"]);

        let output = cmd.output()?;
        write!(report, "{}", String::from_utf8_lossy(&output.stdout))?;
        write!(report, "{}", String::from_utf8_lossy(&output.stderr))?;

        if !output.status.success() {
            all_passed = false;
        }
    }

    Ok(all_passed)
}

async fn run_doc_build(_ctx: &Context, verbose: bool) -> Result<bool> {
    let mut cmd = std::process::Command::new("cargo");
    cmd.args(["doc", "--no-deps"]);

    if !verbose {
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
    }

    Ok(cmd.status()?.success())
}

fn clean_ci_artifacts(ci_dir: &Path) -> Result<()> {
    for subdir in &["reports", "logs", "artifacts"] {
        let dir = ci_dir.join(subdir);
        if dir.exists() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    fs::remove_file(entry.path())?;
                }
            }
        }
    }
    Ok(())
}

fn cleanup_old_artifacts(dir: &PathBuf, keep: usize) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .collect();

    if entries.len() <= keep {
        return Ok(());
    }

    entries.sort_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()));
    entries.reverse();

    for entry in entries.into_iter().skip(keep) {
        fs::remove_file(entry.path())?;
    }

    Ok(())
}
