use anyhow::Result;
use clap::Args;
use colored::*;
use std::env;

use crate::utils::Context;

#[derive(Args)]
pub struct CiCmd {
    /// Skip formatting check
    #[arg(long)]
    skip_fmt: bool,

    /// Skip clippy lints
    #[arg(long)]
    skip_clippy: bool,

    /// Skip tests
    #[arg(long)]
    skip_tests: bool,

    /// Additional arguments to pass to cargo test
    #[arg(last = true)]
    test_args: Vec<String>,
}

pub async fn run(cmd: CiCmd, ctx: Context) -> Result<()> {
    ctx.info("Running CI checks...");

    // Check for CI environment variables for matrix builds
    let ci_os = env::var("CI_OS").ok();
    let ci_rust = env::var("CI_RUST").ok();

    if let Some(os) = &ci_os {
        ctx.info(&format!("CI Matrix OS: {}", os));
    }
    if let Some(rust) = &ci_rust {
        ctx.info(&format!("CI Matrix Rust: {}", rust));
    }

    // Track overall success
    let mut all_passed = true;

    // Step 1: Format check
    if !cmd.skip_fmt {
        ctx.info("Checking code formatting...");
        match run_fmt_check(&ctx).await {
            Ok(_) => ctx.success("Code formatting check passed"),
            Err(e) => {
                ctx.error(&format!("Code formatting check failed: {}", e));
                all_passed = false;
            }
        }
    }

    // Step 2: Clippy lints
    if !cmd.skip_clippy && all_passed {
        ctx.info("Running clippy lints...");
        match run_clippy(&ctx, &ci_rust).await {
            Ok(_) => ctx.success("Clippy checks passed"),
            Err(e) => {
                ctx.error(&format!("Clippy checks failed: {}", e));
                all_passed = false;
            }
        }
    }

    // Step 3: Tests
    if !cmd.skip_tests && all_passed {
        ctx.info("Running tests...");
        match run_tests(&ctx, &cmd.test_args, &ci_os).await {
            Ok(_) => ctx.success("All tests passed"),
            Err(e) => {
                ctx.error(&format!("Tests failed: {}", e));
                all_passed = false;
            }
        }
    }

    // Final summary
    if all_passed {
        ctx.success("All CI checks passed!");
        Ok(())
    } else {
        anyhow::bail!("CI checks failed")
    }
}

async fn run_fmt_check(ctx: &Context) -> Result<()> {
    let args = vec!["fmt", "--", "--check"];
    
    ctx.run_command("cargo", &args)?;
    Ok(())
}

async fn run_clippy(ctx: &Context, ci_rust: &Option<String>) -> Result<()> {
    let mut args = vec!["clippy", "--all-targets", "--all-features"];
    
    // Add CI-specific clippy flags
    args.push("--");
    args.push("-D");
    args.push("warnings");
    args.push("-D");
    args.push("clippy::all");
    args.push("-D");
    args.push("clippy::pedantic");
    
    // Allow certain lints that might be too strict for general use
    args.push("-A");
    args.push("clippy::module_name_repetitions");
    args.push("-A");
    args.push("clippy::must_use_candidate");
    args.push("-A");
    args.push("clippy::missing_errors_doc");
    
    // For older Rust versions, we might need to allow more lints
    if let Some(rust_version) = ci_rust {
        if rust_version.starts_with("1.7") && !rust_version.starts_with("1.79") {
            ctx.debug(&format!("Adjusting clippy flags for Rust {}", rust_version));
            args.push("-A");
            args.push("clippy::needless_pass_by_value");
        }
    }
    
    ctx.run_command("cargo", &args)?;
    Ok(())
}

async fn run_tests(ctx: &Context, test_args: &[String], ci_os: &Option<String>) -> Result<()> {
    let mut args = vec!["test", "--all-features", "--workspace"];
    
    // Add OS-specific test configuration
    if let Some(os) = ci_os {
        match os.as_str() {
            "windows-latest" => {
                ctx.debug("Configuring tests for Windows");
                // Windows might need different test thread count
                args.push("--");
                args.push("--test-threads=1");
            }
            "macos-latest" => {
                ctx.debug("Configuring tests for macOS");
                // macOS specific settings if needed
            }
            "ubuntu-latest" => {
                ctx.debug("Configuring tests for Ubuntu");
                // Linux specific settings if needed
            }
            _ => {
                ctx.warn(&format!("Unknown CI_OS: {}", os));
            }
        }
    } else {
        // Default test arguments
        args.push("--");
    }
    
    // Add any additional test arguments
    for arg in test_args {
        args.push(arg);
    }
    
    ctx.run_command("cargo", &args)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ci_cmd_default() {
        let cmd = CiCmd {
            skip_fmt: false,
            skip_clippy: false,
            skip_tests: false,
            test_args: vec![],
        };
        
        assert!(!cmd.skip_fmt);
        assert!(!cmd.skip_clippy);
        assert!(!cmd.skip_tests);
        assert!(cmd.test_args.is_empty());
    }

    #[tokio::test]
    async fn test_ci_dry_run() {
        let cmd = CiCmd {
            skip_fmt: false,
            skip_clippy: false,
            skip_tests: false,
            test_args: vec![],
        };
        
        let ctx = Context {
            dry_run: true,
            verbose: false,
        };
        
        // In dry run mode, this should succeed without actually running commands
        let result = run(cmd, ctx).await;
        assert!(result.is_ok());
    }
}