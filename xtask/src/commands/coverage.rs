use anyhow::{Context as _, Result};
use clap::Args;
use colored::*;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::utils::{Context, ensure_command_exists, spinner, workspace_root};

#[derive(Args)]
pub struct CoverageCmd {
    /// Generate HTML report
    #[arg(long, default_value = "true")]
    html: bool,

    /// Generate LCOV report
    #[arg(long, default_value = "true")]
    lcov: bool,

    /// Generate summary text report
    #[arg(long)]
    text: bool,

    /// Generate JSON report
    #[arg(long)]
    json: bool,

    /// Open HTML report in browser after generation
    #[arg(long)]
    open: bool,

    /// Coverage for specific package
    #[arg(long)]
    package: Option<String>,

    /// Include integration tests
    #[arg(long)]
    include_integration: bool,

    /// Include doctests
    #[arg(long)]
    include_doctests: bool,

    /// Use nextest runner
    #[arg(long)]
    nextest: bool,

    /// Clean previous coverage data before running
    #[arg(long, default_value = "true")]
    clean: bool,

    /// Fail if coverage is below threshold
    #[arg(long)]
    fail_under: Option<f64>,

    /// Show uncovered lines
    #[arg(long)]
    show_missing: bool,

    /// Ignore specific paths or patterns
    #[arg(long, value_delimiter = ',')]
    ignore: Vec<String>,

    /// Additional arguments to pass to cargo test
    #[arg(last = true)]
    args: Vec<String>,
}

pub async fn run(cmd: CoverageCmd, ctx: Context) -> Result<()> {
    // Ensure cargo-llvm-cov is installed
    ensure_command_exists("cargo-llvm-cov")
        .context("cargo-llvm-cov is required for coverage generation. Install with: cargo install cargo-llvm-cov")?;

    // If using nextest, ensure it's installed
    if cmd.nextest {
        ensure_command_exists("cargo-nextest")
            .context("cargo-nextest is required when --nextest is specified. Install with: cargo install cargo-nextest")?;
    }

    let workspace_dir = workspace_root()?;
    let coverage_dir = workspace_dir.join("target").join("coverage");

    // Clean previous coverage data if requested
    if cmd.clean {
        ctx.info("Cleaning previous coverage data...");
        let _ = std::fs::remove_dir_all(&coverage_dir);
    }

    // Create coverage directory
    std::fs::create_dir_all(&coverage_dir)?;

    // Start timing
    let start = Instant::now();

    // Build the cargo llvm-cov command
    let mut args = vec!["llvm-cov"];

    // Use nextest if requested
    if cmd.nextest {
        args.push("nextest");
    }

    // Add workspace flag
    args.push("--workspace");

    // Add all features
    args.push("--all-features");

    // Add package filter if specified
    if let Some(package) = &cmd.package {
        args.extend(&["-p", package]);
    }

    // Add output format flags
    let mut output_formats = Vec::new();
    
    if cmd.html {
        output_formats.push("--html");
    }
    if cmd.lcov {
        output_formats.push("--lcov");
    }
    if cmd.text {
        output_formats.push("--text");
    }
    if cmd.json {
        output_formats.push("--json");
    }

    // If no output format specified, default to HTML and LCOV
    if output_formats.is_empty() {
        output_formats.push("--html");
        output_formats.push("--lcov");
    }

    args.extend(&output_formats);

    // Set output directory
    args.extend(&["--output-dir", coverage_dir.to_str().unwrap()]);

    // Add ignore patterns
    for pattern in &cmd.ignore {
        args.extend(&["--ignore-filename-regex", pattern]);
    }

    // Include additional test types if requested
    if cmd.include_doctests {
        args.push("--doctests");
    }

    // Add show-missing flag if requested
    if cmd.show_missing {
        args.push("--show-missing-lines");
    }

    // Add any additional test arguments
    if !cmd.args.is_empty() {
        args.push("--");
        args.extend(cmd.args.iter().map(|s| s.as_str()));
    }

    // Run coverage generation
    let spinner = spinner("Generating coverage report...");
    
    ctx.debug(&format!("Running: cargo {}", args.join(" ")));
    
    let result = ctx.run_command("cargo", &args);
    
    spinner.finish_and_clear();

    match result {
        Ok(output) => {
            let duration = start.elapsed();
            ctx.success(&format!("Coverage generated in {:.2}s", duration.as_secs_f64()));
            
            // Parse and display coverage summary
            display_coverage_summary(&output, &ctx)?;
            
            // Show report locations
            ctx.info("\nCoverage reports generated:");
            
            if cmd.html {
                let html_path = coverage_dir.join("html").join("index.html");
                ctx.info(&format!("  HTML: {}", html_path.display()));
                
                // Open in browser if requested
                if cmd.open && html_path.exists() {
                    ctx.info("Opening HTML report in browser...");
                    open_in_browser(&html_path)?;
                }
            }
            
            if cmd.lcov {
                let lcov_path = coverage_dir.join("lcov.info");
                ctx.info(&format!("  LCOV: {}", lcov_path.display()));
            }
            
            if cmd.text {
                let text_path = coverage_dir.join("lcov.txt");
                ctx.info(&format!("  Text: {}", text_path.display()));
            }
            
            if cmd.json {
                let json_path = coverage_dir.join("lcov.json");
                ctx.info(&format!("  JSON: {}", json_path.display()));
            }
            
            // Check coverage threshold if specified
            if let Some(threshold) = cmd.fail_under {
                let coverage = extract_coverage_percentage(&output)?;
                if coverage < threshold {
                    ctx.error(&format!(
                        "Coverage {:.2}% is below threshold {:.2}%",
                        coverage, threshold
                    ));
                    anyhow::bail!("Coverage below threshold");
                }
            }
        }
        Err(e) => {
            ctx.error("Failed to generate coverage");
            return Err(e);
        }
    }

    Ok(())
}

fn display_coverage_summary(output: &str, _ctx: &Context) -> Result<()> {
    // Look for coverage summary in the output
    let lines: Vec<&str> = output.lines().collect();
    
    for (i, line) in lines.iter().enumerate() {
        if line.contains("Coverage") || line.contains("TOTAL") {
            // Print the coverage summary section
            println!("\n{}", "Coverage Summary:".bold());
            println!("{}", "=".repeat(60));
            
            // Print a few lines around the coverage info
            let start = i.saturating_sub(2);
            let end = (i + 3).min(lines.len());
            
            for j in start..end {
                let line = lines[j];
                if line.contains("TOTAL") || line.contains("Coverage") {
                    println!("{}", line.bold());
                } else {
                    println!("{}", line);
                }
            }
            
            println!("{}", "=".repeat(60));
            break;
        }
    }
    
    Ok(())
}

fn extract_coverage_percentage(output: &str) -> Result<f64> {
    // Look for coverage percentage in the output
    // Usually in format like "Coverage: 85.2%" or "TOTAL ... 85.2%"
    for line in output.lines() {
        if let Some(percentage) = extract_percentage_from_line(line) {
            return Ok(percentage);
        }
    }
    
    // If we can't find it in the output, try to parse from the generated reports
    anyhow::bail!("Could not extract coverage percentage from output")
}

fn extract_percentage_from_line(line: &str) -> Option<f64> {
    // Try different patterns to extract percentage
    // Using simple string parsing instead of regex for simplicity
    
    // Check for patterns like "85.2%" or "Coverage: 85.2%" or "TOTAL ... 85.2%"
    if let Some(percent_pos) = line.find('%') {
        // Find the start of the number by going backwards from %
        let mut start = percent_pos;
        let bytes = line.as_bytes();
        
        while start > 0 {
            let prev = start - 1;
            let ch = bytes[prev];
            if ch.is_ascii_digit() || ch == b'.' {
                start = prev;
            } else {
                break;
            }
        }
        
        // Extract and parse the number
        if start < percent_pos {
            if let Ok(percentage) = line[start..percent_pos].parse::<f64>() {
                return Some(percentage);
            }
        }
    }
    
    None
}

fn open_in_browser(path: &Path) -> Result<()> {
    let url = format!("file://{}", path.display());
    
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(&url).spawn()?;
    }
    
    #[cfg(target_os = "linux")]
    {
        if let Ok(_) = Command::new("xdg-open").arg(&url).spawn() {
            // Success
        } else if let Ok(_) = Command::new("firefox").arg(&url).spawn() {
            // Fallback to Firefox
        } else if let Ok(_) = Command::new("chromium").arg(&url).spawn() {
            // Fallback to Chromium
        } else {
            anyhow::bail!("Could not find a browser to open the report");
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        Command::new("cmd").args(&["/C", "start", &url]).spawn()?;
    }
    
    Ok(())
}