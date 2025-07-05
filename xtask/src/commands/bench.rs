//! Benchmark command implementation

use anyhow::Result;
use std::process::Command;

use crate::utils::{cargo, Context};

/// Execute the benchmark command
pub async fn execute(
    ctx: Context,
    bench: Option<String>,
    baseline: Option<String>,
    save: Option<String>,
) -> Result<()> {
    ctx.status("Benchmark", "Running benchmarks");

    // Build the benchmark command
    let mut args = vec!["bench"];
    
    if let Some(ref benchmark_name) = bench {
        args.push(benchmark_name);
    }
    
    // Use criterion features if available
    if let Some(ref baseline_name) = baseline {
        args.push("--");
        args.push("--baseline");
        args.push(baseline_name);
    } else if let Some(ref save_name) = save {
        args.push("--");
        args.push("--save-baseline");
        args.push(save_name);
    }

    // Run benchmarks
    cargo::run_cargo(&ctx, &args)?;

    // Run security-specific benchmarks
    ctx.status("Security", "Running security benchmarks");
    let mut cmd = Command::new("cargo");
    cmd.args(&["bench", "--bench", "security_benchmarks"]);
    let _ = ctx.run_command(&mut cmd); // Don't fail if not present

    // Analyze results if criterion is being used
    if std::path::Path::new("target/criterion").exists() {
        ctx.status("Analysis", "Benchmark results available in target/criterion");
        
        // Show recent benchmark comparisons
        if baseline.is_some() {
            ctx.status("Comparison", "Results compared against baseline");
        }
    }

    ctx.status("Success", "Benchmarks completed");
    
    Ok(())
}