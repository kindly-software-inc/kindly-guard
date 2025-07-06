//! Example of using the tool installation utilities
//!
//! Run with: cargo run -p xtask --example tool_install_example

use anyhow::Result;
use xtask::utils::tools::{common_tools, ToolInstallConfig};
use xtask::utils::Context;
use xtask::utils::tools::{ensure_tool_installed, ensure_tools_installed};

fn main() -> Result<()> {
    // Create a context for the examples
    let ctx = Context {
        dry_run: false,
        verbose: true,
    };

    // Example 1: Install a single tool with default configuration
    println!("Example 1: Installing cargo-audit with default config");
    match ensure_tool_installed(&ctx, "cargo-audit", None) {
        Ok(true) => println!("✅ cargo-audit is available"),
        Ok(false) => println!("❌ User declined installation"),
        Err(e) => eprintln!("💥 Error: {}", e),
    }

    println!("\n---\n");

    // Example 2: Install with custom configuration
    println!("Example 2: Installing with custom config (no auto-install in CI)");
    let config = ToolInstallConfig {
        ci_auto_install: false, // Don't auto-install in CI
        interactive: true,      // Still prompt in interactive mode
        install_command: None,  // Use default cargo install
    };

    match ensure_tool_installed(&ctx, "cargo-nextest", Some(config)) {
        Ok(true) => println!("✅ cargo-nextest is available"),
        Ok(false) => println!("❌ Installation was not performed"),
        Err(e) => eprintln!("💥 Error: {}", e),
    }

    println!("\n---\n");

    // Example 3: Install multiple tools at once
    println!("Example 3: Installing multiple security tools");
    let results = ensure_tools_installed(&ctx, common_tools::SECURITY_TOOLS, None)?;

    println!("\nInstallation results:");
    for (tool, success) in results {
        if success {
            println!("  ✅ {}", tool);
        } else {
            println!("  ❌ {}", tool);
        }
    }

    println!("\n---\n");

    // Example 4: Custom installation command
    println!("Example 4: Tool with custom install command");
    let custom_config = ToolInstallConfig {
        ci_auto_install: true,
        interactive: true,
        install_command: Some(vec![
            "cargo".to_string(),
            "install".to_string(),
            "--locked".to_string(),
            "cargo-outdated".to_string(),
        ]),
    };

    match ensure_tool_installed(&ctx, "cargo-outdated", Some(custom_config)) {
        Ok(true) => println!("✅ cargo-outdated is available"),
        Ok(false) => println!("❌ Installation was not performed"),
        Err(e) => eprintln!("💥 Error: {}", e),
    }

    Ok(())
}
