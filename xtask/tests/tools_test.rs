//! Integration tests for tool installation utilities

use anyhow::Result;
use xtask::utils::{Context, ensure_tool_installed};
use xtask::utils::tools::{is_ci_environment, is_tool_installed, ToolInstallConfig};

#[test]
fn test_ci_environment_detection() {
    // Save original value
    let original = std::env::var("CI").ok();
    
    // Test various CI values
    std::env::set_var("CI", "true");
    assert!(is_ci_environment());
    
    std::env::set_var("CI", "1");
    assert!(is_ci_environment());
    
    std::env::set_var("CI", "false");
    assert!(!is_ci_environment());
    
    std::env::remove_var("CI");
    assert!(!is_ci_environment());
    
    // Restore original value
    if let Some(val) = original {
        std::env::set_var("CI", val);
    }
}

#[test]
fn test_tool_detection() {
    // Test with a tool that should exist (cargo itself)
    // Note: We can't test actual tool installation in unit tests
    // This just verifies the detection logic doesn't panic
    let result = is_tool_installed("cargo");
    assert!(result.is_ok());
}

#[test]
fn test_dry_run_mode() -> Result<()> {
    let ctx = Context {
        dry_run: true,
        verbose: false,
    };
    
    // In dry-run mode, this should succeed without actually installing
    let config = ToolInstallConfig {
        ci_auto_install: true,
        interactive: false,
        install_command: None,
    };
    
    // Set CI to avoid prompts
    let original = std::env::var("CI").ok();
    std::env::set_var("CI", "true");
    
    let result = ensure_tool_installed(&ctx, "nonexistent-tool-12345", Some(config))?;
    assert!(result); // Should return true in dry-run mode
    
    // Restore CI variable
    if let Some(val) = original {
        std::env::set_var("CI", val);
    } else {
        std::env::remove_var("CI");
    }
    
    Ok(())
}

#[test]
fn test_no_interactive_no_ci() -> Result<()> {
    let ctx = Context {
        dry_run: false,
        verbose: false,
    };
    
    let config = ToolInstallConfig {
        ci_auto_install: false,
        interactive: false, // No prompts allowed
        install_command: None,
    };
    
    // Ensure we're not in CI
    let original = std::env::var("CI").ok();
    std::env::remove_var("CI");
    
    // This should return false (not installed) without prompting
    let result = ensure_tool_installed(&ctx, "nonexistent-tool-12345", Some(config))?;
    assert!(!result);
    
    // Restore CI variable
    if let Some(val) = original {
        std::env::set_var("CI", val);
    }
    
    Ok(())
}

/// Verify the module follows KindlyGuard standards
#[test]
fn test_kindlyguard_standards() {
    // Read the tools.rs file and verify it doesn't contain unwrap() or expect()
    let tools_content = std::fs::read_to_string("src/utils/tools.rs")
        .expect("Failed to read tools.rs");
    
    // Check for forbidden patterns
    assert!(!tools_content.contains(".unwrap()"), 
            "tools.rs must not use unwrap() - found forbidden pattern");
    assert!(!tools_content.contains(".expect("), 
            "tools.rs must not use expect() - found forbidden pattern");
    
    // Verify it uses Result types
    assert!(tools_content.contains("Result<"), 
            "tools.rs should use Result<T, E> for fallible operations");
    
    // Verify proper error context
    assert!(tools_content.contains("with_context"), 
            "tools.rs should use with_context for error context");
}