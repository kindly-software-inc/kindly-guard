//! Example demonstrating MCP configuration detection
//! 
//! Run with: cargo run --example detect_mcp

use kindly_guard_server::setup::{McpDetector, IdeType};
use anyhow::Result;

fn main() -> Result<()> {
    // Initialize logging using kindly-guard's logging system
    kindly_guard_server::logging::init_logging("debug");
    
    println!("KindlyGuard MCP Configuration Detector");
    println!("=====================================\n");
    
    // Create detector
    let detector = McpDetector::new();
    
    // Detect active IDE
    println!("Detecting active IDE...");
    match detector.detect_active_ide() {
        Ok(ide) => {
            println!("✓ Active IDE: {}", ide.as_str());
            
            // Try to get the primary config path for this IDE
            if ide != IdeType::Unknown {
                match detector.get_config_path(ide) {
                    Ok(path) => println!("  Primary config location: {}", path.display()),
                    Err(e) => println!("  Error getting config path: {}", e),
                }
            }
        }
        Err(e) => println!("✗ Error detecting IDE: {}", e),
    }
    
    println!("\n{}", "-".repeat(50));
    
    // Detect all configurations
    println!("\nScanning for MCP configurations...\n");
    
    match detector.detect_all() {
        Ok(configs) => {
            println!("Found {} potential config locations:", configs.len());
            
            // Group by IDE
            let mut by_ide = std::collections::HashMap::new();
            for config in &configs {
                by_ide.entry(config.ide).or_insert_with(Vec::new).push(config);
            }
            
            // Display grouped results
            for (ide, ide_configs) in by_ide {
                println!("\n{}:", ide.as_str());
                for config in ide_configs {
                    let status = if config.exists { "✓" } else { "✗" };
                    println!("  {} {:?} - {}", 
                        status,
                        config.format,
                        config.path.display()
                    );
                }
            }
            
            // Summary of existing configs
            let existing: Vec<_> = configs.iter().filter(|c| c.exists).collect();
            println!("\n{}", "-".repeat(50));
            println!("\nSummary:");
            println!("  Total locations checked: {}", configs.len());
            println!("  Existing configurations: {}", existing.len());
            
            if !existing.is_empty() {
                println!("\nExisting configuration files:");
                for config in existing {
                    println!("  - {} ({}): {}", 
                        config.ide.as_str(),
                        config.format.extension(),
                        config.path.display()
                    );
                }
            }
        }
        Err(e) => println!("Error scanning configurations: {}", e),
    }
    
    // Check for specific server
    println!("\n{}", "-".repeat(50));
    println!("\nChecking for kindly-guard server configuration...");
    
    match detector.is_server_configured("kindly-guard") {
        Ok(true) => println!("✓ kindly-guard is configured in at least one MCP config"),
        Ok(false) => println!("✗ kindly-guard is not configured in any MCP config"),
        Err(e) => println!("Error checking server configuration: {}", e),
    }
    
    // Get full status summary
    println!("\n{}", "-".repeat(50));
    println!("\nFull Status Report:");
    println!("{}", "-".repeat(50));
    
    match detector.get_status_summary() {
        Ok(summary) => print!("{}", summary),
        Err(e) => println!("Error generating status summary: {}", e),
    }
    
    Ok(())
}