//! Example demonstrating MCP config writer usage

use anyhow::Result;
use kindly_guard_server::setup::{create_config_writer, ConfigWriter, JsonConfigWriter, JsonLocalConfigWriter};
use std::path::Path;
use tempfile::TempDir;

fn main() -> Result<()> {
    // Create a temporary directory for the example
    let temp_dir = TempDir::new()?;
    
    // Example 1: Write a standard JSON config
    println!("Example 1: Standard JSON config");
    let json_path = temp_dir.path().join("claude_desktop_config.json");
    let json_writer = JsonConfigWriter::new("kindly-guard");
    json_writer.write_config(&json_path, "/usr/local/bin/kindly-guard")?;
    
    let content = std::fs::read_to_string(&json_path)?;
    println!("Created config at: {}", json_path.display());
    println!("{}", content);
    println!();
    
    // Example 2: Write a local settings JSON config
    println!("Example 2: Local settings JSON config");
    let local_path = temp_dir.path().join("settings.local.json");
    let local_writer = JsonLocalConfigWriter::new("kindly-guard");
    local_writer.write_config(&local_path, "/usr/local/bin/kindly-guard")?;
    
    let content = std::fs::read_to_string(&local_path)?;
    println!("Created config at: {}", local_path.display());
    println!("{}", content);
    println!();
    
    // Example 3: Use the factory function
    println!("Example 3: Using factory function");
    let auto_path = temp_dir.path().join("auto_detect.json");
    let auto_writer = create_config_writer(&auto_path, "kindly-guard");
    auto_writer.write_config(&auto_path, "/usr/local/bin/kindly-guard")?;
    
    // Example 4: Update existing config
    println!("Example 4: Updating existing config");
    let existing_config = r#"{
  "mcpServers": {
    "other-server": {
      "command": "/path/to/other",
      "args": []
    }
  }
}"#;
    
    let update_path = temp_dir.path().join("existing.json");
    std::fs::write(&update_path, existing_config)?;
    
    let updater = JsonConfigWriter::new("kindly-guard");
    updater.write_config(&update_path, "/usr/local/bin/kindly-guard")?;
    
    let updated = std::fs::read_to_string(&update_path)?;
    println!("Updated config at: {}", update_path.display());
    println!("{}", updated);
    println!("Note: Original 'other-server' is preserved!");
    
    Ok(())
}