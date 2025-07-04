//! Interactive setup utilities for KindlyGuard MCP server
//! 
//! Provides user-friendly terminal interactions for IDE configuration setup.

use std::io::{self, Write};
use crossterm::style::Stylize;
use anyhow::{Result, anyhow};

use super::{IdeType, ConfigFormat};

/// Prompt user to select an IDE from detected options
pub fn prompt_ide_selection(detected_ides: &[IdeType]) -> Result<IdeType> {
    if detected_ides.is_empty() {
        return Err(anyhow!("No IDEs detected"));
    }

    if detected_ides.len() == 1 {
        println!("{}", "Detected IDE:".green().bold());
        println!("  • {}", format_ide_name(&detected_ides[0]).cyan());
        return Ok(detected_ides[0].clone());
    }

    println!("{}", "Multiple IDEs detected:".green().bold());
    println!();
    
    for (i, ide) in detected_ides.iter().enumerate() {
        println!("  {} {} {}", 
            format!("[{}]", i + 1).yellow(),
            "→".dark_grey(),
            format_ide_name(ide).cyan()
        );
    }
    
    println!();
    print!("{} ", "Select IDE (1-{}):".yellow().bold());
    print!("{}", format!("{}", detected_ides.len()).cyan());
    print!(": ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    let choice = input.trim().parse::<usize>()
        .map_err(|_| anyhow!("Invalid selection"))?;
    
    if choice < 1 || choice > detected_ides.len() {
        return Err(anyhow!("Selection out of range"));
    }
    
    Ok(detected_ides[choice - 1].clone())
}

/// Ask for confirmation before writing configuration
pub fn confirm_action(action: &str, path: &str) -> Result<bool> {
    println!();
    println!("{}", "Configuration Preview:".green().bold());
    println!("  {} {}", "Action:".yellow(), action.cyan());
    println!("  {} {}", "Path:".yellow(), path.cyan());
    println!();
    
    print!("{} {} ", 
        "Proceed?".yellow().bold(),
        "[Y/n]".dark_grey()
    );
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    let response = input.trim().to_lowercase();
    Ok(response.is_empty() || response == "y" || response == "yes")
}

/// Display the result of setup with next steps
pub fn show_setup_result(success: bool, ide: &IdeType, config_path: Option<&str>, error: Option<&str>) {
    println!();
    
    if success {
        println!("{}", "✓ Setup completed successfully!".green().bold());
        println!();
        
        if let Some(path) = config_path {
            println!("{}", "Configuration written to:".green());
            println!("  {}", path.cyan());
            println!();
        }
        
        println!("{}", "Next steps:".yellow().bold());
        match ide {
            IdeType::VsCode | IdeType::Cursor => {
                println!("  1. {} {}", "Restart".yellow(), format_ide_name(ide).cyan());
                println!("  2. {} {}", "Open the MCP panel".yellow(), "(View → MCP Servers)".dark_grey());
                println!("  3. {} {}", "KindlyGuard should appear as".yellow(), "\"kindly-guard\"".green());
            }
            IdeType::Zed => {
                println!("  1. {} {}", "Restart".yellow(), "Zed".cyan());
                println!("  2. {} {}", "Check Assistant panel for".yellow(), "KindlyGuard".green());
            }
            IdeType::Neovim => {
                println!("  1. {} {}", "Restart".yellow(), "Neovim".cyan());
                println!("  2. {} {}", "KindlyGuard MCP server is now available to".yellow(), "LSP clients".cyan());
            }
            IdeType::ClaudeDesktop => {
                println!("  1. {} {}", "Restart".yellow(), "Claude Desktop".cyan());
                println!("  2. {} {}", "KindlyGuard will be available in".yellow(), "MCP menu".green());
            }
            IdeType::ClaudeCode => {
                println!("  1. {} {}", "Restart".yellow(), "Claude Code".cyan());
                println!("  2. {} {}", "KindlyGuard will be available in".yellow(), "MCP menu".green());
            }
            IdeType::Unknown => {
                println!("  1. {} {}", "Restart".yellow(), "your IDE".cyan());
                println!("  2. {} {}", "Check MCP configuration".yellow(), "");
            }
        }
        
        println!();
        println!("{}", "Test the connection:".yellow().bold());
        println!("  {}", "kindly-guard test-connection".cyan());
    } else {
        println!("{}", "✗ Setup failed".red().bold());
        if let Some(err) = error {
            println!();
            println!("{} {}", "Error:".red(), err);
        }
        println!();
        println!("{}", "Troubleshooting:".yellow().bold());
        println!("  • {} {}", "Check permissions for".yellow(), "configuration directory".cyan());
        println!("  • {} {}", "Ensure".yellow(), "kindly-guard is in your PATH".cyan());
        println!("  • {} {}", "Try running with".yellow(), "--debug flag".cyan());
    }
    
    println!();
}

/// Format and preview the configuration that will be written
pub fn format_config_preview(ide: &IdeType, format: &ConfigFormat) -> String {
    let mut preview = String::new();
    
    preview.push_str(&format!("{}\n", "Configuration to be generated:".green().bold()));
    preview.push_str(&format!("  {} {}\n", "IDE:".yellow(), format_ide_name(ide).cyan()));
    preview.push_str(&format!("  {} {}\n", "Format:".yellow(), format_config_format(format).cyan()));
    preview.push_str("\n");
    
    preview.push_str(&format!("{}\n", "Sample configuration:".yellow()));
    
    match format {
        ConfigFormat::Json => {
            preview.push_str(&format!("{}\n", r#"{
  "mcpServers": {
    "kindly-guard": {
      "command": "kindly-guard",
      "args": ["--stdio"],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}"#.dark_grey()));
        }
        ConfigFormat::Toml => {
            preview.push_str(&format!("{}\n", r#"[mcpServers.kindly-guard]
command = "kindly-guard"
args = ["--stdio"]

[mcpServers.kindly-guard.env]
RUST_LOG = "info""#.dark_grey()));
        }
        ConfigFormat::Yaml => {
            preview.push_str(&format!("{}\n", r#"mcpServers:
  kindly-guard:
    command: kindly-guard
    args:
      - --stdio
    env:
      RUST_LOG: info"#.dark_grey()));
        }
        ConfigFormat::JsonLocal => {
            preview.push_str(&format!("{}\n", r#"{
  "mcpServers": {
    "kindly-guard": {
      "provider": "stdio",
      "command": "kindly-guard",
      "args": ["--stdio"],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}"#.dark_grey()));
        }
    }
    
    preview
}

/// Show a progress indicator for long operations
pub fn show_progress(message: &str) {
    print!("{} {} ", message.yellow(), "...".dark_grey());
    io::stdout().flush().unwrap_or(());
}

/// Complete a progress indicator
pub fn complete_progress(success: bool) {
    if success {
        println!("{}", "✓".green().bold());
    } else {
        println!("{}", "✗".red().bold());
    }
}

/// Format IDE name for display
fn format_ide_name(ide: &IdeType) -> String {
    match ide {
        IdeType::ClaudeDesktop => "Claude Desktop",
        IdeType::ClaudeCode => "Claude Code",
        IdeType::VsCode => "Visual Studio Code",
        IdeType::Cursor => "Cursor",
        IdeType::Zed => "Zed",
        IdeType::Neovim => "Neovim",
        IdeType::Unknown => "Unknown IDE",
    }.to_string()
}

/// Format config format for display
fn format_config_format(format: &ConfigFormat) -> String {
    match format {
        ConfigFormat::Json => "JSON",
        ConfigFormat::JsonLocal => "JSON (local settings)",
        ConfigFormat::Toml => "TOML", 
        ConfigFormat::Yaml => "YAML",
    }.to_string()
}

/// Print a welcome banner
pub fn print_welcome_banner() {
    println!();
    println!("{}", "╭─────────────────────────────────────╮".dark_grey());
    println!("{} {} {}", "│".dark_grey(), "    KindlyGuard MCP Setup    ".green().bold(), "│".dark_grey());
    println!("{}", "╰─────────────────────────────────────╯".dark_grey());
    println!();
    println!("{}", "This wizard will help you configure KindlyGuard".cyan());
    println!("{}", "for your development environment.".cyan());
    println!();
}

/// Print a section header
pub fn print_section_header(title: &str) {
    println!();
    println!("{} {}", "▶".yellow(), title.white().bold());
    println!("{}", "─".repeat(40).dark_grey());
}

/// Interactive setup wizard that guides users through the process
pub async fn run_setup_wizard(dry_run: bool) -> Result<()> {
    use super::McpDetector;
    
    print_welcome_banner();
    
    // Step 1: Detect IDEs
    print_section_header("Detecting IDEs");
    show_progress("Scanning for installed IDEs");
    
    let detector = McpDetector::new();
    let detected_configs = detector.detect_all().unwrap_or_default();
    let detected_ides: Vec<IdeType> = detected_configs.iter()
        .filter(|c| c.exists)
        .map(|c| c.ide)
        .collect();
    complete_progress(!detected_ides.is_empty());
    
    if detected_ides.is_empty() {
        println!();
        println!("{}", "No supported IDEs detected!".red().bold());
        println!();
        println!("{}", "Supported IDEs:".yellow());
        println!("  • Visual Studio Code");
        println!("  • Cursor");  
        println!("  • Zed");
        println!("  • Neovim");
        return Err(anyhow!("No IDEs detected"));
    }
    
    // Step 2: Select IDE
    print_section_header("IDE Selection");
    let selected_ide = prompt_ide_selection(&detected_ides)?;
    
    // Step 3: Show configuration preview
    print_section_header("Configuration Preview");
    let format = ConfigFormat::Json; // Default to JSON
    println!("{}", format_config_preview(&selected_ide, &format));
    
    // Step 4: Get config path
    let config_path = detector.get_config_path(selected_ide)?;
    let config_path_str = config_path.to_string_lossy();
    
    // Step 5: Confirm action
    let action = if config_path.exists() {
        "Update existing configuration"
    } else {
        "Create new configuration"
    };
    
    if !confirm_action(action, &config_path_str)? {
        println!();
        println!("{}", "Setup cancelled.".yellow());
        return Ok(());
    }
    
    // Step 6: Write configuration
    print_section_header(if dry_run { "Dry Run Preview" } else { "Writing Configuration" });
    
    if dry_run {
        println!("{}", "Would write configuration to:".yellow());
        println!("  {}", config_path_str.cyan());
        show_setup_result(true, &selected_ide, Some(&config_path_str), None);
        return Ok(());
    }
    
    show_progress("Generating configuration file");
    
    use crate::setup::create_config_writer;
    let writer = create_config_writer(&config_path, "kindly-guard");
    let binary_path = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("kindly-guard"));
    let result = writer.write_config(&config_path, &binary_path.display().to_string());
    
    match result {
        Ok(_) => {
            complete_progress(true);
            show_setup_result(true, &selected_ide, Some(&config_path_str), None);
        }
        Err(e) => {
            complete_progress(false);
            show_setup_result(false, &selected_ide, None, Some(&e.to_string()));
            return Err(e);
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_format_ide_name() {
        assert_eq!(format_ide_name(&IdeType::VsCode), "Visual Studio Code");
        assert_eq!(format_ide_name(&IdeType::Cursor), "Cursor");
        assert_eq!(format_ide_name(&IdeType::Zed), "Zed");
        assert_eq!(format_ide_name(&IdeType::Neovim), "Neovim");
    }
    
    #[test]
    fn test_format_config_format() {
        assert_eq!(format_config_format(&ConfigFormat::Json), "JSON");
        assert_eq!(format_config_format(&ConfigFormat::Toml), "TOML");
        assert_eq!(format_config_format(&ConfigFormat::Yaml), "YAML");
    }
    
    #[test]
    fn test_config_preview_format() {
        let preview = format_config_preview(&IdeType::VsCode, &ConfigFormat::Json);
        assert!(preview.contains("kindly-guard"));
        assert!(preview.contains("--stdio"));
        assert!(preview.contains("RUST_LOG"));
    }
}